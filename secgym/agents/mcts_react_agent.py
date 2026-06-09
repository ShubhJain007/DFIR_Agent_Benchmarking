# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
MCTS ReAct Agent: Uses Monte Carlo Tree Search to select the best action
at each step. Maintains a search tree where each node represents a
conversation state, uses UCB1 for selection, LLM for expansion, and a
scorer LLM for value estimation (simulated rollout replacement).

Unlike beam search which advances all beams in lockstep, MCTS explores a
tree of possible action sequences with exploration-exploitation tradeoffs.
"""

import copy
import math
import json
import re
from autogen import OpenAIWrapper
from secgym.agents.agent_utils import (
    sql_parser, msging, call_llm, call_llm_foundry, update_model_usage
)
from secgym.agents.react_agent import BASE_PROMPT, O1_PROMPT
import os
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

BETTER_SYSTEM_PROMPT = """You're a DFIR analyst hunting threats in a MySQL security log database. You're methodical, skeptical, and you never guess. You chase evidence until you find it or exhaust every option.

### 📊 SCHEMA — MEMORISE THESE COLUMNS
- **AlertInfo**: AlertId, Title, Category, Severity, ServiceSource, DetectionSource, AttackTechniques, Timestamp
- **AlertEvidence**: AlertId, EntityType, EvidenceRole, FileName, FolderPath, RemoteIP, RemoteUrl, AccountName, DeviceName, ProcessCommandLine, AdditionalFields, RegistryKey, RegistryValueData
- **DeviceProcessEvents**: Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ProcessId
- **DeviceNetworkEvents**: Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort

### ⚖️ LAWS — FOLLOW THESE OR YOU WILL FAIL
1. **NO GUESSING**: Only use columns listed above. Unknown column? Run DESCRIBE [table].
2. **JSON FALLBACK**: Any field NULL/empty in AlertEvidence? Run JSON_EXTRACT(AdditionalFields, '$.IpAddress'), JSON_EXTRACT(AdditionalFields, '$.Url'), JSON_EXTRACT(AdditionalFields, '$.Address') — mandatory, not optional. AdditionalFields can be base64 or double-encoded too.
3. **TIMESTAMP FIRST**: Get alert Timestamp from AlertInfo BEFORE touching any Device* table. Never assume a date.
4. **ENTITY PIVOTING**: DeviceName, AccountName, RemoteIP live in AlertEvidence. Get them there first, then pivot to Device* tables.
5. **SELECTION VALIDATION**: Multiple results? Cross-check each one's Timestamp against the alert Timestamp. Closest match wins — not first result.
6. **IOC CHAINING**: Found an IP, URL, hash, or filename? Hunt it across every relevant table.
7. **ATTACK CHAIN**: Think kill-chain. Process execution found? Also check RegistryKey (persistence), repeated AccountName across devices (lateral movement), outbound RemoteIP/RemoteUrl (exfil).

### 🚫 NEVER DO THESE
1. Query DeviceProcessEvents or DeviceNetworkEvents without a Timestamp BETWEEN filter.
2. Guess or assume a timestamp — always query AlertInfo first.
3. Submit "unable to find" without first running JSON_EXTRACT on AdditionalFields.
4. Pick from multiple results by position. Validate by Timestamp proximity.
5. Give up and guess. Stuck? Dump AdditionalFields raw, try ProcessCommandLine LIKE '%keyword%', try a different AlertId.
6. Go to Device* tables for DeviceName when AlertEvidence already has it for that AlertId.

### INVESTIGATION ORDER — EVERY SINGLE TIME
1. SELECT AlertId, Timestamp, Title FROM AlertInfo WHERE Title LIKE '%keyword%'
2. SELECT DeviceName, AccountName, RemoteUrl, RemoteIP, ProcessCommandLine, AdditionalFields FROM AlertEvidence WHERE AlertId = '[id]'
3. Any NULL/empty → JSON_EXTRACT on AdditionalFields immediately
4. Device* tables ONLY with Timestamp BETWEEN '[AlertTime-10m]' AND '[AlertTime+10m]'
5. Multiple results → validate against alert Timestamp
6. Still stuck → ProcessCommandLine LIKE '%keyword%', check RegistryKey, broaden Timestamp range

Format:
Thought: <what you know, what's missing, your next hypothesis>
Action: execute[SQL] or submit[answer]

One thought-action per response. Never invent data not in the logs.
"""

# Load law-demonstrating examples from multi_agent/law_examples/
_law_examples_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "multi_agent", "law_examples")
_law_files = ["law_2_json_fallback.txt", "law_4_entity_pivoting.txt", "law_3_timeline_precision.txt"]
if os.path.exists(_law_examples_path):
    for _f in _law_files:
        _fp = os.path.join(_law_examples_path, _f)
        if os.path.exists(_fp):
            with open(_fp) as _fh:
                BETTER_SYSTEM_PROMPT += "\n" + _fh.read() + "\n" + "-"*50
    BETTER_SYSTEM_PROMPT = BETTER_SYSTEM_PROMPT[:-50].strip()


VALUE_PROMPT = """You are an expert evaluator for security investigation actions.
Given a security investigation question and the conversation trajectory so far
(including the latest action that is about to be executed), estimate the
probability (0.0 to 1.0) that this trajectory will eventually lead to the
correct answer.

Consider:
1. Is the investigation on the right track?
2. Is useful information being gathered progressively?
3. Are the SQL queries well-formed and relevant?
4. How much progress has been made toward answering the question?

You must respond in the following JSON format exactly:
{"value": <float between 0.0 and 1.0>, "reasoning": "<brief explanation>"}

Only output the JSON, nothing else."""


class MCTSNode:
    """A node in the MCTS search tree."""

    def __init__(self, messages, thought=None, action=None, full_response=None, parent=None):
        self.messages = messages          # conversation history at this node
        self.thought = thought            # thought that led to this node
        self.action = action              # action string (e.g. "execute[...]")
        self.full_response = full_response  # full LLM response
        self.parent = parent
        self.children = []
        self.visits = 0
        self.total_value = 0.0

    @property
    def q_value(self):
        """Average value of this node."""
        if self.visits == 0:
            return 0.0
        return self.total_value / self.visits

    def ucb1(self, exploration_weight=1.414):
        """Upper Confidence Bound score for selection."""
        if self.visits == 0:
            return float('inf')  # unexplored nodes have highest priority
        parent_visits = self.parent.visits if self.parent else self.visits
        exploitation = self.q_value
        exploration = exploration_weight * math.sqrt(math.log(parent_visits) / self.visits)
        return exploitation + exploration

    def best_child_ucb(self, exploration_weight=1.414):
        """Select child with highest UCB1 score."""
        return max(self.children, key=lambda c: c.ucb1(exploration_weight))

    def best_child_value(self):
        """Select child with highest average value (for final selection)."""
        return max(self.children, key=lambda c: c.q_value)

    def is_leaf(self):
        return len(self.children) == 0


class MCTSReActAgent:
    """
    MCTS variant of ReActAgent.

    At each environment step, runs a mini MCTS with `n_simulations`
    iterations to select the best action:

    1. SELECT:  Walk down the tree using UCB1 until a leaf node.
    2. EXPAND:  Generate `expand_width` candidate actions from the leaf's
                conversation state using the base LLM (with temperature
                for diversity).
    3. EVALUATE: Use a scorer LLM to estimate the value of each new child
                 node (replaces expensive rollout simulations).
    4. BACKPROP: Propagate the value estimate up to the root.

    After all simulations, pick the root's child with the highest average
    value and return its action to the environment.

    The conversation history is then updated with the chosen action, and
    the next observation feeds back into the next `act()` call.
    """

    def __init__(
        self,
        config_list,
        scorer_config_list=None,
        cache_seed=41,
        max_steps=15,
        submit_summary=False,
        temperature=0.7,
        n_simulations=6,
        expand_width=3,
        exploration_weight=1.414,
        retry_num=10,
        retry_wait_time=5,
    ):
        self.config_list = config_list
        self.scorer_config_list = scorer_config_list or config_list
        self.temperature = temperature
        self.cache_seed = cache_seed
        self.n_simulations = n_simulations
        self.expand_width = expand_width
        self.exploration_weight = exploration_weight
        self.max_steps = max_steps
        self.submit_summary = submit_summary
        self.retry_num = retry_num
        self.retry_wait_time = retry_wait_time
        self.totoal_usage = {}

        # Build system prompt
        self.sys_prompt = BETTER_SYSTEM_PROMPT
        if any(k in config_list[0]['model'] for k in ("o1", "o3", "r1")):
            self.sys_prompt = O1_PROMPT

        # Initialize LLM clients
        self.client = self._make_client(config_list)
        self.scorer_client = self._make_client(self.scorer_config_list)

        # Main conversation history (updated after each act())
        self._messages = [{"role": "system", "content": self.sys_prompt}]
        self.step_count = 0

    def _make_client(self, cfg):
            # Safety Check: If cfg is a single dict, wrap it in a list
            if isinstance(cfg, dict):
                cfg = [cfg]
                
            # Safety Check: If cfg is None or empty, raise clear error
            if not cfg:
                raise ValueError("Client config list is empty or None.")

            # Get API type, defaulting to 'openai' if missing
            api_type = cfg[0].get('api_type', 'openai')
            
            # Normalize to lower case for comparison if it's a string
            if isinstance(api_type, str):
                api_type = api_type.lower()
            else:
                api_type = "openai" # Fallback

            if "ai_foundry" in api_type:
                from secgym.config_key import api_key
                return ChatCompletionsClient(
                    endpoint=cfg[0]['endpoint'],
                    credential=AzureKeyCredential(api_key),
                    seed=self.cache_seed,
                )
            elif "azure" in api_type or "openai" in api_type:
                return OpenAIWrapper(config_list=cfg, cache_seed=self.cache_seed)
            else:
                # Fallback for other types that OpenAIWrapper might handle (e.g. 'ollama')
                print(f"Warning: Unknown api_type '{api_type}', defaulting to OpenAIWrapper")
                return OpenAIWrapper(config_list=cfg, cache_seed=self.cache_seed)

    @property
    def name(self):
        return "MCTSReActAgent"

    # ── LLM call helpers ────────────────────────────────────────────

    def _call_llm(self, messages, config_list=None, client=None, temperature=None):
            cfg = config_list or self.config_list
            cli = client or self.client
            temp = temperature if temperature is not None else self.temperature
            
            # safely get api_type string
            api_type = cfg[0].get('api_type', 'openai').lower()

            # FIX: Check for "openai" here to ensure response is created
            if "azure" in api_type or "openai" in api_type:
                response = call_llm(
                    client=cli, model=cfg[0]['model'],
                    messages=messages, retry_num=self.retry_num,
                    retry_wait_time=self.retry_wait_time,
                    temperature=temp,
                    stop=["Observation:", "observation:"],
                )
                update_model_usage(
                    self.totoal_usage, model_name=response.model,
                    usage_dict=response.usage.model_dump(),
                )
            elif "ai_foundry" in api_type:
                response = call_llm_foundry(
                    client=cli, model=cfg[0]['model'],
                    messages=messages, retry_num=self.retry_num,
                    retry_wait_time=self.retry_wait_time,
                    temperature=temp,
                    stop=["Observation:", "observation:"],
                )
                update_model_usage(
                    self.totoal_usage, model_name=response.model,
                    usage_dict=response.usage.as_dict(),
                )
            else:
                 # Fallback for unknown types to prevent UnboundLocalError
                 raise ValueError(f"Unsupported api_type in _call_llm: {api_type}")

            return response.choices[0].message.content

    def _call_value_estimator(self, messages):
            """Call the scorer LLM to estimate trajectory value."""
            cfg = self.scorer_config_list
            cli = self.scorer_client
            
            # safely get api_type string
            api_type = cfg[0].get('api_type', 'openai').lower()

            # FIX: Check for "openai" here too
            if "azure" in api_type or "openai" in api_type:
                response = call_llm(
                    client=cli, model=cfg[0]['model'],
                    messages=messages, retry_num=self.retry_num,
                    retry_wait_time=self.retry_wait_time,
                    temperature=0,
                    stop=None,
                )
                update_model_usage(
                    self.totoal_usage, model_name=response.model,
                    usage_dict=response.usage.model_dump(),
                )
            elif "ai_foundry" in api_type:
                response = call_llm_foundry(
                    client=cli, model=cfg[0]['model'],
                    messages=messages, retry_num=self.retry_num,
                    retry_wait_time=self.retry_wait_time,
                    temperature=0,
                    stop=None,
                )
                update_model_usage(
                    self.totoal_usage, model_name=response.model,
                    usage_dict=response.usage.as_dict(),
                )
            else:
                 raise ValueError(f"Unsupported api_type in _call_value_estimator: {api_type}")

            return response.choices[0].message.content

    # ── Response parsing ────────────────────────────────────────────

    def _parse_response(self, response):
        """Parse LLM response into (thought, action, full_response)."""
        split_str = "\nAction:"
        if "**Action:**" in response:
            split_str = "\n**Action:**"
        try:
            thought, action = response.strip().split(split_str)
            return thought.strip(), action.strip(), response.strip()
        except ValueError:
            return response.strip(), None, response.strip()

    # ── MCTS core ───────────────────────────────────────────────────

    def _expand(self, node):
        """
        Expand a leaf node by generating `expand_width` candidate actions.
        Returns the list of new child nodes.
        """
        new_children = []
        for i in range(self.expand_width):
            # Generate a candidate from this node's conversation state
            response = self._call_llm(node.messages)
            thought, action, full_resp = self._parse_response(response)

            if action is None:
                # Retry to get action
                retry_resp = self._call_llm(
                    node.messages + [msging(f"{thought}\nAction:")]
                )
                action = retry_resp.strip()
                if "Thought" not in thought:
                    thought = f"Thought: {thought}"
                full_resp = f"{thought}\nAction:{action}"

            # Build child's message history
            child_messages = node.messages.copy()
            child_messages.append(msging(full_resp, role="assistant"))

            child = MCTSNode(
                messages=child_messages,
                thought=thought,
                action=action,
                full_response=full_resp,
                parent=node,
            )
            node.children.append(child)
            new_children.append(child)

            print(f"  [MCTS Expand {i}] {action[:100]}...")

        return new_children

    def _evaluate(self, node):
        """
        Estimate the value of a node using the scorer LLM.
        This replaces the traditional MCTS rollout/simulation phase.
        """
        # Build a trajectory summary for the value estimator
        trajectory = ""
        for msg in node.messages[1:]:  # skip system prompt
            role = msg["role"]
            content = msg["content"][:500]
            trajectory += f"{role}: {content}\n"

        value_messages = [
            {"role": "system", "content": VALUE_PROMPT},
            {"role": "user", "content": (
                f"Investigation trajectory:\n{trajectory}\n\n"
                f"Estimate the value (probability of eventually reaching the correct answer)."
            )},
        ]

        response = self._call_value_estimator(value_messages)

        try:
            result = json.loads(response)
            value = float(result["value"])
            value = max(0.0, min(1.0, value))  # clamp
            return value
        except (json.JSONDecodeError, KeyError, ValueError):
            # Fallback: try to extract value
            match = re.search(r'"value"\s*:\s*([\d.]+)', response)
            if match:
                value = float(match.group(1))
                return max(0.0, min(1.0, value))
            return 0.5  # neutral default

    def _backpropagate(self, node, value):
        """Propagate value estimate up the tree."""
        current = node
        while current is not None:
            current.visits += 1
            current.total_value += value
            current = current.parent

    def _select(self, node):
        """Walk down the tree using UCB1 until we reach a leaf."""
        current = node
        while not current.is_leaf():
            current = current.best_child_ucb(self.exploration_weight)
        return current

    def _run_mcts(self, root):
        """
        Run `n_simulations` iterations of MCTS from the root.
        Each iteration: SELECT → EXPAND → EVALUATE → BACKPROP.
        """
        for sim in range(self.n_simulations):
            print(f"[MCTS Simulation {sim + 1}/{self.n_simulations}]")

            # 1. SELECT: walk to a leaf
            leaf = self._select(root)

            # 2. EXPAND: generate children if this is a fresh leaf
            #    (only expand if it's been visited before OR it's the root)
            if leaf.visits > 0 or leaf is root:
                new_children = self._expand(leaf)

                # 3. EVALUATE each new child and BACKPROP
                for child in new_children:
                    value = self._evaluate(child)
                    print(f"  [MCTS Value] action={child.action[:80]}... → value={value:.3f}")
                    self._backpropagate(child, value)
            else:
                # Node hasn't been visited yet — just evaluate and backprop
                value = self._evaluate(leaf)
                self._backpropagate(leaf, value)

        # Print tree summary
        print(f"\n[MCTS Tree Summary] Root visits={root.visits}")
        for i, child in enumerate(root.children):
            print(f"  Child {i}: visits={child.visits}, Q={child.q_value:.3f}, "
                  f"action={child.action[:80]}...")

    # ── Main interface ──────────────────────────────────────────────

    def act(self, observation: str):
        """
        Main interface — same signature as ReActAgent.act().
        Returns (parsed_action, submit).
        """
        # Add observation to main history
        self._messages.append(msging(observation, role="user"))

        # Handle max-step summary
        if self.step_count >= self.max_steps - 1 and self.submit_summary:
            summary_prompt = (
                "You have reached maximum number of steps. "
                "Please summarize your findings of key information, and submit them."
            )
            self._messages.append(msging(summary_prompt, role="system"))

        # Build root node from current conversation state
        root = MCTSNode(messages=self._messages.copy())

        # Run MCTS
        self._run_mcts(root)

        # Select best child by highest average value (exploitation only)
        if not root.children:
            # Fallback: shouldn't happen, but generate one action directly
            response = self._call_llm(self._messages)
            thought, action, full_resp = self._parse_response(response)
            if action is None:
                action = "submit[Unable to determine]"
                full_resp = f"Thought: Could not parse action\nAction:{action}"
            self._messages.append(msging(full_resp, role="assistant"))
            self.step_count += 1
            parsed_action, is_code, submit = sql_parser(action)
            return parsed_action, submit

        best_child = root.best_child_value()
        print(f"\n[MCTS] Selected action (Q={best_child.q_value:.3f}, "
              f"visits={best_child.visits}): {best_child.action}")
        print("*" * 50)

        # Update main conversation history with chosen action
        self._messages.append(msging(best_child.full_response, role="assistant"))

        self.step_count += 1
        parsed_action, is_code, submit = sql_parser(best_child.action)
        return parsed_action, submit

    # ── Logging / Reset ─────────────────────────────────────────────

    @property
    def messages(self):
        """Return messages for compatibility with logging."""
        return self._messages

    def get_logging(self):
        return {
            "messages": self._messages,
            "usage_summary": self.totoal_usage,
        }

    def reset(self, change_seed=True):
        if change_seed:
            self.cache_seed += 1

        self.client = self._make_client(self.config_list)
        self.scorer_client = self._make_client(self.scorer_config_list)

        self.step_count = 0
        self.sys_prompt = BETTER_SYSTEM_PROMPT
        if any(k in self.config_list[0]['model'] for k in ("o1", "o3", "r1")):
            self.sys_prompt = O1_PROMPT

        self._messages = [{"role": "system", "content": self.sys_prompt}]
        self.totoal_usage = {}
