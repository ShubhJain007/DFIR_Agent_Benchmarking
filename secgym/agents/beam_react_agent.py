# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Beam Search ReAct Agent: maintains n parallel think chains (beams),
scores candidate actions with a separate LLM, and selects the best action
at each step.
"""

import copy
from autogen import OpenAIWrapper
from secgym.agents.agent_utils import (
    sql_parser, msging, call_llm, call_llm_foundry, update_model_usage
)
from secgym.agents.react_agent import BASE_PROMPT, O1_PROMPT
import os
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential

SCORER_PROMPT = """You are an expert evaluator for security investigation actions.
Given a security investigation question, the conversation history so far, and a list of candidate actions (SQL queries or submit answers), score each action on a scale of 1-10 based on:
1. Relevance: Does the action help answer the question?
2. Informativeness: Will the action reveal useful new information?
3. Efficiency: Is this a well-formed, non-redundant query?
4. Progress: Does it build logically on previous observations?

You must respond in the following JSON format exactly:
{"scores": [<score1>, <score2>, ...], "best_index": <0-based index of best action>, "reasoning": "<brief explanation>"}

Only output the JSON, nothing else."""


class BeamSearchReActAgent:
    """
    Beam Search variant of ReActAgent.

    Maintains `beam_width` parallel conversation histories. At each step:
    1. All beams independently generate thought + action via the base LLM.
    2. A scorer LLM evaluates and ranks the candidate actions.
    3. The top-1 action is returned to the environment.
    4. All beams receive the same observation, but only the beam that
       proposed the chosen action keeps its original message history;
       other beams get the chosen thought+action injected.
    """

    def __init__(
        self,
        config_list,
        scorer_config_list=None,
        cache_seed=41,
        max_steps=15,
        submit_summary=False,
        temperature=0.7,
        beam_width=3,
        retry_num=10,
        retry_wait_time=5,
    ):
        self.config_list = config_list
        self.scorer_config_list = scorer_config_list or config_list
        self.temperature = temperature
        self.cache_seed = cache_seed
        self.beam_width = beam_width
        self.max_steps = max_steps
        self.submit_summary = submit_summary
        self.retry_num = retry_num
        self.retry_wait_time = retry_wait_time
        self.totoal_usage = {}

        # Build system prompt
        self.sys_prompt = BASE_PROMPT
        if any(k in config_list[0]['model'] for k in ("o1", "o3", "r1")):
            self.sys_prompt = O1_PROMPT

        # Initialize base LLM client
        self.client = self._make_client(config_list)
        # Initialize scorer LLM client
        self.scorer_client = self._make_client(self.scorer_config_list)

        # Each beam is a separate message history
        self.beams = [
            [{"role": "system", "content": self.sys_prompt}]
            for _ in range(self.beam_width)
        ]
        self.step_count = 0

    def _make_client(self, cfg):
        if "ai_foundry" in cfg[0]['api_type']:
            from secgym.config_key import api_key
            return ChatCompletionsClient(
                endpoint=cfg[0]['endpoint'],
                credential=AzureKeyCredential(api_key),
                seed=self.cache_seed,
            )
        elif "azure" in cfg[0]['api_type']:
            return OpenAIWrapper(config_list=cfg, cache_seed=self.cache_seed)
        else:
            raise ValueError(f"Unsupported api_type: {cfg[0]['api_type']}")

    @property
    def name(self):
        return "BeamSearchReActAgent"

    # ── LLM call helpers ────────────────────────────────────────────

    def _call_llm(self, messages, config_list=None, client=None, temperature=None):
        cfg = config_list or self.config_list
        cli = client or self.client
        temp = temperature if temperature is not None else self.temperature

        if "azure" in cfg[0]['api_type']:
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
        elif "ai_foundry" in cfg[0]['api_type']:
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
        return response.choices[0].message.content

    def _call_scorer(self, messages):
        """Call the scorer LLM (no stop tokens, expects JSON)."""
        cfg = self.scorer_config_list
        cli = self.scorer_client

        if "azure" in cfg[0]['api_type']:
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
        elif "ai_foundry" in cfg[0]['api_type']:
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
        return response.choices[0].message.content

    # ── Core logic ──────────────────────────────────────────────────

    def _parse_response(self, response):
        """Parse LLM response into (thought, action) strings."""
        split_str = "\nAction:"
        if "**Action:**" in response:
            split_str = "\n**Action:**"
        try:
            thought, action = response.strip().split(split_str)
            return thought.strip(), action.strip(), response.strip()
        except ValueError:
            # Could not split — treat entire response as thought
            return response.strip(), None, response.strip()

    def _generate_candidates(self, observation):
        """Generate a thought+action candidate from each beam."""
        candidates = []  # list of (thought, action_str, full_response, beam_idx)
        for i, beam in enumerate(self.beams):
            beam.append(msging(observation, role="user"))
            response = self._call_llm(beam)
            print(f"[Beam {i}] {response}")

            thought, action, full_resp = self._parse_response(response)

            if action is None:
                # Retry: ask LLM to complete the action
                retry_resp = self._call_llm(
                    beam + [msging(f"{thought}\nAction:")]
                )
                action = retry_resp.strip()
                if "Thought" not in thought:
                    thought = f"Thought: {thought}"
                full_resp = f"{thought}\nAction:{action}"

            candidates.append((thought, action, full_resp, i))
        return candidates

    def _score_candidates(self, candidates):
        """Use scorer LLM to pick the best candidate action."""
        import json

        if len(candidates) == 1:
            return 0

        # Build context: use beam 0's history (minus last user msg) as shared context
        history_summary = ""
        for msg in self.beams[0][1:-1]:  # skip system prompt and last observation
            role = msg["role"]
            content = msg["content"][:500]  # truncate for scorer
            history_summary += f"{role}: {content}\n"

        action_list = ""
        for idx, (thought, action, _, _) in enumerate(candidates):
            action_list += f"\nCandidate {idx}:\nThought: {thought[:300]}\nAction: {action}\n"

        scorer_messages = [
            {"role": "system", "content": SCORER_PROMPT},
            {"role": "user", "content": (
                f"Conversation history:\n{history_summary}\n\n"
                f"Candidate actions:\n{action_list}\n\n"
                f"Score each candidate and select the best one."
            )},
        ]

        scorer_response = self._call_scorer(scorer_messages)
        print(f"[Scorer] {scorer_response}")

        try:
            result = json.loads(scorer_response)
            best_idx = int(result["best_index"])
            if 0 <= best_idx < len(candidates):
                return best_idx
        except (json.JSONDecodeError, KeyError, ValueError):
            # Fallback: try to extract best_index from response
            import re
            match = re.search(r'"best_index"\s*:\s*(\d+)', scorer_response)
            if match:
                best_idx = int(match.group(1))
                if 0 <= best_idx < len(candidates):
                    return best_idx

        # Default to first candidate if scoring fails
        return 0

    def act(self, observation: str):
        """
        Main interface — same signature as ReActAgent.act().
        Returns (parsed_action, submit).
        """
        # Handle max-step summary prompt
        if self.step_count >= self.max_steps - 1 and self.submit_summary:
            summary_prompt = (
                "You have reached maximum number of steps. "
                "Please summarize your findings of key information, and submit them."
            )
            for beam in self.beams:
                beam.append(msging(summary_prompt, role="system"))

        # 1. Generate candidates from all beams
        candidates = self._generate_candidates(observation)

        # 2. Score and select best
        best_idx = self._score_candidates(candidates)
        best_thought, best_action, best_full_resp, best_beam = candidates[best_idx]

        print(f"[BeamSearch] Selected beam {best_beam}, action: {best_action}")
        print("*" * 50)

        # 3. Update all beams:
        #    - The winning beam keeps its own response
        #    - Other beams get the winning response injected
        for i, beam in enumerate(self.beams):
            if i == best_beam:
                beam.append(msging(best_full_resp, role="assistant"))
            else:
                # Remove the user observation we appended in _generate_candidates
                # (it's already there), and add the winning assistant response
                beam.append(msging(best_full_resp, role="assistant"))

        self.step_count += 1
        parsed_action, is_code, submit = sql_parser(best_action)
        return parsed_action, submit

    # ── Logging / Reset ─────────────────────────────────────────────

    @property
    def messages(self):
        """Return the first beam's messages for compatibility with logging."""
        return self.beams[0]

    def get_logging(self):
        return {
            "messages": self.beams[0],
            "all_beams": [beam.copy() for beam in self.beams],
            "usage_summary": self.totoal_usage,
        }

    def reset(self, change_seed=True):
        if change_seed:
            self.cache_seed += 1

        self.client = self._make_client(self.config_list)
        self.scorer_client = self._make_client(self.scorer_config_list)

        self.step_count = 0
        self.sys_prompt = BASE_PROMPT
        if any(k in self.config_list[0]['model'] for k in ("o1", "o3", "r1")):
            self.sys_prompt = O1_PROMPT

        self.beams = [
            [{"role": "system", "content": self.sys_prompt}]
            for _ in range(self.beam_width)
        ]
        self.totoal_usage = {}
