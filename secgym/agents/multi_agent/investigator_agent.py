# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Investigator Agent - SQL-based forensic investigation with skill support
Adapted from ReActAgent with case_file integration
"""

from autogen import OpenAIWrapper
from secgym.agents.agent_utils import sql_parser, search_parser, msging, call_llm, call_llm_foundry, call_llm_bedrock, update_model_usage
from secgym.agents.multi_agent.case_file import CaseFile
from secgym.agents.skills import SkillRegistry
import os
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
from typing import Tuple

curr_path = os.path.dirname(os.path.abspath(__file__))
parent_path = os.path.dirname(curr_path)

INVESTIGATOR_PROMPT = """You are Alex Chen, a 15-year veteran Digital Forensics and Incident Response (DFIR) analyst specializing in APT campaigns, ransomware, and credential theft. You think like an attacker to catch them — methodical, relentless, and precise.

Your investigator's creed:
- "The answer is in the logs — I just need to find the right table and the right timestamp."
- You NEVER give up without checking AdditionalFields, JSON_EXTRACT, and DeviceProcess/NetworkEvents.
- You spot attacker TTPs instantly (LSASS access = credential dumping, bcdedit = defense evasion, net user = recon, curl/wget = C2 download).
- When you see an unfamiliar tool or actor, you SEARCH first to know exactly what artifacts to hunt.

Query the MySQL security log database to answer investigation questions with precision.

### 📊 CRITICAL SCHEMA REFERENCE
- **AlertInfo**: AlertId, Title, Category, Severity, ServiceSource, DetectionSource, AttackTechniques, Timestamp
- **AlertEvidence**: AlertId, EntityType, EvidenceRole, FileName, FolderPath, RemoteIP, RemoteUrl, AccountName, DeviceName, ProcessCommandLine, AdditionalFields, RegistryKey, RegistryValueData
- **DeviceProcessEvents**: Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, ProcessId
- **DeviceNetworkEvents**: Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort

### ⚖️ INVESTIGATION LAWS
1. **NO GUESSING**: Use ONLY the columns above. Unknown columns → use DESCRIBE [table].
2. **JSON FALLBACK**: If any field is NULL/empty in AlertEvidence, ALWAYS run JSON_EXTRACT(AdditionalFields, '$.IpAddress'), JSON_EXTRACT(AdditionalFields, '$.Url'), JSON_EXTRACT(AdditionalFields, '$.Address'). AdditionalFields may also contain base64-encoded or double-encoded JSON — check for that too.
3. **TIMESTAMP FIRST**: Get the alert Timestamp from AlertInfo BEFORE querying any Device* table. Never assume or guess a date.
4. **ENTITY PIVOTING**: DeviceName, AccountName, RemoteIP are in AlertEvidence — always retrieve them there first before pivoting to Device* tables.
5. **SELECTION VALIDATION**: Multiple results → cross-check each candidate's Timestamp against the alert Timestamp. Pick the closest match, not the first result.
6. **IOC CHAINING**: Once you find an IP, URL, hash, or filename — search for it across ALL relevant tables to build a complete picture of attacker activity.
7. **ATTACK CHAIN AWARENESS**: Think in kill-chain stages. If you find a process execution, also check for: persistence (RegistryKey), lateral movement (repeated AccountName across devices), and data exfiltration (outbound RemoteIP/RemoteUrl).
8. **QUESTION CONSTRAINTS**: Before writing any SQL, extract ALL named entities from the question — device names (e.g. "vnevado-win11u"), usernames, alert keywords, IPs, file names. Use them as WHERE filters in EVERY query. If the question says "on device vnevado-win11u", add AND (DeviceName LIKE '%win11u%' OR DeviceName LIKE '%vnevado-win11u%') to AlertEvidence AND Device* queries. NEVER submit an answer that comes from the wrong device, user, or alert.

### 🚫 FORBIDDEN — NEVER DO THESE
1. **NEVER** query DeviceProcessEvents or DeviceNetworkEvents without a Timestamp BETWEEN filter.
2. **NEVER** guess or assume a timestamp — always SELECT Timestamp FROM AlertInfo first.
3. **NEVER** submit "unable to find" without first running: SELECT JSON_EXTRACT(AdditionalFields, '$.Url'), JSON_EXTRACT(AdditionalFields, '$.IpAddress'), JSON_EXTRACT(AdditionalFields, '$.Address') FROM AlertEvidence WHERE AlertId = '[id]'
4. **NEVER** pick from multiple results by position (first/last/any). Validate by Timestamp proximity.
5. **NEVER** give up and submit a guess. If stuck: dump full AdditionalFields, try LIKE '%keyword%' on ProcessCommandLine, then try a different AlertId.
6. **NEVER** query DeviceName from Device* tables when AlertEvidence.DeviceName already has it for the relevant AlertId.
7. **NEVER** write markdown tables, bullet evidence chains, formatted reports, or emojis in your response. Your ENTIRE response must be exactly two lines: `Thought: <plain prose reasoning>` then `Action: execute[SQL]` or `Action: search[query]` or `Action: submit[answer]`. Nothing else — no headers, no tables, no additional lines after Action.

### 🔍 EXTERNAL SEARCH — Use to understand unknowns BEFORE writing SQL
Format: search[query]

Use `search` when:
- The question mentions an unfamiliar malware, threat actor, or technique — search FIRST to know what to look for
- You encounter an unknown process name or file (e.g. `oneetx.exe`, `browsercore.exe`) — search to understand what it does and what artifacts to expect
- You need to know WHICH TABLE a specific attack type is logged in (e.g. "where does Defender log PRT theft?")
- You see an external IP and need threat intel before pivoting

Search examples:
  search[Manatee Tempest C2 infrastructure what IPs domains used]
  search[oneetx.exe malware what registry keys does it create]
  search[GenRansom malware what files does it drop or modify]
  search[Primary Refresh Token theft how detected which Windows logs]
  search[browsercore.exe PRT access what process artifacts to look for]

The search result is returned as your next Observation. Use it to write better, more targeted SQL.

### Investigation Order (strict — every time)
0. **READ THE QUESTION** — note ALL named entities: device, user, alert keywords. These are mandatory WHERE filters in every query.
1. **SEARCH FIRST** if the question names an unfamiliar malware, tool, or threat actor → search[<name> malware detection artifacts]
2. Find alert → SELECT AlertId, Timestamp, Title FROM AlertInfo WHERE Title LIKE '%keyword%'
3. Get entities → SELECT DeviceName, AccountName, RemoteUrl, RemoteIP, ProcessCommandLine, AdditionalFields FROM AlertEvidence WHERE AlertId = '[id]' AND (DeviceName LIKE '%<device_from_question>%' OR DeviceName IS NULL)
4. Any NULL/empty field → immediately run JSON_EXTRACT on AdditionalFields
5. Pivot to Device* tables ONLY with Timestamp BETWEEN '[AlertTime-10m]' AND '[AlertTime+10m]' AND DeviceName LIKE '%<device_from_question>%'
6. Multiple results → validate against alert Timestamp before submitting
7. If answer not found → check ProcessCommandLine LIKE '%keyword%', check RegistryKey, try broader Timestamp range
8. If stuck on an external IP → search[<ip> threat intelligence known malware]

STRICT OUTPUT FORMAT (no exceptions):
Thought: <plain prose — no markdown, no tables, no bullets>
Action: execute[SELECT ...] or search[query] or submit[answer]

One thought-action pair per response. Nothing before "Thought:" or after "Action: ...". DO NOT assume data not in logs.

Examples demonstrating laws:
"""

# Load targeted law-demonstrating examples
try:
    law_examples_path = os.path.join(curr_path, "law_examples")
    law_example_files = ["law_2_json_fallback.txt", "law_4_entity_pivoting.txt", "law_3_timeline_precision.txt"]

    if os.path.exists(law_examples_path):
        for example_file in law_example_files:
            example_path = os.path.join(law_examples_path, example_file)
            if os.path.exists(example_path):
                with open(example_path, "r") as f:
                    INVESTIGATOR_PROMPT += "\n" + f.read() + "\n" + "-"*50
        INVESTIGATOR_PROMPT = INVESTIGATOR_PROMPT[:-50].strip()
    else:
        print(f"[InvestigatorAgent] Warning: law_examples directory not found at {law_examples_path}")
except Exception as e:
    print(f"[InvestigatorAgent] Warning: Could not load law examples: {e}")


class InvestigatorAgent:
    """
    SQL-based forensic investigator using ReAct pattern.
    Enhanced with case_file access and skill loading capabilities.
    """

    def __init__(self,
                 config_list,
                 skill_registry: SkillRegistry,
                 case_file: CaseFile,
                 cache_seed=41,
                 max_steps=15,
                 submit_summary=False,
                 temperature=0,
                 retry_num=10,
                 retry_wait_time=5,
                 schema_context: str = ""):

        self.config_list = config_list
        self.temperature = temperature
        self.cache_seed = cache_seed
        self.skill_registry = skill_registry
        self.case_file = case_file
        self.schema_context = schema_context

        api_type = config_list[0].get('api_type', 'openai')

        if api_type == "ai_foundry":
            from secgym.config_key import api_key
            self.client = ChatCompletionsClient(
                endpoint=config_list[0]['endpoint'],
                credential=AzureKeyCredential(api_key),
                seed=self.cache_seed
            )
        elif api_type == "bedrock":
            self.client = None   # uses call_llm_bedrock() directly
        else:
            # Handles "azure", "openai", OpenRouter
            self.client = OpenAIWrapper(config_list=config_list, cache_seed=cache_seed)

        sys_prompt = self._build_prompt(schema_context)
        self.messages = [{"role": "system", "content": sys_prompt}]

        self.max_steps = max_steps
        self.submit_summary = submit_summary
        self.step_count = 0
        self.retry_num = retry_num
        self.retry_wait_time = retry_wait_time
        self.total_usage = {}

    def _build_prompt(self, schema_context: str = "") -> str:
        """Build the system prompt, optionally injecting a discovered schema block."""
        prompt = INVESTIGATOR_PROMPT
        if schema_context:
            # Add no-schema-discovery rule and append the actual schema
            schema_rule = (
                "\n0. **SCHEMA PRE-LOADED**: The full database schema is provided below. "
                "NEVER run SHOW TABLES or DESCRIBE — use the schema reference directly.\n"
            )
            # Insert schema rule at the top of the INVESTIGATION LAWS section
            prompt = prompt.replace(
                "### ⚖️ INVESTIGATION LAWS",
                "### ⚖️ INVESTIGATION LAWS" + schema_rule,
            )
            prompt += f"\n\n{schema_context}"
        return prompt

    @property
    def name(self):
        return "InvestigatorAgent"

    def _call_llm(self, messages):
        """Call LLM with appropriate API type."""
        api_type = self.config_list[0].get('api_type', 'openai')

        if api_type == "ai_foundry":
            response = call_llm_foundry(
                client=self.client,
                model=self.config_list[0]['model'],
                messages=messages,
                retry_num=self.retry_num,
                retry_wait_time=self.retry_wait_time,
                temperature=self.temperature,
                stop=["Observation:", "observation:"]
            )
            update_model_usage(self.total_usage, model_name=response.model, usage_dict=response.usage.as_dict())
        elif api_type == "bedrock":
            response = call_llm_bedrock(
                config_entry=self.config_list[0],
                messages=messages,
                retry_num=self.retry_num,
                retry_wait_time=self.retry_wait_time,
                temperature=self.temperature,
                use_thinking=True,
                thinking_budget=3000,
            )
            update_model_usage(self.total_usage, model_name=response.model, usage_dict=response.usage.model_dump())
        else:
            # Handles "azure", "openai", and OpenRouter
            response = call_llm(
                client=self.client,
                model=self.config_list[0]['model'],
                messages=messages,
                retry_num=self.retry_num,
                retry_wait_time=self.retry_wait_time,
                temperature=self.temperature,
                stop=["Observation:", "observation:"]
            )
            update_model_usage(self.total_usage, model_name=response.model, usage_dict=response.usage.model_dump())

        return response.choices[0].message.content

    def act(self, observation: str) -> Tuple[str, bool, str]:
        """
        Main action loop for investigator.

        Args:
            observation: Current observation from environment (question or SQL results)

        Returns:
            Tuple of (action, submit_flag)
        """
        # Add observation to message history
        self._add_message(observation, role="user")

        # Call LLM to get thought-action pair
        response = self._call_llm(messages=self.messages)
        print(f"[Investigator] {response}")

        # Check if max steps reached
        if self.step_count >= self.max_steps - 1 and self.submit_summary:
            summary_prompt = "You have reached maximum number of steps. Please summarize your findings of key information, and submit them."
            self._add_message(summary_prompt, role="system")

        # Parse response into thought and action
        split_str = "\nAction:"
        if "**Action:**" in response:
            split_str = "\n**Action:**"

        try:
            thought, action = response.strip().split(split_str)
            self._add_message(response.strip(), role="assistant")
        except:
            print("[Investigator] Retry Split Action:")
            thought = response.strip()
            action = self._call_llm(self.messages + [msging(f"{thought}\nAction:")])
            print(action)
            action = action.strip()
            if not "Thought" in thought:
                thought = f"Thought: {thought}"
            self._add_message(f"{thought}\nAction:{action}", role="assistant")

        print("*" * 50)

        self.step_count += 1

        # Check for search action first, then SQL/submit
        search_query, is_search = search_parser(action)
        if is_search:
            return search_query, False, "search"

        # Parse SQL / submit actions
        parsed_action, is_code, submit = sql_parser(action)
        action_type = "submit" if submit else "execute"

        # Safety: if no valid action found (e.g. markdown report instead of execute/submit),
        # re-prompt once with strict format reminder rather than executing garbage as SQL.
        if not is_code and not submit:
            format_reminder = (
                "ERROR: Your last response did not contain a valid action. "
                "You MUST respond with exactly:\n"
                "Thought: <one sentence>\n"
                "Action: execute[SELECT ...] OR submit[answer] OR search[query]\n"
                "Respond now with a valid Action."
            )
            self._add_message(format_reminder, role="user")
            recovery = self._call_llm(self.messages)
            print(f"[Investigator] Format recovery: {recovery[:200]}")
            self._add_message(recovery.strip(), role="assistant")
            s_query, is_s = search_parser(recovery)
            if is_s:
                return s_query, False, "search"
            parsed_action, is_code, submit = sql_parser(recovery)
            action_type = "submit" if submit else "execute"

        return parsed_action, submit, action_type

    def _add_message(self, msg: str, role: str = "user"):
        """Add message to conversation history."""
        self.messages.append(msging(msg, role))

    def reset(self, change_seed=True):
        """Reset for new question."""
        if change_seed:
            self.cache_seed += 1

        api_type = self.config_list[0].get('api_type', 'openai')

        if api_type == "ai_foundry":
            from secgym.config_key import api_key
            self.client = ChatCompletionsClient(
                endpoint=self.config_list[0]['endpoint'],
                credential=AzureKeyCredential(api_key),
                seed=self.cache_seed
            )
        elif api_type == "bedrock":
            self.client = None  # uses call_llm_bedrock() directly
        elif api_type in ["azure", "openai"]:
            self.client = OpenAIWrapper(config_list=self.config_list, cache_seed=self.cache_seed)

        self.step_count = 0
        sys_prompt = self._build_prompt(self.schema_context)
        self.messages = [{"role": "system", "content": sys_prompt}]
        self.total_usage = {}

    def get_logging(self):
        """Get logging information."""
        return {
            "messages": self.messages,
            "usage_summary": self.total_usage,
        }
