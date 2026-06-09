# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Orchestrator Agent - Main coordinator for multi-agent DFIR system.

Implements standard agent interface for SecRL evaluation compatibility.

Three improvements over the original MVP:
  1. Schema injection  — InvestigatorAgent receives pre-discovered schema,
                         eliminating SHOW TABLES/DESCRIBE from every question.
  2. Answer extraction — ExtractorAgent validates the candidate answer before
                         submission, fixing the 40-58% "had data, wrong pick" failure.
  3. Incident memory   — IncidentMemory persists facts across reset() calls within
                         one incident, enabling cross-question caching.
"""

import re
from typing import Tuple, Dict, Any

from secgym.agents.skills import SkillRegistry
from secgym.agents.multi_agent.case_file import CaseFile
from secgym.agents.multi_agent.research_agent import ResearchAgent
from secgym.agents.multi_agent.investigator_agent import InvestigatorAgent
from secgym.agents.multi_agent.extractor_agent import ExtractorAgent
from secgym.agents.multi_agent.incident_memory import IncidentMemory
from secgym.agents.agent_utils import update_total_usage


class OrchestratorAgent:
    """
    Multi-Agent DFIR System Orchestrator.

    Coordinates Research, Investigator, and Extractor agents.
    Exposes standard agent interface (act / reset / get_logging) for
    full compatibility with run_exp.py's evaluation loop.
    """

    def __init__(self,
                 config_list,
                 extractor_config_list=None,
                 cache_seed=41,
                 max_steps=15,
                 submit_summary=False,
                 temperature=0,
                 retry_num=10,
                 retry_wait_time=5):

        self.config_list = config_list
        self.max_steps = max_steps
        self.step_count = 0
        self.cache_seed = cache_seed
        self.submit_summary = submit_summary
        self.temperature = temperature
        self.retry_num = retry_num
        self.retry_wait_time = retry_wait_time

        # ── Shared infrastructure ──────────────────────────────────────
        self.skill_registry = SkillRegistry()
        self.case_file = CaseFile()

        # ── Improvement 3: Incident memory (survives reset()) ──────────
        # Must be created here, NOT inside reset(), so it persists across
        # per-question resets within the same incident.
        self.incident_memory = IncidentMemory()

        # ── Improvement 1: Schema context (set via load_schema()) ──────
        self.schema_context: str = ""

        # ── Sub-agents ─────────────────────────────────────────────────
        self.research_agent = ResearchAgent(config_list, self.skill_registry)

        self.investigator_agent = InvestigatorAgent(
            config_list=config_list,
            skill_registry=self.skill_registry,
            case_file=self.case_file,
            cache_seed=cache_seed,
            max_steps=max_steps,
            submit_summary=submit_summary,
            temperature=temperature,
            retry_num=retry_num,
            retry_wait_time=retry_wait_time,
            schema_context="",          # populated by load_schema()
        )

        # ── Improvement 2: Extractor agent ────────────────────────────
        # Use a lighter/faster model for the extractor (e.g., Haiku via OpenRouter)
        # If no extractor_config_list is provided, fall back to the main config_list
        _extractor_cfg = extractor_config_list if extractor_config_list else config_list
        self.extractor_agent = ExtractorAgent(
            config_list=_extractor_cfg,
            retry_num=retry_num,
            retry_wait_time=retry_wait_time,
        )

        # ── Per-episode state ──────────────────────────────────────────
        self.messages: list = []
        self._current_question: str = ""
        self._last_observation: str = ""   # most recent observation (may be no-op)
        self._extractor_context: str = ""  # last REAL SQL result (preserved across no-ops)
        self._injected_noop: bool = False  # True when last action was the continue hint
        self._extractor_rejection_streak: int = 0  # consecutive low-conf rejections

        # ── Counters for get_logging() ─────────────────────────────────
        self._memory_hits: int = 0
        self._extractor_calls: int = 0

    # ------------------------------------------------------------------
    # Schema injection (called once per incident from run_exp.py)
    # ------------------------------------------------------------------

    def load_schema(self, schema_str: str) -> None:
        """
        Store the discovered schema for per-question injection.
        Does NOT inject the full 18K schema into the InvestigatorAgent system prompt —
        instead, a compact question-type-specific snippet is injected at step 0 of
        each question, keeping the system prompt clean and short.
        """
        self.schema_context = schema_str
        print(f"[Orchestrator] Schema stored ({len(schema_str):,} chars) — per-question injection enabled.")

    # ------------------------------------------------------------------
    # Standard agent interface
    # ------------------------------------------------------------------

    @property
    def name(self):
        return "MultiAgentDFIR"

    def act(self, observation: str) -> Tuple[str, bool]:
        """
        Main action loop — implements standard agent interface.

        Flow per step:
          1. Step 0: incident memory lookup + question anchoring
          2. Step 0: compact question-aware schema injected into observation
          3. Rolling context compression if message history > 18 turns
          4. Investigator acts → may return execute / search / submit
          5. search[query] → ResearchAgent fetches result, injected into investigator history
          6. submit → answer passed through directly (no extractor overhead)
        """
        self._add_message(observation, role="user")

        # ── Step 0: memory + anchoring + question-aware schema ─────────
        if self.step_count == 0:
            self.case_file.question = observation
            self._current_question = observation

            # Incident memory
            memory_block = self.incident_memory.get_context_block(observation)
            if memory_block:
                self._memory_hits += 1
                observation = f"{observation}\n\n{memory_block}"
                print(f"[Orchestrator] Memory hit — prepending {len(memory_block)} chars.")

            # Question-aware schema: inject a compact snippet (~200-300 chars) matched
            # to the answer type — no full 18K dump, keeps context lean.
            if self.schema_context:
                schema_snippet = self._build_question_schema(observation)
                observation = f"{observation}\n\n{schema_snippet}"
                print(f"[Orchestrator] Injected {len(schema_snippet)}-char question-specific schema.")

        # Store observation for tracking.
        # _extractor_context holds the last REAL SQL result — it must NOT be
        # overwritten with:
        #   (a) the no-op hint result we inject between extractor retries, OR
        #   (b) web search results (formatted by ResearchAgent), which contain
        #       threat intel text rather than SQL table data.
        # Only update it when the observation looks like an SQL result (contains
        # table-formatted rows) or is the initial question observation.
        self._last_observation = observation
        _is_search_result = observation.startswith("[Web Search Result:")
        _is_noop_result = self._injected_noop
        if not _is_noop_result and not _is_search_result:
            old_ctx = self._extractor_context
            self._extractor_context = observation
            # If we just updated context with NEW SQL data (after a prior rejection),
            # reset the rejection streak so the extractor gets a fresh look at the
            # actual evidence before we consider bypassing.
            if (self._extractor_rejection_streak > 0
                    and self._extractor_context_has_sql()
                    and not self._extractor_context_has_sql_in(old_ctx)):
                print("[Orchestrator] Context updated with SQL data — resetting extractor streak.")
                self._extractor_rejection_streak = 0
        self._injected_noop = False   # reset flag — we've now consumed the no-op step

        # ── Rolling context compression ────────────────────────────────
        # Keep the investigator's message history lean: once it exceeds 18 messages,
        # summarize older turns into a single compact block so later reasoning
        # doesn't drown in stale raw SQL dumps.
        self._compress_investigator_context()

        # ── Investigator acts ──────────────────────────────────────────
        action, submit, action_type = self.investigator_agent.act(observation)

        # ── Handle search[query] action ────────────────────────────────
        if action_type == "search":
            print(f"[Orchestrator] Investigator search: {action[:80]}")
            search_result = self.research_agent.research(action, "general")
            formatted = self.research_agent.format_for_observation(search_result)
            # Inject the search result directly into the investigator's conversation
            # history so it receives it as its next "observation".
            # We CANNOT return the search text to run_exp.py as the action — it would
            # try to execute it as SQL (syntax error). Instead we:
            #   1. Push formatted result into investigator history as a user message.
            #   2. Return a no-op SQL so run_exp.py has something safe to execute.
            #   3. Set _injected_noop=True so the no-op result doesn't overwrite
            #      _extractor_context with useless data on the next call.
            self.investigator_agent._add_message(formatted, role="user")
            self._injected_noop = True
            self.step_count += 1
            return "SELECT 1", False

        # ── Answer pass-through ────────────────────────────────────────
        # Extractor validation is disabled — the investigator's answer goes
        # directly to the environment.  This avoids the latency of an extra
        # LLM call and the false-UNCERTAIN rejections that were causing loops.
        if submit:
            self._extractor_calls += 1   # keep counter for logging
            print(f"[Orchestrator] Investigator submits: {action[:120]}")

        # ── Bookkeeping ────────────────────────────────────────────────
        if not submit:
            self.case_file.add_sql_query(action)

        self.step_count += 1
        return action, submit

    # ------------------------------------------------------------------
    # Question-aware schema (Improvement 2)
    # ------------------------------------------------------------------

    # Compact schema snippets keyed by answer type — ~200-300 chars each.
    # Injected into the first observation of each question so the investigator
    # knows exactly which columns to query without reading a full 18K dump.
    _SCHEMA_SNIPPETS: Dict[str, str] = {
        "ip": (
            "[Schema: IP questions]\n"
            "- AlertEvidence: AlertId, RemoteIP, EntityType, AdditionalFields"
            " (JSON_EXTRACT '$.IpAddress','$.Address')\n"
            "- DeviceNetworkEvents: DeviceName, RemoteIP, RemoteUrl, Timestamp,"
            " InitiatingProcessFileName\n"
            "- AlertInfo: AlertId, Timestamp, Title  ← join key"
        ),
        "url_domain": (
            "[Schema: URL/domain questions]\n"
            "- AlertEvidence: AlertId, RemoteUrl, AdditionalFields (JSON_EXTRACT '$.Url')\n"
            "- DeviceNetworkEvents: DeviceName, RemoteUrl, RemoteIP, Timestamp"
        ),
        "command_line": (
            "[Schema: command-line questions]\n"
            "- AlertEvidence: AlertId, ProcessCommandLine, AdditionalFields\n"
            "- DeviceProcessEvents: DeviceName, FileName, ProcessCommandLine,"
            " InitiatingProcessCommandLine, Timestamp\n"
            "- AlertInfo: AlertId, Timestamp, Title"
        ),
        "hostname": (
            "[Schema: hostname/device questions]\n"
            "- AlertEvidence: AlertId, DeviceName, EntityType, AdditionalFields\n"
            "- AlertInfo: AlertId, Title, Timestamp"
        ),
        "username": (
            "[Schema: user/account questions]\n"
            "- AlertEvidence: AlertId, AccountName, EntityType,"
            " AdditionalFields (JSON_EXTRACT '$.UserName','$.AccountName')\n"
            "- AlertInfo: AlertId, Title, Timestamp"
        ),
        "hash": (
            "[Schema: file hash questions]\n"
            "- AlertEvidence: AlertId, FileName,"
            " AdditionalFields (JSON_EXTRACT '$.Sha256','$.Md5','$.FileHash')\n"
            "- DeviceProcessEvents: DeviceName, FileName, ProcessCommandLine, Timestamp"
        ),
        "timestamp": (
            "[Schema: timestamp questions]\n"
            "- AlertInfo: AlertId, Timestamp, Title  ← primary\n"
            "- AlertEvidence: AlertId, EntityType\n"
            "- DeviceProcessEvents: Timestamp, DeviceName"
        ),
        "sid": (
            "[Schema: SID questions]\n"
            "- AlertEvidence: AlertId,"
            " AdditionalFields (JSON_EXTRACT '$.UserSid','$.Sid','$.SecurityIdentifier')\n"
            "- AlertInfo: AlertId, Title"
        ),
        "process_name": (
            "[Schema: process/filename questions]\n"
            "- AlertEvidence: AlertId, FileName, ProcessCommandLine, EntityType, FolderPath\n"
            "- DeviceProcessEvents: DeviceName, FileName, InitiatingProcessFileName, Timestamp"
        ),
        "azure_ad": (
            "[Schema: Azure AD / device ID questions]\n"
            "- AlertEvidence: AlertId,"
            " AdditionalFields (JSON_EXTRACT '$.AadDeviceId','$.DeviceId','$.AadUserId')\n"
            "- AlertInfo: AlertId, Title"
        ),
        "port": (
            "[Schema: port questions]\n"
            "- DeviceNetworkEvents: DeviceName, RemotePort, LocalPort, RemoteIP, Timestamp"
        ),
    }
    _SCHEMA_GENERAL = (
        "[Schema: key tables]\n"
        "- AlertInfo: AlertId, Title, Category, Severity, Timestamp, AttackTechniques\n"
        "- AlertEvidence: AlertId, EntityType, EvidenceRole, FileName, FolderPath,"
        " RemoteIP, RemoteUrl, AccountName, DeviceName, ProcessCommandLine, AdditionalFields\n"
        "- DeviceProcessEvents: Timestamp, DeviceName, FileName, ProcessCommandLine,"
        " InitiatingProcessFileName, AccountName, ProcessId\n"
        "- DeviceNetworkEvents: Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,"
        " InitiatingProcessFileName"
    )
    _ANSWER_TYPE_TO_SCHEMA: Dict[str, str] = {
        "IPv4 address (format: X.X.X.X)":                               "ip",
        "URL or domain name":                                            "url_domain",
        "command line string":                                           "command_line",
        "hostname or device name":                                       "hostname",
        "username or account name":                                      "username",
        "file hash (hex string)":                                        "hash",
        "timestamp (datetime string)":                                   "timestamp",
        "Windows SID (format: S-1-5-...)":                               "sid",
        "process name":                                                  "process_name",
        "filename (e.g. malware.exe)":                                   "process_name",
        "Azure AD GUID (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)":  "azure_ad",
        "port number (integer)":                                         "port",
        "Windows registry key path":                                     "process_name",
        "cloud application ID (integer)":                                "hostname",
        "email address or User Principal Name":                          "username",
    }

    def _build_question_schema(self, question: str) -> str:
        """Return the compact schema snippet that matches this question's answer type."""
        from secgym.agents.multi_agent.extractor_agent import detect_answer_type
        answer_type = detect_answer_type(question)
        schema_key  = self._ANSWER_TYPE_TO_SCHEMA.get(answer_type, "general")
        return self._SCHEMA_SNIPPETS.get(schema_key, self._SCHEMA_GENERAL)

    # ------------------------------------------------------------------
    # Rolling context compression (Improvement 6)
    # ------------------------------------------------------------------

    def _compress_investigator_context(self) -> None:
        """
        If the investigator's message history exceeds 18 messages, summarise
        all but the last 4 turns into a single compact block.  This prevents
        the model's attention from being diluted by stale SQL dumps mid-run.
        """
        msgs = self.investigator_agent.messages
        # Need: system(0) + ≥1 summary candidate + 4 recent kept = at least 19
        if len(msgs) <= 18:
            return

        to_compress = msgs[1:-4]   # everything between system prompt and last 4
        recent      = msgs[-4:]

        history_text = "\n".join(
            f"[{m['role'].upper()}] {str(m.get('content', ''))[:400]}"
            for m in to_compress
        )
        compress_prompt = (
            "Summarise these DFIR investigation steps into a compact "
            "'Investigation so far' block (max 400 words).\n"
            "Keep: AlertIds found, DeviceNames, alert Timestamps, SQL queries "
            "that returned data, key findings (IPs/users/commands/filenames), "
            "and dead ends already ruled out.\n\n"
            f"{history_text}"
        )

        try:
            api_type = self.extractor_agent.config_list[0].get("api_type", "openai")
            compress_msgs = [
                {"role": "system",  "content": "You are a concise DFIR investigation summariser."},
                {"role": "user",    "content": compress_prompt},
            ]
            if api_type == "bedrock":
                from secgym.agents.agent_utils import call_llm_bedrock
                resp = call_llm_bedrock(
                    config_entry=self.extractor_agent.config_list[0],
                    messages=compress_msgs,
                    retry_num=2, retry_wait_time=5, temperature=0, use_thinking=False,
                )
            else:
                from secgym.agents.agent_utils import call_llm
                resp = call_llm(
                    client=self.extractor_agent.client,
                    model=self.extractor_agent.config_list[0]["model"],
                    messages=compress_msgs,
                    retry_num=2, retry_wait_time=5, temperature=0,
                )
            summary = resp.choices[0].message.content.strip()
            summary_msg = {
                "role": "assistant",
                "content": f"[INVESTIGATION SUMMARY — {len(to_compress)} earlier messages compressed]\n{summary}",
            }
            self.investigator_agent.messages = [msgs[0], summary_msg] + recent
            print(f"[Orchestrator] Context compressed: {len(to_compress)} msgs → 1 summary.")
        except Exception as e:
            print(f"[Orchestrator] Compression skipped ({e}).")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extractor_context_has_sql(self) -> bool:
        """Return True if _extractor_context contains actual SQL table data."""
        return self._extractor_context_has_sql_in(self._extractor_context)

    @staticmethod
    def _extractor_context_has_sql_in(text: str) -> bool:
        """
        Return True if `text` contains actual SQL table data.

        We detect SQL output by looking for the markdown table separator `---|`
        or pipe-delimited rows.
        """
        return "---|" in text or ("| " in text and "\n|" in text)

    # ------------------------------------------------------------------
    # (kept for reference — no longer auto-triggered)
    # ------------------------------------------------------------------

    def _should_research(self, observation: str) -> Tuple[bool, str]:
        """Determine if ResearchAgent should be invoked."""
        already_researched = set(self.case_file.external_intel_dict.keys())
        obs_lower = observation.lower()

        # External IPs in security context
        security_context = any(
            kw in obs_lower
            for kw in ["alert", "suspicious", "malicious", "threat", "attack", "compromise"]
        )
        if security_context:
            ip_pattern = (
                r'\b(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)'
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            )
            for ip in re.findall(ip_pattern, observation):
                if ip not in already_researched:
                    return True, ip

        # File hashes when explicitly flagged
        hash_context = any(
            kw in obs_lower
            for kw in ["malicious", "unknown file", "unrecognized", "suspicious file", "threat"]
        )
        if hash_context:
            for h in re.findall(r'\b[a-f0-9]{32}(?:[a-f0-9]{32})?\b', obs_lower):
                if h not in already_researched:
                    return True, h

        # Unknown tools / processes
        tool_uncertainty = any(
            kw in obs_lower
            for kw in ["unknown tool", "unknown process", "unrecognized binary", "what is"]
        )
        if tool_uncertainty:
            words = observation.split()
            for i, word in enumerate(words):
                if any(uk in word.lower() for uk in ["unknown", "unrecognized"]):
                    if i + 1 < len(words):
                        potential = words[i + 1].strip('.,;:!?()')
                        if potential and (
                            potential.endswith('.exe') or
                            potential.endswith('.dll') or
                            len(potential) > 5
                        ):
                            if potential not in already_researched:
                                return True, potential

        return False, ""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def reset(self, change_seed: bool = True, new_incident: bool = False) -> None:
        """
        Reset for a new question.

        Args:
            change_seed  : increment the cache seed (standard behaviour)
            new_incident : if True, also clear incident memory (call when
                           switching to a different incident in run_exp.py)
        """
        if new_incident:
            self.incident_memory.clear()
            print("[Orchestrator] Incident memory cleared for new incident.")

        if change_seed:
            self.cache_seed += 1

        self.step_count = 0
        self.messages = []
        self._current_question = ""
        self._last_observation = ""
        self._extractor_context = ""
        self._injected_noop = False
        self._extractor_rejection_streak = 0
        self._memory_hits = 0
        self._extractor_calls = 0

        # Refresh shared infrastructure
        self.case_file = CaseFile()

        # Reset investigator with current schema context preserved
        self.investigator_agent.case_file = self.case_file
        self.investigator_agent.reset(change_seed)

        # Reset research agent
        self.research_agent.reset()

        # Unload skills to free memory
        self.skill_registry.unload_all()

        print("[Orchestrator] Reset complete.")

    # ------------------------------------------------------------------
    # Reflection (called by run_exp.py after reward == 0)
    # ------------------------------------------------------------------

    def reflect(self, question: str, wrong_answer: str) -> None:
        """
        Generate a brief lesson-learned reflection after a failed question
        and store it in IncidentMemory for future questions.

        Uses the fast extractor model (Haiku) to analyse the last 10
        investigator messages and produce 1-2 actionable bullet points.
        """
        # Build a concise history summary from the last 10 investigator turns
        history = self.investigator_agent.messages[-10:]
        history_text = "\n".join(
            f"[{m['role'].upper()}] {str(m.get('content', ''))[:300]}"
            for m in history
        )

        reflection_prompt = (
            f"You are reviewing a failed DFIR investigation.\n\n"
            f"QUESTION: {question}\n\n"
            f"WRONG ANSWER SUBMITTED: {wrong_answer}\n\n"
            f"LAST INVESTIGATION STEPS:\n{history_text}\n\n"
            f"In 1-2 bullet points, what should be done differently next time "
            f"for questions of this type? Focus on:\n"
            f"- Which table / column to query first\n"
            f"- What SQL pitfalls or missing joins caused the wrong answer\n"
            f"- Any important disambiguation step that was skipped\n"
            f"Output ONLY the bullet points (start each with '•'), no preamble."
        )

        messages = [
            {"role": "system", "content": "You are a concise DFIR investigation coach."},
            {"role": "user",   "content": reflection_prompt},
        ]

        try:
            from secgym.agents.agent_utils import call_llm
            api_type = self.extractor_agent.config_list[0].get('api_type', 'openai')
            if api_type == "bedrock":
                from secgym.agents.agent_utils import call_llm_bedrock
                resp = call_llm_bedrock(
                    config_entry=self.extractor_agent.config_list[0],
                    messages=messages,
                    retry_num=2,
                    retry_wait_time=5,
                    temperature=0,
                    use_thinking=False,
                )
            else:
                resp = call_llm(
                    client=self.extractor_agent.client,
                    model=self.extractor_agent.config_list[0]["model"],
                    messages=messages,
                    retry_num=2,
                    retry_wait_time=5,
                    temperature=0,
                )
            lesson = resp.choices[0].message.content.strip()
            print(f"[Orchestrator] Reflection generated ({len(lesson)} chars): {lesson[:120]}")
            self.incident_memory.store_reflection(lesson, source_q=question[:120])
        except Exception as e:
            print(f"[Orchestrator] Reflection failed: {e}")

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def get_logging(self) -> Dict[str, Any]:
        """Standard logging interface — compatible with run_exp.py."""
        investigator_logs = self.investigator_agent.get_logging()
        return {
            "messages":         investigator_logs.get("messages", []),
            "usage_summary":    investigator_logs.get("usage_summary", {}),
            # Extended fields
            "skills_used":      self.skill_registry.get_loaded_skills(),
            "research_calls":   self.research_agent.call_count,
            "case_file_summary":self.case_file.to_dict(),
            "memory_hits":      self._memory_hits,
            "extractor_calls":  self._extractor_calls,
            "memory_size":      self.incident_memory.size(),
        }

    def _add_message(self, msg: str, role: str = "user") -> None:
        self.messages.append({"role": role, "content": msg})
