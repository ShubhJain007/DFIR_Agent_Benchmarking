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
        self.extractor_agent = ExtractorAgent(
            config_list=config_list,
            retry_num=retry_num,
            retry_wait_time=retry_wait_time,
        )

        # ── Per-episode state ──────────────────────────────────────────
        self.messages: list = []
        self._current_question: str = ""
        self._last_observation: str = ""   # most recent SQL result for extractor

        # ── Counters for get_logging() ─────────────────────────────────
        self._memory_hits: int = 0
        self._extractor_calls: int = 0

    # ------------------------------------------------------------------
    # Schema injection (called once per incident from run_exp.py)
    # ------------------------------------------------------------------

    def load_schema(self, schema_str: str) -> None:
        """
        Inject a pre-discovered schema into the InvestigatorAgent's prompt.
        Replaces the investigator in-place with a new instance carrying the schema.
        Called once per incident, before the question loop starts.
        """
        self.schema_context = schema_str

        self.investigator_agent = InvestigatorAgent(
            config_list=self.config_list,
            skill_registry=self.skill_registry,
            case_file=self.case_file,
            cache_seed=self.cache_seed,
            max_steps=self.max_steps,
            submit_summary=self.submit_summary,
            temperature=self.temperature,
            retry_num=self.retry_num,
            retry_wait_time=self.retry_wait_time,
            schema_context=schema_str,
        )
        print(f"[Orchestrator] Schema loaded ({len(schema_str):,} chars).")

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
          1. On step 0: check incident memory for cached facts → prepend to obs
          2. Optionally enrich observation with external threat intel (research agent)
          3. Let investigator act
          4. On submit=True: run extractor to validate answer
             • confidence ≥ 0.6 → submit validated answer
             • confidence < 0.6 → suppress submit, keep investigating
        """
        self._add_message(observation, role="user")

        # ── Step 0: memory check + question anchoring ──────────────────
        if self.step_count == 0:
            self.case_file.question = observation
            self._current_question = observation

            memory_block = self.incident_memory.get_context_block(observation)
            if memory_block:
                self._memory_hits += 1
                observation = f"{observation}\n\n{memory_block}"
                print(f"[Orchestrator] Memory hit — prepending {len(memory_block)} chars.")

        # Store raw observation for the extractor (before enrichment)
        self._last_observation = observation

        # ── Research enrichment (existing logic) ──────────────────────
        should_research, research_query = self._should_research(observation)

        if should_research:
            print(f"[Orchestrator] Triggering research for: {research_query}")
            intel = self.research_agent.research(research_query, "threat_intel")

            if intel.get("confidence", 0.0) > 0.0 and intel.get("threat_context"):
                self.case_file.add_external_intel(intel)
                intel_summary = intel.get("threat_context", "")[:300]
                enriched_obs = f"{observation}\n\n[External Intelligence: {intel_summary}]"
                print("[Orchestrator] Research successful, enriching context")
                action, submit = self.investigator_agent.act(enriched_obs)
            else:
                print(f"[Orchestrator] Research returned no useful data "
                      f"(confidence={intel.get('confidence', 0.0)}), proceeding without enrichment")
                action, submit = self.investigator_agent.act(observation)
        else:
            action, submit = self.investigator_agent.act(observation)

        # ── Answer extraction / validation ────────────────────────────
        if submit:
            # Only run extractor if we still have headroom (avoids infinite loops
            # when we're at the last step and must submit whatever we have)
            if self.step_count < self.max_steps - 1:
                self._extractor_calls += 1
                validated, confidence = self.extractor_agent.extract(
                    question=self._current_question,
                    candidate=action,
                    result_context=self._last_observation,
                )

                if confidence >= 0.6:
                    # Use extractor's (potentially corrected) answer
                    action = validated
                else:
                    # Low confidence — suppress submit, keep investigating
                    submit = False
                    print(f"[Orchestrator] Extractor uncertain (conf={confidence:.2f}), "
                          "forcing one more investigation round.")
            # At max_steps-1 we must submit regardless — trust investigator's answer

        # ── Bookkeeping ────────────────────────────────────────────────
        if not submit:
            self.case_file.add_sql_query(action)
            # Update last observation only for non-submit steps (SQL results)
            # submit steps carry the answer string, not a SQL result

        self.step_count += 1
        return action, submit

    # ------------------------------------------------------------------
    # Research trigger (unchanged from original MVP)
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
