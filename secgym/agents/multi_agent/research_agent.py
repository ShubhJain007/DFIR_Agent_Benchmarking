# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Research Agent - External threat intelligence and attack-pattern search.

Two modes:
  1. On-demand search   — InvestigatorAgent issues search[query] action mid-investigation
  2. Pre-question intel — Orchestrator calls research_question_context() at step 0
                          to prime the investigator with attack-profile knowledge
"""

import re
from typing import Dict, Any, List
from secgym.agents.skills import SkillRegistry

# ---------------------------------------------------------------------------
# Keywords that suggest a search will be useful before querying the DB
# ---------------------------------------------------------------------------
_MALWARE_KEYWORDS = [
    "manatee tempest", "mustard tempest", "lockbit", "ryuk", "conti",
    "mimikatz", "cobalt strike", "meterpreter", "metasploit",
    "oneetx", "genransom", "tempedreve", "wasted locker", "phoenixlocker",
    "macaw", "defray777", "clop", "revil", "darkside",
]
_TECHNIQUE_KEYWORDS = [
    "primary refresh token", "prt", "pass-the-hash", "pass-the-ticket",
    "kerberoasting", "dcsync", "lsass", "credential dumping",
    "wmi", "scheduled task", "registry run key", "vss", "shadow copy",
    "bcdedit", "recovery settings", "lateral movement", "rdp",
    "living off the land", "lolbas",
]


class ResearchAgent:
    """
    External threat intelligence specialist.

    Provides two services:
      research(query, search_type)         — on-demand Tavily search
      research_question_context(question)  — automatic pre-question intel extraction
    """

    def __init__(self, config_list, skill_registry: SkillRegistry):
        self.config_list = config_list
        self.skill_registry = skill_registry
        self.call_count = 0
        self.research_cache: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Pre-question context (called at step 0 by Orchestrator)
    # ------------------------------------------------------------------

    def research_question_context(self, question: str) -> str:
        """
        Automatically extract key entities from the question and search for:
          - Attack-group / malware profiles (what it does, what artifacts it leaves)
          - Relevant detection columns / tables in Defender logs
          - Known IOCs (domains, IPs) associated with the group

        Returns a formatted block to prepend to the investigator's first observation.
        Returns "" if nothing useful is found.
        """
        q_lower = question.lower()
        searches: List[str] = []

        # ── Threat actor / malware names ──────────────────────────────────
        for kw in _MALWARE_KEYWORDS:
            if kw in q_lower:
                searches.append(
                    f"{kw} malware detection artifacts logs IOC indicators"
                )
                break   # one search per question is enough for this category

        # ── Attack technique ──────────────────────────────────────────────
        for kw in _TECHNIQUE_KEYWORDS:
            if kw in q_lower:
                searches.append(
                    f"{kw} detection Windows Defender logs which table column"
                )
                break

        # ── Specific process names in the question ────────────────────────
        proc_pattern = r'\b(\w+\.exe|\w+\.dll)\b'
        procs = re.findall(proc_pattern, question, re.IGNORECASE)
        for proc in procs[:2]:                       # limit to 2 processes
            proc_lower = proc.lower()
            # skip well-known legit processes
            if proc_lower not in {"cmd.exe", "powershell.exe", "explorer.exe",
                                   "svchost.exe", "wmiprvse.exe", "wmic.exe"}:
                searches.append(
                    f"{proc} malware security threat what does it do artifacts"
                )

        if not searches:
            return ""

        # Perform searches and collect context
        context_blocks: List[str] = []
        for query in searches[:3]:                   # cap at 3 searches per question
            result = self.research(query, "general")
            if result.get("confidence", 0) > 0 and result.get("threat_context"):
                ctx = result["threat_context"][:400]
                context_blocks.append(f"• [{result['entity']}]: {ctx}")

        if not context_blocks:
            return ""

        block = (
            "=== PRE-INVESTIGATION THREAT INTELLIGENCE ===\n"
            + "\n".join(context_blocks)
            + "\n"
            "Use the above to guide WHICH columns / tables to query first.\n"
            "============================================="
        )
        print(f"[ResearchAgent] Pre-question intel: {len(context_blocks)} hit(s)")
        return block

    # ------------------------------------------------------------------
    # On-demand search (called when investigator issues search[query])
    # ------------------------------------------------------------------

    def research(self, query: str, search_type: str = "threat_intel") -> Dict[str, Any]:
        """
        Perform external research via Tavily.

        Args:
            query       : free-text search query
            search_type : "threat_intel" | "general" | "ioc" | "tool" | "cve"

        Returns:
            {"entity", "threat_context", "sources", "confidence"}
        """
        cache_key = f"{search_type}:{query}"
        if cache_key in self.research_cache:
            print(f"[ResearchAgent] Cache hit: {query[:60]}")
            return self.research_cache[cache_key]

        self.call_count += 1
        print(f"[ResearchAgent] Searching ({search_type}): {query[:80]}")

        try:
            tavily_search = self.skill_registry.get_skill("tavily_threat_search")
        except Exception as e:
            print(f"[ResearchAgent] Tavily skill unavailable: {e}")
            return self._empty(query)

        # Map search_type to a contextual suffix
        type_suffixes = {
            "threat_intel": "threat intelligence malware cybersecurity IOC",
            "general":      "cybersecurity detection logs SIEM artifacts",
            "ioc":          "indicator of compromise threat actor campaign",
            "tool":         "malware tool technique MITRE ATT&CK",
            "cve":          "CVE vulnerability exploit PoC",
        }
        suffix = type_suffixes.get(search_type, "cybersecurity")
        enhanced_query = f"{query} {suffix}" if suffix not in query else query

        result = tavily_search(enhanced_query, search_type=search_type, max_results=3)
        self.research_cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    # Formatting
    # ------------------------------------------------------------------

    def format_for_observation(self, result: Dict[str, Any]) -> str:
        """
        Format a research() result as an Observation block for the investigator.
        """
        entity  = result.get("entity", "?")
        context = result.get("threat_context", "No results found.")
        sources = result.get("sources", [])
        conf    = result.get("confidence", 0.0)

        lines = [
            f"[Web Search Result: {entity}]",
            context[:600],
        ]
        if sources:
            lines.append(f"Sources: {', '.join(sources[:2])}")
        if conf > 0:
            lines.append(f"Confidence: {conf:.0%}")
        lines.append("Use this context to refine your SQL queries.")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _empty(query: str) -> Dict[str, Any]:
        return {
            "entity": query,
            "threat_context": "No results available.",
            "sources": [],
            "confidence": 0.0,
        }

    def should_research(self, entity: str) -> bool:
        if any(entity in key for key in self.research_cache):
            return False
        return bool(entity and len(entity) >= 3)

    def reset(self):
        self.call_count = 0
        self.research_cache.clear()
