# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Research Agent - External threat intelligence specialist using Tavily
"""

from typing import Dict, Any
from secgym.agents.skills import SkillRegistry


class ResearchAgent:
    """
    External threat intelligence specialist.
    Uses Tavily API to enrich investigation with external context.
    """

    def __init__(self, config_list, skill_registry: SkillRegistry):
        self.config_list = config_list
        self.skill_registry = skill_registry
        self.call_count = 0
        self.research_cache: Dict[str, Dict[str, Any]] = {}  # Simple caching

    def research(self, query: str, search_type: str = "threat_intel") -> Dict[str, Any]:
        """
        Perform threat intelligence research on an entity.

        Args:
            query: Entity to research (IP, hash, malware name, etc.)
            search_type: Type of search (threat_intel, cve, ioc, tool)

        Returns:
            Dictionary with threat context
        """
        # Check cache first
        cache_key = f"{search_type}:{query}"
        if cache_key in self.research_cache:
            print(f"[ResearchAgent] Using cached result for: {query}")
            return self.research_cache[cache_key]

        self.call_count += 1
        print(f"[ResearchAgent] Researching: {query} (type: {search_type})")

        # Load Tavily skill if not loaded
        try:
            tavily_search = self.skill_registry.get_skill("tavily_threat_search")
        except Exception as e:
            print(f"[ResearchAgent] Error loading Tavily skill: {e}")
            return {
                "entity": query,
                "threat_context": f"Research unavailable: {str(e)}",
                "sources": [],
                "confidence": 0.0
            }

        # Perform search
        result = tavily_search(query, search_type=search_type, max_results=2)

        # Cache result
        self.research_cache[cache_key] = result

        return result

    def should_research(self, entity: str) -> bool:
        """
        Determine if we should research this entity.

        Args:
            entity: Entity string

        Returns:
            Boolean indicating if research is warranted
        """
        # Check if already in cache
        if any(entity in key for key in self.research_cache.keys()):
            return False

        # Don't research empty strings
        if not entity or len(entity) < 3:
            return False

        return True

    def format_intel_for_context(self, intel: Dict[str, Any]) -> str:
        """
        Format intelligence for agent consumption.

        Args:
            intel: Intelligence dictionary from research()

        Returns:
            Formatted string
        """
        entity = intel.get("entity", "Unknown")
        context = intel.get("threat_context", "No context available")
        confidence = intel.get("confidence", 0.0)

        formatted = f"[External Intelligence: {entity}]\n"
        formatted += f"{context}\n"

        if confidence > 0:
            formatted += f"Confidence: {confidence:.0%}"

        return formatted

    def reset(self):
        """Reset research agent state."""
        self.call_count = 0
        self.research_cache.clear()
