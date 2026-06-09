# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Skills Registry - Manages dynamic loading of agent skills/tools
"""

import importlib
import re
from typing import Dict, List, Callable, Any


class SkillRegistry:
    """
    Manages lazy loading of skills to prevent context bloat.
    Skills are loaded on-demand based on triggers in observations/context.
    """

    def __init__(self):
        self.loaded_skills: Dict[str, Callable] = {}

        # Skill definitions: name -> {module, function, triggers}
        self.skill_definitions = {
            # Research skills
            "tavily_threat_search": {
                "module": "secgym.agents.skills.research_skills",
                "function": "tavily_threat_search",
                "triggers": ["unknown", "suspicious", "malicious", "what is"],
            },

            # Investigation skills
            "extract_entities": {
                "module": "secgym.agents.skills.investigation_skills",
                "function": "extract_entities",
                "triggers": ["ip", "user", "host", "hash", "entity"],
            },
            "build_timeline": {
                "module": "secgym.agents.skills.investigation_skills",
                "function": "build_timeline",
                "triggers": ["timeline", "chronological", "sequence"],
            },
            "optimize_query": {
                "module": "secgym.agents.skills.investigation_skills",
                "function": "optimize_query",
                "triggers": ["SELECT", "FROM"],  # SQL patterns
            },
        }

    def load_skill(self, skill_name: str) -> Callable:
        """
        Dynamically load a skill function.

        Args:
            skill_name: Name of the skill to load

        Returns:
            Callable function for the skill

        Raises:
            KeyError: If skill_name not found in definitions
            ImportError: If module cannot be imported
        """
        if skill_name in self.loaded_skills:
            return self.loaded_skills[skill_name]

        if skill_name not in self.skill_definitions:
            raise KeyError(f"Skill '{skill_name}' not found in registry")

        skill_def = self.skill_definitions[skill_name]

        try:
            module = importlib.import_module(skill_def["module"])
            skill_function = getattr(module, skill_def["function"])
            self.loaded_skills[skill_name] = skill_function
            print(f"[SkillRegistry] Loaded skill: {skill_name}")
            return skill_function
        except (ImportError, AttributeError) as e:
            raise ImportError(f"Failed to load skill '{skill_name}': {e}")

    def detect_needed_skills(self, context: str) -> List[str]:
        """
        Analyze context and determine which skills should be loaded.

        Args:
            context: Text to analyze for skill triggers

        Returns:
            List of skill names that should be loaded
        """
        needed_skills = []
        context_lower = context.lower()

        for skill_name, skill_def in self.skill_definitions.items():
            # Skip if already loaded
            if skill_name in self.loaded_skills:
                continue

            # Check if any trigger words/patterns are in context
            triggers = skill_def.get("triggers", [])
            for trigger in triggers:
                if trigger.lower() in context_lower:
                    needed_skills.append(skill_name)
                    break

        # Special patterns
        # External IP address pattern (not internal)
        ip_pattern = r'\b(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        if re.search(ip_pattern, context) and "tavily_threat_search" not in self.loaded_skills:
            if "tavily_threat_search" not in needed_skills:
                needed_skills.append("tavily_threat_search")

        # File hash pattern (MD5/SHA256)
        hash_pattern = r'\b[a-f0-9]{32,64}\b'
        if re.search(hash_pattern, context_lower) and "tavily_threat_search" not in self.loaded_skills:
            if "tavily_threat_search" not in needed_skills:
                needed_skills.append("tavily_threat_search")

        return needed_skills

    def auto_load_skills(self, context: str) -> List[str]:
        """
        Automatically detect and load needed skills based on context.

        Args:
            context: Text to analyze

        Returns:
            List of skill names that were loaded
        """
        needed = self.detect_needed_skills(context)
        loaded = []

        for skill_name in needed:
            try:
                self.load_skill(skill_name)
                loaded.append(skill_name)
            except (KeyError, ImportError) as e:
                print(f"[SkillRegistry] Warning: Could not load skill '{skill_name}': {e}")

        return loaded

    def get_skill(self, skill_name: str) -> Callable:
        """
        Get a loaded skill function. Loads if not already loaded.

        Args:
            skill_name: Name of the skill

        Returns:
            Callable skill function
        """
        if skill_name not in self.loaded_skills:
            return self.load_skill(skill_name)
        return self.loaded_skills[skill_name]

    def unload_all(self):
        """Unload all skills to free memory."""
        self.loaded_skills.clear()
        print("[SkillRegistry] All skills unloaded")

    def get_loaded_skills(self) -> List[str]:
        """Return list of currently loaded skill names."""
        return list(self.loaded_skills.keys())

    def is_loaded(self, skill_name: str) -> bool:
        """Check if a skill is currently loaded."""
        return skill_name in self.loaded_skills
