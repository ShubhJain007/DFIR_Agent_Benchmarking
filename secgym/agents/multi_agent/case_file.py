# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
CaseFile - Shared memory structure for multi-agent coordination
"""

from typing import Dict, List, Any
import json


class CaseFile:
    """
    Lightweight shared memory for investigation context.
    Stores entities, findings, timeline, and SQL history.
    """

    def __init__(self):
        self.question: str = ""
        self.entities: Dict[str, List[str]] = {
            "ips": [],
            "users": [],
            "hosts": [],
            "hashes": [],
            "domains": [],
            "emails": []
        }
        self.timeline: List[Dict[str, Any]] = []
        self.key_findings: List[str] = []
        self.external_intel: List[Dict[str, Any]] = []  # Research results
        self.external_intel_dict: Dict[str, Dict[str, Any]] = {}  # For deduplication
        self.current_hypothesis: str = ""
        self.tokens_used: int = 0
        self.sql_history: List[str] = []

    def add_entity(self, entity_type: str, value: str):
        """Add an entity to the case file."""
        if entity_type not in self.entities:
            self.entities[entity_type] = []

        if value not in self.entities[entity_type]:
            self.entities[entity_type].append(value)

    def add_entities(self, entities: Dict[str, List[str]]):
        """Add multiple entities at once."""
        for entity_type, values in entities.items():
            if entity_type not in self.entities:
                self.entities[entity_type] = []

            for value in values:
                if value not in self.entities[entity_type]:
                    self.entities[entity_type].append(value)

    def add_finding(self, finding: str):
        """Add a key finding to the case."""
        if finding and finding not in self.key_findings:
            self.key_findings.append(finding)

    def add_external_intel(self, intel: Dict[str, Any]):
        """Add external threat intelligence."""
        entity = intel.get("entity", "")

        # Avoid duplicates
        if entity and entity not in self.external_intel_dict:
            self.external_intel.append(intel)
            self.external_intel_dict[entity] = intel

    def add_sql_query(self, query: str):
        """Record a SQL query in history."""
        if query:
            self.sql_history.append(query)

    def update_hypothesis(self, hypothesis: str):
        """Update current working hypothesis."""
        self.current_hypothesis = hypothesis

    def to_context_string(self, max_length: int = 1000) -> str:
        """
        Generate a compressed context string for agent consumption.

        Args:
            max_length: Maximum character length

        Returns:
            Formatted context string
        """
        context_parts = []

        # Question
        if self.question:
            context_parts.append(f"Question: {self.question}")

        # Key findings
        if self.key_findings:
            findings_str = "; ".join(self.key_findings[:3])  # Top 3
            context_parts.append(f"Findings: {findings_str}")

        # Entities
        entity_summary = []
        for entity_type, values in self.entities.items():
            if values:
                count = len(values)
                sample = values[0] if count == 1 else f"{values[0]} (+{count-1} more)"
                entity_summary.append(f"{entity_type}: {sample}")

        if entity_summary:
            context_parts.append(f"Entities: {', '.join(entity_summary)}")

        # External intel
        if self.external_intel:
            intel_summary = []
            for intel in self.external_intel[:2]:  # Top 2
                entity = intel.get("entity", "")
                context = intel.get("threat_context", "")[:100]
                intel_summary.append(f"{entity}: {context}")

            context_parts.append(f"Intel: {'; '.join(intel_summary)}")

        # Hypothesis
        if self.current_hypothesis:
            context_parts.append(f"Hypothesis: {self.current_hypothesis}")

        # Combine and truncate
        full_context = " | ".join(context_parts)

        if len(full_context) > max_length:
            full_context = full_context[:max_length] + "..."

        return full_context

    def to_dict(self) -> Dict[str, Any]:
        """Convert case file to dictionary for logging."""
        return {
            "question": self.question,
            "entities": self.entities,
            "timeline_count": len(self.timeline),
            "findings_count": len(self.key_findings),
            "intel_count": len(self.external_intel),
            "sql_queries": len(self.sql_history),
            "hypothesis": self.current_hypothesis
        }

    def __repr__(self) -> str:
        return f"<CaseFile: {len(self.key_findings)} findings, {len(self.sql_history)} queries>"
