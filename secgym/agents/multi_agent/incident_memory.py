# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
IncidentMemory - Lightweight cross-question fact store.

Persists across agent.reset() calls within a single incident so that
facts discovered in question N are available to question N+K without
re-querying the database. Cleared on incident change (new_incident=True).

No external dependencies — pure Python dict/list store with keyword
matching for retrieval.
"""

import re
from typing import Dict, List, Any


# Common words to skip when indexing / matching
_STOPWORDS = {
    "what", "which", "where", "when", "that", "this", "with", "from",
    "have", "been", "were", "there", "their", "about", "could", "would",
    "should", "does", "security", "alert", "incident", "identify",
    "provide", "related", "involved", "following", "associated",
    "recent", "please", "given", "there", "also", "into", "your",
    "find", "name", "used", "using", "detected", "found",
}


def _tokens(text: str) -> List[str]:
    """Extract meaningful tokens from text for indexing."""
    words = re.split(r'[\s.,;:!?()\[\]"\'`/\\]+', text.lower())
    return [w for w in words if len(w) > 3 and w not in _STOPWORDS]


def _detect_answer_type(question: str) -> str:
    """Infer property label from question phrasing."""
    q = question.lower()
    if any(x in q for x in ["ip address", "ip addr", "ip of", "ip used", "ip associated"]):
        return "ip_address"
    if any(x in q for x in ["email", "user principal", "upn"]):
        return "email"
    if any(x in q for x in ["user", "account", "who "]):
        return "user_account"
    if any(x in q for x in ["hostname", "device name", "host of", "machine name"]):
        return "hostname"
    if any(x in q for x in ["command line", "commandline", "command used", "cmd"]):
        return "command_line"
    if any(x in q for x in ["file name", "filename", "file associated", "name of the file"]):
        return "filename"
    if any(x in q for x in ["process", "process name"]):
        return "process_name"
    if any(x in q for x in ["hash", "sha", "md5"]):
        return "file_hash"
    if any(x in q for x in ["when", "timestamp", "time of", "date"]):
        return "timestamp"
    if any(x in q for x in ["app id", "application id", "cloud app"]):
        return "cloud_app_id"
    if any(x in q for x in ["sid ", "security identifier"]):
        return "sid"
    if any(x in q for x in ["aad", "azure ad", "object id", "device id", "aaddeviceid"]):
        return "azure_ad_id"
    return "finding"


def _extract_anchors(text: str) -> List[str]:
    """
    Pull named entities from backtick and quoted strings in question text.
    These become the primary index keys.
    """
    anchors = re.findall(r'`([^`]+)`', text)
    anchors += re.findall(r'"([^"]+)"', text)
    # Also grab CamelCase alert-style names (e.g. "ManateeTempest", "LockBit")
    anchors += re.findall(
        r'\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b', text
    )
    return [a.strip() for a in anchors if a.strip()]


class IncidentMemory:
    """
    In-memory fact store that survives agent.reset() within one incident.

    Storage structure:
        facts        : list of fact dicts
        entity_index : token → list of fact indices  (for fast lookup)
    """

    def __init__(self):
        self.facts: List[Dict[str, Any]] = []
        self.entity_index: Dict[str, List[int]] = {}
        self._memory_hits: int = 0

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def store(
        self,
        entity: str,
        property: str,
        value: str,
        source_q: str = "",
    ) -> None:
        """Store a single entity→property:value fact."""
        if not value or not entity:
            return

        fact = {
            "entity":   entity.strip(),
            "property": property.strip(),
            "value":    value.strip(),
            "source_q": source_q[:120],
        }
        idx = len(self.facts)
        self.facts.append(fact)

        # Index every meaningful token from entity + property
        for tok in _tokens(entity) + _tokens(property):
            self.entity_index.setdefault(tok, []).append(idx)

        # Also index raw anchor strings (full entity name, split on spaces)
        for part in entity.lower().split():
            if len(part) > 2:
                self.entity_index.setdefault(part, []).append(idx)

    def store_from_answer(self, question: str, answer: str) -> None:
        """
        Automatically extract entity + property from question text,
        then store the answer as the value.
        Called externally by run_exp.py after reward > 0.
        """
        if not answer or not question:
            return

        prop = _detect_answer_type(question)
        anchors = _extract_anchors(question)
        entity = anchors[0] if anchors else question[:60]

        self.store(
            entity=entity,
            property=prop,
            value=answer,
            source_q=question[:120],
        )

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def lookup(self, question: str) -> List[str]:
        """
        Return up to 5 relevant cached facts for this question as
        human-readable strings.  Uses keyword matching — no embeddings.
        """
        if not self.facts:
            return []

        # Build query token set from question
        query_tokens = set(_tokens(question))

        # Add explicit anchors (backtick/quoted terms) — high signal
        anchors = _extract_anchors(question)
        for a in anchors:
            for tok in _tokens(a) + a.lower().split():
                if len(tok) > 2:
                    query_tokens.add(tok)

        # Score each fact by token overlap
        scores: Dict[int, int] = {}
        for tok in query_tokens:
            # Exact token match
            for idx in self.entity_index.get(tok, []):
                scores[idx] = scores.get(idx, 0) + 2
            # Partial match (token is substring of index key or vice versa)
            for idx_key, idx_list in self.entity_index.items():
                if tok != idx_key and (tok in idx_key or idx_key in tok):
                    for idx in idx_list:
                        scores[idx] = scores.get(idx, 0) + 1

        if not scores:
            return []

        self._memory_hits += 1

        # Return top-5 facts by score, formatted as strings
        top = sorted(scores.items(), key=lambda x: -x[1])[:5]
        results = []
        for idx, _ in top:
            f = self.facts[idx]
            results.append(
                f"{f['entity']} → {f['property']}: {f['value']}"
            )
        return results

    def get_context_block(self, question: str) -> str:
        """
        Return a formatted block to prepend to the agent's first observation.
        Empty string if no relevant facts found.
        """
        hits = self.lookup(question)
        if not hits:
            return ""
        lines = ["[Cached facts from earlier questions in this incident:]"]
        lines.extend(f"  • {h}" for h in hits)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Wipe all facts — call when switching to a new incident."""
        self.facts = []
        self.entity_index = {}
        self._memory_hits = 0

    def size(self) -> int:
        return len(self.facts)

    @property
    def memory_hits(self) -> int:
        return self._memory_hits

    def __repr__(self) -> str:
        return (
            f"<IncidentMemory: {len(self.facts)} facts, "
            f"{self._memory_hits} hits>"
        )
