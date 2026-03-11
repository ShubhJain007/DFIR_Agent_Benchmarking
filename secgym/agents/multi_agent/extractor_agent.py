# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
ExtractorAgent - Dedicated answer validation and disambiguation.

Addresses the #1 Category A failure mode: agent has the correct data in
query results but selects the wrong value (51% of failures for claude-opus).

The extractor receives (question, candidate_answer, raw_result_context) and
returns (validated_answer, confidence). It never writes SQL — its sole job
is to pick the right value from evidence already retrieved.
"""

import re
from typing import Tuple
from autogen import OpenAIWrapper
from secgym.agents.agent_utils import call_llm, update_model_usage


# ---------------------------------------------------------------------------
# Answer-type detection
# ---------------------------------------------------------------------------

def detect_answer_type(question: str) -> str:
    """
    Infer the expected answer format from question phrasing.
    Returned string is injected into the extractor prompt to constrain
    which values the model should consider.
    """
    q = question.lower()
    if any(x in q for x in ["ip address", "ip addr", "ip of", "ip used", "ip associated",
                              "what is the ip", "identify the ip"]):
        return "IPv4 address (format: X.X.X.X)"
    if any(x in q for x in ["email", "user principal", "upn"]):
        return "email address or User Principal Name"
    if any(x in q for x in ["user", "account", "who "]):
        return "username or account name"
    if any(x in q for x in ["hostname", "device name", "host of", "machine name"]):
        return "hostname or device name"
    if any(x in q for x in ["command line", "commandline", "command used"]):
        return "command line string"
    if any(x in q for x in ["file name", "filename", "file associated",
                              "name of the file", "name of the malware"]):
        return "filename (e.g. malware.exe)"
    if any(x in q for x in ["process name", "process involved"]):
        return "process name"
    if any(x in q for x in ["hash", "sha", "md5"]):
        return "file hash (hex string)"
    if any(x in q for x in ["timestamp", "time of", "when did", "when was"]):
        return "timestamp (datetime string)"
    if any(x in q for x in ["cloud app", "application id", "app id"]):
        return "cloud application ID (integer)"
    if any(x in q for x in ["sid ", "security identifier"]):
        return "Windows SID (format: S-1-5-...)"
    if any(x in q for x in ["aad", "azure ad", "object id",
                              "device id", "aaddeviceid", "aaduser"]):
        return "Azure AD GUID (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
    if any(x in q for x in ["port", "remote port", "local port"]):
        return "port number (integer)"
    if any(x in q for x in ["registry", "regkey"]):
        return "Windows registry key path"
    return "specific string value"


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

EXTRACTOR_SYSTEM = """You are a precision answer extractor for cybersecurity investigations.

You receive:
- QUESTION     : the investigation question
- ANSWER TYPE  : the expected format/type of the answer
- CANDIDATE    : what the investigator proposes to submit
- EVIDENCE     : raw database result(s) that were retrieved

Your ONLY job: verify or correct the candidate against the evidence.

Output format (one line, exactly):
ANSWER: <value> | CONFIDENCE: <0.0-1.0> | REASON: <one sentence>

Rules:
1. If the candidate is correct and clearly supported by the evidence, confirm it (CONFIDENCE > 0.8).
2. If multiple values of the expected type exist in the evidence, pick the one semantically
   closest to the question's specific constraint (e.g., the one on the same row as the
   alert name mentioned in the question).
3. If you find a more precise match than the candidate, use that instead.
4. If you cannot determine the correct answer (CONFIDENCE < 0.5), output:
   ANSWER: UNCERTAIN | CONFIDENCE: 0.0 | REASON: <why>
5. Do NOT invent values not present in the evidence.
6. Do NOT explain at length — output ONLY the single answer line.
"""


# ---------------------------------------------------------------------------
# Agent class
# ---------------------------------------------------------------------------

class ExtractorAgent:
    """
    Validates the investigator's proposed answer before submission.

    Called by OrchestratorAgent when InvestigatorAgent returns submit=True.
    A confidence < 0.6 signals the orchestrator to keep investigating.
    """

    def __init__(self, config_list, retry_num: int = 3, retry_wait_time: int = 5):
        self.config_list = config_list
        self.retry_num = retry_num
        self.retry_wait_time = retry_wait_time
        self.client = OpenAIWrapper(config_list=config_list, cache_seed=None)
        self.total_usage: dict = {}
        self._call_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        question: str,
        candidate: str,
        result_context: str,
    ) -> Tuple[str, float]:
        """
        Validate candidate_answer against the evidence in result_context.

        Args:
            question       : original investigation question
            candidate      : answer the investigator wants to submit
            result_context : last SQL observation (raw result rows)

        Returns:
            (validated_answer, confidence)
            confidence < 0.6 → caller should continue investigating
        """
        self._call_count += 1
        answer_type = detect_answer_type(question)

        user_msg = (
            f"QUESTION: {question}\n\n"
            f"ANSWER TYPE: {answer_type}\n\n"
            f"CANDIDATE ANSWER: {candidate}\n\n"
            f"EVIDENCE (raw database results — up to 3000 chars):\n"
            f"{result_context[:3000]}"
        )

        messages = [
            {"role": "system", "content": EXTRACTOR_SYSTEM},
            {"role": "user",   "content": user_msg},
        ]

        try:
            response = call_llm(
                client=self.client,
                model=self.config_list[0]["model"],
                messages=messages,
                retry_num=self.retry_num,
                retry_wait_time=self.retry_wait_time,
                temperature=0,
            )
            update_model_usage(
                self.total_usage,
                model_name=response.model,
                usage_dict=response.usage.model_dump(),
            )
            text = response.choices[0].message.content.strip()
        except Exception as e:
            print(f"[Extractor] LLM call failed: {e}. Falling back to candidate.")
            return candidate, 0.5

        return self._parse(text, candidate)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _parse(self, text: str, fallback: str) -> Tuple[str, float]:
        """Parse ANSWER: X | CONFIDENCE: Y | REASON: Z."""
        try:
            answer_m = re.search(r'ANSWER:\s*(.+?)\s*\|', text)
            conf_m   = re.search(r'CONFIDENCE:\s*([0-9.]+)', text)

            answer     = answer_m.group(1).strip() if answer_m else fallback
            confidence = float(conf_m.group(1))    if conf_m   else 0.5

            if answer.upper() == "UNCERTAIN" or not answer:
                print(f"[Extractor] Uncertain — keeping candidate: {fallback}")
                return fallback, 0.0

            print(f"[Extractor] Validated: {answer!r} (conf={confidence:.2f})")
            return answer, confidence

        except Exception:
            return fallback, 0.5

    @property
    def call_count(self) -> int:
        return self._call_count
