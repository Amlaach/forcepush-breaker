"""
Entropy Detector and Strict Secret Redactor.

Calculates Shannon entropy, detects sensitive tokens and credentials
via high-precision regex patterns, and enforces strict redaction so that raw secrets
are NEVER emitted in terminal output, exported reports, or AI prompts.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies: Dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def mask_credential(value: str, preserve_head: int = 4, preserve_tail: int = 4) -> str:
    if len(value) <= (preserve_head + preserve_tail):
        return "*" * len(value)
    middle_len = len(value) - preserve_head - preserve_tail
    return value[:preserve_head] + ("*" * min(middle_len, 12)) + value[-preserve_tail:]


@dataclass
class SecretFinding:
    finding_id: str
    rule_name: str
    match_type: str
    severity_estimate: str
    masked_value: str
    line_number: int
    context_line: str
    entropy: float
    file_path: Optional[str] = None
    commit_hash: Optional[str] = None
    blob_hash: Optional[str] = None


@dataclass
class RedactionResult:
    redacted_text: str
    findings: List[SecretFinding] = field(default_factory=list)


class SecretRedactor:
    ENTROPY_THRESHOLD = 4.3
    MIN_ENTROPY_LEN = 16

    RULES = [
        {
            "name": "AWS Access Key ID",
            "regex": re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"),
            "severity": "Critical",
            "mask_type": "preserve_edges",
        },
        {
            "name": "AWS Secret Access Key",
            "regex": re.compile(r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['\"]?([0-9a-zA-Z/+=]{40})['\"]?"),
            "severity": "Critical",
            "mask_type": "full",
        },
        {
            "name": "GitHub Personal Access Token",
            "regex": re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"),
            "severity": "Critical",
            "mask_type": "preserve_edges",
        },
        {
            "name": "GitLab Personal Access Token",
            "regex": re.compile(r"\b(glpat-[0-9a-zA-Z\-]{20,})\b"),
            "severity": "Critical",
            "mask_type": "preserve_edges",
        },
        {
            "name": "Slack Token",
            "regex": re.compile(r"\b(xox[baprs]-[0-9a-zA-Z\-]{20,80})\b"),
            "severity": "High",
            "mask_type": "preserve_edges",
        },
        {
            "name": "Google API Key",
            "regex": re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
            "severity": "High",
            "mask_type": "preserve_edges",
        },
        {
            "name": "OpenAI / Anthropic API Key",
            "regex": re.compile(r"\b(sk-proj-[a-zA-Z0-9_\-]{40,}|sk-ant-[a-zA-Z0-9_\-]{40,}|sk-[a-zA-Z0-9]{32,})\b"),
            "severity": "Critical",
