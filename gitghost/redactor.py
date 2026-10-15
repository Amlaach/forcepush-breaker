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
            "mask_type": "preserve_edges",
        },
        {
            "name": "Private Key Block",
            "regex": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
            "severity": "Critical",
            "mask_type": "private_key",
        },
        {
            "name": "Database Connection URI with Password",
            "regex": re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[a-zA-Z0-9_.%+-]+:)([^@\s/]+)(@[a-zA-Z0-9.-]+(?::[0-9]+)?(?:\/[a-zA-Z0-9_.-]+)?)\b"),
            "severity": "Critical",
            "mask_type": "db_uri",
        },
        {
            "name": "Generic Secret in Configuration / Env",
            "regex": re.compile(r"(?i)\b(password|passwd|secret|token|api_key|apikey|access_token|auth_token|client_secret|private_key)\s*[:=]\s*['\"]?([^\s\"'#;]{8,})['\"]?"),
            "severity": "High",
            "mask_type": "env_secret",
        },
        {
            "name": "JSON Web Token (JWT)",
            "regex": re.compile(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"),
            "severity": "Medium",
            "mask_type": "preserve_edges",
        },
    ]

    FALSE_POSITIVE_TERMS: Set[str] = {
        "your_api_key_here", "insert_token_here", "changeme", "placeholder",
        "dummy_key", "fake_key", "test_key", "null", "undefined", "your_secret_here"
    }

    def __init__(self, entropy_threshold: float = ENTROPY_THRESHOLD):
        self.entropy_threshold = entropy_threshold

    def scan_and_redact(
        self,
        text: str,
        file_path: Optional[str] = None,
        commit_hash: Optional[str] = None,
        blob_hash: Optional[str] = None,
    ) -> RedactionResult:
        if not text:
            return RedactionResult(redacted_text="", findings=[])

        lines = text.splitlines(keepends=True)
        sanitized_lines: List[str] = []
        findings: List[SecretFinding] = []
        finding_counter = 0

        for line_idx, line in enumerate(lines, start=1):
            current_line = line
            line_without_newline = line.rstrip("\r\n")

            for rule in self.RULES:
                rule_name = rule["name"]
                regex = rule["regex"]
                severity = rule["severity"]
                mask_type = rule["mask_type"]

                if mask_type == "private_key":
                    continue

                for match in regex.finditer(current_line):
                    finding_counter += 1
                    fid = f"SEC-{finding_counter:04d}"

                    if mask_type == "db_uri":
                        prefix = match.group(1)
