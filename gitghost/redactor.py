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
from typing import Dict, List, Optional, Set, Tuple, Union


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
    diff_hunk: str = ""


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
            "regex": re.compile(
                r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"
            ),
            "severity": "Critical",
            "mask_type": "preserve_edges",
        },
        {
            "name": "AWS Secret Access Key",
            "regex": re.compile(
                r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['\"]?([0-9a-zA-Z/+=]{40})['\"]?"
            ),
            "severity": "Critical",
            "mask_type": "full",
        },
        {
            "name": "GitHub Personal Access Token",
            "regex": re.compile(
                r"\b(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"
            ),
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
            "regex": re.compile(
                r"\b(sk-proj-[a-zA-Z0-9_\-]{40,}|sk-ant-[a-zA-Z0-9_\-]{40,}|sk-[a-zA-Z0-9]{32,})\b"
            ),
            "severity": "Critical",
            "mask_type": "preserve_edges",
        },
        {
            "name": "Private Key Block",
            "regex": re.compile(
                r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"
            ),
            "severity": "Critical",
            "mask_type": "private_key",
        },
        {
            "name": "Database Connection URI with Password",
            "regex": re.compile(
                r"\b((?:postgres|postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[a-zA-Z0-9_.%+-]+:)([^@\s/]+)(@[a-zA-Z0-9.-]+(?::[0-9]+)?(?:\/[a-zA-Z0-9_.-]+)?)\b"
            ),
            "severity": "Critical",
            "mask_type": "db_uri",
        },
        {
            "name": "Generic Secret in Configuration / Env",
            "regex": re.compile(
                r"(?i)\b(password|passwd|secret|token|api_key|apikey|access_token|auth_token|client_secret|private_key)\s*[:=]\s*['\"]?([^\s\"'#;]{8,})['\"]?"
            ),
            "severity": "High",
            "mask_type": "env_secret",
        },
        {
            "name": "JSON Web Token (JWT)",
            "regex": re.compile(
                r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b"
            ),
            "severity": "Medium",
            "mask_type": "preserve_edges",
        },
    ]

    FALSE_POSITIVE_TERMS: Set[str] = {
        "your_api_key_here",
        "insert_token_here",
        "changeme",
        "placeholder",
        "dummy_key",
        "fake_key",
        "test_key",
        "null",
        "undefined",
        "your_secret_here",
        "your_api_key",
        "insert_token",
        "fake_secret",
        "dummy_value",
        "my_secret_key",
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

        findings: List[SecretFinding] = []
        finding_counter = 0

        # Step 1: Pre-process and mask Asymmetric Private Key blocks across lines
        working_text = text
        pk_regex = re.compile(
            r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----[\s\S]*?-----END (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"
        )
        for match in pk_regex.finditer(text):
            finding_counter += 1
            fid = f"PK-{finding_counter:04d}"
            raw_pk_block = match.group(0)
            entropy = shannon_entropy(raw_pk_block)
            masked_pk = "-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY_BLOCK]\n-----END PRIVATE KEY-----"
            working_text = working_text.replace(raw_pk_block, masked_pk)
            findings.append(
                SecretFinding(
                    finding_id=fid,
                    rule_name="Asymmetric Private Key Block",
                    match_type="pattern",
                    severity_estimate="Critical",
                    masked_value="[REDACTED_PRIVATE_KEY_BLOCK]",
                    line_number=1,
                    context_line="-----BEGIN PRIVATE KEY----- ... [REDACTED_PRIVATE_KEY_BLOCK]",
                    entropy=round(entropy, 2),
                    file_path=file_path,
                    commit_hash=commit_hash,
                    blob_hash=blob_hash,
                )
            )

        # Step 2: Line-by-line scanning and multi-secret masking
        lines = working_text.splitlines(keepends=True)
        sanitized_lines: List[str] = []

        for line_idx, line in enumerate(lines, start=1):
            current_line = line
            line_without_newline = line.rstrip("\r\n")
            line_findings: List[SecretFinding] = []
            line_replacements: List[Tuple[str, str]] = []

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
                        raw_pwd = match.group(2)
                        suffix = match.group(3)
                        masked_pwd = "[REDACTED_DB_PASSWORD]"
                        replacement = f"{prefix}{masked_pwd}{suffix}"
                        entropy = shannon_entropy(raw_pwd)
                        current_line = current_line.replace(match.group(0), replacement)
                        line_replacements.append((raw_pwd, masked_pwd))
                        line_findings.append(
                            SecretFinding(
                                finding_id=fid,
                                rule_name=rule_name,
                                match_type="pattern",
                                severity_estimate=severity,
                                masked_value=replacement,
                                line_number=line_idx,
                                context_line="",
                                entropy=round(entropy, 2),
                                file_path=file_path,
                                commit_hash=commit_hash,
                                blob_hash=blob_hash,
                            )
                        )

                    elif mask_type == "env_secret":
                        key_name = match.group(1)
                        raw_secret = match.group(2)
                        if self._is_dummy_value(raw_secret):
                            continue
                        entropy = shannon_entropy(raw_secret)
                        masked_val = "[REDACTED_SECRET_KEY]"
                        replacement = f"{key_name}={masked_val}"
                        current_line = current_line.replace(match.group(0), replacement)
                        line_replacements.append((raw_secret, masked_val))
                        line_findings.append(
                            SecretFinding(
                                finding_id=fid,
                                rule_name=f"{rule_name} ({key_name})",
                                match_type="pattern",
                                severity_estimate=severity,
                                masked_value=masked_val,
                                line_number=line_idx,
                                context_line="",
                                entropy=round(entropy, 2),
                                file_path=file_path,
                                commit_hash=commit_hash,
                                blob_hash=blob_hash,
                            )
                        )

                    elif mask_type == "preserve_edges":
                        raw_val = match.group(1)
                        if self._is_dummy_value(raw_val):
                            continue
                        masked_val = mask_credential(raw_val)
                        entropy = shannon_entropy(raw_val)
                        current_line = current_line.replace(raw_val, masked_val)
                        line_replacements.append((raw_val, masked_val))
                        line_findings.append(
                            SecretFinding(
                                finding_id=fid,
                                rule_name=rule_name,
                                match_type="pattern",
                                severity_estimate=severity,
                                masked_value=masked_val,
                                line_number=line_idx,
                                context_line="",
                                entropy=round(entropy, 2),
                                file_path=file_path,
                                commit_hash=commit_hash,
                                blob_hash=blob_hash,
                            )
                        )

                    elif mask_type == "full":
                        raw_val = match.group(1)
                        masked_val = "[REDACTED_AWS_SECRET_KEY]"
                        entropy = shannon_entropy(raw_val)
                        current_line = current_line.replace(raw_val, masked_val)
                        line_replacements.append((raw_val, masked_val))
                        line_findings.append(
                            SecretFinding(
                                finding_id=fid,
                                rule_name=rule_name,
                                match_type="pattern",
                                severity_estimate=severity,
                                masked_value=masked_val,
                                line_number=line_idx,
                                context_line="",
                                entropy=round(entropy, 2),
                                file_path=file_path,
                                commit_hash=commit_hash,
                                blob_hash=blob_hash,
                            )
                        )

            tokens = re.findall(r"[A-Za-z0-9+/=_-]{16,}", current_line)
            for token in tokens:
                if "REDACTED" in token or "****" in token or self._is_dummy_value(token):
                    continue
                entropy = shannon_entropy(token)
                if entropy >= self.entropy_threshold:
                    finding_counter += 1
                    fid = f"ENT-{finding_counter:04d}"
                    masked_token = mask_credential(token, 3, 3)
                    current_line = current_line.replace(
                        token, "[REDACTED_HIGH_ENTROPY_SECRET]"
                    )
                    line_replacements.append((token, "[REDACTED_HIGH_ENTROPY_SECRET]"))
                    line_findings.append(
                        SecretFinding(
                            finding_id=fid,
                            rule_name="High Entropy Suspicious Secret",
                            match_type="entropy",
                            severity_estimate="High" if entropy > 4.6 else "Medium",
                            masked_value=masked_token,
                            line_number=line_idx,
                            context_line="",
                            entropy=round(entropy, 2),
                            file_path=file_path,
                            commit_hash=commit_hash,
                            blob_hash=blob_hash,
                        )
                    )

            # Strictly mask ALL secrets detected on this line in each finding's context_line
            for f in line_findings:
                f.context_line = self._mask_raw_line(
                    line_without_newline, line_replacements
                )

            findings.extend(line_findings)
            sanitized_lines.append(current_line)

        clean_sanitized = [ln.rstrip("\r\n") for ln in sanitized_lines]
        for f in findings:
            if f.finding_id.startswith("PK-"):
                f.diff_hunk = (
                    "-----BEGIN PRIVATE KEY-----\n"
                    "[REDACTED_PRIVATE_KEY_BLOCK]\n"
                    "-----END PRIVATE KEY-----"
                )
            elif clean_sanitized:
                idx0 = max(0, f.line_number - 1)
                start_idx = max(0, idx0 - 3)
                end_idx = min(len(clean_sanitized), idx0 + 4)
                f.diff_hunk = "\n".join(clean_sanitized[start_idx:end_idx])
            else:
                f.diff_hunk = f.context_line

        redacted_full_text = "".join(sanitized_lines)
        return RedactionResult(redacted_text=redacted_full_text, findings=findings)

    def _is_dummy_value(self, value: str) -> bool:
        val_lower = value.strip().lower()
        if val_lower in self.FALSE_POSITIVE_TERMS or val_lower in ("none", "example", "dummy"):
            return True
        if any(term in val_lower for term in self.FALSE_POSITIVE_TERMS):
            return True
        if len(set(value)) <= 2:
            return True
        return False

    def _mask_raw_line(
        self,
        original_line: str,
        secret: Union[str, List[Tuple[str, str]], Dict[str, str], List[str]],
        replacement: str = "[REDACTED]",
    ) -> str:
        """Strictly masks one or multiple secrets within a code context line."""
        if isinstance(secret, str):
            return original_line.replace(secret, replacement) if secret in original_line else original_line
        elif isinstance(secret, dict):
            line = original_line
            for s, r in secret.items():
                if s in line:
                    line = line.replace(s, r)
            return line
        elif isinstance(secret, (list, tuple)):
            line = original_line
            for item in secret:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    s, r = str(item[0]), str(item[1])
                else:
                    s, r = str(item), replacement
                if s in line:
                    line = line.replace(s, r)
            return line
        return original_line
