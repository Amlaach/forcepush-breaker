"""
AI-Powered Context Triage Engine.

Evaluates strictly redacted git findings to distinguish real credential leaks
(e.g., panicked commits removed via git reset) from false positives (tests, mocks, documentation).
Supports OpenAI, Anthropic, Gemini, Ollama, and a robust built-in Heuristic Fallback.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional
import urllib.request
import urllib.error


@dataclass
class AITriageResult:
    severity: str
    is_false_positive: bool
    risk_score: float
    technical_explanation: str
    recommended_action: str
    provider_used: str


class AITriage:
    def __init__(self, provider: str = "auto", model: Optional[str] = None, timeout_seconds: int = 15):
        self.provider = provider.lower()
        self.model = model
        self.timeout = timeout_seconds

    def triage_finding(
        self, finding_rule: str, masked_snippet: str, context_line: str,
        commit_message: Optional[str] = None, author: Optional[str] = None, file_path: Optional[str] = None
    ) -> AITriageResult:
        active_provider = self._resolve_provider()
        prompt = self._build_prompt(
            finding_rule=finding_rule, masked_snippet=masked_snippet, context_line=context_line,
            commit_message=commit_message, author=author, file_path=file_path
        )
        try:
