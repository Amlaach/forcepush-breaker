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
            if active_provider == "gemini": return self._call_gemini(prompt)
            elif active_provider == "openai": return self._call_openai(prompt)
            elif active_provider == "anthropic": return self._call_anthropic(prompt)
            elif active_provider == "ollama": return self._call_ollama(prompt)
        except Exception as e:
            heuristic = self._heuristic_triage(finding_rule, masked_snippet, context_line, commit_message, file_path)
            heuristic.technical_explanation += f" (Note: {active_provider} fallback: {str(e)[:50]})"
            return heuristic

        return self._heuristic_triage(finding_rule, masked_snippet, context_line, commit_message, file_path)

    def _resolve_provider(self) -> str:
        if self.provider != "auto": return self.provider
        if os.getenv("GEMINI_API_KEY"): return "gemini"
        if os.getenv("OPENAI_API_KEY"): return "openai"
        if os.getenv("ANTHROPIC_API_KEY"): return "anthropic"
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=1):
                return "ollama"
        except Exception: pass
        return "heuristic"

    def _build_prompt(self, finding_rule: str, masked_snippet: str, context_line: str, commit_message: Optional[str], author: Optional[str], file_path: Optional[str]) -> str:
        return f"""You are a Git Forensics and Application Security Expert.
An orphaned commit or dangling blob was exhumed from a local Git repository.
All sensitive strings have ALREADY been strictly REDACTED for security.

Analyze whether this is a TRUE POSITIVE leak or FALSE POSITIVE.
Context:
- Finding Rule: {finding_rule}
- File Path: {file_path or "Unknown"}
- Commit Message: {commit_message or "N/A"}
- Author: {author or "Unknown"}
- Redacted Snippet: {masked_snippet}
- Surrounding Line: {context_line}

Return ONLY a valid JSON object matching this schema:
{{
  "severity": "Critical" | "High" | "Medium" | "Low",
  "is_false_positive": boolean,
  "risk_score": float (1.0 to 10.0),
  "technical_explanation": "concise explanation (1-2 sentences)",
  "recommended_action": "recommended remediation step"
}}"""

    def _call_openai(self, prompt: str) -> AITriageResult:
        api_key = os.getenv("OPENAI_API_KEY", "")
        model = self.model or "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a Git security forensics auditor. Always respond with strict JSON."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            parsed = self._extract_json(content)
            return self._build_result_from_dict(parsed, f"OpenAI ({model})")

    def _call_anthropic(self, prompt: str) -> AITriageResult:
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        model = self.model or "claude-3-5-sonnet-20241022"
        url = "https://api.anthropic.com/v1/messages"
        payload = {"model": model, "max_tokens": 512, "temperature": 0.1, "messages": [{"role": "user", "content": prompt}]}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
