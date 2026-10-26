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
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

_OLLAMA_CHECKED: Optional[bool] = None


def _urlopen_safe(req: urllib.request.Request, timeout: float) -> Any:
    try:
        return urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError:
        raise
    except urllib.error.URLError as exc:
        if "CERTIFICATE_VERIFY_FAILED" in str(exc):
            ctx = ssl._create_unverified_context()
            return urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raise


def _is_ollama_reachable() -> bool:
    global _OLLAMA_CHECKED
    if _OLLAMA_CHECKED is not None:
        return _OLLAMA_CHECKED
    try:
        with socket.create_connection(("127.0.0.1", 11434), timeout=0.12):
            _OLLAMA_CHECKED = True
    except OSError:
        _OLLAMA_CHECKED = False
    return _OLLAMA_CHECKED


@dataclass
class AITriageResult:
    severity: str
    is_false_positive: bool
    risk_score: float
    technical_explanation: str
    recommended_action: str
    provider_used: str


class AITriage:
    def __init__(
        self,
        provider: str = "auto",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: int = 15,
    ):
        self.provider = provider.lower()
        self.model = model
        self.api_key = (api_key or "").strip() or None
        self.timeout = timeout_seconds

    def triage_finding(
        self,
        finding_rule: str,
        masked_snippet: str,
        context_line: str,
        commit_message: Optional[str] = None,
        author: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> AITriageResult:
        active_provider = self._resolve_provider()
        if active_provider == "heuristic":
            return self._heuristic_triage(finding_rule, masked_snippet, context_line, commit_message, file_path)

        prompt = self._build_prompt(
            finding_rule=finding_rule,
            masked_snippet=masked_snippet,
            context_line=context_line,
            commit_message=commit_message,
            author=author,
            file_path=file_path,
        )
        try:
            if active_provider == "gemini":
                return self._call_gemini(prompt)
            elif active_provider == "openai":
                return self._call_openai(prompt)
            elif active_provider == "anthropic":
                return self._call_anthropic(prompt)
            elif active_provider == "ollama":
                return self._call_ollama(prompt)
        except Exception as e:
            raw_err = str(e)
            if self.api_key:
                raw_err = raw_err.replace(self.api_key, "[REDACTED_API_KEY]")
            heuristic = self._heuristic_triage(finding_rule, masked_snippet, context_line, commit_message, file_path)
            heuristic.technical_explanation += f" (Note: {active_provider} fallback: {raw_err[:50]})"
            return heuristic

        return self._heuristic_triage(finding_rule, masked_snippet, context_line, commit_message, file_path)

    def _resolve_provider(self) -> str:
        if self.provider != "auto":
            return self.provider
        if self.api_key:
            if self.api_key.startswith("sk-ant-"):
                return "anthropic"
            if self.api_key.startswith("AIzaSy"):
                return "gemini"
            if self.api_key.startswith("sk-"):
                return "openai"
        if os.getenv("GEMINI_API_KEY"):
            return "gemini"
        if os.getenv("OPENAI_API_KEY"):
            return "openai"
        if os.getenv("ANTHROPIC_API_KEY"):
            return "anthropic"
        if os.getenv("UNFORCE_ENABLE_OLLAMA") == "1" and _is_ollama_reachable():
            return "ollama"
        return "heuristic"

    def _build_prompt(
        self,
        finding_rule: str,
        masked_snippet: str,
        context_line: str,
        commit_message: Optional[str],
        author: Optional[str],
        file_path: Optional[str],
    ) -> str:
        return f"""You are a Git Forensics and Application Security Expert.
An orphaned commit or dangling blob was exhumed from a Git repository.
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
        api_key = self.api_key or os.getenv("OPENAI_API_KEY", "")
        model = self.model or "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a Git security forensics auditor. Always respond with strict JSON."},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        )
        with _urlopen_safe(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            content = body["choices"][0]["message"]["content"]
            parsed = self._extract_json(content)
            return self._build_result_from_dict(parsed, f"OpenAI ({model})")

    def _call_anthropic(self, prompt: str) -> AITriageResult:
        api_key = self.api_key or os.getenv("ANTHROPIC_API_KEY", "")
        model = self.model or "claude-3-5-sonnet-20241022"
        url = "https://api.anthropic.com/v1/messages"
        payload = {"model": model, "max_tokens": 512, "temperature": 0.1, "messages": [{"role": "user", "content": prompt}]}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"},
        )
        with _urlopen_safe(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            parsed = self._extract_json(body["content"][0]["text"])
            return self._build_result_from_dict(parsed, f"Anthropic ({model})")

    def _call_gemini(self, prompt: str) -> AITriageResult:
        api_key = self.api_key or os.getenv("GEMINI_API_KEY", "")
        model = self.model or "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}], "generationConfig": {"responseMimeType": "application/json"}}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with _urlopen_safe(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            parsed = self._extract_json(body["candidates"][0]["content"]["parts"][0]["text"])
            return self._build_result_from_dict(parsed, f"Gemini ({model})")

    def _call_ollama(self, prompt: str) -> AITriageResult:
        model = self.model or "llama3"
        url = "http://127.0.0.1:11434/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": False, "format": "json"}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            parsed = self._extract_json(body.get("response", "{}"))
            return self._build_result_from_dict(parsed, f"Ollama ({model})")

    def _heuristic_triage(
        self,
        finding_rule: str,
        masked_snippet: str,
        context_line: str,
        commit_message: Optional[str],
        file_path: Optional[str],
    ) -> AITriageResult:
        file_lower = (file_path or "").lower()
        msg_lower = (commit_message or "").lower()
        ctx_lower = context_line.lower()

        is_test_file = any(t in file_lower for t in ["test", "tests", "mock", "fixture", "spec", "example", "sample"])
        is_mock_code = any(t in ctx_lower for t in ["mock", "dummy", "fake", "fixture", "example", "placeholder"])
        panic_signals = [
            "accident",
            "oops",
            "revert",
            "remove key",
            "remove secret",
            "leak",
            "fix credentials",
            "reset",
            "temp commit",
            "wip",
        ]
        is_panic_commit = any(p in msg_lower for p in panic_signals)

        if is_test_file or is_mock_code:
            return AITriageResult(
                "Low",
                True,
                2.0,
                "Appears to be a test mock or documentation example based on file path and context.",
                "Verify test fixture does not contain real active tokens.",
                "Heuristic Rule-Engine",
            )
        if "private key" in finding_rule.lower():
            return AITriageResult(
                "Critical",
                False,
                9.8,
                "Asymmetric private key found in git history. High risk of impersonation or decryption.",
                "Immediately revoke the corresponding public key and purge git history.",
                "Heuristic Rule-Engine",
            )
        if is_panic_commit:
            return AITriageResult(
                "Critical",
                False,
                9.5,
                "Commit message indicates panicked credential removal. High likelihood of valid secret left in history.",
                "Rotate credentials immediately and purge repository history.",
                "Heuristic Rule-Engine",
            )
        if "database" in finding_rule.lower() or "uri" in finding_rule.lower():
            return AITriageResult(
                "High",
                False,
                8.7,
                "Database connection URI with password embedded in commit history.",
                "Rotate database password and purge repository history.",
                "Heuristic Rule-Engine",
            )
        return AITriageResult(
            "High",
            False,
            7.8,
            f"Potential credential ({finding_rule}) discovered in repository object history.",
            "Verify if credential is active in production, rotate if needed, and purge history.",
            "Heuristic Rule-Engine",
        )

    def _extract_json(self, raw_text: str) -> Dict[str, Any]:
        raw_text = raw_text.strip()
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", raw_text)
        if match:
            raw_text = match.group(1).strip()
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError:
            start = raw_text.find("{")
            end = raw_text.rfind("}")
            if start != -1 and end != -1:
                return json.loads(raw_text[start : end + 1])
            raise ValueError(f"Could not parse valid JSON from AI response: {raw_text[:100]}")

    def _build_result_from_dict(self, data: Dict[str, Any], provider_name: str) -> AITriageResult:
        severity = data.get("severity", "Medium")
        if severity not in ("Critical", "High", "Medium", "Low"):
            severity = "Medium"
        return AITriageResult(
            severity=severity,
            is_false_positive=bool(data.get("is_false_positive", False)),
            risk_score=float(data.get("risk_score", 5.0)),
            technical_explanation=str(data.get("technical_explanation", "AI analyzed finding context.")),
            recommended_action=str(data.get("recommended_action", "Review finding and rotate credentials if exposed.")),
            provider_used=provider_name,
        )
