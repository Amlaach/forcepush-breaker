"""
Conversational Cyber-Forensics AI Assistant for UnForce.

Provides interactive chat with tool calling / function execution, allowing
AI models (Gemini, OpenAI, Anthropic, Ollama, and local fallback) to directly
inspect scan results, examine dangling commits, extract file diffs, verify token
liveness, and generate remediation actions on behalf of the user.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from gitghost.crypto_vault import SecretVault
from gitghost.git_forensics import GitForensics
from gitghost.liveness import SafeKeyLivenessChecker
from gitghost.recovery import ObjectRecoveryEngine
from gitghost.redactor import SecretRedactor


# ---------------------------------------------------------------------------
# Tool Specifications (JSON-schema format)
# ---------------------------------------------------------------------------
FORENSICS_TOOLS = [
    {
        "name": "get_scan_summary",
        "description": "Returns a high-level summary of the active repository forensics scan, including hygiene score, findings count, dangling commits count, and detached blobs.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "list_dangling_commits",
        "description": "Lists dangling (overwritten / orphaned) commits discovered in the git graveyard, including commit hash, author, date, and commit message.",
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Maximum number of commits to list (default 10)."},
            },
        },
    },
    {
        "name": "get_commit_diff",
        "description": "Retrieves the unified diff (patch) for a specific dangling commit hash to see what code or secrets were changed/deleted.",
        "parameters": {
            "type": "object",
            "properties": {
                "commit_hash": {"type": "string", "description": "The commit SHA hash to inspect."},
            },
            "required": ["commit_hash"],
        },
    },
    {
        "name": "list_secret_findings",
        "description": "Lists detected secrets, leaked tokens, or credentials with their severity, rule name, and location.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity_filter": {"type": "string", "description": "Optional filter: 'Critical', 'High', 'Medium', or 'Low'."},
            },
        },
    },
    {
        "name": "verify_credential_liveness",
        "description": "Safely verifies whether a detected credential finding is still active and valid in production against cloud provider APIs without making unauthorized state changes.",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "The finding ID (e.g. 'SEC-0001')."},
            },
            "required": ["finding_id"],
        },
    },
    {
        "name": "get_remediation_guide",
        "description": "Generates step-by-step commands to purge leaked files from git history and excise dangling objects using git-filter-repo and git gc.",
        "parameters": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "description": "'bash' or 'powershell'."},
            },
        },
    },
]


SYSTEM_PROMPT = """You are UnForce AI, an elite Cyber-Forensics & Application Security assistant built directly into the UnForce (ForcePush-Breaker) studio.
You specialize in analyzing overwritten Git commits, recovering deleted history, detecting exposed secrets, assessing risk, and guiding users through history excision.

Guidelines:
1. Always be helpful, concise, and technically authoritative.
2. If the user asks about the repository status, dangling commits, or secrets, USE YOUR TOOLS to fetch actual data from the active scan!
3. When discussing secrets, NEVER display full unmasked tokens. Respect strict redaction.
4. If the user speaks Hebrew, respond in natural, professional Hebrew. If English, respond in English.
5. When recommending remediation, remind the user to rotate exposed credentials immediately because history rewriting does not un-compromise an already exposed key.
"""


class ForensicsToolExecutor:
    """Executes tool requests against the active scanned pipeline result."""

    def __init__(self, pipeline_res: Any):
        self.pipeline_res = pipeline_res

    def execute(self, tool_name: str, args: Dict[str, Any]) -> str:
        if not self.pipeline_res:
            return json.dumps({"error": "No active repository scan in session. Please scan a repository first."})

        if tool_name == "get_scan_summary":
            return self._tool_get_scan_summary()
        elif tool_name == "list_dangling_commits":
            limit = int(args.get("limit") or 10)
            return self._tool_list_dangling_commits(limit)
        elif tool_name == "get_commit_diff":
            c_hash = str(args.get("commit_hash") or "").strip()
            return self._tool_get_commit_diff(c_hash)
        elif tool_name == "list_secret_findings":
            sev = args.get("severity_filter")
            return self._tool_list_secret_findings(sev)
        elif tool_name == "verify_credential_liveness":
            fid = str(args.get("finding_id") or "").strip()
            return self._tool_verify_credential(fid)
        elif tool_name == "get_remediation_guide":
            fmt = str(args.get("format") or "bash").lower()
            return self._tool_get_remediation(fmt)

        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    def _tool_get_scan_summary(self) -> str:
        res = self.pipeline_res
        crit = sum(1 for f in res.findings if (res.triage_map.get(f.finding_id) and res.triage_map[f.finding_id].severity == "Critical") or f.severity_estimate == "Critical")
        high = sum(1 for f in res.findings if (res.triage_map.get(f.finding_id) and res.triage_map[f.finding_id].severity == "High") or f.severity_estimate == "High")
        return json.dumps({
            "repo_path": res.repo_path,
            "is_remote": getattr(res, "is_remote", False),
            "hygiene_score": res.hygiene.score,
            "hygiene_grade": res.hygiene.grade,
            "dangling_commits_count": len(res.scan_result.dangling_commits),
            "dangling_blobs_count": len(res.scan_result.dangling_blobs),
            "deleted_config_files_count": len(getattr(res.scan_result, "deleted_config_files", [])),
            "total_findings": len(res.findings),
            "critical_findings": crit,
            "high_findings": high,
        })

    def _tool_list_dangling_commits(self, limit: int) -> str:
        commits = self.pipeline_res.scan_result.dangling_commits[:limit]
        return json.dumps([
            {
                "commit_hash": c.commit_hash[:10],
                "full_hash": c.commit_hash,
                "author": c.author,
                "date": c.date,
                "message": (c.redacted_message or c.message).splitlines()[0] if c.message else "",
                "changed_files": c.changed_files[:5],
                "ai_agent": c.ai_agent.agent_name if (c.ai_agent and c.ai_agent.is_ai_agent) else None,
            }
            for c in commits
        ])

    def _tool_get_commit_diff(self, commit_hash: str) -> str:
        for c in self.pipeline_res.scan_result.dangling_commits:
            if c.commit_hash == commit_hash or c.commit_hash.startswith(commit_hash):
                diff = c.redacted_diff or c.diff_content or "(Empty diff)"
                return json.dumps({
                    "commit_hash": c.commit_hash,
                    "message": c.redacted_message or c.message,
                    "diff_snippet": diff[:3000] if len(diff) > 3000 else diff,
                })
        return json.dumps({"error": f"Commit {commit_hash} not found among dangling commits."})

    def _tool_list_secret_findings(self, severity_filter: Optional[str]) -> str:
        findings = []
        for f in self.pipeline_res.findings[:20]:
            t = self.pipeline_res.triage_map.get(f.finding_id)
            sev = t.severity if t else f.severity_estimate
            if severity_filter and sev.lower() != severity_filter.lower():
                continue
            findings.append({
                "finding_id": f.finding_id,
                "rule_name": f.rule_name,
                "severity": sev,
                "masked_value": f.masked_value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "entropy": round(f.entropy, 2),
            })
        return json.dumps(findings)

    def _tool_verify_credential(self, finding_id: str) -> str:
        target_f = next((f for f in self.pipeline_res.findings if f.finding_id == finding_id), None)
        if not target_f or not target_f.raw_value:
            return json.dumps({"error": f"Finding {finding_id} not found or raw secret unavailable."})

        res = SafeKeyLivenessChecker.check(
            token=target_f.raw_value,
            rule_name=target_f.rule_name,
            finding_id=finding_id,
        )
        return json.dumps(res.to_dict())

    def _tool_get_remediation(self, fmt: str) -> str:
        rem = self.pipeline_res.remediation
        if fmt == "powershell":
            script = rem.powershell_script
        else:
            script = rem.bash_script
        return json.dumps({
            "format": fmt,
            "script": script[:2500],
            "rotation_warning": rem.rotation_warning,
        })


# ---------------------------------------------------------------------------
# Chat Engine Implementation
# ---------------------------------------------------------------------------
class AIChatSession:
    """Manages chat session history and LLM interaction with function calling."""

    def __init__(
        self,
        provider: str = "auto",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.provider = (provider or "auto").lower()
        self.api_key = (api_key or "").strip() or None
        self.model = model
        self.history: List[Dict[str, Any]] = []

    def _resolve_effective_key_and_provider(self) -> tuple[str, str]:
        prov = self.provider
        k = self.api_key or SecretVault.get(f"{prov}_api_key") or SecretVault.get("ai_api_key")

        if prov == "auto" or not k:
            # Detect from vault or env
            gem_k = self.api_key if (self.api_key and self.api_key.startswith("AIza")) else (SecretVault.get("gemini_api_key") or os.getenv("GEMINI_API_KEY"))
            oai_k = self.api_key if (self.api_key and self.api_key.startswith("sk-") and not self.api_key.startswith("sk-ant-")) else (SecretVault.get("openai_api_key") or os.getenv("OPENAI_API_KEY"))
            ant_k = self.api_key if (self.api_key and self.api_key.startswith("sk-ant-")) else (SecretVault.get("anthropic_api_key") or os.getenv("ANTHROPIC_API_KEY"))

            if gem_k:
                return "gemini", gem_k
            if oai_k:
                return "openai", oai_k
            if ant_k:
                return "anthropic", ant_k
            return "heuristic", ""

        return prov, k or ""

    def chat(self, user_message: str, pipeline_res: Any = None) -> Dict[str, Any]:
        executor = ForensicsToolExecutor(pipeline_res)
        provider, key = self._resolve_effective_key_and_provider()

        self.history.append({"role": "user", "content": user_message})

        if provider == "heuristic" or not key:
            reply, tools_called = self._heuristic_chat_reply(user_message, executor)
            self.history.append({"role": "assistant", "content": reply})
            return {
                "role": "assistant",
                "content": reply,
                "provider": "Local Forensics Assistant",
                "tools_executed": tools_called,
            }

        try:
            if provider == "gemini":
                reply, tools_called = self._call_gemini_chat(user_message, key, executor)
            elif provider == "openai":
                reply, tools_called = self._call_openai_chat(user_message, key, executor)
            elif provider == "anthropic":
                reply, tools_called = self._call_anthropic_chat(user_message, key, executor)
            else:
                reply, tools_called = self._heuristic_chat_reply(user_message, executor)
        except Exception as exc:
            err_msg = str(exc)
            if key in err_msg:
                err_msg = err_msg.replace(key, "[REDACTED_KEY]")
            fallback_reply, tools_called = self._heuristic_chat_reply(user_message, executor)
            reply = f"{fallback_reply}\n\n*(Note: {provider.capitalize()} API error: {err_msg[:60]})*"

        self.history.append({"role": "assistant", "content": reply})
        return {
            "role": "assistant",
            "content": reply,
            "provider": provider.capitalize(),
            "tools_executed": tools_called,
        }

    def _heuristic_chat_reply(self, message: str, executor: ForensicsToolExecutor) -> tuple[str, List[str]]:
        msg = message.lower()
        tools_called = []

        if any(w in msg for w in ["summary", "status", "ציון", "מדדים", "סטטוס", "סקירה", "דוח", "report", "סרוק"]):
            summary_raw = executor.execute("get_scan_summary", {})
            tools_called.append("get_scan_summary")
            summary = json.loads(summary_raw)
            if "error" in summary:
                return f"⚠️ {summary['error']}", tools_called

            reply = (
                f"📊 **סקירת סטטוס אבטחה של המאגר:**\n\n"
                f"• **ציון היגיינה:** {summary.get('hygiene_score')}/100 ({summary.get('hygiene_grade')})\n"
                f"• **קומיטים שנדרסו (Dangling Commits):** {summary.get('dangling_commits_count')}\n"
                f"• **קבצי קונפיגורציה שנמחקו (.env):** {summary.get('deleted_config_files_count')}\n"
                f"• **סך דליפות סודיות:** {summary.get('total_findings')} (קריטי: {summary.get('critical_findings')}, גבוה: {summary.get('high_findings')})\n\n"
                f"במה תרצה שנתמקד כעת? באפשרותי להציג פירוט קומיטים, לחלץ diff של שינויים, או להפיק פקודות ניקוי."
            )
            return reply, tools_called

        if any(w in msg for w in ["commit", "dangling", "קומיט", "קומיטים", "ghost"]):
            commits_raw = executor.execute("list_dangling_commits", {"limit": 5})
            tools_called.append("list_dangling_commits")
            commits = json.loads(commits_raw)
            if not isinstance(commits, list) or not commits:
                return "לא אותרו קומיטים מנותקים (dangling commits) במאגר זה.", tools_called

            lines = ["🔍 **קומיטים מנותקים שאותרו ב-Git Graveyard:**\n"]
            for c in commits:
                ai_tag = f" `[AI: {c['ai_agent']}]`" if c.get("ai_agent") else ""
                lines.append(f"• `{c['commit_hash']}`: **{c['message']}** ({c['author']}, {c['date'][:10]}){ai_tag}")
            lines.append("\nתוכל לבקש ממני להציג את ה-diff של כל קומיט באמצעות ציון ה-SHA שלו.")
            return "\n".join(lines), tools_called

        if any(w in msg for w in ["clean", "fix", "purge", "remediate", "נקה", "טיהור", "תיקון", "מחק"]):
            rem_raw = executor.execute("get_remediation_guide", {"format": "bash"})
            tools_called.append("get_remediation_guide")
            rem = json.loads(rem_raw)
            return (
                f"🛡️ **תוכנית עבודה מומלצת לטיהור סופי:**\n\n"
                f"```bash\n{rem.get('script', '')[:600]}...\n```\n"
                f"\n**תזכורת חשובה:** {rem.get('rotation_warning', 'יש לבטל סודות שדלפו!')}"
            ), tools_called

        if any(w in msg for w in ["secret", "leak", "סוד", "סיסמה", "טוקן", "מפתח", "key", "token"]):
            findings_raw = executor.execute("list_secret_findings", {})
            tools_called.append("list_secret_findings")
            findings = json.loads(findings_raw)
            if not isinstance(findings, list) or not findings:
                return "✅ לא אותרו סודות או מפתחות שדלפו בקומיטים שנמחקו.", tools_called

            lines = [f"🚨 **אותרו {len(findings)} ממצאי סודות:**\n"]
            for f in findings[:6]:
                lines.append(f"• `[{f['finding_id']}]` **{f['rule_name']}** ({f['severity']}) בנתיב `{f['file_path']}:{f['line_number']}`: `{f['masked_value']}`")
            lines.append("\n⚠️ **המלצה קריטית:** יש לבטל ולבצע Rotate מיידי לכל מפתח שדלף בחשבון השירות הרלוונטי.")
            return "\n".join(lines), tools_called

        return (
            "שלום! אני סייר ה-AI המובנה של **UnForce**. 🕵️‍♂️\n"
            "יש לי גישה מלאה לכלי הפורנזיקה של המערכת. תוכל לבקש ממני:\n"
            "• **סקירת מצב האבטחה וההיגיינה** של הריפו\n"
            "• **רשימת קומיטים מנותקים (dangling commits)** שנדרסו ב-force-push\n"
            "• **בדיקת סודות ומפתחות שדלפו** ומיקומם\n"
            "• **שליפת diff או שחזור קבצים** מתוך קומיט ספציפי\n"
            "• **הפקת סקריפט ניקוי וטיהור** (`git filter-repo` ו-`git gc`)\n\n"
            "במה תרצה שנתחיל?"
        ), tools_called

    def _call_gemini_chat(self, user_msg: str, api_key: str, executor: ForensicsToolExecutor) -> tuple[str, List[str]]:
        model = self.model or "gemini-1.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

        # Step 1: Query LLM with tools
        tools_def = [
            {
                "function_declarations": [
                    {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["parameters"],
                    }
                    for t in FORENSICS_TOOLS
                ]
            }
        ]
        history_parts = [{"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["content"]}]} for m in self.history[-6:]]
        payload = {
            "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": history_parts,
            "tools": tools_def,
        }
        headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        tools_executed = []

        with urllib.request.urlopen(req, timeout=18) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        candidate = (data.get("candidates") or [{}])[0]
        content_parts = (candidate.get("content") or {}).get("parts") or []

        # Check for function call
        fn_call = next((p.get("functionCall") for p in content_parts if p.get("functionCall")), None)
        if fn_call:
            fn_name = fn_call.get("name")
            fn_args = fn_call.get("args") or {}
            tools_executed.append(fn_name)
            tool_output = executor.execute(fn_name, fn_args)

            # Follow up turn with tool response
            follow_contents = list(history_parts)
            follow_contents.append({"role": "model", "parts": [{"functionCall": fn_call}]})
            follow_contents.append({
                "role": "user",
                "parts": [{
                    "functionResponse": {
                        "name": fn_name,
                        "response": {"result": json.loads(tool_output)},
                    }
                }]
            })
            follow_payload = {
                "system_instruction": {"parts": [{"text": SYSTEM_PROMPT}]},
                "contents": follow_contents,
            }
            follow_req = urllib.request.Request(url, data=json.dumps(follow_payload).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(follow_req, timeout=18) as follow_resp:
                follow_data = json.loads(follow_resp.read().decode("utf-8"))
            follow_parts = (follow_data.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
            text_reply = "".join(p.get("text", "") for p in follow_parts if p.get("text"))
            return text_reply or "בוצע בהצלחה.", tools_executed

        text_reply = "".join(p.get("text", "") for p in content_parts if p.get("text"))
        return text_reply or "שלום, במה אוכל לסייע?", tools_executed

    def _call_openai_chat(self, user_msg: str, api_key: str, executor: ForensicsToolExecutor) -> tuple[str, List[str]]:
        model = self.model or "gpt-4o-mini"
        url = "https://api.openai.com/v1/chat/completions"
        oai_tools = [{"type": "function", "function": t} for t in FORENSICS_TOOLS]
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        for m in self.history[-6:]:
            messages.append({"role": m["role"], "content": m["content"]})

        payload = {
            "model": model,
            "messages": messages,
            "tools": oai_tools,
            "temperature": 0.2,
        }
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        tools_executed = []

        with urllib.request.urlopen(req, timeout=18) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        msg_obj = data["choices"][0]["message"]
        tool_calls = msg_obj.get("tool_calls") or []

        if tool_calls:
            tc = tool_calls[0]
            fn_name = tc["function"]["name"]
            try:
                fn_args = json.loads(tc["function"]["arguments"])
            except Exception:
                fn_args = {}
            tools_executed.append(fn_name)
            tool_res = executor.execute(fn_name, fn_args)

            messages.append(msg_obj)
            messages.append({
                "role": "tool",
                "tool_call_id": tc["id"],
                "content": tool_res,
            })
            sec_payload = {"model": model, "messages": messages, "temperature": 0.2}
            sec_req = urllib.request.Request(url, data=json.dumps(sec_payload).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(sec_req, timeout=18) as sec_resp:
                sec_data = json.loads(sec_resp.read().decode("utf-8"))
            return sec_data["choices"][0]["message"].get("content", ""), tools_executed

        return msg_obj.get("content", ""), tools_executed

    def _call_anthropic_chat(self, user_msg: str, api_key: str, executor: ForensicsToolExecutor) -> tuple[str, List[str]]:
        # Anthropic claude-3-5-sonnet format
        model = self.model or "claude-3-5-sonnet-20241022"
        url = "https://api.anthropic.com/v1/messages"
        ant_tools = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in FORENSICS_TOOLS]
        messages = [{"role": m["role"], "content": m["content"]} for m in self.history[-6:]]

        payload = {
            "model": model,
            "max_tokens": 1024,
            "system": SYSTEM_PROMPT,
            "messages": messages,
            "tools": ant_tools,
        }
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
        tools_executed = []

        with urllib.request.urlopen(req, timeout=18) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        content_list = data.get("content") or []
        use_tool = next((c for c in content_list if c.get("type") == "tool_use"), None)
        if use_tool:
            fn_name = use_tool["name"]
            fn_args = use_tool.get("input") or {}
            tools_executed.append(fn_name)
            tool_res = executor.execute(fn_name, fn_args)

            messages.append({"role": "assistant", "content": content_list})
            messages.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": use_tool["id"],
                    "content": tool_res,
                }]
            })
            sec_payload = {
                "model": model,
                "max_tokens": 1024,
                "system": SYSTEM_PROMPT,
                "messages": messages,
            }
            sec_req = urllib.request.Request(url, data=json.dumps(sec_payload).encode("utf-8"), headers=headers)
            with urllib.request.urlopen(sec_req, timeout=18) as sec_resp:
                sec_data = json.loads(sec_resp.read().decode("utf-8"))
            sec_content = sec_data.get("content") or []
            return "".join(c.get("text", "") for c in sec_content if c.get("type") == "text"), tools_executed

        return "".join(c.get("text", "") for c in content_list if c.get("type") == "text"), tools_executed
