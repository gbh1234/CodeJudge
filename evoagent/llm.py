"""OpenAI 兼容的 JSON 模型客户端，并记录可审计的调用用量。

模型输出属于不稳定边界：本模块负责约束 JSON 协议、兼容常见包裹格式，
并在首次格式错误时追加纠正指令重试一次。
"""
import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .telemetry import ExecutionLedger


class JsonChatClient:
    """只暴露结构化 JSON 完成接口，屏蔽不同兼容 Provider 的传输细节。"""
    def __init__(
        self, base_url: str, api_key: str, model: str,
        provider: str = "openai-compatible", timeout: int = 60,
        extra_headers: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.provider = provider
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})

    def complete_json(
        self, role: str, system: str, user: str,
        ledger: Optional[ExecutionLedger] = None,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """请求一个 JSON 对象；协议不合法时执行一次格式纠正重试。"""
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        last_error = ""
        for attempt in range(2):
            payload: Dict[str, Any] = {
                "model": self.model,
                "temperature": 0,
                "messages": messages,
                "response_format": {"type": "json_object"},
            }
            # DeepSeek 默认开启思考模式；在较小 max_tokens 下，推理内容可能耗尽
            # 输出预算，导致 JSON Mode 的最终 content 为空。结构化协议调用不需要
            # 暴露推理过程，因此显式关闭思考模式以提高 JSON 返回稳定性。
            if self.provider == "deepseek":
                payload["thinking"] = {"type": "disabled"}
            if max_tokens:
                payload["max_tokens"] = int(max_tokens)
            try:
                return self._complete_once(role, payload, ledger)
            except _ModelJsonError as exc:
                last_error = str(exc)
                if attempt:
                    break
                messages = messages + [{
                    "role": "user",
                    "content": (
                        "Your previous response was not one valid JSON object. "
                        "Return exactly one schema-compliant JSON object with no Markdown, "
                        "commentary, or trailing content."
                    ),
                }]
        raise RuntimeError(last_error)

    def _complete_once(
        self, role: str, payload: Dict[str, Any],
        ledger: Optional[ExecutionLedger],
    ) -> Dict[str, Any]:
        """完成单次 HTTP 调用，并将成功、失败、Token 与延迟写入账本。"""
        headers = {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        headers.update(self.extra_headers)
        request = urllib.request.Request(
            self.base_url + "/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers, method="POST",
        )
        started = time.monotonic()
        usage: Dict[str, Any] = {}
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
            usage = body.get("usage") or {}
            content = body["choices"][0]["message"]["content"]
            result = self._parse_json_object(content)
            if ledger:
                ledger.record_model(
                    role, self.provider, self.model, usage,
                    int((time.monotonic() - started) * 1000), True,
                )
            return result
        except urllib.error.HTTPError as exc:
            detail = exc.read(1000).decode("utf-8", errors="replace")
            message = "%s API returned HTTP %d: %s" % (
                self.provider, exc.code, detail,
            )
        except _ModelJsonError as exc:
            message = "%s JSON request failed: %s" % (self.provider, exc)
            if ledger:
                ledger.record_model(
                    role, self.provider, self.model, usage,
                    int((time.monotonic() - started) * 1000), False, message,
                )
            raise _ModelJsonError(message) from exc
        except (urllib.error.URLError, socket.timeout, ValueError, KeyError,
                IndexError, TypeError, json.JSONDecodeError) as exc:
            message = "%s JSON request failed: %s" % (self.provider, exc)
        if ledger:
            ledger.record_model(
                role, self.provider, self.model, {},
                int((time.monotonic() - started) * 1000), False, message,
            )
        raise RuntimeError(message)

    @staticmethod
    def _parse_json_object(content: Any) -> Dict[str, Any]:
        """解析单个 JSON 对象，同时容忍 Markdown 围栏和前后说明文本。"""
        if isinstance(content, dict):
            return content
        if not isinstance(content, str) or not content.strip():
            raise _ModelJsonError("model content is empty or is not text")

        text = content.strip()
        candidates = [text]
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].strip().lower() in {"```", "```json"}:
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            candidates.insert(0, "\n".join(lines).strip())

        for candidate in candidates:
            try:
                value = json.loads(candidate)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                return value

        decoder = json.JSONDecoder()
        for index, character in enumerate(text):
            if character != "{":
                continue
            try:
                value, _end = decoder.raw_decode(text[index:])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                return value
        raise _ModelJsonError("model response does not contain a valid JSON object")


class _ModelJsonError(ValueError):
    """Provider 已返回消息，但消息内容违反了约定的 JSON 协议。"""
