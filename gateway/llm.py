"""Model calls for agents, through Bedrock Converse, using the gateway's own AWS role.

Agents never get AWS credentials. The grant decides which models an agent may use
(`resources.models`) and a hard output cap (`resources.max_tokens`).
"""

from __future__ import annotations

import re

MAX_MESSAGES = 20
MAX_MESSAGE_CHARS = 8_000
MAX_SYSTEM_CHARS = 4_000
DEFAULT_MAX_TOKENS = 1_024
HARD_MAX_TOKENS = 2_000
_MODEL_ID = re.compile(r"^[A-Za-z0-9._:/-]{1,200}$")


class LLMError(RuntimeError):
    """A model call failed or the request was invalid. The message is safe to show an agent."""


def validate_messages(messages) -> list[dict]:
    """Return Converse-format messages, or raise LLMError. Roles are only user or assistant."""
    if not isinstance(messages, list) or not messages:
        raise LLMError("messages must be a non-empty list")
    if len(messages) > MAX_MESSAGES:
        raise LLMError(f"at most {MAX_MESSAGES} messages")
    out = []
    for i, m in enumerate(messages):
        if not isinstance(m, dict) or set(m) - {"role", "content"}:
            raise LLMError("each message needs only role and content")
        role, content = m.get("role"), m.get("content")
        if role not in ("user", "assistant"):
            raise LLMError("role must be user or assistant")
        if not isinstance(content, str) or not content.strip():
            raise LLMError("content must be non-empty text")
        if len(content) > MAX_MESSAGE_CHARS:
            raise LLMError(f"a message is longer than {MAX_MESSAGE_CHARS} characters")
        if i == 0 and role != "user":
            raise LLMError("the first message must be from the user")
        if out and out[-1]["role"] == role:
            raise LLMError("roles must alternate")
        out.append({"role": role, "content": [{"text": content}]})
    if out[-1]["role"] != "user":
        raise LLMError("the last message must be from the user")
    return out


def effective_max_tokens(grant_limit) -> int:
    """The grant's cap, never above the hard limit; the default when the grant has none."""
    if isinstance(grant_limit, int) and not isinstance(grant_limit, bool) and grant_limit > 0:
        return min(grant_limit, HARD_MAX_TOKENS)
    return DEFAULT_MAX_TOKENS


class BedrockLLM:
    def __init__(self, client=None, region: str = "us-east-1"):
        self._client = client
        self._region = region

    def _bedrock(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("bedrock-runtime", region_name=self._region)
        return self._client

    def converse(self, model: str, messages, system: str | None, max_tokens: int) -> dict:
        if not isinstance(model, str) or not _MODEL_ID.match(model):
            raise LLMError("invalid model id")
        converse_messages = validate_messages(messages)
        kwargs = {"modelId": model, "messages": converse_messages,
                  "inferenceConfig": {"maxTokens": max_tokens}}
        if system is not None:
            if not isinstance(system, str) or len(system) > MAX_SYSTEM_CHARS:
                raise LLMError(f"system must be text up to {MAX_SYSTEM_CHARS} characters")
            if system.strip():
                kwargs["system"] = [{"text": system}]
        try:
            r = self._bedrock().converse(**kwargs)
        except Exception as e:  # botocore ClientError and friends
            code = getattr(e, "response", {}).get("Error", {}).get("Code") or type(e).__name__
            raise LLMError(f"model call failed: {code}") from e
        try:
            text = "".join(b["text"] for b in r["output"]["message"]["content"] if "text" in b)
            usage = r.get("usage", {})
            return {"model": model, "text": text, "stop_reason": r.get("stopReason"),
                    "input_tokens": usage.get("inputTokens"),
                    "output_tokens": usage.get("outputTokens")}
        except (KeyError, TypeError) as e:
            raise LLMError("model returned an unexpected response") from e
