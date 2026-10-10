"""Provider-agnostic LLM interface. Providers are selected by environment variables; keys are never logged or returned."""
from __future__ import annotations

from typing import Protocol
from urllib.parse import urlparse

import httpx

from ..config import Settings


class LLMError(Exception):
    pass


class LLMTimeout(LLMError):
    pass


class LLMAuthError(LLMError):
    pass


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, system: str, messages: list[dict], max_tokens: int = 2000) -> str: ...


class _HTTPProvider:
    name = "http"

    def __init__(self, model: str, api_key: str | None, timeout: float, transport: httpx.BaseTransport | None = None):
        self.model, self._key, self._timeout, self._transport = model, api_key, timeout, transport

    def _post(self, url: str, headers: dict, body: dict) -> dict:
        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport) as c:
                r = c.post(url, headers=headers, json=body)
        except httpx.TimeoutException as exc:
            raise LLMTimeout(f"{self.name}: request timed out after {self._timeout}s") from exc
        except httpx.HTTPError as exc:
            raise LLMError(f"{self.name}: network error ({type(exc).__name__})") from exc
        if r.status_code in (401, 403):
            raise LLMAuthError(f"{self.name}: authentication failed (HTTP {r.status_code}); check the API key")
        if r.status_code == 429:
            raise LLMError(f"{self.name}: rate limited (HTTP 429)")
        if r.status_code >= 400:
            raise LLMError(f"{self.name}: HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as exc:
            raise LLMError(f"{self.name}: response was not JSON") from exc


class AnthropicProvider(_HTTPProvider):
    name = "anthropic"
    URL = "https://api.anthropic.com/v1/messages"

    def complete(self, system, messages, max_tokens=2000):
        data = self._post(self.URL, {"x-api-key": self._key or "", "anthropic-version": "2023-06-01"},
                          {"model": self.model, "max_tokens": max_tokens, "system": system, "messages": messages})
        try:
            return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
        except (KeyError, TypeError) as exc:
            raise LLMError("anthropic: unexpected response shape") from exc


class OpenAICompatProvider(_HTTPProvider):
    name = "openai"

    def __init__(self, model, api_key, timeout, base_url, transport=None):
        super().__init__(model, api_key, timeout, transport)
        self.base = base_url.rstrip("/")

    def complete(self, system, messages, max_tokens=2000):
        hdr = {"Authorization": f"Bearer {self._key}"} if self._key else {}
        data = self._post(f"{self.base}/chat/completions", hdr,
                          {"model": self.model, "max_tokens": max_tokens,
                           "messages": [{"role": "system", "content": system}, *messages]})
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError("openai: unexpected response shape") from exc


def llm_status(s: Settings) -> dict:
    if s.llm_provider in ("", "none"):
        return {"configured": False, "provider": None, "model": None, "status": "NOT_CONFIGURED",
                "message": "No LLM provider configured. Rule-based findings are available; AI investigation is disabled."}
    problems = []
    if s.llm_provider not in ("anthropic", "openai"):
        problems.append(f"unknown SENTINEL_LLM_PROVIDER '{s.llm_provider}' (use anthropic or openai)")
    if not s.llm_model:
        problems.append("SENTINEL_LLM_MODEL is not set")
    if s.llm_provider == "anthropic" and not s.llm_api_key:
        problems.append("SENTINEL_LLM_API_KEY is not set")
    if s.llm_provider == "openai" and not s.llm_api_key and not s.llm_base_url:
        problems.append("SENTINEL_LLM_API_KEY is not set")
    if problems:
        return {"configured": False, "provider": s.llm_provider, "model": s.llm_model, "status": "MISCONFIGURED",
                "message": "; ".join(problems)}
    return {"configured": True, "provider": s.llm_provider, "model": s.llm_model, "status": "CONFIGURED",
            "message": "Provider configured (credentials not verified until first use)."}


def build_provider(s: Settings, transport: httpx.BaseTransport | None = None) -> LLMProvider | None:
    st = llm_status(s)
    if not st["configured"]:
        return None
    if s.llm_provider == "anthropic":
        return AnthropicProvider(s.llm_model, s.llm_api_key, s.llm_timeout, transport)
    base = s.llm_base_url or "https://api.openai.com/v1"
    u = urlparse(base)
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1")):
        raise LLMError("SENTINEL_LLM_BASE_URL must be https (http allowed only for localhost)")
    return OpenAICompatProvider(s.llm_model, s.llm_api_key, s.llm_timeout, base, transport)
