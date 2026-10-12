"""AI provider abstraction. The rest of the app depends only on `AIProvider.complete`, so a
different vendor (or a local model) can be added without touching routes or services."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from app.config import Settings


class AIProviderError(Exception):
    """The provider failed. The message is safe to show to users (never contains the API key)."""


@dataclass
class AIResult:
    text: str
    model: str
    prompt_tokens: int | None = None
    completion_tokens: int | None = None

    @property
    def total_tokens(self) -> int | None:
        if self.prompt_tokens is None and self.completion_tokens is None:
            return None
        return (self.prompt_tokens or 0) + (self.completion_tokens or 0)


class AIProvider(ABC):
    name: str
    model: str

    @abstractmethod
    def complete(self, system: str, messages: list[dict], max_tokens: int) -> AIResult: ...


class OpenAICompatibleProvider(AIProvider):
    """Any server implementing POST {base_url}/chat/completions (OpenAI, Azure-style gateways,
    vLLM, Ollama's OpenAI endpoint, ...)."""

    name = "openai"

    def __init__(self, base_url: str, api_key: str, model: str, timeout_s: int,
                 transport: httpx.BaseTransport | None = None):
        self.base_url, self._key, self.model, self.timeout_s = base_url, api_key, model, timeout_s
        self._transport = transport

    def complete(self, system: str, messages: list[dict], max_tokens: int) -> AIResult:
        payload = {"model": self.model, "max_tokens": max_tokens, "temperature": 0.2,
                   "messages": [{"role": "system", "content": system}, *messages]}
        try:
            with httpx.Client(timeout=self.timeout_s, transport=self._transport) as client:
                r = client.post(f"{self.base_url}/chat/completions", json=payload,
                                headers={"Authorization": f"Bearer {self._key}"})
        except httpx.TimeoutException:
            raise AIProviderError("The AI provider timed out.")
        except httpx.HTTPError:
            raise AIProviderError("Could not reach the AI provider.")
        if r.status_code == 401:
            raise AIProviderError("The AI provider rejected the configured API key.")
        if r.status_code == 429:
            raise AIProviderError("The AI provider is rate limiting requests. Try again shortly.")
        if r.status_code >= 400:
            raise AIProviderError(f"The AI provider returned HTTP {r.status_code}.")
        try:
            data = r.json()
            text = data["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError):
            raise AIProviderError("The AI provider returned an unexpected response.")
        usage = data.get("usage") or {}
        return AIResult(text.strip(), data.get("model") or self.model,
                        usage.get("prompt_tokens"), usage.get("completion_tokens"))


def get_provider(settings: Settings) -> AIProvider | None:
    """None when no provider is configured: LLM features are then unavailable (or fall back to
    clearly labelled rule-based text); vulnerability detection never depends on this."""
    if settings.ai_provider == "openai" and settings.ai_api_key:
        return OpenAICompatibleProvider(settings.ai_base_url, settings.ai_api_key, settings.ai_model, settings.ai_timeout_s)
    return None
