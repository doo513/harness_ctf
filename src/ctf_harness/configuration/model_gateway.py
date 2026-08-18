from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol

from ctf_harness.agent_adapters.external_process import ExternalProcessModelAdapter

from .models import HarnessConfiguration, ModelProviderConfig


class ModelGatewayError(RuntimeError):
    pass


class ModelAdapter(Protocol):
    def complete(self, *, system: str, user: str) -> str: ...
    def descriptor(self) -> dict: ...


ProviderFactory = Callable[[ModelProviderConfig, Mapping[str, str]], ModelAdapter]


def _canonical_decision(text: str) -> str:
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ModelGatewayError("model output is not a JSON Decision object") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str) or not isinstance(raw.get("payload"), dict):
        raise ModelGatewayError("model output must contain Decision kind:string and payload:object")
    return json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _require_model(cfg: ModelProviderConfig) -> str:
    if not cfg.model:
        raise ModelGatewayError(f"model profile {cfg.name!r} requires model")
    return cfg.model


def _require_api_key(cfg: ModelProviderConfig, environ: Mapping[str, str]) -> str:
    if not cfg.api_key_env:
        raise ModelGatewayError(f"model profile {cfg.name!r} requires api_key_env")
    value = environ.get(cfg.api_key_env, "")
    if not isinstance(value, str) or not value.strip():
        raise ModelGatewayError(
            f"model profile {cfg.name!r} requires non-empty environment variable {cfg.api_key_env}"
        )
    return value.strip()


@dataclass
class _HTTPModelAdapter:
    provider: str
    model: str
    api_key: str = field(repr=False)
    api_key_env: str
    base_url: str
    timeout_seconds: float
    max_output_bytes: int
    max_tokens: int | None
    opener: object | None = field(default=None, repr=False)
    _last_usage: dict = field(default_factory=dict, init=False, repr=False)

    def _post(self, *, url: str, headers: Mapping[str, str], payload: dict) -> dict:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", **dict(headers)},
            method="POST",
        )
        transport = self.opener or urllib.request.build_opener()
        try:
            response = transport.open(request, timeout=float(self.timeout_seconds))
            with response:
                raw = response.read(self.max_output_bytes + 1)
        except urllib.error.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", errors="replace")
            raise ModelGatewayError(f"{self.provider} API returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ModelGatewayError(f"{self.provider} API request failed: {exc.reason}") from exc
        except OSError as exc:
            raise ModelGatewayError(f"{self.provider} API request failed: {exc}") from exc
        if len(raw) > self.max_output_bytes:
            raise ModelGatewayError(f"{self.provider} API response exceeds configured byte limit")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ModelGatewayError(f"{self.provider} API response is not valid UTF-8 JSON") from exc
        if not isinstance(parsed, dict):
            raise ModelGatewayError(f"{self.provider} API response must be a JSON object")
        return parsed

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-http-model-adapter-v1",
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "timeout_seconds": float(self.timeout_seconds),
            "max_output_bytes": self.max_output_bytes,
            "max_tokens": self.max_tokens,
            "credential_values_persisted": False,
            "last_usage": dict(self._last_usage),
        }


@dataclass
class OpenAIResponsesModelAdapter(_HTTPModelAdapter):
    def complete(self, *, system: str, user: str) -> str:
        payload: dict = {
            "model": self.model,
            "input": [
                {"role": "system", "content": [{"type": "input_text", "text": system}]},
                {"role": "user", "content": [{"type": "input_text", "text": user}]},
            ],
        }
        if self.max_tokens is not None:
            payload["max_output_tokens"] = self.max_tokens
        raw = self._post(
            url=f"{self.base_url.rstrip('/')}/responses",
            headers={"Authorization": f"Bearer {self.api_key}"},
            payload=payload,
        )
        usage = raw.get("usage")
        self._last_usage = dict(usage) if isinstance(usage, dict) else {}
        text = raw.get("output_text")
        if not isinstance(text, str):
            chunks: list[str] = []
            for item in raw.get("output", []) if isinstance(raw.get("output"), list) else []:
                if not isinstance(item, dict) or item.get("type") != "message":
                    continue
                for part in item.get("content", []) if isinstance(item.get("content"), list) else []:
                    if isinstance(part, dict) and part.get("type") == "output_text" and isinstance(part.get("text"), str):
                        chunks.append(part["text"])
            text = "".join(chunks)
        if not isinstance(text, str) or not text.strip():
            raise ModelGatewayError("openai response did not contain output text")
        return _canonical_decision(text)


@dataclass
class AnthropicMessagesModelAdapter(_HTTPModelAdapter):
    def complete(self, *, system: str, user: str) -> str:
        raw = self._post(
            url=f"{self.base_url.rstrip('/')}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            payload={
                "model": self.model,
                "max_tokens": self.max_tokens or 4096,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        usage = raw.get("usage")
        self._last_usage = dict(usage) if isinstance(usage, dict) else {}
        chunks = [
            part["text"]
            for part in raw.get("content", []) if isinstance(raw.get("content"), list)
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str)
        ]
        text = "".join(chunks)
        if not text.strip():
            raise ModelGatewayError("anthropic response did not contain text content")
        return _canonical_decision(text)


@dataclass
class GeminiGenerateContentModelAdapter(_HTTPModelAdapter):
    def complete(self, *, system: str, user: str) -> str:
        quoted_model = urllib.parse.quote(self.model, safe="-._")
        generation_config: dict = {"responseMimeType": "application/json"}
        if self.max_tokens is not None:
            generation_config["maxOutputTokens"] = self.max_tokens
        raw = self._post(
            url=f"{self.base_url.rstrip('/')}/models/{quoted_model}:generateContent",
            headers={"x-goog-api-key": self.api_key},
            payload={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": generation_config,
            },
        )
        usage = raw.get("usageMetadata")
        self._last_usage = dict(usage) if isinstance(usage, dict) else {}
        chunks: list[str] = []
        candidates = raw.get("candidates")
        for candidate in candidates if isinstance(candidates, list) else []:
            if not isinstance(candidate, dict):
                continue
            content = candidate.get("content")
            if not isinstance(content, dict):
                continue
            parts = content.get("parts")
            for part in parts if isinstance(parts, list) else []:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    chunks.append(part["text"])
        text = "".join(chunks)
        if not text.strip():
            raise ModelGatewayError("gemini response did not contain text content")
        return _canonical_decision(text)


class ModelGateway:
    """Resolve a configured model profile without giving it Harness authority.

    The gateway only constructs the ModelAdapter used by the existing verified
    Agent/controller loop. It does not execute tools, write facts, verify claims,
    or decide completion.
    """

    def __init__(self, config: HarnessConfiguration, *, environ: Mapping[str, str] | None = None):
        self.config = config
        self.environ = dict(os.environ if environ is None else environ)
        self._factories: dict[str, ProviderFactory] = {}

    def register(self, provider: str, factory: ProviderFactory) -> None:
        normalized = provider.strip().lower()
        if not normalized:
            raise ValueError("provider name must be non-empty")
        if normalized in self._factories:
            raise ValueError(f"provider {normalized!r} is already registered")
        self._factories[normalized] = factory

    def build(self, name: str | None = None) -> ModelAdapter:
        cfg = self.config.model(name)
        provider = cfg.provider.strip().lower()
        try:
            factory = self._factories[provider]
        except KeyError as exc:
            raise ModelGatewayError(f"unsupported model provider {cfg.provider!r}") from exc
        return factory(cfg, self.environ)

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-model-gateway-v1",
            "active_model": self.config.active_model,
            "registered_providers": sorted(self._factories),
            "credential_values_persisted": False,
        }


def build_default_model_gateway(
    config: HarnessConfiguration,
    *,
    environ: Mapping[str, str] | None = None,
    opener: object | None = None,
) -> ModelGateway:
    gateway = ModelGateway(config, environ=environ)

    def external_factory(cfg: ModelProviderConfig, env: Mapping[str, str]) -> ModelAdapter:
        if not cfg.command:
            raise ModelGatewayError(f"external_process profile {cfg.name!r} requires command")
        if not cfg.revision:
            raise ModelGatewayError(f"external_process profile {cfg.name!r} requires revision")
        forwarded = {name: env[name] for name in cfg.pass_env_names if name in env}
        return ExternalProcessModelAdapter(
            argv=cfg.command,
            revision=cfg.revision,
            timeout_seconds=cfg.timeout_seconds,
            max_output_bytes=cfg.max_output_bytes,
            env=forwarded,
            inherit_env=False,
        )

    def http_factory(provider: str, adapter_type: type[_HTTPModelAdapter], default_base_url: str) -> ProviderFactory:
        def factory(cfg: ModelProviderConfig, env: Mapping[str, str]) -> ModelAdapter:
            return adapter_type(
                provider=provider,
                model=_require_model(cfg),
                api_key=_require_api_key(cfg, env),
                api_key_env=cfg.api_key_env or "",
                base_url=cfg.base_url or default_base_url,
                timeout_seconds=cfg.timeout_seconds,
                max_output_bytes=cfg.max_output_bytes,
                max_tokens=cfg.max_tokens,
                opener=opener,
            )
        return factory

    gateway.register("external_process", external_factory)
    gateway.register("openai", http_factory("openai", OpenAIResponsesModelAdapter, "https://api.openai.com/v1"))
    gateway.register("anthropic", http_factory("anthropic", AnthropicMessagesModelAdapter, "https://api.anthropic.com"))
    gateway.register("gemini", http_factory("gemini", GeminiGenerateContentModelAdapter, "https://generativelanguage.googleapis.com/v1beta"))
    return gateway
