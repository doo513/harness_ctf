from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_harness.configuration import (
    ConfigurationError,
    ModelGatewayError,
    build_default_model_gateway,
    load_configuration,
)


class _FakeResponse:
    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, limit: int) -> bytes:
        return self._raw[:limit]


class _FakeOpener:
    def __init__(self, payloads: list[dict]):
        self.payloads = list(payloads)
        self.requests = []

    def open(self, request, timeout: float):
        self.requests.append((request, timeout))
        if not self.payloads:
            raise AssertionError("unexpected HTTP request")
        return _FakeResponse(self.payloads.pop(0))


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_configuration_is_strict_and_does_not_accept_inline_secrets(tmp_path: Path):
    path = _write(
        tmp_path / "harness.toml",
        """
[model]
active = "primary"

[models.primary]
provider = "openai"
model = "gpt-test"
api_key = "must-not-be-here"
""",
    )
    with pytest.raises(ConfigurationError, match="inline secret"):
        load_configuration(path)


def test_configuration_selects_declared_profile_via_environment_override(tmp_path: Path):
    path = _write(
        tmp_path / "harness.toml",
        """
[model]
active = "primary"

[models.primary]
provider = "openai"
model = "gpt-a"
api_key_env = "OPENAI_API_KEY"

[models.fallback]
provider = "anthropic"
model = "claude-a"
api_key_env = "ANTHROPIC_API_KEY"
max_tokens = 2048
""",
    )
    cfg = load_configuration(path, environ={"CTF_HARNESS_MODEL": "fallback"})
    assert cfg.active_model == "fallback"
    assert cfg.model().provider == "anthropic"
    descriptor = cfg.descriptor()
    assert descriptor["credential_values_persisted"] is False
    assert "OPENAI_API_KEY" in json.dumps(descriptor)
    assert "sk-" not in json.dumps(descriptor)


def test_gateway_fails_closed_when_api_key_environment_is_missing(tmp_path: Path):
    path = _write(
        tmp_path / "harness.toml",
        """
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"
""",
    )
    gateway = build_default_model_gateway(load_configuration(path), environ={})
    with pytest.raises(ModelGatewayError, match="OPENAI_API_KEY"):
        gateway.build()


def test_openai_adapter_extracts_decision_and_does_not_persist_key(tmp_path: Path):
    path = _write(
        tmp_path / "harness.toml",
        """
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"
max_tokens = 1000
""",
    )
    opener = _FakeOpener([
        {
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": '{"kind":"STOP","payload":{}}'}],
                }
            ],
            "usage": {"input_tokens": 12, "output_tokens": 4},
        }
    ])
    gateway = build_default_model_gateway(
        load_configuration(path),
        environ={"OPENAI_API_KEY": "sk-test-secret"},
        opener=opener,
    )
    adapter = gateway.build()
    assert adapter.complete(system="system", user="user") == '{"kind":"STOP","payload":{}}'
    descriptor = adapter.descriptor()
    rendered = json.dumps(descriptor)
    assert "sk-test-secret" not in rendered
    assert descriptor["last_usage"]["input_tokens"] == 12
    request, _ = opener.requests[0]
    assert request.full_url.endswith("/v1/responses")
    assert request.get_header("Authorization") == "Bearer sk-test-secret"


def test_anthropic_and_gemini_adapters_share_gateway_contract(tmp_path: Path):
    path = _write(
        tmp_path / "harness.toml",
        """
[model]
active = "anthropic-main"

[models.anthropic-main]
provider = "anthropic"
model = "claude-test"
api_key_env = "ANTHROPIC_API_KEY"

[models.gemini-main]
provider = "gemini"
model = "gemini-test"
api_key_env = "GEMINI_API_KEY"
""",
    )
    opener = _FakeOpener([
        {
            "content": [{"type": "text", "text": '{"kind":"STOP","payload":{}}'}],
            "usage": {"input_tokens": 7, "output_tokens": 3},
        },
        {
            "candidates": [{"content": {"parts": [{"text": '{"kind":"STOP","payload":{}}'}]}}],
            "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 3},
        },
    ])
    gateway = build_default_model_gateway(
        load_configuration(path),
        environ={"ANTHROPIC_API_KEY": "ant-secret", "GEMINI_API_KEY": "gem-secret"},
        opener=opener,
    )
    anthropic = gateway.build("anthropic-main")
    gemini = gateway.build("gemini-main")
    assert json.loads(anthropic.complete(system="s", user="u"))["kind"] == "STOP"
    assert json.loads(gemini.complete(system="s", user="u"))["kind"] == "STOP"
    assert anthropic.descriptor()["credential_values_persisted"] is False
    assert gemini.descriptor()["credential_values_persisted"] is False


def test_gateway_provider_registry_is_explicit(tmp_path: Path):
    path = _write(
        tmp_path / "harness.toml",
        """
[model]
active = "future"
[models.future]
provider = "future-provider"
model = "future-model"
api_key_env = "FUTURE_API_KEY"
""",
    )
    gateway = build_default_model_gateway(load_configuration(path), environ={"FUTURE_API_KEY": "x"})
    with pytest.raises(ModelGatewayError, match="unsupported model provider"):
        gateway.build()
