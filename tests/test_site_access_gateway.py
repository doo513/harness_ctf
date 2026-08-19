from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_harness.competition.ctfd import HttpResponse
from ctf_harness.configuration import ConfigurationError, load_configuration
from ctf_harness.site_access import SiteAccessError, build_default_site_gateway


class _FakeCTFdTransport:
    def __init__(self):
        self.calls = []

    def request(self, *, method: str, url: str, headers, body: bytes | None) -> HttpResponse:
        self.calls.append((method, url, dict(headers), body))
        if url.endswith("/api/v1/challenges/attempt"):
            payload = {"success": True, "data": {"status": "correct"}}
        elif url.endswith("/api/v1/challenges"):
            payload = {"success": True, "data": []}
        else:
            payload = {"success": True, "data": {"id": 1, "name": "test", "description": "", "files": []}}
        return HttpResponse(200, {"Content-Type": "application/json"}, json.dumps(payload).encode("utf-8"))


def _config(path: Path, *, allow_submit: bool = False) -> Path:
    path.write_text(
        f"""
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"

[site]
active = "competition"
[sites.competition]
provider = "ctfd"
base_url = "https://ctf.example"
credential_kind = "env"
credential_locator = "CTFD_TOKEN"
auth_mode = "token"
allow_submit = {str(allow_submit).lower()}
""",
        encoding="utf-8",
    )
    return path


def test_site_configuration_rejects_inline_secret(tmp_path: Path):
    path = tmp_path / "bad.toml"
    path.write_text(
        """
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"
[site]
active = "competition"
[sites.competition]
provider = "ctfd"
base_url = "https://ctf.example"
token = "secret"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="inline secret"):
        load_configuration(path)


def test_site_gateway_uses_existing_ctfd_boundary_and_transient_env_credential(tmp_path: Path):
    transport = _FakeCTFdTransport()
    cfg = load_configuration(_config(tmp_path / "harness.toml"))
    gateway = build_default_site_gateway(
        cfg,
        environ={"CTFD_TOKEN": "ctfd-secret"},
        ctfd_transport=transport,
    )
    session = gateway.build()
    assert session.validate_session() is True
    assert session.list_challenges() == ()
    assert session.descriptor()["truth_authority"] == "none"
    _, _, headers, _ = transport.calls[0]
    assert headers["Authorization"] == "Token ctfd-secret"
    assert "ctfd-secret" not in json.dumps(gateway.descriptor())


def test_site_submission_is_operator_gated(tmp_path: Path):
    transport = _FakeCTFdTransport()
    cfg = load_configuration(_config(tmp_path / "harness.toml", allow_submit=False))
    session = build_default_site_gateway(
        cfg,
        environ={"CTFD_TOKEN": "ctfd-secret"},
        ctfd_transport=transport,
    ).build()
    with pytest.raises(SiteAccessError, match="disabled"):
        session.submit_flag("1", "flag{x}")
    assert not any(call[0] == "POST" for call in transport.calls)


def test_site_submission_can_be_enabled_explicitly(tmp_path: Path):
    transport = _FakeCTFdTransport()
    cfg = load_configuration(_config(tmp_path / "harness.toml", allow_submit=True))
    session = build_default_site_gateway(
        cfg,
        environ={"CTFD_TOKEN": "ctfd-secret"},
        ctfd_transport=transport,
    ).build()
    assert session.submit_flag("1", "flag{x}") is True
    post = [call for call in transport.calls if call[0] == "POST"]
    assert len(post) == 1
