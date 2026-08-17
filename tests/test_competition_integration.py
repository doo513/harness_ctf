from __future__ import annotations

import json

import pytest

from ctf_harness.competition.credentials import CredentialResolver, SecretRedactor
from ctf_harness.competition.ctfd import CTFdAdapter, HttpResponse
from ctf_harness.competition.ingest import build_manifest_input, normalize_connection_endpoint
from ctf_harness.competition.submission import SubmissionGuard, SubmissionMode
from ctf_harness.operational.models import CredentialKind, CredentialRef, OperationalChallengeRef


class FakeTransport:
    def __init__(self):
        self.calls = []

    def request(self, *, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if url.endswith("/api/v1/challenges"):
            data = [{"id": 7, "name": "stack", "description": "desc", "category": "pwn"}]
            return HttpResponse(200, {}, json.dumps({"success": True, "data": data}).encode())
        if url.endswith("/api/v1/challenges/7/files"):
            return HttpResponse(200, {}, json.dumps({"success": True, "data": ["/files/chal"]}).encode())
        if url.endswith("/api/v1/challenges/7"):
            data = {
                "id": 7,
                "name": "stack",
                "description": "untrusted challenge text",
                "category": "pwn",
                "connection_info": "nc challenge.example 31337",
            }
            return HttpResponse(200, {}, json.dumps({"success": True, "data": data}).encode())
        if url.endswith("/files/chal"):
            return HttpResponse(200, {"Content-Type": "application/octet-stream"}, b"ELF-FIXTURE")
        if url.endswith("/api/v1/challenges/attempt"):
            payload = json.loads(body)
            status = "correct" if payload["submission"] == "flag{ok}" else "incorrect"
            return HttpResponse(200, {}, json.dumps({"success": True, "data": {"status": status}}).encode())
        return HttpResponse(404, {}, b"{}")


def _adapter(monkeypatch):
    monkeypatch.setenv("CTFD_TOKEN", "canary-secret-token")
    transport = FakeTransport()
    adapter = CTFdAdapter(
        "https://ctf.example",
        credential_ref=CredentialRef(CredentialKind.ENV, "CTFD_TOKEN"),
        credential_resolver=CredentialResolver(),
        transport=transport,
    )
    return adapter, transport


def test_ctfd_list_detail_download_manifest_admission_chain(monkeypatch) -> None:
    adapter, transport = _adapter(monkeypatch)
    assert adapter.validate_session()
    assert adapter.list_challenges()[0].challenge_id == "7"
    snapshot = adapter.get_challenge("7")
    assert snapshot.file_urls == ("/files/chal",)
    artifact = adapter.download(snapshot.file_urls[0])
    built = build_manifest_input(
        snapshot,
        (artifact,),
        event="fixture",
        runner_image_digest="sha256:" + "a" * 64,
        challenge_revision="r1",
        flag_format="flag{...}",
        allowed_tools=("target_exec",),
    )
    operational = OperationalChallengeRef.from_manifest(built.manifest, built.hash_mapping())
    assert operational.artifact_sha256("chal") == artifact.sha256
    assert operational.remote_endpoints == ("tcp://challenge.example:31337",)
    assert all(call[2].get("Authorization") == "Token canary-secret-token" for call in transport.calls)
    # Credential values are transient request data, not normalized snapshot/manifest state.
    assert "canary-secret-token" not in repr(snapshot)
    assert "canary-secret-token" not in repr(built)


def test_ctfd_cross_origin_download_is_rejected(monkeypatch) -> None:
    adapter, _ = _adapter(monkeypatch)
    with pytest.raises(ValueError, match="cross-origin"):
        adapter.download("https://evil.example/payload")


def test_connection_parser_handles_nc_and_does_not_treat_nc_as_host() -> None:
    assert normalize_connection_endpoint("nc host.example 4444") == "tcp://host.example:4444"
    assert normalize_connection_endpoint("tcp://host.example:4444") == "tcp://host.example:4444"
    assert normalize_connection_endpoint("visit the web page") is None


def test_secret_redactor_is_defense_in_depth() -> None:
    redactor = SecretRedactor(("super-secret",))
    rendered = redactor.redact_text("Authorization: Token super-secret\nCookie: session=super-secret")
    assert "super-secret" not in rendered
    sanitized = redactor.sanitize_url("https://x.example/p?a=1&token=super-secret")
    assert "super-secret" not in sanitized


def test_submission_guard_requires_confirmation_dedupes_and_stores_only_hash(monkeypatch) -> None:
    adapter, _ = _adapter(monkeypatch)
    guard = SubmissionGuard(SubmissionMode.CONFIRM, budget=2)
    with pytest.raises(PermissionError):
        guard.submit(adapter, "7", "flag{ok}")
    receipt = guard.submit(adapter, "7", "flag{bad}", confirmed=True)
    assert not receipt.accepted
    assert guard.was_rejected("flag{bad}")
    with pytest.raises(ValueError, match="already submitted"):
        guard.submit(adapter, "7", "flag{bad}", confirmed=True)
    desc = guard.descriptor()
    assert desc["raw_candidates_persisted"] is False
    assert "flag{bad}" not in repr(desc)
