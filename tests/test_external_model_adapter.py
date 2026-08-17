from __future__ import annotations

import json
import sys

import pytest

from ctf_harness.agent_adapters import ExternalProcessModelAdapter, ModelProcessError


_ECHO_DECISION = r'''
import json,sys
request=json.loads(sys.stdin.read())
assert request["schema_version"]=="ctf-model-process-request-v1"
assert "secret-do-not-forward" not in repr(request)
print(json.dumps({"kind":"complete","payload":{"reason":"external-process-round-trip"}}))
'''


def test_external_process_adapter_round_trip_is_json_only_and_no_shell() -> None:
    adapter = ExternalProcessModelAdapter(
        argv=(sys.executable, "-c", _ECHO_DECISION),
        revision="fixture-r1",
        timeout_seconds=5.0,
        env={"PROVIDER_TEST_SECRET": "secret-do-not-forward"},
    )
    result = json.loads(adapter.complete(system="system", user="{}"))
    assert result == {"kind": "complete", "payload": {"reason": "external-process-round-trip"}}
    desc = adapter.descriptor()
    assert desc["transport"] == "json_over_stdin_stdout"
    assert desc["inherit_env"] is False
    assert desc["credential_values_persisted"] is False
    assert "secret-do-not-forward" not in repr(desc)


def test_external_process_adapter_rejects_non_decision_output() -> None:
    adapter = ExternalProcessModelAdapter(
        argv=(sys.executable, "-c", "print('not-json')"),
        revision="fixture-r1",
        timeout_seconds=5.0,
    )
    with pytest.raises(ModelProcessError):
        adapter.complete(system="system", user="{}")


def test_external_process_adapter_rejects_oversized_output() -> None:
    adapter = ExternalProcessModelAdapter(
        argv=(sys.executable, "-c", "print('x'*1024)"),
        revision="fixture-r1",
        timeout_seconds=5.0,
        max_output_bytes=128,
    )
    with pytest.raises(ModelProcessError, match="byte limit"):
        adapter.complete(system="system", user="{}")


def test_environment_factory_fails_closed_without_operator_configuration(monkeypatch) -> None:
    monkeypatch.delenv("CTF_MODEL_ADAPTER_CMD", raising=False)
    monkeypatch.delenv("CTF_MODEL_ADAPTER_REVISION", raising=False)
    with pytest.raises(ModelProcessError, match="CTF_MODEL_ADAPTER_CMD"):
        ExternalProcessModelAdapter.from_environment()
