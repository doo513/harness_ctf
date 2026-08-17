from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from harness.core.sandbox import RecordingIsolatedTestBackend
from harness.core.storage import canonical_hash

from ctf_harness.target.runners import NativeRunner
from ctf_harness.tools.target_exec import TargetExecutionBackend


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _launch(delegate: RecordingIsolatedTestBackend) -> dict:
    helper = delegate.calls[-1]["argv"]
    return json.loads(base64.b64decode(helper[-1], validate=True).decode())


def test_target_exec_binds_target_runtime_and_launch_before_delegate(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"target-exec-fixture")
    target.chmod(0o755)
    delegate = RecordingIsolatedTestBackend()
    adapter = TargetExecutionBackend(
        delegate,
        runners={"fixture-native": NativeRunner("fixture-native")},
        default_profile_id="fixture-native",
        expected_target_sha256={"chal": _sha(target)},
    )
    result = adapter.run_argv(
        workspace=tmp_path,
        argv=["chal", base64.b64encode(b"stdin\n").decode(), "fixture-native"],
        timeout_seconds=8.0,
    )
    assert result.returncode == 0
    launch = _launch(delegate)
    assert launch["target_sha256"] == _sha(target)
    assert launch["runtime"]["runtime_kind"] == "native"
    assert launch["runtime"]["profile_id"] == "fixture-native"
    assert launch["runtime_fingerprint"] == canonical_hash(launch["runtime"])
    assert launch["launch_fingerprint"] == canonical_hash({
        "target_sha256": launch["target_sha256"],
        "runtime_fingerprint": launch["runtime_fingerprint"],
        "argv": launch["argv"],
    })


def test_target_exec_rejects_unregistered_runtime_before_delegate(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"x")
    target.chmod(0o755)
    delegate = RecordingIsolatedTestBackend()
    adapter = TargetExecutionBackend(
        delegate,
        runners={"fixture-native": NativeRunner("fixture-native")},
        default_profile_id="fixture-native",
    )
    result = adapter.run_argv(
        workspace=tmp_path,
        argv=["chal", base64.b64encode(b"x").decode(), "missing"],
        timeout_seconds=8.0,
    )
    assert result.returncode == 2
    assert "not registered" in result.stderr
    assert delegate.calls == []


def test_target_exec_rejects_target_identity_drift_before_delegate(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"v1")
    target.chmod(0o755)
    delegate = RecordingIsolatedTestBackend()
    adapter = TargetExecutionBackend(
        delegate,
        runners={"fixture-native": NativeRunner("fixture-native")},
        default_profile_id="fixture-native",
        expected_target_sha256={"chal": "0" * 64},
    )
    result = adapter.run_argv(
        workspace=tmp_path,
        argv=["chal", base64.b64encode(b"x").decode()],
        timeout_seconds=8.0,
    )
    assert result.returncode == 2
    assert "target SHA-256 differs" in result.stderr
    assert delegate.calls == []
