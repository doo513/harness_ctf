from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from harness.core.sandbox import RecordingIsolatedTestBackend
from harness.core.storage import ArtifactStore, canonical_hash
from ctf_harness.operational.models import RuntimeKind
from ctf_harness.target.runners import NativeRunner
from ctf_harness.tools.control import ControlProbeBackend
from ctf_harness.verifiers.pwn.control import ControlFlowVerifier


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _decode_launch(backend: RecordingIsolatedTestBackend) -> dict:
    return json.loads(base64.b64decode(backend.calls[-1]["argv"][-1], validate=True))


def test_control_probe_binds_native_runtime_and_target_identity(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"native-x86")
    target.chmod(0o755)
    delegate = RecordingIsolatedTestBackend()
    adapter = ControlProbeBackend(
        delegate,
        expected_target_sha256={"chal": _sha(target)},
    )
    result = adapter.run_argv(
        workspace=tmp_path,
        argv=["chal", base64.b64encode(b"input").decode()],
        timeout_seconds=5.0,
    )
    assert result.returncode == 0
    launch = _decode_launch(delegate)
    assert launch["target_sha256"] == _sha(target)
    assert launch["runtime"]["runtime_kind"] == "native"
    assert launch["runtime_fingerprint"] == canonical_hash(launch["runtime"])
    assert launch["launch_fingerprint"] == canonical_hash({
        "target_sha256": launch["target_sha256"],
        "runtime_fingerprint": launch["runtime_fingerprint"],
        "argv": launch["argv"],
    })


def test_control_probe_rejects_non_native_runtime_before_execution(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"target")
    target.chmod(0o755)

    class NonNativeRunner:
        profile_id = "emulated"
        runtime_kind = RuntimeKind.QEMU_USER
        def build_launch(self, **kwargs):
            raise AssertionError("must not build unsupported P2 launch")

    delegate = RecordingIsolatedTestBackend()
    adapter = ControlProbeBackend(
        delegate,
        runners={"native-default": NativeRunner(), "emulated": NonNativeRunner()},
    )
    result = adapter.run_argv(
        workspace=tmp_path,
        argv=["chal", base64.b64encode(b"x").decode(), "emulated"],
        timeout_seconds=5.0,
    )
    assert result.returncode == 2
    assert "only native" in result.stderr
    assert delegate.calls == []


def _record(profile: str = "native-default") -> dict:
    runtime = {
        "profile_id": profile,
        "runtime_kind": "native",
        "runtime_artifacts": [],
        "runtime_args": [],
    }
    runtime_fp = canonical_hash(runtime)
    argv = ["./chal"]
    target_sha = "a" * 64
    return {
        "schema_version": 2,
        "kind": "pwn_control_probe_x86_64",
        "target_sha256": target_sha,
        "input_sha256": "b" * 64,
        "runtime": runtime,
        "runtime_fingerprint": runtime_fp,
        "launch_argv": argv,
        "launch_fingerprint": canonical_hash({
            "target_sha256": target_sha,
            "runtime_fingerprint": runtime_fp,
            "argv": argv,
        }),
        "register": "rip",
        "value": 0x414141414141,
        "input_offset": 0,
        "gdb_returncode": 0,
        "timed_out": False,
    }


def _context(tmp_path: Path, records: list[dict]) -> dict:
    store = ArtifactStore(tmp_path / "artifacts")
    refs, observations = [], []
    for index, record in enumerate(records):
        ref = store.put_json(f"control-{index}.json", {
            "ok": True,
            "output": {
                "returncode": 0,
                "stdout": json.dumps(record, sort_keys=True, separators=(",", ":")),
                "stderr": "",
                "timed_out": False,
            },
            "error": None,
        })
        refs.append(ref)
        observations.append({"source": "pwn_control_probe", "ok": True, "artifact_ref": ref})
    return {
        "state": {"artifacts": refs, "evidence_refs": refs, "observations": observations},
        "artifact_root": str(store.root),
        "claim_evidence_refs": refs,
        "claim_key": "ctf.pwn.control_flow",
    }


def test_control_verifier_fact_contains_runtime_identity(tmp_path: Path) -> None:
    first = _record()
    candidate = {
        "target_sha256": first["target_sha256"],
        "input_sha256": first["input_sha256"],
        "register": first["register"],
        "value": first["value"],
        "input_offset": first["input_offset"],
        "runtime_fingerprint": first["runtime_fingerprint"],
        "launch_fingerprint": first["launch_fingerprint"],
    }
    verifier = ControlFlowVerifier()
    assert verifier.verify(candidate, _context(tmp_path / "ok", [first, _record()])).verified
    mixed = verifier.verify(candidate, _context(tmp_path / "mixed", [first, _record("other")]))
    assert not mixed.verified
    assert "different runtime/launch" in mixed.reason
    assert not verifier.verify(
        {**candidate, "runtime_fingerprint": "0" * 64},
        _context(tmp_path / "tamper", [first, _record()]),
    ).verified
