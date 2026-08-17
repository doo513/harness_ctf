from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from harness.core.sandbox import RecordingIsolatedTestBackend
from harness.core.storage import ArtifactStore, canonical_hash
from ctf_harness.target.runners import NativeRunner, QemuUserRunner, fingerprint_workspace_tree
from ctf_harness.tools.crash import CrashProbeBackend
from ctf_harness.verifiers.pwn.crash import CrashReproducibleVerifier


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _decode_launch(backend: RecordingIsolatedTestBackend) -> dict:
    helper = backend.calls[-1]["argv"]
    return json.loads(base64.b64decode(helper[-1], validate=True).decode("utf-8"))


def test_crash_backend_defaults_to_registered_native_runner(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"native-target")
    target.chmod(0o755)
    delegate = RecordingIsolatedTestBackend()
    adapter = CrashProbeBackend(delegate)
    result = adapter.run_argv(
        workspace=tmp_path,
        argv=["chal", base64.b64encode(b"input\n").decode("ascii")],
        timeout_seconds=5.0,
    )
    assert result.returncode == 0
    launch = _decode_launch(delegate)
    assert launch["target_sha256"] == _sha(target)
    assert launch["runtime"]["profile_id"] == "native-default"
    assert launch["runtime"]["runtime_kind"] == "native"
    assert launch["argv"] == ["./chal"]
    assert launch["runtime_fingerprint"] == canonical_hash(launch["runtime"])
    assert launch["launch_fingerprint"] == canonical_hash({
        "target_sha256": launch["target_sha256"],
        "runtime_fingerprint": launch["runtime_fingerprint"],
        "argv": launch["argv"],
    })


def test_crash_backend_selects_only_pre_registered_qemu_profile(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "chal"
    target.write_bytes(b"aarch64-target")
    target.chmod(0o755)
    qemu = tmp_path / "qemu-aarch64-static"
    qemu.write_bytes(b"qemu-v1")
    qemu.chmod(0o755)
    sysroot = workspace / "rootfs"
    (sysroot / "lib").mkdir(parents=True)
    loader = sysroot / "lib" / "ld-musl-aarch64.so.1"
    loader.write_bytes(b"loader-v1")
    (sysroot / "lib" / "libc.so").write_bytes(b"libc-v1")
    qemu_runner = QemuUserRunner(
        profile_id="aarch64-qemu",
        qemu_path=str(qemu.resolve()),
        qemu_sha256=_sha(qemu),
        sysroot_relpath="rootfs",
        sysroot_fingerprint=fingerprint_workspace_tree(sysroot),
        loader_relpath="rootfs/lib/ld-musl-aarch64.so.1",
        loader_sha256=_sha(loader),
        loader_args=("--library-path", "./rootfs/lib"),
    )
    delegate = RecordingIsolatedTestBackend()
    adapter = CrashProbeBackend(delegate, runners={
        "native-default": NativeRunner(),
        "aarch64-qemu": qemu_runner,
    })
    result = adapter.run_argv(
        workspace=workspace,
        argv=["chal", base64.b64encode(b"x").decode("ascii"), "aarch64-qemu"],
        timeout_seconds=5.0,
    )
    assert result.returncode == 0
    launch = _decode_launch(delegate)
    assert launch["runtime"]["profile_id"] == "aarch64-qemu"
    assert launch["runtime"]["runtime_kind"] == "qemu_user"
    assert {item["role"] for item in launch["runtime"]["runtime_artifacts"]} == {"qemu", "loader", "sysroot"}
    assert launch["argv"][-1] == "./chal"
    rejected = adapter.run_argv(
        workspace=workspace,
        argv=["chal", base64.b64encode(b"x").decode("ascii"), "not-registered"],
        timeout_seconds=5.0,
    )
    assert rejected.returncode == 2
    assert "not registered" in rejected.stderr


def test_crash_backend_can_bind_expected_admitted_target_identity(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"target-v1")
    target.chmod(0o755)
    delegate = RecordingIsolatedTestBackend()
    adapter = CrashProbeBackend(delegate, expected_target_sha256={"chal": "0" * 64})
    result = adapter.run_argv(
        workspace=tmp_path,
        argv=["chal", base64.b64encode(b"x").decode("ascii")],
        timeout_seconds=5.0,
    )
    assert result.returncode == 2
    assert "target SHA-256 differs" in result.stderr
    assert delegate.calls == []


def _schema2_record(*, runtime_profile: str = "native-default") -> dict:
    runtime = {
        "profile_id": runtime_profile,
        "runtime_kind": "native",
        "runtime_artifacts": [],
        "runtime_args": [],
    }
    runtime_fp = canonical_hash(runtime)
    argv = ["./chal"]
    target_sha = "a" * 64
    return {
        "schema_version": 2,
        "kind": "pwn_crash_probe",
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
        "timed_out": False,
        "returncode": -11,
        "signal": 11,
        "stdout_sha256": "c" * 64,
        "stderr_sha256": "d" * 64,
    }


def _context_for_records(tmp_path: Path, records: list[dict]) -> dict:
    store = ArtifactStore(tmp_path / "artifacts")
    refs, observations = [], []
    for index, record in enumerate(records):
        ref = store.put_json(f"crash-{index}.json", {
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
        observations.append({"source": "pwn_crash_probe", "ok": True, "artifact_ref": ref})
    return {
        "state": {"artifacts": refs, "evidence_refs": refs, "observations": observations},
        "artifact_root": str(store.root),
        "claim_evidence_refs": refs,
        "claim_key": "ctf.pwn.crash_reproducible",
    }


def _candidate(record: dict) -> dict:
    return {
        "target_sha256": record["target_sha256"],
        "input_sha256": record["input_sha256"],
        "signal": record["signal"],
        "runtime_fingerprint": record["runtime_fingerprint"],
        "launch_fingerprint": record["launch_fingerprint"],
    }


def test_crash_verifier_accepts_same_schema2_runtime_and_rejects_runtime_mix(tmp_path: Path) -> None:
    first = _schema2_record()
    candidate = _candidate(first)
    verifier = CrashReproducibleVerifier()
    accepted = verifier.verify(candidate, _context_for_records(tmp_path / "same", [first, _schema2_record()]))
    assert accepted.verified
    assert accepted.details == candidate
    rejected = verifier.verify(candidate, _context_for_records(
        tmp_path / "mixed",
        [first, _schema2_record(runtime_profile="different-runtime")],
    ))
    assert not rejected.verified
    assert "different runtime/launch identities" in rejected.reason


def test_crash_verifier_rejects_tampered_runtime_receipt_and_candidate(tmp_path: Path) -> None:
    first = _schema2_record()
    second = _schema2_record()
    second["runtime_fingerprint"] = "0" * 64
    result = CrashReproducibleVerifier().verify(
        _candidate(first),
        _context_for_records(tmp_path / "receipt", [first, second]),
    )
    assert not result.verified
    assert "runtime fingerprint mismatch" in result.reason

    good = _schema2_record()
    result = CrashReproducibleVerifier().verify(
        {**_candidate(good), "runtime_fingerprint": "0" * 64},
        _context_for_records(tmp_path / "candidate", [good, _schema2_record()]),
    )
    assert not result.verified
    assert "execution identity" in result.reason
