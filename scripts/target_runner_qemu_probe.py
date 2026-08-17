from __future__ import annotations

import base64
import hashlib
import json
import shutil
import struct
import tempfile
from pathlib import Path

from harness.core.sandbox import LinuxNamespaceSandboxBackend, NetworkPolicy
from harness.core.storage import ArtifactStore
from harness.core.tools import ActionRuntime, ToolCall

from ctf_harness.target.runners import NativeRunner, QemuUserRunner
from ctf_harness.tools.crash import make_crash_probe_tool
from ctf_harness.verifiers.pwn.crash import CrashReproducibleVerifier


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _minimal_aarch64_segv_elf() -> bytes:
    """Build a tiny AArch64 ET_EXEC that dereferences NULL and SIGSEGVs.

    This avoids introducing a cross-compiler into the controlled runner probe.
    It is an execution fixture, not a challenge or exploit payload.
    """
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 2  # ELFCLASS64
    ident[5] = 1  # ELFDATA2LSB
    ident[6] = 1  # EV_CURRENT
    ident[7] = 0  # ELFOSABI_SYSV

    # AArch64 instructions:
    #   mov x0, #0
    #   ldr x1, [x0]   ; deterministic NULL dereference
    #   mov x8, #93    ; exit syscall fallback (should never execute)
    #   mov x0, #0
    #   svc #0
    code = struct.pack(
        "<IIIII",
        0xD2800000,
        0xF9400001,
        0xD2800BA8,
        0xD2800000,
        0xD4000001,
    )

    elf_header_size = 64
    program_header_size = 56
    code_offset = elf_header_size + program_header_size
    base = 0x400000
    entry = base + code_offset
    file_size = code_offset + len(code)

    elf_header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(ident),
        2,          # ET_EXEC
        183,        # EM_AARCH64
        1,          # EV_CURRENT
        entry,
        elf_header_size,
        0,          # section table absent
        0,          # flags
        elf_header_size,
        program_header_size,
        1,
        0,
        0,
        0,
    )
    program_header = struct.pack(
        "<IIQQQQQQ",
        1,          # PT_LOAD
        5,          # PF_R | PF_X
        0,
        base,
        base,
        file_size,
        file_size,
        0x1000,
    )
    return elf_header + program_header + code


def main() -> int:
    qemu_raw = shutil.which("qemu-aarch64-static")
    if not qemu_raw:
        raise RuntimeError("qemu-aarch64-static is unavailable")
    qemu = Path(qemu_raw).resolve(strict=True)
    qemu_sha256 = _sha256_file(qemu)

    with tempfile.TemporaryDirectory(prefix="ctf-qemu-runner-probe-") as td:
        root = Path(td)
        workspace = root / "workspace"
        workspace.mkdir()
        target = workspace / "aarch64-segv"
        target.write_bytes(_minimal_aarch64_segv_elf())
        target.chmod(0o755)

        target_sha256 = _sha256_file(target)
        raw_input = b"controlled-qemu-input\n"
        input_sha256 = hashlib.sha256(raw_input).hexdigest()
        input_b64 = base64.b64encode(raw_input).decode("ascii")

        qemu_runner = QemuUserRunner(
            profile_id="controlled-aarch64-qemu",
            qemu_path=str(qemu),
            qemu_sha256=qemu_sha256,
        )

        backend = LinuxNamespaceSandboxBackend(network_policy=NetworkPolicy.DENY)
        attestation = backend.isolation_attestation(workspace=workspace)
        if attestation.source != "runtime_probe":
            raise RuntimeError(
                f"live namespace attestation unavailable: {attestation.evidence}"
            )

        tool = make_crash_probe_tool(
            workspace,
            backend=backend,
            runners={
                "native-default": NativeRunner(),
                "controlled-aarch64-qemu": qemu_runner,
            },
            expected_target_sha256={"aarch64-segv": target_sha256},
        )
        runtime = ActionRuntime(
            {"pwn_crash_probe": tool},
            strict_isolation=True,
            network_policy=NetworkPolicy.DENY,
        )

        results = [
            runtime.execute(
                ToolCall(
                    "pwn_crash_probe",
                    {
                        "argv": [
                            "aarch64-segv",
                            input_b64,
                            "controlled-aarch64-qemu",
                        ]
                    },
                )
            )
            for _ in range(2)
        ]
        if not all(result.ok for result in results):
            raise RuntimeError(
                "controlled QEMU crash executions failed: "
                + repr([result.error for result in results])
            )

        store = ArtifactStore(root / "artifacts")
        refs: list[str] = []
        observations: list[dict[str, object]] = []
        records: list[dict[str, object]] = []
        for index, result in enumerate(results):
            record = json.loads(result.output["stdout"].strip())
            records.append(record)
            if record.get("schema_version") != 2:
                raise AssertionError("QEMU crash evidence did not use schema v2")
            if record.get("signal") != 11:
                raise AssertionError(
                    f"QEMU guest SIGSEGV was not observed as signal 11: {record}"
                )
            runtime_descriptor = record.get("runtime")
            if not isinstance(runtime_descriptor, dict):
                raise AssertionError("runtime descriptor missing")
            if runtime_descriptor.get("runtime_kind") != "qemu_user":
                raise AssertionError("runtime kind is not qemu_user")
            artifacts = runtime_descriptor.get("runtime_artifacts")
            if not isinstance(artifacts, list) or not any(
                isinstance(item, dict)
                and item.get("role") == "qemu"
                and item.get("sha256") == qemu_sha256
                for item in artifacts
            ):
                raise AssertionError("QEMU runtime artifact identity is not bound")

            ref = store.put_json(
                f"qemu-crash-{index}.json",
                {"ok": result.ok, "output": result.output, "error": result.error},
            )
            refs.append(ref)
            observations.append(
                {"source": "pwn_crash_probe", "ok": True, "artifact_ref": ref}
            )

        if records[0]["runtime_fingerprint"] != records[1]["runtime_fingerprint"]:
            raise AssertionError("repeated QEMU runs changed runtime identity")
        if records[0]["launch_fingerprint"] != records[1]["launch_fingerprint"]:
            raise AssertionError("repeated QEMU runs changed launch identity")

        context = {
            "state": {
                "artifacts": refs,
                "evidence_refs": refs,
                "observations": observations,
            },
            "artifact_root": str(store.root),
            "claim_evidence_refs": refs,
            "claim_key": "ctf.pwn.crash_reproducible",
        }
        candidate = {
            "target_sha256": target_sha256,
            "input_sha256": input_sha256,
            "signal": 11,
        }
        verified = CrashReproducibleVerifier().verify(candidate, context)
        if not verified.verified:
            raise AssertionError(verified.reason)

        print(
            json.dumps(
                {
                    "probe": "ctf-target-runner-qemu-aarch64-controlled-v1",
                    "all_passed": True,
                    "attestation_source": attestation.source,
                    "target_architecture": "aarch64",
                    "runtime_kind": "qemu_user",
                    "qemu_sha256": qemu_sha256,
                    "target_sha256": target_sha256,
                    "input_sha256": input_sha256,
                    "signal": 11,
                    "evidence_count": len(refs),
                    "runtime_fingerprint": records[0]["runtime_fingerprint"],
                    "launch_fingerprint": records[0]["launch_fingerprint"],
                },
                sort_keys=True,
                indent=2,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
