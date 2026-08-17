from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from harness.core.sandbox import LinuxNamespaceSandboxBackend, NetworkPolicy
from harness.core.storage import ArtifactStore
from harness.core.tools import ActionRuntime, ToolCall
from ctf_harness.tools.control import make_control_probe_tool
from ctf_harness.verifiers.pwn.control import ControlFlowVerifier

ASM = r'''
.global _start
.text
_start:
    sub $16, %rsp
    xor %rax, %rax
    xor %rdi, %rdi
    mov %rsp, %rsi
    mov $64, %rdx
    syscall
    ret
'''


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-control-probe-") as td:
        root = Path(td)
        workspace = root / "workspace"
        workspace.mkdir()
        asm = workspace / "control.S"
        target = workspace / "control"
        asm.write_text(ASM, encoding="utf-8")
        subprocess.run(["/usr/bin/gcc", "-nostdlib", "-no-pie", "-Wl,--build-id=none", "-o", str(target), str(asm)], check=True)

        # Canonical lower-half, intentionally unmapped x86_64 address.  A
        # non-canonical 0x4141414141414141 faults at RET before RIP is loaded,
        # which cannot demonstrate instruction-pointer control.
        marker = 0x0000414141414141
        data = marker.to_bytes(8, "little") + b"B" * 24
        input_b64 = base64.b64encode(data).decode("ascii")
        target_sha = hashlib.sha256(target.read_bytes()).hexdigest()
        input_sha = hashlib.sha256(data).hexdigest()

        backend = LinuxNamespaceSandboxBackend(network_policy=NetworkPolicy.DENY)
        att = backend.isolation_attestation(workspace=workspace)
        if att.source != "runtime_probe":
            raise RuntimeError(f"live namespace attestation unavailable: {att.evidence}")
        runtime = ActionRuntime(
            {"pwn_control_probe": make_control_probe_tool(workspace, backend=backend)},
            strict_isolation=True,
            network_policy=NetworkPolicy.DENY,
        )
        results = [runtime.execute(ToolCall("pwn_control_probe", {"argv": ["control", input_b64]})) for _ in range(2)]
        diagnostics = [
            {"ok": r.ok, "error": r.error, "output": r.output, "isolation": r.isolation}
            for r in results
        ]
        if not all(r.ok for r in results):
            raise AssertionError(json.dumps(diagnostics, sort_keys=True, indent=2))

        observed_records = []
        for result in results:
            output = result.output or {}
            stdout = output.get("stdout") if isinstance(output, dict) else None
            if isinstance(stdout, str):
                try:
                    observed_records.append(json.loads(stdout.strip()))
                except json.JSONDecodeError:
                    observed_records.append({"unparsed_stdout": stdout, "stderr": output.get("stderr")})
            else:
                observed_records.append({"missing_stdout": True, "output": output})
        print("CONTROL_DIAGNOSTICS=" + json.dumps(observed_records, sort_keys=True))

        store = ArtifactStore(root / "artifacts")
        refs = []
        observations = []
        for i, result in enumerate(results):
            ref = store.put_json(f"control-{i}.json", {"ok": result.ok, "output": result.output, "error": result.error})
            refs.append(ref)
            observations.append({"source":"pwn_control_probe", "ok":True, "artifact_ref":ref})
        context = {
            "state":{"artifacts":refs, "evidence_refs":refs, "observations":observations},
            "artifact_root":str(store.root),
            "claim_evidence_refs":refs,
            "claim_key":"ctf.pwn.control_flow",
        }
        candidate = {"target_sha256":target_sha, "input_sha256":input_sha, "register":"rip", "value":marker, "input_offset":0}
        verifier = ControlFlowVerifier()
        accepted = verifier.verify(candidate, context)
        assert accepted.verified, accepted.reason
        assert not verifier.verify({**candidate, "value":0x0000424242424242}, context).verified
        one = dict(context)
        one["claim_evidence_refs"] = [refs[0]]
        assert not verifier.verify(candidate, one).verified
        print(json.dumps({
            "probe":"pwn-control-flow-live",
            "all_passed":True,
            "attestation_source":att.source,
            "register":"rip",
            "value":hex(marker),
            "input_offset":0,
            "evidence_count":2,
            "target_sha256":target_sha,
            "input_sha256":input_sha,
        }, sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
