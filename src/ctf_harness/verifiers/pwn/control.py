from __future__ import annotations

import json
from typing import Any

from harness.core.verification import VerificationLevel, VerificationResult
from ctf_harness.verifiers.pwn.core import _registered_observation_artifacts


class ControlFlowVerifier:
    name = "pwn_control_flow_x86_64"
    level = VerificationLevel.EXECUTION
    covers = ("ctf_semantic",)
    claim_key = "ctf.pwn.control_flow"

    def verify(self, candidate: Any, context: dict) -> VerificationResult:
        refs = list(context.get("claim_evidence_refs") or [])
        if context.get("claim_key") != self.claim_key:
            return VerificationResult(False, self.level, "verifier is not bound to this exact claim key", evidence_refs=refs)
        if len(set(refs)) < 2:
            return VerificationResult(False, self.level, "control-flow claim requires at least two independent evidence artifacts", evidence_refs=refs)
        try:
            loaded = _registered_observation_artifacts(context, source="pwn_control_probe")
            records = []
            for _, payload in loaded:
                output = payload.get("output")
                if not isinstance(output, dict) or output.get("returncode") != 0 or output.get("timed_out") is not False:
                    raise ValueError("control probe wrapper did not complete successfully")
                stdout = output.get("stdout")
                if not isinstance(stdout, str):
                    raise ValueError("control probe stdout is unavailable")
                record = json.loads(stdout.strip())
                if record.get("kind") != "pwn_control_probe_x86_64" or record.get("schema_version") != 1:
                    raise ValueError("control probe schema mismatch")
                if record.get("timed_out") is not False:
                    raise ValueError("timed-out GDB probe cannot establish control")
                if record.get("register") != "rip":
                    raise ValueError("only x86_64 RIP control is currently authorized")
                if not isinstance(record.get("value"), int) or not (0 <= record["value"] < 2**64):
                    raise ValueError("RIP value is unavailable")
                if not isinstance(record.get("input_offset"), int) or record["input_offset"] < 0:
                    raise ValueError("observed RIP is not uniquely sourced from the supplied input")
                for field in ("target_sha256", "input_sha256"):
                    value = record.get(field)
                    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                        raise ValueError(f"invalid {field}")
                records.append(record)
        except Exception as exc:
            return VerificationResult(False, self.level, f"{type(exc).__name__}: {exc}", evidence_refs=refs)

        first = records[0]
        identity = (first["target_sha256"], first["input_sha256"], first["register"], first["value"], first["input_offset"])
        if any((r["target_sha256"], r["input_sha256"], r["register"], r["value"], r["input_offset"]) != identity for r in records[1:]):
            return VerificationResult(False, self.level, "control-flow evidence is not reproducible for one target/input/value/offset", evidence_refs=refs)
        expected = {
            "target_sha256": identity[0],
            "input_sha256": identity[1],
            "register": identity[2],
            "value": identity[3],
            "input_offset": identity[4],
        }
        if candidate != expected:
            return VerificationResult(False, self.level, "candidate does not exactly bind target/input/register/value/offset", evidence_refs=refs, details={"expected": expected})
        return VerificationResult(True, self.level, "same input reproducibly controls x86_64 RIP with a uniquely input-sourced value", evidence_refs=refs, details=expected, confidence=1.0)
