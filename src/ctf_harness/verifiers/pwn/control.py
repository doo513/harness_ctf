from __future__ import annotations

import json
from typing import Any

from harness.core.storage import canonical_hash
from harness.core.verification import VerificationLevel, VerificationResult
from ctf_harness.verifiers.pwn.core import _registered_observation_artifacts


def _require_sha256(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"invalid {field}")
    return value


def _parse_record(payload: dict[str, Any]) -> dict[str, Any]:
    output = payload.get("output")
    if (
        not isinstance(output, dict)
        or output.get("returncode") != 0
        or output.get("timed_out") is not False
    ):
        raise ValueError("control probe wrapper did not complete successfully")
    stdout = output.get("stdout")
    if not isinstance(stdout, str):
        raise ValueError("control probe stdout is unavailable")
    record = json.loads(stdout.strip())
    if not isinstance(record, dict) or record.get("kind") != "pwn_control_probe_x86_64":
        raise ValueError("control probe schema mismatch")
    schema_version = record.get("schema_version")
    if schema_version not in (1, 2):
        raise ValueError("control probe schema mismatch")
    if record.get("timed_out") is not False:
        raise ValueError("timed-out GDB probe cannot establish control")
    if record.get("register") != "rip":
        raise ValueError("only x86_64 RIP control is currently authorized")
    if not isinstance(record.get("value"), int) or not (0 <= record["value"] < 2**64):
        raise ValueError("RIP value is unavailable")
    if not isinstance(record.get("input_offset"), int) or record["input_offset"] < 0:
        raise ValueError("observed RIP is not uniquely sourced from the supplied input")
    _require_sha256(record, "target_sha256")
    _require_sha256(record, "input_sha256")

    if schema_version == 2:
        runtime = record.get("runtime")
        if not isinstance(runtime, dict):
            raise ValueError("control probe runtime descriptor is missing")
        if runtime.get("runtime_kind") != "native":
            raise ValueError("x86_64 RIP verifier currently authorizes native runtime evidence only")
        runtime_fingerprint = _require_sha256(record, "runtime_fingerprint")
        if canonical_hash(runtime) != runtime_fingerprint:
            raise ValueError("control probe runtime fingerprint mismatch")
        launch_argv = record.get("launch_argv")
        if not isinstance(launch_argv, list) or not launch_argv or any(
            not isinstance(item, str) or not item or "\x00" in item for item in launch_argv
        ):
            raise ValueError("control probe launch argv is malformed")
        launch_fingerprint = _require_sha256(record, "launch_fingerprint")
        expected_launch = canonical_hash(
            {
                "target_sha256": record["target_sha256"],
                "runtime_fingerprint": runtime_fingerprint,
                "argv": launch_argv,
            }
        )
        if launch_fingerprint != expected_launch:
            raise ValueError("control probe launch fingerprint mismatch")
    return record


class ControlFlowVerifier:
    name = "pwn_control_flow_x86_64"
    level = VerificationLevel.EXECUTION
    covers = ("ctf_semantic",)
    claim_key = "ctf.pwn.control_flow"

    def verify(self, candidate: Any, context: dict) -> VerificationResult:
        refs = list(context.get("claim_evidence_refs") or [])
        if context.get("claim_key") != self.claim_key:
            return VerificationResult(
                False,
                self.level,
                "verifier is not bound to this exact claim key",
                evidence_refs=refs,
            )
        if len(set(refs)) < 2:
            return VerificationResult(
                False,
                self.level,
                "control-flow claim requires at least two independent evidence artifacts",
                evidence_refs=refs,
            )
        try:
            records = [
                _parse_record(payload)
                for _, payload in _registered_observation_artifacts(
                    context, source="pwn_control_probe"
                )
            ]
        except Exception as exc:
            return VerificationResult(
                False,
                self.level,
                f"{type(exc).__name__}: {exc}",
                evidence_refs=refs,
            )

        first = records[0]
        schema_version = first["schema_version"]
        identity = (
            first["target_sha256"],
            first["input_sha256"],
            first["register"],
            first["value"],
            first["input_offset"],
        )
        runtime_fingerprint = first.get("runtime_fingerprint") if schema_version == 2 else None
        launch_fingerprint = first.get("launch_fingerprint") if schema_version == 2 else None
        for record in records[1:]:
            if record["schema_version"] != schema_version:
                return VerificationResult(
                    False,
                    self.level,
                    "control-flow evidence mixes legacy and runtime-bound probe schemas",
                    evidence_refs=refs,
                )
            other = (
                record["target_sha256"],
                record["input_sha256"],
                record["register"],
                record["value"],
                record["input_offset"],
            )
            if other != identity:
                return VerificationResult(
                    False,
                    self.level,
                    "control-flow evidence is not reproducible for one target/input/value/offset",
                    evidence_refs=refs,
                )
            if schema_version == 2 and (
                record.get("runtime_fingerprint") != runtime_fingerprint
                or record.get("launch_fingerprint") != launch_fingerprint
            ):
                return VerificationResult(
                    False,
                    self.level,
                    "runtime-bound control evidence was produced by different runtime/launch identities",
                    evidence_refs=refs,
                )

        expected = {
            "target_sha256": identity[0],
            "input_sha256": identity[1],
            "register": identity[2],
            "value": identity[3],
            "input_offset": identity[4],
        }
        if schema_version == 2:
            expected.update(
                {
                    "runtime_fingerprint": runtime_fingerprint,
                    "launch_fingerprint": launch_fingerprint,
                }
            )
        if candidate != expected:
            return VerificationResult(
                False,
                self.level,
                "candidate does not exactly bind the authorized control-flow execution identity",
                evidence_refs=refs,
                details={"expected": expected},
            )
        return VerificationResult(
            True,
            self.level,
            "same input reproducibly controls x86_64 RIP with one exact target/runtime/launch identity",
            evidence_refs=refs,
            details=expected,
            confidence=1.0,
        )
