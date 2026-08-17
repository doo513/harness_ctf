from __future__ import annotations

import json
from typing import Any

from harness.core.storage import canonical_hash
from harness.core.verification import VerificationLevel, VerificationResult
from ctf_harness.verifiers.pwn.core import _registered_observation_artifacts


def _require_sha256(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"invalid {field}")
    return value


def _parse_probe(payload: dict[str, Any]) -> dict[str, Any]:
    output = payload.get("output")
    if not isinstance(output, dict) or output.get("returncode") != 0 or output.get("timed_out") is not False:
        raise ValueError("crash probe wrapper did not complete successfully")
    stdout = output.get("stdout")
    if not isinstance(stdout, str):
        raise ValueError("crash probe stdout is unavailable")
    record = json.loads(stdout.strip())
    if not isinstance(record, dict) or record.get("kind") != "pwn_crash_probe" or record.get("schema_version") not in (1, 2):
        raise ValueError("crash probe schema mismatch")
    _require_sha256(record, "target_sha256"); _require_sha256(record, "input_sha256")
    if record["schema_version"] == 2:
        runtime = record.get("runtime")
        if not isinstance(runtime, dict): raise ValueError("crash probe runtime descriptor is missing")
        runtime_fp = _require_sha256(record, "runtime_fingerprint")
        if canonical_hash(runtime) != runtime_fp: raise ValueError("crash probe runtime fingerprint mismatch")
        argv = record.get("launch_argv")
        if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x or "\x00" in x for x in argv): raise ValueError("crash probe launch argv is malformed")
        launch_fp = _require_sha256(record, "launch_fingerprint")
        if launch_fp != canonical_hash({"target_sha256": record["target_sha256"], "runtime_fingerprint": runtime_fp, "argv": argv}):
            raise ValueError("crash probe launch fingerprint mismatch")
    return record


class CrashReproducibleVerifier:
    name = "pwn_crash_reproducible"
    level = VerificationLevel.EXECUTION
    covers = ("ctf_semantic",)
    claim_key = "ctf.pwn.crash_reproducible"

    def verify(self, candidate: Any, context: dict) -> VerificationResult:
        refs = list(context.get("claim_evidence_refs") or [])
        if context.get("claim_key") != self.claim_key:
            return VerificationResult(False, self.level, "verifier is not bound to this exact claim key", evidence_refs=refs)
        if len(set(refs)) < 2:
            return VerificationResult(False, self.level, "reproducible crash requires at least two independent evidence artifacts", evidence_refs=refs)
        try:
            records = [_parse_probe(payload) for _, payload in _registered_observation_artifacts(context, source="pwn_crash_probe")]
        except Exception as exc:
            return VerificationResult(False, self.level, f"{type(exc).__name__}: {exc}", evidence_refs=refs)
        first = records[0]
        schema = first["schema_version"]
        identity = (first["target_sha256"], first["input_sha256"], first.get("signal"))
        if first.get("timed_out") is not False or not isinstance(first.get("signal"), int) or first["signal"] <= 0:
            return VerificationResult(False, self.level, "probe did not observe a terminating signal", evidence_refs=refs)
        runtime_fp = first.get("runtime_fingerprint") if schema == 2 else None
        launch_fp = first.get("launch_fingerprint") if schema == 2 else None
        for record in records[1:]:
            if record["schema_version"] != schema:
                return VerificationResult(False, self.level, "crash evidence mixes legacy and runtime-bound probe schemas", evidence_refs=refs)
            if (record["target_sha256"], record["input_sha256"], record.get("signal")) != identity:
                return VerificationResult(False, self.level, "crash evidence is not reproducible for the same target/input/signal", evidence_refs=refs)
            if record.get("timed_out") is not False:
                return VerificationResult(False, self.level, "timed-out execution is not a reproduced crash", evidence_refs=refs)
            if schema == 2 and (record.get("runtime_fingerprint") != runtime_fp or record.get("launch_fingerprint") != launch_fp):
                return VerificationResult(False, self.level, "runtime-bound crash evidence was produced by different runtime/launch identities", evidence_refs=refs)
        expected = {"target_sha256": identity[0], "input_sha256": identity[1], "signal": identity[2]}
        if schema == 2:
            expected.update({"runtime_fingerprint": runtime_fp, "launch_fingerprint": launch_fp})
        if candidate != expected:
            return VerificationResult(False, self.level, "candidate does not exactly bind the reproduced crash execution identity", evidence_refs=refs, details={"expected": expected})
        return VerificationResult(True, self.level, "same target/input reproduced the same terminating signal under one exact runtime/launch identity", evidence_refs=refs, details=expected, confidence=1.0)
