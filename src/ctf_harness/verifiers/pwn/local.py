from __future__ import annotations

import re
from typing import Any

from harness.core.verification import VerificationLevel, VerificationResult
from ctf_harness.verifiers.pwn.core import _registered_observation_artifacts

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TRUSTED_INDEPENDENCE = {
    "operator_fixed_digest_and_filesystem_isolation",
    "sealed_integrity_and_filesystem_isolation",
}


class LocalExploitVerifier:
    name = "pwn_local_exploit"
    level = VerificationLevel.EXECUTION
    covers = ("ctf_semantic",)
    claim_key = "ctf.pwn.local_exploit"

    def verify(self, candidate: Any, context: dict) -> VerificationResult:
        refs = list(context.get("claim_evidence_refs") or [])
        if context.get("claim_key") != self.claim_key:
            return VerificationResult(False, self.level, "verifier is not bound to this exact claim key", evidence_refs=refs)
        try:
            loaded = _registered_observation_artifacts(context, source="pwn_local_proof_oracle")
            if not loaded:
                raise ValueError("local proof receipt is unavailable")
            records = []
            for _, payload in loaded:
                record = payload.get("output")
                if not isinstance(record, dict):
                    raise ValueError("local proof receipt output is not an object")
                if record.get("kind") != "pwn_local_proof_receipt" or record.get("schema_version") != 1:
                    raise ValueError("local proof receipt schema mismatch")
                if record.get("proof_level") != "P3_LOCAL":
                    raise ValueError("receipt is not a P3 local proof")
                if record.get("accepted") is not True:
                    raise ValueError("local proof oracle rejected the exploit")
                if record.get("independence_level") not in _TRUSTED_INDEPENDENCE:
                    raise ValueError("local proof oracle independence is insufficient")
                for field in ("target_sha256", "exploit_sha256", "environment_fingerprint", "oracle_evidence_hash", "reason_hash"):
                    value = record.get(field)
                    if not isinstance(value, str) or not _HEX64.fullmatch(value):
                        raise ValueError(f"invalid {field}")
                if not isinstance(record.get("oracle_id"), str) or not record["oracle_id"]:
                    raise ValueError("local proof oracle_id is unavailable")
                records.append(record)
        except Exception as exc:
            return VerificationResult(False, self.level, f"{type(exc).__name__}: {exc}", evidence_refs=refs)

        first = records[0]
        identity = (
            first["target_sha256"],
            first["exploit_sha256"],
            first["environment_fingerprint"],
            first["oracle_id"],
        )
        for record in records[1:]:
            other = (
                record["target_sha256"],
                record["exploit_sha256"],
                record["environment_fingerprint"],
                record["oracle_id"],
            )
            if other != identity:
                return VerificationResult(False, self.level, "local proof evidence mixes different target/exploit/environment/oracle identities", evidence_refs=refs)

        expected = {
            "target_sha256": identity[0],
            "exploit_sha256": identity[1],
            "environment_fingerprint": identity[2],
            "oracle_id": identity[3],
        }
        if candidate != expected:
            return VerificationResult(False, self.level, "candidate does not exactly bind the accepted local proof identity", evidence_refs=refs, details={"expected": expected})
        return VerificationResult(
            True,
            self.level,
            "operator-fixed local oracle accepted this exact exploit against this exact target/environment",
            evidence_refs=refs,
            details=expected,
            confidence=1.0,
        )
