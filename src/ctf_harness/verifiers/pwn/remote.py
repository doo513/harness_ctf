from __future__ import annotations

import ipaddress
import re
from typing import Any

from harness.core.verification import VerificationLevel, VerificationResult
from ctf_harness.verifiers.pwn.core import _registered_observation_artifacts

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class RemoteBehaviorVerifier:
    name = "pwn_remote_behavior"
    level = VerificationLevel.EXECUTION
    covers = ("ctf_semantic",)
    claim_key = "ctf.pwn.remote_behavior"

    def verify(self, candidate: Any, context: dict) -> VerificationResult:
        refs = list(context.get("claim_evidence_refs") or [])
        if context.get("claim_key") != self.claim_key:
            return VerificationResult(False, self.level, "verifier is not bound to this exact claim key", evidence_refs=refs)
        try:
            loaded = _registered_observation_artifacts(context, source="pwn_remote_proof_oracle")
            if not loaded:
                raise ValueError("remote behavior receipt is unavailable")
            records = []
            for _, payload in loaded:
                record = payload.get("output")
                if not isinstance(record, dict):
                    raise ValueError("remote behavior receipt output is not an object")
                if record.get("kind") != "pwn_remote_behavior_receipt" or record.get("schema_version") != 1:
                    raise ValueError("remote behavior receipt schema mismatch")
                if record.get("proof_level") != "P5_REMOTE":
                    raise ValueError("receipt is not a P5 remote proof")
                if record.get("accepted") is not True:
                    raise ValueError("remote behavior oracle rejected the exchange")
                if record.get("independence_level") != "operator_fixed_endpoint_and_response_digest":
                    raise ValueError("remote behavior oracle independence is insufficient")
                if record.get("response_complete") is not True:
                    raise ValueError("remote response was not complete")
                for field in (
                    "endpoint_id", "payload_sha256", "response_sha256",
                    "remote_environment_fingerprint", "reason_hash",
                ):
                    value = record.get(field)
                    if not isinstance(value, str) or not _HEX64.fullmatch(value):
                        raise ValueError(f"invalid {field}")
                if not isinstance(record.get("oracle_id"), str) or not record["oracle_id"]:
                    raise ValueError("remote behavior oracle_id is unavailable")
                peer = ipaddress.ip_address(record.get("peer_ip"))
                if peer.is_unspecified:
                    raise ValueError("remote peer address is unspecified")
                port = record.get("peer_port")
                if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
                    raise ValueError("remote peer port is invalid")
                response_bytes = record.get("response_bytes")
                if not isinstance(response_bytes, int) or isinstance(response_bytes, bool) or response_bytes < 0:
                    raise ValueError("remote response byte count is invalid")
                records.append(record)
        except Exception as exc:
            return VerificationResult(False, self.level, f"{type(exc).__name__}: {exc}", evidence_refs=refs)

        first = records[0]
        identity = (
            first["endpoint_id"],
            first["payload_sha256"],
            first["response_sha256"],
            first["remote_environment_fingerprint"],
            first["oracle_id"],
        )
        for record in records[1:]:
            other = (
                record["endpoint_id"],
                record["payload_sha256"],
                record["response_sha256"],
                record["remote_environment_fingerprint"],
                record["oracle_id"],
            )
            if other != identity:
                return VerificationResult(False, self.level, "remote proof evidence mixes different endpoint/payload/response/environment/oracle identities", evidence_refs=refs)

        expected = {
            "endpoint_id": identity[0],
            "payload_sha256": identity[1],
            "response_sha256": identity[2],
            "remote_environment_fingerprint": identity[3],
            "oracle_id": identity[4],
        }
        if candidate != expected:
            return VerificationResult(False, self.level, "candidate does not exactly bind the accepted remote exchange", evidence_refs=refs, details={"expected": expected})
        return VerificationResult(
            True,
            self.level,
            "operator-fixed endpoint returned the operator-fixed remote behavior for this exact payload and environment",
            evidence_refs=refs,
            details=expected,
            confidence=1.0,
        )
