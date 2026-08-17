from __future__ import annotations

import re
from typing import Any

from harness.core.verification import VerificationLevel, VerificationResult
from ctf_harness.proof.environment_diff import (
    BASELINE_PWN_COMPATIBILITY_FIELDS,
    TRUSTED_ENVIRONMENT_SOURCES,
)
from ctf_harness.verifiers.pwn.core import _registered_observation_artifacts

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EnvironmentCompatibilityVerifier:
    name = "pwn_environment_compatible"
    level = VerificationLevel.LOGICAL
    covers = ("ctf_semantic",)
    claim_key = "ctf.environment.compatible"

    def verify(self, candidate: Any, context: dict) -> VerificationResult:
        refs = list(context.get("claim_evidence_refs") or [])
        if context.get("claim_key") != self.claim_key:
            return VerificationResult(False, self.level, "verifier is not bound to this exact claim key", evidence_refs=refs)
        try:
            loaded = _registered_observation_artifacts(context, source="pwn_environment_compare")
            if not loaded:
                raise ValueError("environment compatibility receipt is unavailable")
            records = []
            for _, payload in loaded:
                record = payload.get("output")
                if not isinstance(record, dict):
                    raise ValueError("environment receipt output is not an object")
                if record.get("kind") != "pwn_environment_compatibility_receipt" or record.get("schema_version") != 1:
                    raise ValueError("environment receipt schema mismatch")
                if record.get("proof_level") != "P4_ENVIRONMENT":
                    raise ValueError("receipt is not a P4 environment proof")
                if record.get("compatible") is not True:
                    raise ValueError("environment contract is not compatible")
                if record.get("differences") not in ([], ()): 
                    raise ValueError("compatible receipt contains environment differences")
                if record.get("missing_local") not in ([], ()) or record.get("missing_remote") not in ([], ()):
                    raise ValueError("compatible receipt contains unknown required fields")
                if record.get("local_source") not in TRUSTED_ENVIRONMENT_SOURCES or record.get("remote_source") not in TRUSTED_ENVIRONMENT_SOURCES:
                    raise ValueError("environment source is not trusted")
                for field in ("local_fingerprint", "remote_fingerprint"):
                    value = record.get(field)
                    if not isinstance(value, str) or not _HEX64.fullmatch(value):
                        raise ValueError(f"invalid {field}")
                fields = record.get("contract_fields")
                if not isinstance(fields, list) or not fields or any(not isinstance(item, str) or not item for item in fields):
                    raise ValueError("environment contract_fields are invalid")
                if len(set(fields)) != len(fields):
                    raise ValueError("environment contract_fields contain duplicates")
                missing_baseline = set(BASELINE_PWN_COMPATIBILITY_FIELDS) - set(fields)
                if missing_baseline:
                    raise ValueError("environment receipt omits baseline Pwn fields")
                records.append(record)
        except Exception as exc:
            return VerificationResult(False, self.level, f"{type(exc).__name__}: {exc}", evidence_refs=refs)

        first = records[0]
        identity = (
            first["local_fingerprint"],
            first["remote_fingerprint"],
            tuple(first["contract_fields"]),
        )
        if any((record["local_fingerprint"], record["remote_fingerprint"], tuple(record["contract_fields"])) != identity for record in records[1:]):
            return VerificationResult(False, self.level, "environment evidence mixes different compatibility identities", evidence_refs=refs)
        expected = {
            "local_fingerprint": identity[0],
            "remote_fingerprint": identity[1],
            "contract_fields": list(identity[2]),
        }
        if candidate != expected:
            return VerificationResult(False, self.level, "candidate does not exactly bind the compatible local/remote environment contract", evidence_refs=refs, details={"expected": expected})
        return VerificationResult(
            True,
            self.level,
            "all baseline and declared target-environment fields are known and equal under trusted local/remote sources",
            evidence_refs=refs,
            details=expected,
            confidence=1.0,
        )
