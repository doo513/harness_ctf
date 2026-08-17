from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harness.core.storage import ArtifactStore
from ctf_harness.proof.environment_diff import (
    BASELINE_PWN_COMPATIBILITY_FIELDS,
    TargetEnvironmentFingerprint,
    build_environment_compatibility_receipt,
    persist_environment_compatibility_receipt,
)
from ctf_harness.proof.ladder import proof_level_from_verified_keys
from ctf_harness.proof.models import ProofLevel
from ctf_harness.verifiers.pwn.environment import EnvironmentCompatibilityVerifier

LIBC = "a" * 64
LOADER = "b" * 64
CONTRACT = (*BASELINE_PWN_COMPATIBILITY_FIELDS, "libc_sha256", "loader_sha256")


def env(*, libc: str | None = LIBC, nx: bool | None = True) -> TargetEnvironmentFingerprint:
    return TargetEnvironmentFingerprint(
        architecture="x86_64",
        bits=64,
        endianness="little",
        pie=False,
        nx=nx,
        protocol="tcp-line-v1",
        target_revision="challenge-rev-1",
        libc_sha256=libc,
        loader_sha256=LOADER,
        canary=False,
    )


def context_for(store: ArtifactStore, ref: str, *, source: str = "pwn_environment_compare") -> dict:
    return {
        "state": {
            "artifacts": [ref],
            "evidence_refs": [ref],
            "observations": [{"source": source, "ok": True, "artifact_ref": ref}],
        },
        "artifact_root": str(store.root),
        "claim_evidence_refs": [ref],
        "claim_key": "ctf.environment.compatible",
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-env-proof-") as td:
        store = ArtifactStore(Path(td) / "artifacts")
        local = env()
        remote = env()
        receipt = build_environment_compatibility_receipt(
            local,
            remote,
            local_source="local_probe",
            remote_source="operator_manifest",
            required_fields=CONTRACT,
        )
        assert receipt.compatible
        assert receipt.differences == () and receipt.missing_local == () and receipt.missing_remote == ()
        ref = persist_environment_compatibility_receipt(store, receipt)
        candidate = {
            "local_fingerprint": receipt.local_fingerprint,
            "remote_fingerprint": receipt.remote_fingerprint,
            "contract_fields": list(receipt.contract_fields),
        }
        verifier = EnvironmentCompatibilityVerifier()
        accepted = verifier.verify(candidate, context_for(store, ref))
        assert accepted.verified, accepted.reason

        mismatch = build_environment_compatibility_receipt(
            local,
            env(libc="c" * 64),
            local_source="local_probe",
            remote_source="remote_probe",
            required_fields=CONTRACT,
        )
        assert not mismatch.compatible
        assert any(item[0] == "libc_sha256" for item in mismatch.differences)
        mismatch_ref = persist_environment_compatibility_receipt(store, mismatch, name="mismatch.json")
        assert not verifier.verify(candidate, context_for(store, mismatch_ref)).verified

        incomplete = build_environment_compatibility_receipt(
            env(nx=None),
            remote,
            local_source="local_probe",
            remote_source="operator_manifest",
            required_fields=CONTRACT,
        )
        assert not incomplete.compatible and "nx" in incomplete.missing_local
        incomplete_ref = persist_environment_compatibility_receipt(store, incomplete, name="incomplete.json")
        assert not verifier.verify(candidate, context_for(store, incomplete_ref)).verified

        assert not verifier.verify(candidate, context_for(store, ref, source="actor_claim")).verified
        try:
            build_environment_compatibility_receipt(
                local,
                remote,
                local_source="actor_claim",
                remote_source="operator_manifest",
                required_fields=CONTRACT,
            )
        except ValueError:
            untrusted_source_rejected = True
        else:
            untrusted_source_rejected = False
        assert untrusted_source_rejected

        try:
            build_environment_compatibility_receipt(
                local,
                remote,
                local_source="local_probe",
                remote_source="operator_manifest",
                required_fields=("architecture",),
            )
        except ValueError:
            baseline_omission_rejected = True
        else:
            baseline_omission_rejected = False
        assert baseline_omission_rejected

        assert proof_level_from_verified_keys({
            "ctf.pwn.arch",
            "ctf.pwn.crash_reproducible",
            "ctf.pwn.control_flow",
            "ctf.pwn.local_exploit",
            "ctf.environment.compatible",
        }) == ProofLevel.P4_ENVIRONMENT

        print(json.dumps({
            "probe": "pwn-environment-compatibility-controlled",
            "all_passed": True,
            "compatible": receipt.compatible,
            "contract_fields": list(receipt.contract_fields),
            "local_fingerprint": receipt.local_fingerprint,
            "remote_fingerprint": receipt.remote_fingerprint,
            "mismatch_rejected": True,
            "missing_field_rejected": True,
            "actor_source_rejected": True,
            "untrusted_source_rejected": untrusted_source_rejected,
            "baseline_omission_rejected": baseline_omission_rejected,
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
