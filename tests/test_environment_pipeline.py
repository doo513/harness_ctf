from __future__ import annotations

import pytest

from harness.core.storage import ArtifactStore
from ctf_harness.proof.environment_diff import (
    BASELINE_PWN_COMPATIBILITY_FIELDS,
    TargetEnvironmentFingerprint,
    build_environment_compatibility_receipt,
    persist_environment_compatibility_receipt,
)
from ctf_harness.verifiers.pwn.environment import EnvironmentCompatibilityVerifier


def _env(*, nx=True, libc="a" * 64):
    return TargetEnvironmentFingerprint(
        architecture="x86_64",
        bits=64,
        endianness="little",
        pie=False,
        nx=nx,
        protocol="tcp",
        target_revision="rev1",
        libc_sha256=libc,
        loader_sha256="b" * 64,
    )


def _ctx(store, ref, source="pwn_environment_compare"):
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


def test_p4_compatible_receipt_requires_exact_trusted_contract(tmp_path):
    contract = (*BASELINE_PWN_COMPATIBILITY_FIELDS, "libc_sha256", "loader_sha256")
    receipt = build_environment_compatibility_receipt(
        _env(), _env(), local_source="local_probe", remote_source="operator_manifest", required_fields=contract
    )
    assert receipt.compatible and not receipt.differences
    store = ArtifactStore(tmp_path / "artifacts")
    ref = persist_environment_compatibility_receipt(store, receipt)
    candidate = {
        "local_fingerprint": receipt.local_fingerprint,
        "remote_fingerprint": receipt.remote_fingerprint,
        "contract_fields": list(receipt.contract_fields),
    }
    verifier = EnvironmentCompatibilityVerifier()
    assert verifier.verify(candidate, _ctx(store, ref)).verified
    assert not verifier.verify({**candidate, "remote_fingerprint": "0" * 64}, _ctx(store, ref)).verified
    assert not verifier.verify(candidate, _ctx(store, ref, source="actor_claim")).verified


def test_p4_mismatch_and_missing_fields_fail_closed(tmp_path):
    contract = (*BASELINE_PWN_COMPATIBILITY_FIELDS, "libc_sha256", "loader_sha256")
    mismatch = build_environment_compatibility_receipt(
        _env(), _env(libc="c" * 64), local_source="local_probe", remote_source="remote_probe", required_fields=contract
    )
    assert not mismatch.compatible
    assert any(item[0] == "libc_sha256" for item in mismatch.differences)

    incomplete = build_environment_compatibility_receipt(
        _env(nx=None), _env(), local_source="local_probe", remote_source="operator_manifest", required_fields=contract
    )
    assert not incomplete.compatible and "nx" in incomplete.missing_local

    store = ArtifactStore(tmp_path / "artifacts")
    ref = persist_environment_compatibility_receipt(store, mismatch)
    candidate = {
        "local_fingerprint": mismatch.local_fingerprint,
        "remote_fingerprint": mismatch.remote_fingerprint,
        "contract_fields": list(mismatch.contract_fields),
    }
    assert not EnvironmentCompatibilityVerifier().verify(candidate, _ctx(store, ref)).verified


def test_p4_contract_and_source_validation():
    with pytest.raises(ValueError, match="cannot omit baseline"):
        build_environment_compatibility_receipt(
            _env(), _env(), local_source="local_probe", remote_source="operator_manifest", required_fields=("architecture",)
        )
    with pytest.raises(ValueError, match="source is not trusted"):
        build_environment_compatibility_receipt(
            _env(), _env(), local_source="actor_claim", remote_source="operator_manifest"
        )
    with pytest.raises(ValueError):
        TargetEnvironmentFingerprint(
            architecture="x86_64", bits=128, endianness="little", pie=False, nx=True,
            protocol="tcp", target_revision="rev1"
        )
