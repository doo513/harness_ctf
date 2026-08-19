from __future__ import annotations

from harness.core.storage import ArtifactStore
from ctf_harness.proof.ladder import proof_level_from_verified_keys
from ctf_harness.proof.models import ProofLevel
from ctf_harness.verifiers.pwn.local import LocalExploitVerifier


def test_wp05_proof_ladder_is_contiguous_but_external_acceptance_is_final():
    assert proof_level_from_verified_keys({"ctf.pwn.remote_behavior"}) is None
    assert proof_level_from_verified_keys({"ctf.pwn.arch"}) == ProofLevel.P0_SURFACE
    assert proof_level_from_verified_keys({
        "ctf.pwn.arch",
        "ctf.pwn.crash_reproducible",
        "ctf.pwn.control_flow",
        "ctf.pwn.local_exploit",
    }) == ProofLevel.P3_LOCAL
    assert proof_level_from_verified_keys(set(), completed=True) == ProofLevel.P6_ACCEPTED


def test_wp04_local_exploit_verifier_requires_control_plane_accepted_receipt(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    output = {
        "schema_version": 1,
        "kind": "pwn_local_proof_receipt",
        "proof_level": "P3_LOCAL",
        "target_sha256": "1" * 64,
        "exploit_sha256": "2" * 64,
        "environment_fingerprint": "3" * 64,
        "oracle_id": "local:test",
        "independence_level": "operator_fixed_digest_and_filesystem_isolation",
        "oracle_evidence_hash": "4" * 64,
        "accepted": True,
        "reason_hash": "5" * 64,
    }
    ref = store.put_json("local.json", {"ok": True, "output": output, "error": None})
    context = {
        "state": {
            "artifacts": [ref],
            "evidence_refs": [ref],
            "observations": [{"source": "pwn_local_proof_oracle", "ok": True, "artifact_ref": ref}],
        },
        "artifact_root": str(store.root),
        "claim_evidence_refs": [ref],
        "claim_key": "ctf.pwn.local_exploit",
    }
    candidate = {
        "target_sha256": "1" * 64,
        "exploit_sha256": "2" * 64,
        "environment_fingerprint": "3" * 64,
        "oracle_id": "local:test",
    }
    verifier = LocalExploitVerifier()
    assert verifier.verify(candidate, context).verified

    actor_context = dict(context)
    actor_context["state"] = {
        "artifacts": [ref],
        "evidence_refs": [ref],
        "observations": [{"source": "actor_claim", "ok": True, "artifact_ref": ref}],
    }
    assert not verifier.verify(candidate, actor_context).verified

    rejected = dict(output)
    rejected["accepted"] = False
    rejected_ref = store.put_json("rejected.json", {"ok": True, "output": rejected, "error": None})
    rejected_context = {
        "state": {
            "artifacts": [rejected_ref],
            "evidence_refs": [rejected_ref],
            "observations": [{"source": "pwn_local_proof_oracle", "ok": True, "artifact_ref": rejected_ref}],
        },
        "artifact_root": str(store.root),
        "claim_evidence_refs": [rejected_ref],
        "claim_key": "ctf.pwn.local_exploit",
    }
    assert not verifier.verify(candidate, rejected_context).verified
