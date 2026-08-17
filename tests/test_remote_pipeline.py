from __future__ import annotations

from harness.core.storage import ArtifactStore
from ctf_harness.verifiers.pwn.remote import RemoteBehaviorVerifier


def _receipt(*, accepted=True):
    return {
        "schema_version": 1,
        "kind": "pwn_remote_behavior_receipt",
        "proof_level": "P5_REMOTE",
        "endpoint_id": "1" * 64,
        "peer_ip": "127.0.0.1",
        "peer_port": 31337,
        "payload_sha256": "2" * 64,
        "response_sha256": "3" * 64,
        "response_bytes": 12,
        "response_complete": True,
        "remote_environment_fingerprint": "4" * 64,
        "oracle_id": "pwn_remote_tcp_response_digest:test",
        "independence_level": "operator_fixed_endpoint_and_response_digest",
        "accepted": accepted,
        "reason_hash": "5" * 64,
    }


def _context(store, ref, source="pwn_remote_proof_oracle"):
    return {
        "state": {
            "artifacts": [ref],
            "evidence_refs": [ref],
            "observations": [{"source": source, "ok": True, "artifact_ref": ref}],
        },
        "artifact_root": str(store.root),
        "claim_evidence_refs": [ref],
        "claim_key": "ctf.pwn.remote_behavior",
    }


def test_p5_remote_verifier_requires_exact_control_plane_receipt(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    receipt = _receipt()
    ref = store.put_json("remote.json", {"ok": True, "output": receipt, "error": None})
    candidate = {
        "endpoint_id": "1" * 64,
        "payload_sha256": "2" * 64,
        "response_sha256": "3" * 64,
        "remote_environment_fingerprint": "4" * 64,
        "oracle_id": "pwn_remote_tcp_response_digest:test",
    }
    verifier = RemoteBehaviorVerifier()
    assert verifier.verify(candidate, _context(store, ref)).verified
    assert not verifier.verify({**candidate, "payload_sha256": "6" * 64}, _context(store, ref)).verified
    assert not verifier.verify(candidate, _context(store, ref, source="actor_claim")).verified


def test_p5_rejected_or_incomplete_remote_receipt_fails_closed(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    rejected = _receipt(accepted=False)
    ref = store.put_json("rejected.json", {"ok": True, "output": rejected, "error": None})
    candidate = {
        "endpoint_id": "1" * 64,
        "payload_sha256": "2" * 64,
        "response_sha256": "3" * 64,
        "remote_environment_fingerprint": "4" * 64,
        "oracle_id": "pwn_remote_tcp_response_digest:test",
    }
    verifier = RemoteBehaviorVerifier()
    assert not verifier.verify(candidate, _context(store, ref)).verified

    incomplete = _receipt()
    incomplete["response_complete"] = False
    ref2 = store.put_json("incomplete.json", {"ok": True, "output": incomplete, "error": None})
    assert not verifier.verify(candidate, _context(store, ref2)).verified
