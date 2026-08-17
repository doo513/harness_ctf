from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import threading
from pathlib import Path

from harness.core.storage import ArtifactStore
from ctf_harness.proof.ladder import proof_level_from_verified_keys
from ctf_harness.proof.models import ProofLevel
from ctf_harness.proof.remote_oracle import TCPRemoteBehaviorOracle, persist_remote_behavior_receipt
from ctf_harness.verifiers.pwn.remote import RemoteBehaviorVerifier

GOOD_PAYLOAD = b"REMOTE_PROBE_513\n"
GOOD_RESPONSE = b"REMOTE_PROOF_OK_513\n"
REMOTE_ENV = "3f90aea773eba2fdc4b10a5270224f59188ca6e2d758f4b52d5cfa3bee3149fe"


def _serve(listener: socket.socket, errors: list[str]) -> None:
    try:
        for _ in range(2):
            conn, _addr = listener.accept()
            with conn:
                chunks = []
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                payload = b"".join(chunks)
                conn.sendall(GOOD_RESPONSE if payload == GOOD_PAYLOAD else b"REMOTE_PROOF_REJECTED\n")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        listener.close()


def _ctx(store: ArtifactStore, ref: str, *, source: str = "pwn_remote_proof_oracle") -> dict:
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


def main() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    errors: list[str] = []
    thread = threading.Thread(target=_serve, args=(listener, errors), daemon=True)
    thread.start()

    expected = hashlib.sha256(GOOD_RESPONSE).hexdigest()
    oracle = TCPRemoteBehaviorOracle(
        host="127.0.0.1",
        port=port,
        expected_response_sha256=expected,
        endpoint_source="challenge_admission",
        timeout_seconds=2.0,
        max_payload_bytes=1024,
        max_response_bytes=1024,
    )
    assert oracle.pinned_ips == ("127.0.0.1",)

    accepted = oracle.evaluate(payload=GOOD_PAYLOAD, remote_environment_fingerprint=REMOTE_ENV)
    assert accepted.accepted
    assert accepted.response_complete
    assert accepted.response_sha256 == expected
    assert accepted.peer_ip == "127.0.0.1"
    serialized = json.dumps(accepted.dump(), sort_keys=True)
    assert GOOD_PAYLOAD.decode().strip() not in serialized
    assert GOOD_RESPONSE.decode().strip() not in serialized

    rejected = oracle.evaluate(payload=b"WRONG\n", remote_environment_fingerprint=REMOTE_ENV)
    assert not rejected.accepted
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert not errors, errors

    with tempfile.TemporaryDirectory(prefix="ctf-remote-proof-") as td:
        store = ArtifactStore(Path(td) / "artifacts")
        ref = persist_remote_behavior_receipt(store, accepted)
        candidate = {
            "endpoint_id": accepted.endpoint_id,
            "payload_sha256": accepted.payload_sha256,
            "response_sha256": accepted.response_sha256,
            "remote_environment_fingerprint": accepted.remote_environment_fingerprint,
            "oracle_id": accepted.oracle_id,
        }
        verifier = RemoteBehaviorVerifier()
        verified = verifier.verify(candidate, _ctx(store, ref))
        assert verified.verified, verified.reason
        assert not verifier.verify({**candidate, "endpoint_id": "0" * 64}, _ctx(store, ref)).verified
        assert not verifier.verify(candidate, _ctx(store, ref, source="actor_claim")).verified

        rejected_ref = persist_remote_behavior_receipt(store, rejected, name="rejected-remote.json")
        assert not verifier.verify(candidate, _ctx(store, rejected_ref)).verified

    full = {
        "ctf.pwn.arch",
        "ctf.pwn.crash_reproducible",
        "ctf.pwn.control_flow",
        "ctf.pwn.local_exploit",
        "ctf.environment.compatible",
        "ctf.pwn.remote_behavior",
    }
    assert proof_level_from_verified_keys(full) == ProofLevel.P5_REMOTE
    assert proof_level_from_verified_keys({"ctf.pwn.remote_behavior"}) is None

    try:
        TCPRemoteBehaviorOracle(
            host="127.0.0.1",
            port=port,
            expected_response_sha256=expected,
            endpoint_source="actor_input",
        )
    except ValueError:
        actor_endpoint_source_rejected = True
    else:
        actor_endpoint_source_rejected = False
    assert actor_endpoint_source_rejected

    print(json.dumps({
        "probe": "pwn-remote-behavior-controlled",
        "all_passed": True,
        "endpoint_id": accepted.endpoint_id,
        "pinned_ips": list(oracle.pinned_ips),
        "peer_ip": accepted.peer_ip,
        "peer_port": accepted.peer_port,
        "payload_sha256": accepted.payload_sha256,
        "response_sha256": accepted.response_sha256,
        "remote_environment_fingerprint": accepted.remote_environment_fingerprint,
        "oracle_id": accepted.oracle_id,
        "accepted": accepted.accepted,
        "wrong_payload_rejected": not rejected.accepted,
        "actor_source_rejected": True,
        "actor_endpoint_source_rejected": actor_endpoint_source_rejected,
        "candidate_mismatch_rejected": True,
        "plaintext_payload_persisted": False,
        "plaintext_response_persisted": False,
        "contiguous_p5_reached": True,
        "isolated_p5_blocked": True,
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
