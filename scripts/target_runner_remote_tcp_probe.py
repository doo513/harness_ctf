from __future__ import annotations

import hashlib
import json
import socket
import threading
import time

from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    NetworkPolicy,
    OperationalChallengeRef,
    RemoteTargetSpec,
    RemoteTransport,
)
from ctf_harness.target.remote import RemoteTcpRunner

REQUEST = b"TARGET_RUNNER_PING_513\n"
RESPONSE = b"TARGET_RUNNER_PONG_513\n"
TAIL = b"TAIL"
ARTIFACT_SHA = "a" * 64
RUNNER_DIGEST = "sha256:" + "f" * 64


def _serve(listener: socket.socket, errors: list[str]) -> None:
    try:
        conn, _addr = listener.accept()
        with conn:
            received = conn.recv(4096)
            if received != REQUEST:
                raise AssertionError(f"unexpected request: {received!r}")
            conn.sendall(b"TARGET_RUNNER_")
            time.sleep(0.05)
            conn.sendall(b"PONG_513\n" + TAIL)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        listener.close()


def _challenge(endpoint: str) -> OperationalChallengeRef:
    manifest = ChallengeManifest(
        challenge_id="controlled-remote-runner",
        event="controlled",
        description="WP11 remote transport probe",
        artifact_refs=("chal",),
        remote_endpoints=(endpoint,),
        category_hint="pwn",
        flag_format="flag{...}",
        allowed_network=True,
        allowed_tools=("remote_tcp",),
        runner_image_digest=RUNNER_DIGEST,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    return OperationalChallengeRef.from_manifest(manifest, {"chal": ARTIFACT_SHA})


def main() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    errors: list[str] = []
    thread = threading.Thread(target=_serve, args=(listener, errors), daemon=True)
    thread.start()

    endpoint = f"tcp://127.0.0.1:{port}"
    challenge = _challenge(endpoint)
    target = RemoteTargetSpec(endpoint=endpoint, transport=RemoteTransport.TCP)
    policy = NetworkPolicy(challenge_transport=True, general_internet=False, external_retrieval=False)
    runner = RemoteTcpRunner(
        challenge,
        target,
        network_policy=policy,
        timeout_seconds=2.0,
        max_send_bytes=1024,
        max_read_bytes=1024,
    )
    assert runner.pinned_ips == ("127.0.0.1",)
    assert runner.describe()["general_internet"] is False
    assert runner.describe()["external_retrieval"] is False
    assert runner.describe()["challenge_manifest_fingerprint"] == challenge.manifest_fingerprint

    session = runner.open_session()
    session.send(REQUEST)
    response = session.read_until(b"\n", wait_seconds=0.5)
    assert response == RESPONSE
    assert session.pending_bytes == len(TAIL)
    assert session.read_exact(len(TAIL), wait_seconds=0.2) == TAIL
    assert session.pending_bytes == 0
    receipt = session.close()

    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert not errors, errors
    network_response = RESPONSE + TAIL
    assert receipt.closed
    assert receipt.challenge_manifest_fingerprint == challenge.manifest_fingerprint
    assert receipt.sent_sha256 == hashlib.sha256(REQUEST).hexdigest()
    assert receipt.received_sha256 == hashlib.sha256(network_response).hexdigest()
    assert receipt.received_bytes == len(network_response)
    serialized_receipt = json.dumps(receipt.descriptor(), sort_keys=True)
    assert REQUEST.decode().strip() not in serialized_receipt
    assert RESPONSE.decode().strip() not in serialized_receipt
    assert TAIL.decode() not in serialized_receipt

    blocked = False
    try:
        RemoteTcpRunner(
            challenge,
            target,
            network_policy=NetworkPolicy(
                challenge_transport=False,
                general_internet=False,
                external_retrieval=False,
            ),
        )
    except ValueError:
        blocked = True
    assert blocked

    unadmitted = False
    try:
        RemoteTcpRunner(_challenge("tcp://127.0.0.1:1"), target, network_policy=policy)
    except ValueError:
        unadmitted = True
    assert unadmitted

    print(json.dumps({
        "probe": "ctf-target-runner-remote-tcp-controlled-v3",
        "all_passed": True,
        "challenge_manifest_fingerprint": challenge.manifest_fingerprint,
        "endpoint_id": runner.endpoint_id,
        "pinned_ips": list(runner.pinned_ips),
        "peer_ip": receipt.peer_ip,
        "sent_sha256": receipt.sent_sha256,
        "received_sha256": receipt.received_sha256,
        "event_fingerprint": receipt.event_fingerprint,
        "challenge_transport": True,
        "general_internet": False,
        "external_retrieval": False,
        "delayed_response_accumulated": True,
        "delimiter_overread_preserved": True,
        "plaintext_persisted": False,
        "blocked_policy_rejected": blocked,
        "unadmitted_endpoint_rejected": unadmitted,
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
