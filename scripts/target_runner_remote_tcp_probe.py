from __future__ import annotations

import hashlib
import json
import socket
import threading

from ctf_harness.operational.models import NetworkPolicy, RemoteTargetSpec, RemoteTransport
from ctf_harness.target.remote import RemoteTcpRunner


REQUEST = b"TARGET_RUNNER_PING_513\n"
RESPONSE = b"TARGET_RUNNER_PONG_513\n"


def _serve(listener: socket.socket, errors: list[str]) -> None:
    try:
        conn, _addr = listener.accept()
        with conn:
            received = conn.recv(4096)
            if received != REQUEST:
                raise AssertionError(f"unexpected request: {received!r}")
            conn.sendall(RESPONSE)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        listener.close()


def main() -> int:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    errors: list[str] = []
    thread = threading.Thread(target=_serve, args=(listener, errors), daemon=True)
    thread.start()

    target = RemoteTargetSpec(
        endpoint=f"tcp://127.0.0.1:{port}",
        transport=RemoteTransport.TCP,
    )
    policy = NetworkPolicy(
        challenge_transport=True,
        general_internet=False,
        external_retrieval=False,
    )
    runner = RemoteTcpRunner(
        target,
        network_policy=policy,
        timeout_seconds=2.0,
        max_send_bytes=1024,
        max_read_bytes=1024,
    )
    assert runner.pinned_ips == ("127.0.0.1",)
    assert runner.describe()["general_internet"] is False
    assert runner.describe()["external_retrieval"] is False

    session = runner.open_session()
    session.send(REQUEST)
    response = session.read(1024)
    assert response == RESPONSE
    receipt = session.close()

    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert not errors, errors
    assert receipt.closed
    assert receipt.sent_sha256 == hashlib.sha256(REQUEST).hexdigest()
    assert receipt.received_sha256 == hashlib.sha256(RESPONSE).hexdigest()
    serialized_receipt = json.dumps(receipt.descriptor(), sort_keys=True)
    assert REQUEST.decode().strip() not in serialized_receipt
    assert RESPONSE.decode().strip() not in serialized_receipt

    blocked = False
    try:
        RemoteTcpRunner(
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

    print(
        json.dumps(
            {
                "probe": "ctf-target-runner-remote-tcp-controlled-v1",
                "all_passed": True,
                "endpoint_id": runner.endpoint_id,
                "pinned_ips": list(runner.pinned_ips),
                "peer_ip": receipt.peer_ip,
                "sent_sha256": receipt.sent_sha256,
                "received_sha256": receipt.received_sha256,
                "event_fingerprint": receipt.event_fingerprint,
                "challenge_transport": True,
                "general_internet": False,
                "external_retrieval": False,
                "plaintext_persisted": False,
                "blocked_policy_rejected": blocked,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
