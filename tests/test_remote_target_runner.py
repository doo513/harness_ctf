from __future__ import annotations

import hashlib
import json
import socket
import threading

import pytest

from ctf_harness.operational.models import (
    CredentialKind,
    CredentialRef,
    NetworkPolicy,
    RemoteTargetSpec,
    RemoteTransport,
)
from ctf_harness.target.remote import RemoteTcpRunner


REQUEST = b"PING\n"
RESPONSE = b"PONG\n"


def _serve_once(listener: socket.socket, errors: list[str]) -> None:
    try:
        conn, _addr = listener.accept()
        with conn:
            received = conn.recv(4096)
            if received != REQUEST:
                errors.append(f"unexpected request: {received!r}")
            conn.sendall(RESPONSE)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        listener.close()


def _listener() -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    return listener, listener.getsockname()[1]


def _network(*, challenge_transport: bool = True) -> NetworkPolicy:
    return NetworkPolicy(
        challenge_transport=challenge_transport,
        general_internet=False,
        external_retrieval=False,
    )


def test_remote_tcp_runner_pins_endpoint_and_hashes_transcript_without_plaintext() -> None:
    listener, port = _listener()
    errors: list[str] = []
    thread = threading.Thread(target=_serve_once, args=(listener, errors), daemon=True)
    thread.start()

    target = RemoteTargetSpec(
        endpoint=f"tcp://127.0.0.1:{port}",
        transport=RemoteTransport.TCP,
    )
    runner = RemoteTcpRunner(target, network_policy=_network())

    assert runner.pinned_ips == ("127.0.0.1",)
    assert runner.describe()["challenge_transport"] is True
    assert runner.describe()["general_internet"] is False

    session = runner.open_session()
    assert session.send(REQUEST) == len(REQUEST)
    assert session.read(1024) == RESPONSE
    receipt = session.close()

    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert errors == []
    assert receipt.closed
    assert receipt.peer_ip == "127.0.0.1"
    assert receipt.sent_bytes == len(REQUEST)
    assert receipt.received_bytes == len(RESPONSE)
    assert receipt.sent_sha256 == hashlib.sha256(REQUEST).hexdigest()
    assert receipt.received_sha256 == hashlib.sha256(RESPONSE).hexdigest()
    serialized = json.dumps(receipt.descriptor(), sort_keys=True)
    assert REQUEST.decode().strip() not in serialized
    assert RESPONSE.decode().strip() not in serialized


def test_remote_tcp_runner_requires_explicit_challenge_transport_policy() -> None:
    target = RemoteTargetSpec(
        endpoint="tcp://127.0.0.1:31337",
        transport=RemoteTransport.TCP,
    )
    with pytest.raises(ValueError, match="blocks challenge transport"):
        RemoteTcpRunner(target, network_policy=_network(challenge_transport=False))


def test_remote_tcp_runner_rejects_credentials_embedded_in_endpoint() -> None:
    target = RemoteTargetSpec(
        endpoint="tcp://user:secret@127.0.0.1:31337",
        transport=RemoteTransport.TCP,
    )
    with pytest.raises(ValueError, match="must not contain credentials"):
        RemoteTcpRunner(target, network_policy=_network())


def test_remote_tcp_runner_descriptor_exposes_only_credential_presence() -> None:
    target = RemoteTargetSpec(
        endpoint="tcp://127.0.0.1:31337",
        transport=RemoteTransport.TCP,
        credential_ref=CredentialRef(CredentialKind.SESSION, "private-session-key"),
    )
    runner = RemoteTcpRunner(target, network_policy=_network())
    serialized = json.dumps(runner.describe(), sort_keys=True)

    assert runner.describe()["credential_ref_present"] is True
    assert "private-session-key" not in serialized


def test_remote_tcp_session_limits_and_closed_state_fail_closed() -> None:
    listener, port = _listener()
    errors: list[str] = []
    thread = threading.Thread(target=_serve_once, args=(listener, errors), daemon=True)
    thread.start()

    runner = RemoteTcpRunner(
        RemoteTargetSpec(f"tcp://127.0.0.1:{port}", RemoteTransport.TCP),
        network_policy=_network(),
        max_send_bytes=len(REQUEST),
        max_read_bytes=len(RESPONSE),
    )
    session = runner.open_session()

    with pytest.raises(ValueError, match="send exceeds"):
        session.send(REQUEST + b"x")
    session.send(REQUEST)
    with pytest.raises(ValueError, match="read exceeds"):
        session.read(len(RESPONSE) + 1)
    assert session.read() == RESPONSE
    session.close()
    with pytest.raises(RuntimeError, match="closed"):
        session.send(b"x")

    thread.join(timeout=2.0)
    assert errors == []
