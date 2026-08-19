from __future__ import annotations

import hashlib
import json
import socket
import threading
import time

import pytest

from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    CredentialKind,
    CredentialRef,
    NetworkPolicy,
    OperationalChallengeRef,
    RemoteTargetSpec,
    RemoteTransport,
)
from ctf_harness.target.remote import RemoteTcpRunner


REQUEST = b"PING\n"
RESPONSE = b"PONG\n"
ARTIFACT_SHA = "a" * 64
RUNNER_DIGEST = "sha256:" + "f" * 64


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


def _serve_delayed(listener: socket.socket, errors: list[str]) -> None:
    try:
        conn, _addr = listener.accept()
        with conn:
            received = conn.recv(4096)
            if received != REQUEST:
                errors.append(f"unexpected request: {received!r}")
            conn.sendall(b"BANNER")
            time.sleep(0.05)
            conn.sendall(b"\nPROMPT> ")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        listener.close()


def _serve_overread(listener: socket.socket, errors: list[str]) -> None:
    try:
        conn, _addr = listener.accept()
        with conn:
            received = conn.recv(4096)
            if received != REQUEST:
                errors.append(f"unexpected request: {received!r}")
            conn.sendall(b"PROMPT> NEXT")
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


def _challenge(endpoint: str, *, allowed_network: bool = True) -> OperationalChallengeRef:
    manifest = ChallengeManifest(
        challenge_id="remote-runner-fixture",
        event="controlled",
        description="WP11 remote target runner fixture",
        artifact_refs=("chal",),
        remote_endpoints=(endpoint,),
        category_hint="pwn",
        flag_format="flag{...}",
        allowed_network=allowed_network,
        allowed_tools=("remote_tcp",),
        runner_image_digest=RUNNER_DIGEST,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    return OperationalChallengeRef.from_manifest(manifest, {"chal": ARTIFACT_SHA})


def _runner_for(listener: socket.socket, port: int, **kwargs) -> RemoteTcpRunner:
    endpoint = f"tcp://127.0.0.1:{port}"
    return RemoteTcpRunner(
        _challenge(endpoint),
        RemoteTargetSpec(endpoint=endpoint, transport=RemoteTransport.TCP),
        network_policy=_network(),
        **kwargs,
    )


def test_remote_tcp_runner_pins_endpoint_and_hashes_transcript_without_plaintext() -> None:
    listener, port = _listener()
    errors: list[str] = []
    thread = threading.Thread(target=_serve_once, args=(listener, errors), daemon=True)
    thread.start()

    endpoint = f"tcp://127.0.0.1:{port}"
    challenge = _challenge(endpoint)
    target = RemoteTargetSpec(endpoint=endpoint, transport=RemoteTransport.TCP)
    runner = RemoteTcpRunner(challenge, target, network_policy=_network())
    assert runner.pinned_ips == ("127.0.0.1",)
    assert runner.describe()["challenge_transport"] is True
    assert runner.describe()["general_internet"] is False
    assert runner.describe()["challenge_manifest_fingerprint"] == challenge.manifest_fingerprint

    session = runner.open_session()
    assert session.send(REQUEST) == len(REQUEST)
    assert session.read(1024) == RESPONSE
    receipt = session.close()

    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert errors == []
    assert receipt.closed
    assert receipt.peer_ip == "127.0.0.1"
    assert receipt.challenge_manifest_fingerprint == challenge.manifest_fingerprint
    assert receipt.sent_bytes == len(REQUEST)
    assert receipt.received_bytes == len(RESPONSE)
    assert receipt.sent_sha256 == hashlib.sha256(REQUEST).hexdigest()
    assert receipt.received_sha256 == hashlib.sha256(RESPONSE).hexdigest()
    serialized = json.dumps(receipt.descriptor(), sort_keys=True)
    assert REQUEST.decode().strip() not in serialized
    assert RESPONSE.decode().strip() not in serialized


def test_remote_tcp_session_accumulates_delayed_response_in_bounded_window() -> None:
    listener, port = _listener()
    errors: list[str] = []
    thread = threading.Thread(target=_serve_delayed, args=(listener, errors), daemon=True)
    thread.start()
    runner = _runner_for(listener, port, timeout_seconds=1.0)
    session = runner.open_session()
    session.send(REQUEST)
    observed = session.read(wait_seconds=0.30, idle_grace_seconds=0.10)
    receipt = session.close()
    thread.join(timeout=2.0)
    assert errors == []
    assert observed == b"BANNER\nPROMPT> "
    assert receipt.received_bytes == len(observed)
    assert receipt.received_sha256 == hashlib.sha256(observed).hexdigest()


def test_remote_tcp_session_read_until_preserves_overread_without_double_hashing() -> None:
    listener, port = _listener()
    errors: list[str] = []
    thread = threading.Thread(target=_serve_overread, args=(listener, errors), daemon=True)
    thread.start()
    runner = _runner_for(listener, port, timeout_seconds=1.0)
    session = runner.open_session()
    session.send(REQUEST)
    first = session.read_until(b"> ", wait_seconds=0.5)
    assert first == b"PROMPT> "
    assert session.pending_bytes == len(b"NEXT")
    second = session.read(4)
    assert second == b"NEXT"
    assert session.pending_bytes == 0
    receipt = session.close()
    thread.join(timeout=2.0)
    network_bytes = b"PROMPT> NEXT"
    assert errors == []
    assert receipt.received_bytes == len(network_bytes)
    assert receipt.received_sha256 == hashlib.sha256(network_bytes).hexdigest()


def test_remote_tcp_session_read_until_timeout_preserves_partial_bytes() -> None:
    listener, port = _listener()
    errors: list[str] = []
    thread = threading.Thread(target=_serve_once, args=(listener, errors), daemon=True)
    thread.start()
    runner = _runner_for(listener, port, timeout_seconds=1.0)
    session = runner.open_session()
    session.send(REQUEST)
    with pytest.raises((EOFError, TimeoutError)):
        session.read_until(b"NEVER", wait_seconds=0.3)
    assert session.pending_bytes == len(RESPONSE)
    assert session.read(len(RESPONSE)) == RESPONSE
    session.close()
    thread.join(timeout=2.0)
    assert errors == []


def test_remote_tcp_runner_requires_admission_and_network_authority() -> None:
    endpoint = "tcp://127.0.0.1:31337"
    target = RemoteTargetSpec(endpoint=endpoint, transport=RemoteTransport.TCP)
    with pytest.raises(ValueError, match="not admitted"):
        RemoteTcpRunner(_challenge("tcp://127.0.0.1:31338"), target, network_policy=_network())
    with pytest.raises(ValueError, match="does not allow network"):
        RemoteTcpRunner(_challenge(endpoint, allowed_network=False), target, network_policy=_network())
    with pytest.raises(ValueError, match="blocks challenge transport"):
        RemoteTcpRunner(_challenge(endpoint), target, network_policy=_network(challenge_transport=False))


def test_remote_tcp_runner_never_receives_credential_bearing_endpoint() -> None:
    with pytest.raises(ValueError, match="embedded credentials"):
        RemoteTargetSpec(
            endpoint="tcp://user:secret@127.0.0.1:31337",
            transport=RemoteTransport.TCP,
        )


def test_remote_tcp_runner_descriptor_exposes_only_credential_presence() -> None:
    endpoint = "tcp://127.0.0.1:31337"
    target = RemoteTargetSpec(
        endpoint=endpoint,
        transport=RemoteTransport.TCP,
        credential_ref=CredentialRef(CredentialKind.SESSION, "private-session-key"),
    )
    runner = RemoteTcpRunner(_challenge(endpoint), target, network_policy=_network())
    serialized = json.dumps(runner.describe(), sort_keys=True)
    assert runner.describe()["credential_ref_present"] is True
    assert "private-session-key" not in serialized


def test_remote_tcp_session_limits_and_closed_state_fail_closed() -> None:
    listener, port = _listener()
    errors: list[str] = []
    thread = threading.Thread(target=_serve_once, args=(listener, errors), daemon=True)
    thread.start()
    runner = _runner_for(
        listener,
        port,
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
