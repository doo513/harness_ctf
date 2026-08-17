from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import math
import select
import socket
import time
from typing import Any
from urllib.parse import urlsplit

from harness.core.storage import canonical_hash

from ctf_harness.operational.models import (
    NetworkPolicy,
    OperationalChallengeRef,
    RemoteTargetSpec,
    RemoteTransport,
)


def _normalized_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


def _parse_tcp_endpoint(endpoint: str) -> tuple[str, int]:
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise ValueError("remote endpoint must be a non-empty string")
    parsed = urlsplit(endpoint.strip())
    if parsed.scheme != "tcp":
        raise ValueError("RemoteTcpRunner requires a tcp:// endpoint")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("remote endpoint must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("remote TCP endpoint must not contain path/query/fragment")
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("remote TCP endpoint port is invalid") from exc
    if not host:
        raise ValueError("remote TCP endpoint host is missing")
    if port is None or not (1 <= port <= 65535):
        raise ValueError("remote TCP endpoint port must be in 1..65535")
    return host, port


@dataclass(frozen=True)
class RemoteTranscriptReceipt:
    schema_version: int
    kind: str
    endpoint_id: str
    challenge_manifest_fingerprint: str
    peer_ip: str
    peer_port: int
    opened: bool
    closed: bool
    sent_bytes: int
    received_bytes: int
    sent_sha256: str
    received_sha256: str
    event_fingerprint: str

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "endpoint_id": self.endpoint_id,
            "challenge_manifest_fingerprint": self.challenge_manifest_fingerprint,
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port,
            "opened": self.opened,
            "closed": self.closed,
            "sent_bytes": self.sent_bytes,
            "received_bytes": self.received_bytes,
            "sent_sha256": self.sent_sha256,
            "received_sha256": self.received_sha256,
            "event_fingerprint": self.event_fingerprint,
        }


class RemoteTcpSession:
    """Bounded persistent TCP session for one admitted challenge endpoint.

    Network bytes are hashed exactly once when received from the socket. Logical
    reads may consume from an internal pending buffer, allowing delimiter/exact
    reads to preserve over-read bytes without corrupting transcript provenance.
    """

    def __init__(
        self,
        *,
        sock: socket.socket,
        endpoint_id: str,
        challenge_manifest_fingerprint: str,
        peer_ip: str,
        peer_port: int,
        timeout_seconds: float,
        max_send_bytes: int,
        max_read_bytes: int,
    ):
        self._sock = sock
        self.endpoint_id = endpoint_id
        self.challenge_manifest_fingerprint = challenge_manifest_fingerprint
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.timeout_seconds = timeout_seconds
        self.max_send_bytes = max_send_bytes
        self.max_read_bytes = max_read_bytes
        self._closed = False
        self._sent = hashlib.sha256()
        self._received = hashlib.sha256()
        self._sent_bytes = 0
        self._received_bytes = 0
        self._pending = bytearray()
        self._events: list[dict[str, Any]] = [
            {"event": "open", "peer_ip": peer_ip, "peer_port": peer_port}
        ]

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def pending_bytes(self) -> int:
        return len(self._pending)

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("remote TCP session is closed")

    def _read_limit(self, value: int | None) -> int:
        limit = self.max_read_bytes if value is None else value
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("remote TCP read limit must be a positive integer")
        if limit > self.max_read_bytes:
            raise ValueError("remote TCP read exceeds configured per-action maximum")
        return limit

    def _wait_value(self, value: float | None, *, field_name: str, allow_zero: bool) -> float:
        resolved = self.timeout_seconds if value is None else value
        if (
            not isinstance(resolved, (int, float))
            or isinstance(resolved, bool)
            or not math.isfinite(float(resolved))
            or (float(resolved) < 0 if allow_zero else float(resolved) <= 0)
        ):
            relation = "non-negative" if allow_zero else "positive"
            raise ValueError(f"{field_name} must be finite and {relation}")
        return float(resolved)

    def _record_network_read(self, data: bytes) -> None:
        digest = hashlib.sha256(data).hexdigest()
        self._received.update(data)
        self._received_bytes += len(data)
        self._events.append({"event": "read", "bytes": len(data), "sha256": digest})

    def _recv_network(self, limit: int) -> bytes:
        data = self._sock.recv(limit)
        self._record_network_read(data)
        return data

    def _socket_ready(self, wait_seconds: float) -> bool:
        ready, _, _ = select.select([self._sock], [], [], max(0.0, wait_seconds))
        return bool(ready)

    def _take_pending(self, count: int) -> bytes:
        count = min(count, len(self._pending))
        data = bytes(self._pending[:count])
        del self._pending[:count]
        return data

    def send(self, data: bytes) -> int:
        self._ensure_open()
        if not isinstance(data, bytes):
            raise TypeError("remote TCP send data must be bytes")
        if len(data) > self.max_send_bytes:
            raise ValueError("remote TCP send exceeds configured per-action maximum")
        self._sock.sendall(data)
        digest = hashlib.sha256(data).hexdigest()
        self._sent.update(data)
        self._sent_bytes += len(data)
        self._events.append({"event": "send", "bytes": len(data), "sha256": digest})
        return len(data)

    def read(
        self,
        max_bytes: int | None = None,
        *,
        wait_seconds: float = 0.0,
        idle_grace_seconds: float = 0.05,
    ) -> bytes:
        """Read bytes, optionally accumulating delayed chunks in a bounded window.

        With the default ``wait_seconds=0`` this preserves the historical
        single-recv behavior (after consuming any pending bytes). A positive
        wait observes until the overall deadline, stopping after an idle grace
        period once at least one byte has been obtained.
        """

        self._ensure_open()
        limit = self._read_limit(max_bytes)
        wait = self._wait_value(wait_seconds, field_name="wait_seconds", allow_zero=True)
        idle = self._wait_value(
            idle_grace_seconds, field_name="idle_grace_seconds", allow_zero=True
        )
        output = bytearray(self._take_pending(limit))
        if len(output) >= limit:
            return bytes(output)

        if wait == 0:
            if output:
                return bytes(output)
            return self._recv_network(limit)

        overall_deadline = time.monotonic() + wait
        got_any = bool(output)
        idle_deadline = min(overall_deadline, time.monotonic() + idle) if got_any else None
        while len(output) < limit:
            now = time.monotonic()
            deadline = idle_deadline if idle_deadline is not None else overall_deadline
            remaining_wait = deadline - now
            if remaining_wait <= 0 or not self._socket_ready(remaining_wait):
                break
            data = self._recv_network(limit - len(output))
            if not data:
                break
            output.extend(data)
            got_any = True
            idle_deadline = min(overall_deadline, time.monotonic() + idle)
        return bytes(output)

    def read_until(
        self,
        delimiter: bytes,
        *,
        max_bytes: int | None = None,
        wait_seconds: float | None = None,
    ) -> bytes:
        """Return through ``delimiter`` while preserving any over-read tail."""

        self._ensure_open()
        if not isinstance(delimiter, bytes) or not delimiter:
            raise ValueError("remote TCP delimiter must be non-empty bytes")
        limit = self._read_limit(max_bytes)
        wait = self._wait_value(wait_seconds, field_name="wait_seconds", allow_zero=False)
        deadline = time.monotonic() + wait
        while True:
            index = self._pending.find(delimiter)
            if index >= 0:
                end = index + len(delimiter)
                if end > limit:
                    raise ValueError("remote TCP delimiter exceeds configured read limit")
                return self._take_pending(end)
            if len(self._pending) >= limit:
                raise ValueError("remote TCP delimiter not found within configured read limit")
            remaining_wait = deadline - time.monotonic()
            if remaining_wait <= 0 or not self._socket_ready(remaining_wait):
                raise TimeoutError("remote TCP delimiter was not observed before deadline")
            data = self._recv_network(limit - len(self._pending))
            if not data:
                raise EOFError("remote TCP peer closed before delimiter was observed")
            self._pending.extend(data)

    def read_exact(self, byte_count: int, *, wait_seconds: float | None = None) -> bytes:
        """Read exactly ``byte_count`` bytes or fail without discarding partial data."""

        self._ensure_open()
        limit = self._read_limit(byte_count)
        wait = self._wait_value(wait_seconds, field_name="wait_seconds", allow_zero=False)
        deadline = time.monotonic() + wait
        while len(self._pending) < limit:
            remaining_wait = deadline - time.monotonic()
            if remaining_wait <= 0 or not self._socket_ready(remaining_wait):
                raise TimeoutError("remote TCP exact read did not complete before deadline")
            data = self._recv_network(limit - len(self._pending))
            if not data:
                raise EOFError("remote TCP peer closed before exact read completed")
            self._pending.extend(data)
        return self._take_pending(limit)

    def bounded_drain(
        self,
        *,
        wait_seconds: float,
        max_bytes: int | None = None,
        idle_grace_seconds: float = 0.05,
    ) -> bytes:
        """Accumulate currently arriving response bytes within a strict bound."""

        wait = self._wait_value(wait_seconds, field_name="wait_seconds", allow_zero=False)
        return self.read(
            max_bytes,
            wait_seconds=wait,
            idle_grace_seconds=idle_grace_seconds,
        )

    def interrupt(self) -> None:
        self._ensure_open()
        try:
            self._sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self._events.append({"event": "interrupt"})

    def close(self) -> RemoteTranscriptReceipt:
        if not self._closed:
            try:
                self._sock.close()
            finally:
                self._closed = True
                self._events.append({"event": "close"})
        return self.receipt()

    def receipt(self) -> RemoteTranscriptReceipt:
        return RemoteTranscriptReceipt(
            schema_version=1,
            kind="ctf_remote_tcp_transcript",
            endpoint_id=self.endpoint_id,
            challenge_manifest_fingerprint=self.challenge_manifest_fingerprint,
            peer_ip=self.peer_ip,
            peer_port=self.peer_port,
            opened=True,
            closed=self._closed,
            sent_bytes=self._sent_bytes,
            received_bytes=self._received_bytes,
            sent_sha256=self._sent.copy().hexdigest(),
            received_sha256=self._received.copy().hexdigest(),
            event_fingerprint=canonical_hash({"events": list(self._events)}),
        )

    def __enter__(self) -> "RemoteTcpSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class RemoteTcpRunner:
    """Operational challenge transport restricted to one admitted TCP endpoint.

    This is transport, not a P5 truth oracle. It returns response bytes to the
    solve runtime while receipts persist only hashes/counts. The target must be
    bound to an `OperationalChallengeRef`, DNS is resolved at construction, and
    later connections use only the pinned numeric addresses.
    """

    def __init__(
        self,
        challenge: OperationalChallengeRef,
        target: RemoteTargetSpec,
        *,
        network_policy: NetworkPolicy,
        timeout_seconds: float = 3.0,
        max_send_bytes: int = 65536,
        max_read_bytes: int = 65536,
    ):
        if not isinstance(challenge, OperationalChallengeRef):
            raise ValueError("challenge must be OperationalChallengeRef")
        if not isinstance(target, RemoteTargetSpec):
            raise ValueError("target must be RemoteTargetSpec")
        if target.transport is not RemoteTransport.TCP:
            raise ValueError("RemoteTcpRunner requires TCP transport")
        if target.endpoint not in challenge.remote_endpoints:
            raise ValueError("remote endpoint is not admitted by challenge manifest")
        if not challenge.allowed_network:
            raise ValueError("challenge manifest does not allow network target access")
        if not isinstance(network_policy, NetworkPolicy):
            raise ValueError("network_policy must be NetworkPolicy")
        if not network_policy.challenge_transport:
            raise ValueError("solve network policy blocks challenge transport")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        for field_name, value in (
            ("max_send_bytes", max_send_bytes),
            ("max_read_bytes", max_read_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")

        host, port = _parse_tcp_endpoint(target.endpoint)
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses: list[tuple[int, str]] = []
        for family, socktype, _proto, _canonname, sockaddr in infos:
            if socktype != socket.SOCK_STREAM or family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            item = (family, _normalized_ip(sockaddr[0]))
            if item not in addresses:
                addresses.append(item)
        if not addresses:
            raise ValueError("remote endpoint resolved to no TCP IPv4/IPv6 address")

        self.challenge = challenge
        self.target = target
        self.network_policy = network_policy
        self.host = host
        self.port = port
        self.timeout_seconds = float(timeout_seconds)
        self.max_send_bytes = max_send_bytes
        self.max_read_bytes = max_read_bytes
        self._pinned_addresses = tuple(sorted(addresses, key=lambda item: (item[0], item[1])))
        self.endpoint_id = canonical_hash(
            {
                "schema_version": 1,
                "transport": "tcp",
                "challenge_manifest_fingerprint": challenge.manifest_fingerprint,
                "endpoint": target.endpoint,
                "host": host,
                "port": port,
                "pinned_ips": list(self.pinned_ips),
                "max_send_bytes": max_send_bytes,
                "max_read_bytes": max_read_bytes,
            }
        )

    @property
    def pinned_ips(self) -> tuple[str, ...]:
        return tuple(ip for _family, ip in self._pinned_addresses)

    def describe(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "kind": "ctf_remote_tcp_runner",
            "endpoint_id": self.endpoint_id,
            "challenge_manifest_fingerprint": self.challenge.manifest_fingerprint,
            "transport": "tcp",
            "host": self.host,
            "port": self.port,
            "pinned_ips": list(self.pinned_ips),
            "challenge_transport": self.network_policy.challenge_transport,
            "general_internet": self.network_policy.general_internet,
            "external_retrieval": self.network_policy.external_retrieval,
            "credential_ref_present": self.target.credential_ref is not None,
            "max_send_bytes": self.max_send_bytes,
            "max_read_bytes": self.max_read_bytes,
        }

    def open_session(self) -> RemoteTcpSession:
        last_error: OSError | None = None
        for family, ip in self._pinned_addresses:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_seconds)
            try:
                if family == socket.AF_INET6:
                    sock.connect((ip, self.port, 0, 0))
                else:
                    sock.connect((ip, self.port))
                peer = sock.getpeername()
                peer_ip = _normalized_ip(peer[0])
                if peer_ip != ip or peer_ip not in self.pinned_ips:
                    raise OSError("connected peer is outside the pinned endpoint set")
                return RemoteTcpSession(
                    sock=sock,
                    endpoint_id=self.endpoint_id,
                    challenge_manifest_fingerprint=self.challenge.manifest_fingerprint,
                    peer_ip=peer_ip,
                    peer_port=self.port,
                    timeout_seconds=self.timeout_seconds,
                    max_send_bytes=self.max_send_bytes,
                    max_read_bytes=self.max_read_bytes,
                )
            except OSError as exc:
                last_error = exc
                sock.close()
        if last_error is None:
            raise OSError("remote endpoint connection failed")
        raise last_error
