from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit

from harness.core.storage import canonical_hash

from ctf_harness.operational.models import NetworkPolicy, RemoteTargetSpec, RemoteTransport


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
    def __init__(
        self,
        *,
        sock: socket.socket,
        endpoint_id: str,
        peer_ip: str,
        peer_port: int,
        timeout_seconds: float,
        max_send_bytes: int,
        max_read_bytes: int,
    ):
        self._sock = sock
        self.endpoint_id = endpoint_id
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
        self._events: list[dict[str, Any]] = [
            {"event": "open", "peer_ip": peer_ip, "peer_port": peer_port}
        ]

    @property
    def closed(self) -> bool:
        return self._closed

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("remote TCP session is closed")

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
        self._events.append(
            {"event": "send", "bytes": len(data), "sha256": digest}
        )
        return len(data)

    def read(self, max_bytes: int | None = None) -> bytes:
        self._ensure_open()
        limit = self.max_read_bytes if max_bytes is None else max_bytes
        if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
            raise ValueError("remote TCP read limit must be a positive integer")
        if limit > self.max_read_bytes:
            raise ValueError("remote TCP read exceeds configured per-action maximum")
        data = self._sock.recv(limit)
        digest = hashlib.sha256(data).hexdigest()
        self._received.update(data)
        self._received_bytes += len(data)
        self._events.append(
            {"event": "read", "bytes": len(data), "sha256": digest}
        )
        return data

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
    solve runtime while receipts persist only hashes/counts. DNS is resolved at
    construction and later connections use only the pinned numeric addresses.
    """

    def __init__(
        self,
        target: RemoteTargetSpec,
        *,
        network_policy: NetworkPolicy,
        timeout_seconds: float = 3.0,
        max_send_bytes: int = 65536,
        max_read_bytes: int = 65536,
    ):
        if not isinstance(target, RemoteTargetSpec):
            raise ValueError("target must be RemoteTargetSpec")
        if target.transport is not RemoteTransport.TCP:
            raise ValueError("RemoteTcpRunner requires TCP transport")
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
