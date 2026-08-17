from __future__ import annotations

import hashlib
import ipaddress
import socket
from dataclasses import asdict, dataclass
from typing import Iterable

from harness.core.storage import ArtifactStore, canonical_hash


def _hex64(value: str, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a 64-character SHA-256 hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be hexadecimal") from exc
    if value.lower() != value:
        raise ValueError(f"{field} must use lowercase hex")
    return value


def _normalized_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


@dataclass(frozen=True)
class RemoteBehaviorReceipt:
    schema_version: int
    kind: str
    proof_level: str
    endpoint_id: str
    peer_ip: str
    peer_port: int
    payload_sha256: str
    response_sha256: str
    response_bytes: int
    response_complete: bool
    remote_environment_fingerprint: str
    oracle_id: str
    independence_level: str
    accepted: bool
    reason_hash: str

    def dump(self) -> dict:
        return asdict(self)


class TCPRemoteBehaviorOracle:
    """Control-plane TCP behavior oracle bound to one operator-fixed endpoint.

    Hostname resolution occurs once during construction. Evaluation connects to
    the pinned numeric addresses rather than resolving the hostname again, which
    prevents the Actor payload from selecting a different destination and avoids
    DNS changes silently changing the proof target between configuration and use.

    This class is intentionally not exposed as an Actor tool.
    """

    name = "pwn_remote_tcp_response_digest"

    def __init__(
        self,
        *,
        host: str,
        port: int,
        expected_response_sha256: str,
        timeout_seconds: float = 3.0,
        max_payload_bytes: int = 65536,
        max_response_bytes: int = 65536,
        endpoint_source: str = "operator_manifest",
    ):
        if not isinstance(host, str) or not host.strip():
            raise ValueError("host must be non-empty")
        if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
            raise ValueError("port must be in 1..65535")
        _hex64(expected_response_sha256, field="expected_response_sha256")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(max_payload_bytes, int) or max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        if not isinstance(max_response_bytes, int) or max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if endpoint_source not in {"operator_manifest", "challenge_admission"}:
            raise ValueError("remote endpoint must come from operator-controlled admission data")

        self.host = host.strip()
        self.port = port
        self.expected_response_sha256 = expected_response_sha256
        self.timeout_seconds = float(timeout_seconds)
        self.max_payload_bytes = max_payload_bytes
        self.max_response_bytes = max_response_bytes
        self.endpoint_source = endpoint_source

        infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        addresses: list[tuple[int, str]] = []
        for family, socktype, proto, _canonname, sockaddr in infos:
            if socktype != socket.SOCK_STREAM or family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            ip = _normalized_ip(sockaddr[0])
            item = (family, ip)
            if item not in addresses:
                addresses.append(item)
        if not addresses:
            raise ValueError("remote endpoint resolved to no TCP IPv4/IPv6 address")
        self._pinned_addresses = tuple(sorted(addresses, key=lambda item: (item[0], item[1])))
        descriptor = {
            "schema_version": 1,
            "protocol": "tcp",
            "host": self.host,
            "port": self.port,
            "pinned_ips": [ip for _, ip in self._pinned_addresses],
            "expected_response_sha256": expected_response_sha256,
            "max_payload_bytes": max_payload_bytes,
            "max_response_bytes": max_response_bytes,
            "endpoint_source": endpoint_source,
        }
        self.endpoint_id = canonical_hash(descriptor)
        self.oracle_id = f"{self.name}:{self.endpoint_id[:16]}"

    @property
    def pinned_ips(self) -> tuple[str, ...]:
        return tuple(ip for _, ip in self._pinned_addresses)

    def _exchange(self, payload: bytes) -> tuple[str, bytes, bool, bool]:
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
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                response = bytearray()
                timed_out = False
                response_complete = False
                while len(response) <= self.max_response_bytes:
                    try:
                        chunk = sock.recv(min(4096, self.max_response_bytes + 1 - len(response)))
                    except socket.timeout:
                        timed_out = True
                        break
                    if not chunk:
                        response_complete = True
                        break
                    response.extend(chunk)
                    if len(response) > self.max_response_bytes:
                        break
                return peer_ip, bytes(response), response_complete, timed_out
            except OSError as exc:
                last_error = exc
            finally:
                sock.close()
        if last_error is None:
            raise OSError("remote endpoint connection failed")
        raise last_error

    def evaluate(self, *, payload: bytes, remote_environment_fingerprint: str) -> RemoteBehaviorReceipt:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) > self.max_payload_bytes:
            raise ValueError("payload exceeds configured maximum")
        _hex64(remote_environment_fingerprint, field="remote_environment_fingerprint")

        payload_sha = hashlib.sha256(payload).hexdigest()
        try:
            peer_ip, response, response_complete, timed_out = self._exchange(payload)
            over_limit = len(response) > self.max_response_bytes
            response_sha = hashlib.sha256(response).hexdigest()
            accepted = (
                not timed_out
                and not over_limit
                and response_complete
                and response_sha == self.expected_response_sha256
            )
            reason = "operator-fixed remote response contract matched" if accepted else "remote response did not satisfy the operator-fixed contract"
            response_bytes = min(len(response), self.max_response_bytes + 1)
        except OSError as exc:
            peer_ip = "0.0.0.0"
            response_sha = hashlib.sha256(b"").hexdigest()
            response_bytes = 0
            response_complete = False
            accepted = False
            reason = f"remote endpoint exchange failed: {type(exc).__name__}"

        return RemoteBehaviorReceipt(
            schema_version=1,
            kind="pwn_remote_behavior_receipt",
            proof_level="P5_REMOTE",
            endpoint_id=self.endpoint_id,
            peer_ip=peer_ip,
            peer_port=self.port,
            payload_sha256=payload_sha,
            response_sha256=response_sha,
            response_bytes=response_bytes,
            response_complete=response_complete,
            remote_environment_fingerprint=remote_environment_fingerprint,
            oracle_id=self.oracle_id,
            independence_level="operator_fixed_endpoint_and_response_digest",
            accepted=accepted,
            reason_hash=hashlib.sha256(reason.encode()).hexdigest(),
        )


def persist_remote_behavior_receipt(
    store: ArtifactStore,
    receipt: RemoteBehaviorReceipt,
    *,
    name: str = "pwn-remote-behavior.json",
) -> str:
    return store.put_json(name, {"ok": True, "output": receipt.dump(), "error": None})
