from __future__ import annotations

import atexit
import base64
import uuid
from typing import Any

from harness.core.tools import SideEffect, ToolSpec

from ctf_harness.target.remote import RemoteTcpRunner, RemoteTcpSession


class RemoteTcpToolRuntime:
    """Persistent session adapter over one admitted RemoteTcpRunner.

    The runtime has no endpoint parsing, DNS, or network-scope authority of its
    own. Those decisions are already frozen by RemoteTcpRunner. Session IDs are
    ephemeral control handles and are deliberately not resumable after process
    loss; transcript receipts retain hashes/counts without becoming semantic
    proof.
    """

    def __init__(self, runner: RemoteTcpRunner, *, max_sessions: int = 8):
        if not isinstance(runner, RemoteTcpRunner):
            raise ValueError("remote TCP tool requires RemoteTcpRunner")
        if not isinstance(max_sessions, int) or isinstance(max_sessions, bool) or max_sessions <= 0:
            raise ValueError("remote TCP max_sessions must be a positive integer")
        self.runner = runner
        self.max_sessions = max_sessions
        self._sessions: dict[str, RemoteTcpSession] = {}
        atexit.register(self.close_all)

    @staticmethod
    def _decode(value: str | None, *, field_name: str) -> bytes:
        if not isinstance(value, str):
            raise ValueError(f"{field_name} must be base64 text")
        try:
            return base64.b64decode(value, validate=True)
        except Exception as exc:
            raise ValueError(f"{field_name} is not valid base64") from exc

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    def _session(self, session_id: str | None) -> RemoteTcpSession:
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("remote TCP operation requires session_id")
        session = self._sessions.get(session_id)
        if session is None or session.closed:
            raise ValueError("remote TCP session is unknown or closed")
        return session

    def _prune_closed(self) -> None:
        for session_id, session in list(self._sessions.items()):
            if session.closed:
                self._sessions.pop(session_id, None)

    def _open(self) -> dict[str, Any]:
        self._prune_closed()
        if len(self._sessions) >= self.max_sessions:
            raise RuntimeError(f"remote TCP active session limit reached: {self.max_sessions}")
        session = self.runner.open_session()
        session_id = uuid.uuid4().hex[:16]
        while session_id in self._sessions:
            session_id = uuid.uuid4().hex[:16]
        self._sessions[session_id] = session
        return {
            "operation": "open",
            "session_id": session_id,
            "runner": self.runner.describe(),
            "receipt": session.receipt().descriptor(),
            "response_b64": "",
            "response_bytes": 0,
            "truth_authority": "transport_observation_only",
        }

    def execute(
        self,
        operation: str,
        *,
        session_id: str | None = None,
        data_b64: str | None = None,
        delimiter_b64: str | None = None,
        max_bytes: int | None = None,
        byte_count: int | None = None,
        wait_seconds: float | None = None,
        idle_grace_seconds: float = 0.05,
    ) -> dict[str, Any]:
        if operation == "open":
            if session_id is not None:
                raise ValueError("open does not accept session_id")
            return self._open()
        if operation not in {"send", "read", "read_until", "read_exact", "drain", "interrupt", "close"}:
            raise ValueError("unsupported remote TCP operation")
        session = self._session(session_id)
        response = b""
        sent = 0
        if operation == "send":
            sent = session.send(self._decode(data_b64, field_name="data_b64"))
        elif operation == "read":
            response = session.read(
                max_bytes,
                wait_seconds=0.0 if wait_seconds is None else wait_seconds,
                idle_grace_seconds=idle_grace_seconds,
            )
        elif operation == "read_until":
            response = session.read_until(
                self._decode(delimiter_b64, field_name="delimiter_b64"),
                max_bytes=max_bytes,
                wait_seconds=wait_seconds,
            )
        elif operation == "read_exact":
            if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count <= 0:
                raise ValueError("read_exact requires positive byte_count")
            response = session.read_exact(byte_count, wait_seconds=wait_seconds)
        elif operation == "drain":
            if wait_seconds is None:
                raise ValueError("drain requires wait_seconds")
            response = session.bounded_drain(
                wait_seconds=wait_seconds,
                max_bytes=max_bytes,
                idle_grace_seconds=idle_grace_seconds,
            )
        elif operation == "interrupt":
            session.interrupt()
        elif operation == "close":
            receipt = session.close().descriptor()
            self._sessions.pop(session_id, None)
            return {
                "operation": operation,
                "session_id": session_id,
                "sent_bytes": 0,
                "response_b64": "",
                "response_bytes": 0,
                "receipt": receipt,
                "truth_authority": "transport_observation_only",
            }
        return {
            "operation": operation,
            "session_id": session_id,
            "sent_bytes": sent,
            "response_b64": self._encode(response),
            "response_bytes": len(response),
            "receipt": session.receipt().descriptor(),
            "truth_authority": "transport_observation_only",
        }

    def close_all(self) -> None:
        for session_id, session in list(self._sessions.items()):
            try:
                session.close()
            finally:
                self._sessions.pop(session_id, None)

    def control_projection(self) -> dict[str, Any]:
        """Return non-lossy ephemeral handles needed to continue live sessions.

        Session IDs are Harness-generated control capabilities, not semantic
        evidence. They must not depend on lossy observation previews because a
        truncated preview can otherwise make a live stateful tool unusable on
        the next Actor turn.
        """
        self._prune_closed()
        sessions = [
            {"session_id": session_id, "state": "open"}
            for session_id, session in sorted(self._sessions.items())
            if not session.closed
        ]
        return {
            "schema_version": "ctf-remote-tcp-control-v1",
            "authority": "kernel_control",
            "instruction_authority": "none",
            "truth_authority": "none",
            "ephemeral": True,
            "resumable_after_process_loss": False,
            "max_sessions": self.max_sessions,
            "sessions": sessions,
        }

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": "ctf-remote-tcp-tool-v2",
            "runner": self.runner.describe(),
            "persistent_sessions": True,
            "session_resume": False,
            "max_sessions": self.max_sessions,
            "endpoint_authority": "remote_tcp_runner_only",
            "truth_authority": "none",
        }

    def make_tool(self) -> ToolSpec:
        return ToolSpec(
            name="remote_tcp",
            description=(
                "Open and operate a bounded persistent TCP session only through the admitted RemoteTcpRunner. "
                "Operations: open/send/read/read_until/read_exact/drain/interrupt/close. Bytes use base64."
            ),
            handler=self.execute,
            side_effect=SideEffect.EXTERNAL,
            idempotent=False,
            permission="auto",
            failure_modes=[
                "session_unknown",
                "session_limit",
                "endpoint_unavailable",
                "send_limit",
                "read_limit",
                "read_timeout",
                "peer_closed",
            ],
            provenance={
                "kind": "ctf_remote_tcp_tool",
                "schema": "ctf-remote-tcp-tool-v2",
                "endpoint_authority": "remote_tcp_runner_only",
                "truth_authority": "none",
            },
        )
