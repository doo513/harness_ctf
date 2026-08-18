from __future__ import annotations

import base64
import json
import socketserver
import tempfile
import threading
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.sandbox import RecordingIsolatedTestBackend

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    AgentSpec,
    NetworkPolicy,
    OperationalChallengeRef,
    OraclePolicy,
    RemoteTargetSpec,
    RemoteTransport,
    RunIntent,
    SolveBudget,
    SolveSpec,
)
from ctf_harness.operational.solve_engine import SolveEngine, SolveRuntimeBinding
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.target.remote import RemoteTcpRunner


FLAG = b"flag{competition_remote_513}\n"


class DaemonThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class ChallengeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5.0)
        self.request.sendall(b"READY\n")
        data = b""
        while not data.endswith(b"\n") and len(data) < 64:
            try:
                chunk = self.request.recv(64 - len(data))
            except TimeoutError:
                return
            if not chunk:
                return
            data += chunk
        if data == b"PING\n":
            self.request.sendall(FLAG)
        else:
            self.request.sendall(b"NO\n")


class Model:
    def __init__(self):
        self.calls = 0
        self.session_id = None

    @staticmethod
    def hypothesis(identifier, primitive, claim):
        return {
            "id": identifier,
            "category": "pwn",
            "target": "remote",
            "vulnerability_class": "controlled-protocol",
            "primitive": primitive,
            "claim": claim,
            "evidence_refs": [],
        }

    @staticmethod
    def _visible_remote_records(context: dict) -> list[dict]:
        records = []
        observations = context.get("untrusted", {}).get("observations", [])
        for observation in observations:
            if observation.get("source") != "remote_tcp":
                continue
            preview = observation.get("preview")
            if not isinstance(preview, dict) or preview.get("format") != "canonical_json":
                continue
            text = preview.get("text")
            if not isinstance(text, str):
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
        return records

    @staticmethod
    def _visible_remote_session_ids(context: dict) -> list[str]:
        operational = context.get("ctf", {}).get("operational_control", {})
        handles = operational.get("handles", {}) if isinstance(operational, dict) else {}
        remote = handles.get("remote_tcp", {}) if isinstance(handles, dict) else {}
        sessions = remote.get("sessions", []) if isinstance(remote, dict) else []
        result = []
        for session in sessions if isinstance(sessions, list) else []:
            if not isinstance(session, dict):
                continue
            session_id = session.get("session_id")
            if isinstance(session_id, str) and session_id:
                result.append(session_id)
        return result

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        if self.calls == 1:
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "remote_tcp",
                    "args": {"operation": "open"},
                    "ctf_hypothesis": self.hypothesis("H-open", "remote_connect", "open only the admitted endpoint"),
                },
            }
        else:
            request = json.loads(user)
            context = request.get("context", {})
            records = self._visible_remote_records(context)
            if self.session_id is None:
                session_ids = self._visible_remote_session_ids(context)
                if session_ids:
                    self.session_id = session_ids[0]
            if not self.session_id:
                # A stateful transport continuation handle must never depend on a
                # lossy observation preview. Keep this compatibility read only as
                # a diagnostic so the probe catches regressions in control projection.
                for record in records:
                    session_id = record.get("session_id")
                    if isinstance(session_id, str) and session_id:
                        raise RuntimeError(
                            "remote session id is only visible through lossy observation preview; "
                            "operational control projection is missing"
                        )
                raise RuntimeError("remote session id was not projected into governed operational control context")
            if self.calls == 2:
                decision = {
                    "kind": "tool",
                    "payload": {
                        "tool": "remote_tcp",
                        "args": {
                            "operation": "read_until",
                            "session_id": self.session_id,
                            "delimiter_b64": base64.b64encode(b"\n").decode(),
                            "wait_seconds": 2.0,
                        },
                        "ctf_hypothesis": self.hypothesis("H-banner", "protocol_banner", "confirm the controlled service banner"),
                    },
                }
            elif self.calls == 3:
                decision = {
                    "kind": "tool",
                    "payload": {
                        "tool": "remote_tcp",
                        "args": {
                            "operation": "send",
                            "session_id": self.session_id,
                            "data_b64": base64.b64encode(b"PING\n").decode(),
                        },
                        "ctf_hypothesis": self.hypothesis("H-send", "protocol_input", "send bounded challenge protocol input"),
                    },
                }
            elif self.calls == 4:
                decision = {
                    "kind": "tool",
                    "payload": {
                        "tool": "remote_tcp",
                        "args": {
                            "operation": "read_until",
                            "session_id": self.session_id,
                            "delimiter_b64": base64.b64encode(b"\n").decode(),
                            "wait_seconds": 2.0,
                        },
                        "ctf_hypothesis": self.hypothesis("H-result", "remote_result", "observe candidate remote result"),
                    },
                }
            elif self.calls == 5:
                decision = {"kind": "complete", "payload": {"reason": "request independent remote acceptance"}}
            else:
                raise RuntimeError("competition model exhausted")
        return json.dumps(decision, sort_keys=True)


class BindingFactory:
    def __init__(self, *, root: Path, model: Model, oracle):
        self.root = root
        self.model = model
        self.oracle = oracle

    def prepare(self, spec: SolveSpec) -> SolveRuntimeBinding:
        runner = RemoteTcpRunner(
            spec.challenge,
            spec.target,
            network_policy=spec.network_policy,
            timeout_seconds=2.0,
            max_send_bytes=1024,
            max_read_bytes=1024,
        )
        profile = VerifiedCTFProfile(
            workspace=self.root / "workspace",
            execution_backend=RecordingIsolatedTestBackend(),
            external_oracle=self.oracle,
            remote_tcp_runner=runner,
            active_domains=("pwn",),
        )
        return SolveRuntimeBinding(
            profile=profile,
            goal=GoalContract(
                goal="interact with the admitted controlled remote service and request external acceptance",
                acceptance=["external oracle observes accepted remote response"],
                task_id=spec.challenge.challenge_id,
            ),
            controller=CTFLLMController(self.model),
            workspace=self.root / "workspace",
            run_dir=self.root / "run",
            target_relpath=None,
            agent=spec.agent,
            oracle_policy_id=spec.oracle_policy.policy_id,
        )


def oracle(*, goal, state, workspace):
    expected = base64.b64encode(FLAG).decode()
    for observation in state.observations:
        if observation.ok and isinstance(observation.preview, dict):
            if observation.preview.get("response_b64") == expected:
                return True
    return False


def main() -> int:
    server = DaemonThreadingTCPServer(("127.0.0.1", 0), ChallengeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"tcp://127.0.0.1:{server.server_address[1]}"
        challenge = OperationalChallengeRef(
            challenge_id="competition-remote-tcp",
            source="controlled-fixture",
            category="pwn",
        )
        target = RemoteTargetSpec(
            transport=RemoteTransport.TCP,
            endpoint=endpoint,
        )
        with tempfile.TemporaryDirectory(prefix="ctf-competition-remote-") as tmp:
            root = Path(tmp)
            model = Model()
            spec = SolveSpec(
                challenge=challenge,
                target=target,
                agent=AgentSpec(provider="fixture", model="deterministic", revision="competition-remote-v1"),
                intent=RunIntent.SOLVE,
                budget=SolveBudget(max_steps=10),
                network_policy=NetworkPolicy(
                    challenge_transport=True,
                    general_internet=False,
                    external_retrieval=False,
                ),
                oracle_policy=OraclePolicy(policy_id="controlled-remote-oracle"),
            )
            engine = SolveEngine(BindingFactory(root=root, model=model, oracle=oracle))
            receipt = engine.execute(spec)
            tool_phases = [call.phase for call in receipt.tool_calls]
            assert tool_phases == ["open", "read", "write", "read"], receipt
            assert receipt.completed is True, receipt
            assert receipt.outcome.value == "solved", receipt
            assert model.calls == 5, model.calls
            print(json.dumps(receipt.descriptor(), sort_keys=True))
            return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


if __name__ == "__main__":
    raise SystemExit(main())
