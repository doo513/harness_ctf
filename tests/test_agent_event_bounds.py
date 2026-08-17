from __future__ import annotations

import hashlib
import json
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.sandbox import RecordingIsolatedTestBackend

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.agent_runtime import AgentCTFRuntime
from ctf_harness.operational.models import RunIntent
from ctf_harness.profile import VerifiedCTFProfile


class OneShotModel:
    def __init__(self, decision: dict):
        self.output = json.dumps(decision, sort_keys=True)

    def complete(self, *, system: str, user: str) -> str:
        return self.output


def test_smoke_stop_bounds_untrusted_reason_and_preserves_digest(tmp_path: Path) -> None:
    reason = "UNTRUSTED-" + ("x" * 5000)
    model = OneShotModel({"kind": "complete", "payload": {"reason": reason}})
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runtime = AgentCTFRuntime(
        run_intent=RunIntent.SMOKE,
        goal=GoalContract(goal="event bound fixture", acceptance=["remain incomplete"]),
        profile=VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=RecordingIsolatedTestBackend(),
            external_oracle=lambda *, goal, state, workspace: True,
        ),
        controller=CTFLLMController(model),
        run_dir=tmp_path / "run",
    )
    state = runtime.run()
    assert not state.completed
    stops = [record for record in runtime.events.verify_chain() if record.get("kind") == "ctf.run.stop"]
    assert len(stops) == 1
    payload = stops[0]["payload"]
    assert len(payload["reason_preview"]) == 512
    assert payload["reason_sha256"] == hashlib.sha256(reason.encode()).hexdigest()
    assert reason not in json.dumps(payload, sort_keys=True)
    assert payload["completion_authority"] == "external_oracle_only"
