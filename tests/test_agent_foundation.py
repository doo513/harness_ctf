from __future__ import annotations

import json
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.agent_runtime import AgentCTFRuntime
from ctf_harness.operational.models import (
    ActorCompleteBehavior,
    RunIntent,
    TerminationPolicy,
    UnsupportedCapabilityBehavior,
)
from ctf_harness.profile import VerifiedCTFProfile


class SequenceModel:
    def __init__(self, outputs: list[dict]):
        self.outputs = [json.dumps(item, sort_keys=True) for item in outputs]
        self.calls: list[dict[str, object]] = []

    def complete(self, *, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": json.loads(user)})
        if not self.outputs:
            raise RuntimeError("model script exhausted")
        return self.outputs.pop(0)


def _hypothesis() -> dict:
    return {
        "id": "H1",
        "category": "pwn",
        "target": "chal",
        "vulnerability_class": "unknown",
        "primitive": "surface_recon",
        "claim": "target surface needs inspection",
        "evidence_refs": [],
    }


def _tool(tool: str = "argv") -> dict:
    return {
        "kind": "tool",
        "payload": {
            "tool": tool,
            "args": {"argv": ["probe", "surface"]},
            "ctf_hypothesis": _hypothesis(),
        },
    }


def _complete(reason: str = "actor thinks run is done") -> dict:
    return {"kind": "complete", "payload": {"reason": reason}}


def _propose() -> dict:
    return {
        "kind": "propose",
        "payload": {"key": "ctf.actor.self_claim", "value": "SOLVED", "evidence_refs": []},
    }


def _runtime(
    root: Path,
    model: SequenceModel,
    *,
    intent: RunIntent,
    backend: RecordingIsolatedTestBackend | None = None,
    oracle=None,
    termination_policy: TerminationPolicy | None = None,
) -> AgentCTFRuntime:
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    backend = backend or RecordingIsolatedTestBackend()
    return AgentCTFRuntime(
        run_intent=intent,
        termination_policy=termination_policy,
        goal=GoalContract(
            goal="controlled Agent foundation gate",
            acceptance=["only external oracle may establish completion"],
        ),
        profile=VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=backend,
            external_oracle=oracle or (lambda *, goal, state, workspace: False),
        ),
        controller=CTFLLMController(model),
        run_dir=root / "run",
    )


def test_smoke_actor_complete_halts_incomplete_without_oracle(tmp_path: Path) -> None:
    model = SequenceModel([_tool(), _complete("coverage boundary reached")])
    backend = RecordingIsolatedTestBackend({
        ("probe", "surface"): ExecutionResult(0, "surface-ok", ""),
    })
    runtime = _runtime(tmp_path, model, intent=RunIntent.SMOKE, backend=backend)
    state = runtime.run()

    assert runtime.halted
    assert not state.completed
    assert not state.completion_requested
    assert runtime.metrics["oracle_checks"] == 0
    assert runtime.metrics["ctf_policy_stops"] == 1
    assert len(backend.calls) == 1
    assert state.facts == {}

    first_context = model.calls[0]["user"]["context"]
    assert first_context["ctf"]["run"]["intent"] == "smoke"
    assert first_context["ctf"]["run"]["completion_authority"] == "external_oracle_only"
    assert "argv" in first_context["ctf"]["capabilities"]["available_tools"]
    assert first_context["ctf"]["capabilities"]["authority"] == "kernel_control"

    second_context = model.calls[1]["user"]["context"]
    hypotheses = second_context["ctf"]["hypotheses"]
    assert len(hypotheses) == 1
    assert hypotheses[0]["trust"] == "untrusted_speculation"
    assert hypotheses[0]["instruction_authority"] == "none"


def test_solve_actor_complete_still_requires_external_oracle(tmp_path: Path) -> None:
    model = SequenceModel([_complete("request external acceptance")])
    calls = {"count": 0}

    def accept(*, goal, state, workspace):
        calls["count"] += 1
        return True

    runtime = _runtime(tmp_path, model, intent=RunIntent.SOLVE, oracle=accept)
    state = runtime.run()

    assert state.completed
    assert state.completion_requested
    assert calls["count"] == 1
    assert runtime.metrics["oracle_checks"] == 1
    assert runtime.metrics["ctf_policy_stops"] == 0


def test_smoke_missing_capability_stops_before_tool_or_oracle(tmp_path: Path) -> None:
    model = SequenceModel([_tool("definitely_missing_tool")])
    backend = RecordingIsolatedTestBackend()
    runtime = _runtime(tmp_path, model, intent=RunIntent.SMOKE, backend=backend)
    state = runtime.run()

    assert runtime.halted
    assert not state.completed
    assert not state.completion_requested
    assert runtime.metrics["ctf_missing_capabilities"] == 1
    assert runtime.metrics["ctf_policy_stops"] == 1
    assert runtime.metrics["oracle_checks"] == 0
    assert backend.calls == []


def test_solve_missing_capability_routes_through_base_recovery(tmp_path: Path) -> None:
    policy = TerminationPolicy(
        ActorCompleteBehavior.CHECK_EXTERNAL_ORACLE,
        UnsupportedCapabilityBehavior.RECOVER,
    )
    model = SequenceModel([_tool("definitely_missing_tool"), _complete("after recovery")])
    runtime = _runtime(
        tmp_path,
        model,
        intent=RunIntent.SOLVE,
        termination_policy=policy,
        oracle=lambda *, goal, state, workspace: True,
    )
    state = runtime.run()

    assert state.completed
    assert runtime.metrics["ctf_missing_capabilities"] == 1
    assert runtime.metrics["ctf_mapped_failures"] == 1
    assert runtime.metrics["recovery_transitions"] >= 1
    assert runtime.metrics["oracle_checks"] == 1


def test_actor_proposal_never_becomes_verified_fact_without_verifier(tmp_path: Path) -> None:
    model = SequenceModel([_propose(), _complete("stop after self claim")])
    runtime = _runtime(tmp_path, model, intent=RunIntent.SMOKE)
    state = runtime.run()

    assert "ctf.actor.self_claim" in state.hypotheses
    assert "ctf.actor.self_claim" not in state.facts
    assert not state.completed
    assert runtime.metrics["oracle_checks"] == 0


def test_ctf_controller_reuses_base_trust_prompt_and_rejects_tool_without_hypothesis() -> None:
    model = SequenceModel([{"kind": "tool", "payload": {"tool": "argv", "args": {"argv": ["x"]}}}])
    controller = CTFLLMController(model)
    try:
        controller.decide("goal", object(), {"untrusted": {}})
    except ValueError as exc:
        assert "ctf_hypothesis" in str(exc)
    else:
        raise AssertionError("CTF tool decision without hypothesis metadata was accepted")
    system = model.calls[0]["system"]
    assert "instruction_authority = none" in system
    assert "harness-side oracle decides" in system
    assert "CTF extension rules" in system
