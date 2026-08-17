from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.agent_runtime import AgentCTFRuntime
from ctf_harness.operational.models import RunIntent
from ctf_harness.profile import VerifiedCTFProfile


class ControlledModel:
    """Deterministic ModelAdapter fixture; this is not a production LLM."""

    def __init__(self, outputs: list[dict]):
        self.outputs = [json.dumps(item, sort_keys=True) for item in outputs]
        self.calls: list[dict] = []

    def complete(self, *, system: str, user: str) -> str:
        self.calls.append({"system": system, "user": json.loads(user)})
        if not self.outputs:
            raise RuntimeError("controlled model output exhausted")
        return self.outputs.pop(0)


def hypothesis() -> dict:
    return {
        "id": "H-agent-foundation",
        "category": "pwn",
        "target": "controlled-target",
        "vulnerability_class": "unknown",
        "primitive": "surface_recon",
        "claim": "a deterministic surface observation is needed",
        "evidence_refs": [],
    }


def tool_decision(tool: str = "argv") -> dict:
    return {
        "kind": "tool",
        "payload": {
            "tool": tool,
            "args": {"argv": ["probe", "surface"]},
            "ctf_hypothesis": hypothesis(),
        },
    }


def complete(reason: str) -> dict:
    return {"kind": "complete", "payload": {"reason": reason}}


def runtime(root: Path, model: ControlledModel, *, intent: RunIntent, backend, oracle):
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return AgentCTFRuntime(
        run_intent=intent,
        goal=GoalContract(
            goal="controlled Agent foundation probe",
            acceptance=["external oracle remains sole completion authority"],
        ),
        profile=VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=backend,
            external_oracle=oracle,
        ),
        controller=CTFLLMController(model),
        run_dir=root / "run",
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-agent-foundation-") as td:
        root = Path(td)

        smoke_model = ControlledModel([
            tool_decision(),
            complete("controlled smoke boundary reached"),
        ])
        smoke_backend = RecordingIsolatedTestBackend({
            ("probe", "surface"): ExecutionResult(0, "surface-ok", ""),
        })
        smoke_oracle_calls = {"count": 0}

        def smoke_oracle(*, goal, state, workspace):
            smoke_oracle_calls["count"] += 1
            return True

        smoke = runtime(
            root / "smoke",
            smoke_model,
            intent=RunIntent.SMOKE,
            backend=smoke_backend,
            oracle=smoke_oracle,
        )
        smoke_state = smoke.run()
        assert smoke.halted
        assert not smoke_state.completed
        assert not smoke_state.completion_requested
        assert smoke_oracle_calls["count"] == 0
        assert smoke.metrics["oracle_checks"] == 0
        assert smoke.metrics["ctf_policy_stops"] == 1
        assert len(smoke_backend.calls) == 1

        second_context = smoke_model.calls[1]["user"]["context"]
        assert second_context["ctf"]["run"]["intent"] == "smoke"
        assert second_context["ctf"]["run"]["completion_authority"] == "external_oracle_only"
        assert second_context["ctf"]["hypotheses"][0]["instruction_authority"] == "none"
        assert "argv" in second_context["ctf"]["capabilities"]["available_tools"]

        missing_model = ControlledModel([tool_decision("not_available")])
        missing_backend = RecordingIsolatedTestBackend()
        missing = runtime(
            root / "missing",
            missing_model,
            intent=RunIntent.SMOKE,
            backend=missing_backend,
            oracle=lambda *, goal, state, workspace: True,
        )
        missing_state = missing.run()
        assert missing.halted and not missing_state.completed
        assert missing.metrics["ctf_missing_capabilities"] == 1
        assert missing.metrics["oracle_checks"] == 0
        assert missing_backend.calls == []

        solve_model = ControlledModel([complete("request independent acceptance")])
        solve_oracle_calls = {"count": 0}

        def solve_oracle(*, goal, state, workspace):
            solve_oracle_calls["count"] += 1
            return True

        solve = runtime(
            root / "solve",
            solve_model,
            intent=RunIntent.SOLVE,
            backend=RecordingIsolatedTestBackend(),
            oracle=solve_oracle,
        )
        solve_state = solve.run()
        assert solve_state.completed
        assert solve_state.completion_requested
        assert solve_oracle_calls["count"] == 1
        assert solve.metrics["oracle_checks"] == 1

        print(json.dumps({
            "probe": "ctf-agent-foundation-controlled-v1",
            "all_passed": True,
            "actual_production_llm_executed": False,
            "base_llm_controller_reused": True,
            "base_context_projector_reused": True,
            "base_decision_contract_reused": True,
            "smoke_actor_complete_halted_incomplete": True,
            "smoke_oracle_checks": smoke.metrics["oracle_checks"],
            "missing_capability_halted_before_tool": True,
            "solve_completion_required_external_oracle": True,
            "solve_oracle_checks": solve.metrics["oracle_checks"],
            "ctf_hypothesis_truth_authority": "none",
            "completion_authority": "external_oracle_only",
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
