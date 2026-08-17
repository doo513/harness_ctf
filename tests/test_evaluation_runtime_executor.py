from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from ctf_harness.evaluation.executor import BenchmarkExecutorDescriptor
from ctf_harness.evaluation.models import (
    ArmConfig,
    BenchmarkCase,
    BenchmarkRunSpec,
    EvaluationMode,
    ExperimentContract,
)
from ctf_harness.evaluation.runtime_executor import RuntimeBenchmarkExecutor, RuntimeBinding


class _Factory:
    def __init__(self, root: Path):
        self.root = root

    def prepare(self, spec: BenchmarkRunSpec) -> RuntimeBinding:
        workspace = self.root / "workspace"
        workspace.mkdir()
        return RuntimeBinding(
            profile=object(),
            goal=object(),
            controller=object(),
            workspace=workspace,
            run_dir=self.root / "run",
        )


def _descriptor() -> BenchmarkExecutorDescriptor:
    return BenchmarkExecutorDescriptor(
        executor_id="budget-adapter-fixture",
        model_id="fixture-model",
        model_revision="fixture-model-r1",
        controller_revision="fixture-controller-r1",
        tool_inventory=("argv",),
        sandbox_id="fixture-sandbox-r1",
        oracle_policy_id="fixture-oracle-r1",
        web_search_enabled=False,
        external_retrieval_enabled=False,
        general_internet_egress_enabled=False,
        challenge_transport_only=True,
    )


def _spec() -> BenchmarkRunSpec:
    case = BenchmarkCase(
        case_id="budget-adapter-case",
        challenge_id="budget-adapter-case",
        challenge_revision="r1",
        manifest_fingerprint="a" * 64,
        mode=EvaluationMode.RESEARCH,
        category="pwn",
    )
    experiment = ExperimentContract(
        mode=EvaluationMode.RESEARCH,
        model_id="fixture-model",
        model_revision="fixture-model-r1",
        controller_revision="fixture-controller-r1",
        tool_inventory=("argv",),
        sandbox_id="fixture-sandbox-r1",
        oracle_policy_id="fixture-oracle-r1",
        max_steps=7,
        max_wall_seconds=12.5,
        max_tokens=None,
        seed=1,
    )
    return BenchmarkRunSpec(case=case, experiment=experiment, arm=ArmConfig.minimal())


def test_runtime_executor_translates_evaluation_budget_to_pinned_base_contract(tmp_path, monkeypatch):
    captured = {}

    class FakeState:
        completed = False
        failures = []
        facts = {}
        step = 3
        recovery_halted = False
        recovery_halt_reason = None

        def snapshot(self):
            return {"step": self.step, "completed": self.completed}

    class FakeRuntime:
        metrics = {"tool_calls": 0, "wall_seconds": 0.25}

        def run(self):
            return FakeState()

    def fake_build_runtime_for_arm(*, budget, **kwargs):
        captured["hard_max_steps"] = budget.hard_max_steps
        captured["hard_wall_seconds"] = budget.hard_wall_seconds
        captured["soft_max_steps"] = budget.soft_max_steps
        return FakeRuntime()

    monkeypatch.setattr(
        "ctf_harness.evaluation.runtime_executor.build_runtime_for_arm",
        fake_build_runtime_for_arm,
    )

    spec = _spec()
    receipt = RuntimeBenchmarkExecutor(
        descriptor=_descriptor(),
        binding_factory=_Factory(tmp_path),
    ).execute(spec)

    assert captured == {
        "hard_max_steps": spec.experiment.max_steps,
        "hard_wall_seconds": spec.experiment.max_wall_seconds,
        "soft_max_steps": None,
    }
    assert receipt.run_id == spec.run_id()
    assert receipt.outcome.steps == 3
