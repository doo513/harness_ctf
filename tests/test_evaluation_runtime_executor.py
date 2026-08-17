from __future__ import annotations

import json
from pathlib import Path

import pytest

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


class _FakeState:
    completed = False
    failures = []
    facts = {}
    step = 3
    recovery_halted = False
    recovery_halt_reason = None

    def snapshot(self):
        return {"step": self.step, "completed": self.completed}


class _FakeRuntime:
    def __init__(self, run_dir: Path, *, metrics_steps=3):
        self.run_dir = run_dir
        self.run_id = "base-runtime-fixture"
        self.metrics = {
            "tool_calls": 999,
            "wall_seconds": 999.0,
        }
        self.metrics_steps = metrics_steps

    def run(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "metrics.json").write_text(
            json.dumps({
                "run_id": self.run_id,
                "steps": self.metrics_steps,
                "tool_calls": 2,
                "completed": False,
                "wall_seconds": 0.25,
            }),
            encoding="utf-8",
        )
        return _FakeState()


def _install_fake_runtime(monkeypatch, captured: dict, *, metrics_steps=3):
    def fake_build_runtime_for_arm(*, budget, run_dir, **kwargs):
        captured["hard_max_steps"] = budget.hard_max_steps
        captured["hard_wall_seconds"] = budget.hard_wall_seconds
        captured["soft_max_steps"] = budget.soft_max_steps
        return _FakeRuntime(Path(run_dir), metrics_steps=metrics_steps)

    monkeypatch.setattr(
        "ctf_harness.evaluation.runtime_executor.build_runtime_for_arm",
        fake_build_runtime_for_arm,
    )


def test_runtime_executor_translates_budget_and_uses_durable_metrics(tmp_path, monkeypatch):
    captured = {}
    _install_fake_runtime(monkeypatch, captured)

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
    assert receipt.outcome.tool_calls == 2
    assert receipt.outcome.wall_seconds == 0.25
    # Deliberately different in-memory values prove metrics.json is the authority.
    assert receipt.outcome.tool_calls != 999
    assert receipt.outcome.wall_seconds != 999.0


def test_runtime_executor_rejects_durable_metrics_that_disagree_with_state(tmp_path, monkeypatch):
    captured = {}
    _install_fake_runtime(monkeypatch, captured, metrics_steps=4)

    with pytest.raises(ValueError, match="steps disagree"):
        RuntimeBenchmarkExecutor(
            descriptor=_descriptor(),
            binding_factory=_Factory(tmp_path),
        ).execute(_spec())
