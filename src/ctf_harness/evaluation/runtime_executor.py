from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from harness.core.budget import Budget
from harness.core.storage import atomic_write_json, canonical_hash

from ctf_harness.durable_runtime import file_sha256, load_durable_runtime_metrics

from .arm_runtime import build_runtime_for_arm, canonical_arm_selection
from .executor import BenchmarkExecutorDescriptor, ExecutorRunReceipt
from .models import BenchmarkRunSpec, RawRunOutcome


@dataclass(frozen=True)
class RuntimeBinding:
    """Prepared per-run objects supplied by corpus/controller integration."""

    profile: object
    goal: object
    controller: object
    workspace: Path
    run_dir: Path

    def __post_init__(self) -> None:
        if not isinstance(self.workspace, Path) or not isinstance(self.run_dir, Path):
            raise ValueError("workspace and run_dir must be pathlib.Path")
        if not self.workspace.exists() or not self.workspace.is_dir():
            raise ValueError("runtime binding workspace must exist")
        if self.run_dir.exists() and any(self.run_dir.iterdir()):
            raise ValueError("runtime binding run_dir must be empty before execution")


class RuntimeBindingFactory(Protocol):
    def prepare(self, spec: BenchmarkRunSpec) -> RuntimeBinding: ...


@dataclass(frozen=True)
class UsageSnapshot:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None

    def __post_init__(self) -> None:
        for field in ("input_tokens", "output_tokens"):
            value = getattr(self, field)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                raise ValueError(f"{field} must be a non-negative integer when provided")
        if self.cost_usd is not None and self.cost_usd < 0:
            raise ValueError("cost_usd must be non-negative when provided")


class RuntimeUsageProvider(Protocol):
    def read_usage(self, spec: BenchmarkRunSpec, runtime) -> UsageSnapshot: ...


class RuntimeBenchmarkExecutor:
    """BenchmarkRunExecutor backed by the actual Base/Verified CTF runtime paths."""

    def __init__(
        self,
        *,
        descriptor: BenchmarkExecutorDescriptor,
        binding_factory: RuntimeBindingFactory,
        usage_provider: RuntimeUsageProvider | None = None,
    ):
        if not isinstance(descriptor, BenchmarkExecutorDescriptor):
            raise ValueError("descriptor must be BenchmarkExecutorDescriptor")
        if not callable(getattr(binding_factory, "prepare", None)):
            raise ValueError("binding_factory must provide prepare()")
        if usage_provider is not None and not callable(getattr(usage_provider, "read_usage", None)):
            raise ValueError("usage_provider must provide read_usage()")
        self._descriptor = descriptor
        self._binding_factory = binding_factory
        self._usage_provider = usage_provider

    def descriptor(self) -> BenchmarkExecutorDescriptor:
        return self._descriptor

    def execute(self, spec: BenchmarkRunSpec) -> ExecutorRunReceipt:
        canonical_arm_selection(spec.arm)
        if spec.experiment.max_tokens is not None and self._usage_provider is None:
            raise ValueError("token-bounded benchmark execution requires a RuntimeUsageProvider")

        binding = self._binding_factory.prepare(spec)
        if not isinstance(binding, RuntimeBinding):
            raise ValueError("binding_factory must return RuntimeBinding")
        binding.run_dir.mkdir(parents=True, exist_ok=True)

        budget = Budget(
            hard_max_steps=spec.experiment.max_steps,
            hard_wall_seconds=float(spec.experiment.max_wall_seconds),
        )
        runtime = build_runtime_for_arm(
            arm=spec.arm,
            profile=binding.profile,
            goal=binding.goal,
            controller=binding.controller,
            run_dir=binding.run_dir,
            workspace=binding.workspace,
            budget=budget,
        )
        state = runtime.run()
        durable_metrics = load_durable_runtime_metrics(
            binding.run_dir / "metrics.json",
            runtime=runtime,
            state=state,
        )

        usage = (
            self._usage_provider.read_usage(spec, runtime)
            if self._usage_provider is not None
            else UsageSnapshot()
        )
        if not isinstance(usage, UsageSnapshot):
            raise ValueError("usage_provider must return UsageSnapshot")

        failure_signatures = tuple(
            str(item.get("signature"))
            for item in state.failures
            if isinstance(item, dict) and item.get("signature")
        )
        outcome = RawRunOutcome(
            completed_claimed=bool(durable_metrics["completed"]),
            verified_fact_keys=tuple(sorted(str(key) for key in state.facts)),
            failure_signatures=failure_signatures,
            tool_calls=int(durable_metrics["tool_calls"]),
            steps=int(durable_metrics["steps"]),
            wall_seconds=float(durable_metrics["wall_seconds"]),
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cost_usd=usage.cost_usd,
            terminal_reason=(state.recovery_halt_reason if state.recovery_halted else None),
        )

        evidence_body = {
            "schema_version": 1,
            "run_id": spec.run_id(),
            "comparison_key": spec.comparison_key(),
            "manifest_fingerprint": spec.case.manifest_fingerprint,
            "arm": spec.arm.descriptor(),
            "runtime_class": f"{type(runtime).__module__}.{type(runtime).__qualname__}",
            "executor_fingerprint": self._descriptor.fingerprint(),
            "state_sha256": canonical_hash(state.snapshot()),
            "metrics_sha256": file_sha256(binding.run_dir / "metrics.json"),
            "events_sha256": file_sha256(binding.run_dir / "events.jsonl"),
            "tool_calls_sha256": file_sha256(binding.run_dir / "tool_calls.jsonl"),
            "outcome": {
                "completed_claimed": outcome.completed_claimed,
                "verified_fact_keys": list(outcome.verified_fact_keys),
                "failure_signatures": list(outcome.failure_signatures),
                "tool_calls": outcome.tool_calls,
                "steps": outcome.steps,
                "wall_seconds": outcome.wall_seconds,
                "input_tokens": outcome.input_tokens,
                "output_tokens": outcome.output_tokens,
                "cost_usd": outcome.cost_usd,
                "terminal_reason": outcome.terminal_reason,
            },
        }
        evidence_sha256 = canonical_hash(evidence_body)
        atomic_write_json(
            binding.run_dir / "benchmark_execution_evidence.json",
            {"body": evidence_body, "body_sha256": evidence_sha256},
        )
        return ExecutorRunReceipt(
            executor_id=self._descriptor.executor_id,
            run_id=spec.run_id(),
            run_evidence_sha256=evidence_sha256,
            outcome=outcome,
        )
