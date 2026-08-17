from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from harness.core.budget import Budget
from harness.core.storage import atomic_write_json, canonical_hash

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


def _file_sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_durable_metrics(path: Path, *, runtime, state) -> dict:
    """Load the Base-produced metrics.json and bind it back to the returned state.

    Base computes wall_seconds only in the persisted metrics snapshot; the mutable
    runtime.metrics dictionary is not the authoritative wall-time source.
    """
    if not path.exists() or not path.is_file():
        raise ValueError("runtime did not persist metrics.json")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime metrics.json is unreadable or invalid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("runtime metrics.json must contain an object")

    required = ("run_id", "steps", "tool_calls", "completed", "wall_seconds")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError("runtime metrics.json missing required fields: " + ", ".join(missing))

    if raw["run_id"] != getattr(runtime, "run_id", None):
        raise ValueError("runtime metrics.json is bound to a different Base runtime run_id")
    if not isinstance(raw["steps"], int) or isinstance(raw["steps"], bool) or raw["steps"] < 0:
        raise ValueError("runtime metrics steps must be a non-negative integer")
    if not isinstance(raw["tool_calls"], int) or isinstance(raw["tool_calls"], bool) or raw["tool_calls"] < 0:
        raise ValueError("runtime metrics tool_calls must be a non-negative integer")
    if not isinstance(raw["completed"], bool):
        raise ValueError("runtime metrics completed must be boolean")
    if (
        not isinstance(raw["wall_seconds"], (int, float))
        or isinstance(raw["wall_seconds"], bool)
        or not math.isfinite(float(raw["wall_seconds"]))
        or float(raw["wall_seconds"]) < 0
    ):
        raise ValueError("runtime metrics wall_seconds must be finite and non-negative")

    if raw["steps"] != int(state.step):
        raise ValueError("runtime metrics steps disagree with returned HarnessState")
    if raw["completed"] is not bool(state.completed):
        raise ValueError("runtime metrics completed disagrees with returned HarnessState")
    return raw


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

        # Base 0.9.1 owns runtime termination through hard_max_steps / hard_wall_seconds.
        # The evaluation contract keeps the public max_steps/max_wall_seconds vocabulary,
        # but the adapter must translate it rather than invent Base constructor fields.
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
        durable_metrics = _load_durable_metrics(
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
            "metrics_sha256": _file_sha256(binding.run_dir / "metrics.json"),
            "events_sha256": _file_sha256(binding.run_dir / "events.jsonl"),
            "tool_calls_sha256": _file_sha256(binding.run_dir / "tool_calls.jsonl"),
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
