from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from harness.core.budget import Budget
from harness.core.contracts import GoalContract
from harness.core.security import SecurityConfig
from harness.core.storage import atomic_write_json, canonical_hash

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.agent_runtime import AgentCTFRuntime
from ctf_harness.durable_runtime import file_sha256, load_durable_runtime_metrics
from ctf_harness.operational.models import (
    AgentSpec,
    LocalTargetSpec,
    NetworkPolicy,
    SolveSpec,
)
from ctf_harness.profile import VerifiedCTFProfile


@dataclass(frozen=True)
class SolveRuntimeBinding:
    """Operator-prepared objects that are checked against one immutable SolveSpec.

    The binding is wiring, not authority. SolveEngine verifies every field it can
    derive from the operational contract before creating the Base runtime.
    """

    profile: VerifiedCTFProfile
    goal: GoalContract
    controller: CTFLLMController
    workspace: Path
    run_dir: Path
    agent: AgentSpec
    oracle_policy_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.profile, VerifiedCTFProfile):
            raise ValueError("solve binding profile must be VerifiedCTFProfile")
        if not isinstance(self.goal, GoalContract):
            raise ValueError("solve binding goal must be GoalContract")
        if not isinstance(self.controller, CTFLLMController):
            raise ValueError("solve binding controller must be CTFLLMController")
        if not isinstance(self.workspace, Path) or not isinstance(self.run_dir, Path):
            raise ValueError("solve binding workspace/run_dir must be pathlib.Path")
        if not isinstance(self.agent, AgentSpec):
            raise ValueError("solve binding agent must be AgentSpec")
        if not isinstance(self.oracle_policy_id, str) or not self.oracle_policy_id.strip():
            raise ValueError("solve binding oracle_policy_id must be non-empty")
        workspace = self.workspace.resolve()
        if not workspace.exists() or not workspace.is_dir():
            raise ValueError("solve binding workspace must exist")
        if self.run_dir.exists() and any(self.run_dir.iterdir()):
            raise ValueError("solve binding run_dir must be empty before execution")


class SolveBindingFactory(Protocol):
    def prepare(self, spec: SolveSpec) -> SolveRuntimeBinding: ...


@dataclass(frozen=True)
class SolveRunReceipt:
    schema_version: int
    kind: str
    solve_spec_fingerprint: str
    base_run_id: str
    run_evidence_sha256: str
    completed: bool
    completion_requested: bool
    halted: bool
    steps: int
    tool_calls: int
    wall_seconds: float
    verified_fact_keys: tuple[str, ...]

    def descriptor(self) -> dict:
        data = asdict(self)
        data["verified_fact_keys"] = list(self.verified_fact_keys)
        return data


class SolveEngine:
    """Minimal production orchestration boundary over AgentCTFRuntime.

    This engine has no fact/proof/completion write path. `completed` in the
    returned receipt is a projection of the Base HarnessState after the normal
    External Oracle path.
    """

    schema_version = 1

    def __init__(self, *, binding_factory: SolveBindingFactory):
        if not callable(getattr(binding_factory, "prepare", None)):
            raise ValueError("binding_factory must provide prepare(spec)")
        self.binding_factory = binding_factory

    @staticmethod
    def _validate_network_policy(spec: SolveSpec) -> SecurityConfig:
        required = NetworkPolicy(
            challenge_transport=False,
            general_internet=False,
            external_retrieval=False,
        )
        if spec.network_policy != required:
            raise ValueError(
                "WP13 minimal SolveEngine supports only network-isolated local runs; "
                "remote/challenge transport integration is a later stage"
            )
        return SecurityConfig(
            strict_layout=True,
            strict_tool_isolation=False,
            network_policy="deny",
            allow_test_attestation=False,
            require_sealed_oracle=False,
        )

    @staticmethod
    def _validate_binding(spec: SolveSpec, binding: SolveRuntimeBinding) -> dict:
        if binding.agent != spec.agent:
            raise ValueError("solve binding AgentSpec differs from SolveSpec")
        if binding.oracle_policy_id != spec.oracle_policy.policy_id:
            raise ValueError("solve binding oracle policy differs from SolveSpec")
        if spec.agent.controller_revision != binding.controller.revision:
            raise ValueError("SolveSpec controller_revision differs from bound controller implementation")

        workspace = binding.workspace.resolve()
        profile_workspace = Path(binding.profile.workspace).resolve()
        if profile_workspace != workspace:
            raise ValueError("solve profile workspace differs from binding workspace")

        if not isinstance(spec.target, LocalTargetSpec):
            raise ValueError("WP13 minimal SolveEngine currently supports local targets only")

        profile_id = spec.target.runtime_profile_id
        runner = binding.profile.target_runners.get(profile_id)
        if runner is None:
            raise ValueError("SolveSpec target runtime profile is not registered in bound profile")
        if getattr(runner, "runtime_kind", None) is not spec.target.runtime_kind:
            raise ValueError("SolveSpec runtime kind differs from registered target runner")
        if binding.profile.default_target_profile_id != profile_id:
            raise ValueError("bound profile default target runtime differs from SolveSpec")

        expected_sha = binding.profile.expected_target_sha256.get(spec.target.artifact_ref)
        if expected_sha != spec.target.target_sha256:
            raise ValueError("bound profile expected target SHA-256 differs from SolveSpec")

        launch = runner.build_launch(
            workspace=workspace,
            target_relpath=spec.target.artifact_ref,
            expected_target_sha256=spec.target.target_sha256,
        )
        if launch.target_sha256 != spec.target.target_sha256:
            raise ValueError("prepared target launch differs from SolveSpec target identity")

        return {
            "target_sha256": launch.target_sha256,
            "runtime_profile_id": profile_id,
            "runtime_kind": spec.target.runtime_kind.value,
            "runtime_fingerprint": launch.runtime_fingerprint(),
            "launch_fingerprint": launch.launch_fingerprint(),
        }

    def execute(self, spec: SolveSpec) -> SolveRunReceipt:
        if not isinstance(spec, SolveSpec):
            raise ValueError("spec must be SolveSpec")
        if spec.budget.max_tokens is not None:
            raise ValueError(
                "token-bounded SolveSpec requires a token-enforcing production model adapter; "
                "WP13 minimal SolveEngine fails closed instead of post-hoc accounting"
            )

        binding = self.binding_factory.prepare(spec)
        if not isinstance(binding, SolveRuntimeBinding):
            raise ValueError("binding_factory must return SolveRuntimeBinding")
        security_config = self._validate_network_policy(spec)
        target_binding = self._validate_binding(spec, binding)

        run_dir = binding.run_dir.resolve()
        run_dir.mkdir(parents=True, exist_ok=True)
        budget = Budget(
            hard_max_steps=spec.budget.max_steps,
            hard_wall_seconds=float(spec.budget.max_wall_seconds),
        )
        runtime = AgentCTFRuntime(
            run_intent=spec.run_intent,
            termination_policy=spec.termination_policy,
            goal=binding.goal,
            profile=binding.profile,
            controller=binding.controller,
            run_dir=run_dir,
            workspace=binding.workspace,
            budget=budget,
            security_config=security_config,
            model_revision=spec.agent.model_revision,
            task_revision=spec.challenge.challenge_revision,
        )
        state = runtime.run()
        metrics = load_durable_runtime_metrics(
            run_dir / "metrics.json",
            runtime=runtime,
            state=state,
        )

        evidence_body = {
            "schema_version": self.schema_version,
            "kind": "ctf_solve_execution_evidence",
            "solve_spec_fingerprint": spec.fingerprint(),
            "challenge_manifest_fingerprint": spec.challenge.manifest_fingerprint,
            "challenge_revision": spec.challenge.challenge_revision,
            "target": spec.target.descriptor(),
            "target_binding": target_binding,
            "agent": spec.agent.descriptor(),
            "controller_class": f"{type(binding.controller).__module__}.{type(binding.controller).__qualname__}",
            "controller_revision": binding.controller.revision,
            "agent_identity_attestation": "operator_bound_only",
            "oracle_policy_id": spec.oracle_policy.policy_id,
            "run_intent": spec.run_intent.value,
            "termination_policy": spec.termination_policy.descriptor(),
            "goal_sha256": canonical_hash(asdict(binding.goal)),
            "base_budget": {
                "hard_max_steps": budget.hard_max_steps,
                "hard_wall_seconds": float(budget.hard_wall_seconds),
            },
            "base_run_id": runtime.run_id,
            "runtime_class": f"{type(runtime).__module__}.{type(runtime).__qualname__}",
            "state_sha256": canonical_hash(state.snapshot()),
            "run_manifest_sha256": file_sha256(run_dir / "run_manifest.json"),
            "metrics_sha256": file_sha256(run_dir / "metrics.json"),
            "events_sha256": file_sha256(run_dir / "events.jsonl"),
            "tool_calls_sha256": file_sha256(run_dir / "tool_calls.jsonl"),
            "outcome": {
                "completed": bool(state.completed),
                "completion_requested": bool(state.completion_requested),
                "halted": bool(runtime.halted),
                "steps": int(metrics["steps"]),
                "tool_calls": int(metrics["tool_calls"]),
                "wall_seconds": float(metrics["wall_seconds"]),
                "verified_fact_keys": sorted(str(key) for key in state.facts),
                "completion_authority": "base_runtime_external_oracle",
            },
        }
        evidence_sha256 = canonical_hash(evidence_body)
        atomic_write_json(
            run_dir / "solve_execution_evidence.json",
            {"body": evidence_body, "body_sha256": evidence_sha256},
        )
        return SolveRunReceipt(
            schema_version=1,
            kind="ctf_solve_run_receipt",
            solve_spec_fingerprint=spec.fingerprint(),
            base_run_id=runtime.run_id,
            run_evidence_sha256=evidence_sha256,
            completed=bool(state.completed),
            completion_requested=bool(state.completion_requested),
            halted=bool(runtime.halted),
            steps=int(metrics["steps"]),
            tool_calls=int(metrics["tool_calls"]),
            wall_seconds=float(metrics["wall_seconds"]),
            verified_fact_keys=tuple(sorted(str(key) for key in state.facts)),
        )
