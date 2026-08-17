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
    RemoteTargetSpec,
    RemoteTransport,
    SolveSpec,
)
from ctf_harness.profile import VerifiedCTFProfile


@dataclass(frozen=True)
class SolveRuntimeBinding:
    """Operator wiring checked against one immutable SolveSpec.

    `target_relpath` is an execution location only for local targets. Remote
    targets must leave it unset and are bound through the profile's admitted
    RemoteTcpRunner. Challenge/target identity remains owned by SolveSpec.
    """

    profile: VerifiedCTFProfile
    goal: GoalContract
    controller: CTFLLMController
    workspace: Path
    run_dir: Path
    target_relpath: str | None
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
        if self.target_relpath is not None:
            if not isinstance(self.target_relpath, str) or not self.target_relpath.strip():
                raise ValueError("solve binding target_relpath must be non-empty when provided")
            raw = Path(self.target_relpath)
            if raw.is_absolute():
                raise ValueError("solve binding target_relpath must be workspace-relative")
        if not isinstance(self.agent, AgentSpec):
            raise ValueError("solve binding agent must be AgentSpec")
        if not isinstance(self.oracle_policy_id, str) or not self.oracle_policy_id.strip():
            raise ValueError("solve binding oracle_policy_id must be non-empty")
        workspace = self.workspace.resolve()
        if not workspace.exists() or not workspace.is_dir():
            raise ValueError("solve binding workspace must exist")
        if self.target_relpath is not None:
            resolved_target = (workspace / Path(self.target_relpath)).resolve(strict=True)
            try:
                resolved_target.relative_to(workspace)
            except ValueError as exc:
                raise ValueError("solve binding target_relpath escapes workspace") from exc
            if not resolved_target.is_file():
                raise ValueError("solve binding target_relpath must resolve to a regular file")
        if self.run_dir.exists():
            if not self.run_dir.is_dir():
                raise ValueError("solve binding run_dir must be a directory when it exists")
            if any(self.run_dir.iterdir()):
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
    """Operational orchestration boundary over AgentCTFRuntime; no truth writes."""

    schema_version = 2

    def __init__(self, *, binding_factory: SolveBindingFactory):
        if not callable(getattr(binding_factory, "prepare", None)):
            raise ValueError("binding_factory must provide prepare(spec)")
        self.binding_factory = binding_factory

    @staticmethod
    def _validate_network_policy(spec: SolveSpec) -> SecurityConfig:
        if isinstance(spec.target, LocalTargetSpec):
            required = NetworkPolicy(False, False, False)
            if spec.network_policy != required:
                raise ValueError(
                    "local SolveEngine runs require network-isolated policy; "
                    "challenge/general/retrieval network must be disabled"
                )
        elif isinstance(spec.target, RemoteTargetSpec):
            required = NetworkPolicy(True, False, False)
            if spec.network_policy != required:
                raise ValueError(
                    "remote challenge runs require challenge_transport=true with "
                    "general_internet=false and external_retrieval=false"
                )
            if spec.target.credential_ref is not None:
                raise ValueError(
                    "credentialed remote target requires a credential-aware scoped transport provider"
                )
        else:
            raise ValueError("unsupported SolveSpec target type")

        # Keep arbitrary actor subprocess network denied in both modes. Remote
        # access occurs only through Harness-owned scoped transport tools.
        return SecurityConfig(
            strict_layout=True,
            strict_tool_isolation=False,
            network_policy="deny",
            allow_test_attestation=False,
            require_sealed_oracle=False,
        )

    @staticmethod
    def _validate_common_binding(spec: SolveSpec, binding: SolveRuntimeBinding) -> None:
        if binding.agent != spec.agent:
            raise ValueError("solve binding AgentSpec differs from SolveSpec")
        if binding.oracle_policy_id != spec.oracle_policy.policy_id:
            raise ValueError("solve binding oracle policy differs from SolveSpec")
        if spec.agent.controller_revision != binding.controller.revision:
            raise ValueError("SolveSpec controller_revision differs from bound controller implementation")
        if binding.goal.task_id != spec.challenge.challenge_id:
            raise ValueError("solve binding goal task_id differs from SolveSpec challenge_id")
        workspace = binding.workspace.resolve()
        if Path(binding.profile.workspace).resolve() != workspace:
            raise ValueError("solve profile workspace differs from binding workspace")

    @staticmethod
    def _validate_local_binding(spec: SolveSpec, binding: SolveRuntimeBinding) -> dict:
        if not isinstance(spec.target, LocalTargetSpec):
            raise TypeError("local binding validator requires LocalTargetSpec")
        if binding.target_relpath is None:
            raise ValueError("local SolveSpec requires a bound target_relpath")
        workspace = binding.workspace.resolve()
        profile_id = spec.target.runtime_profile_id
        runner = binding.profile.target_runners.get(profile_id)
        if runner is None:
            raise ValueError("SolveSpec target runtime profile is not registered in bound profile")
        if getattr(runner, "runtime_kind", None) is not spec.target.runtime_kind:
            raise ValueError("SolveSpec runtime kind differs from registered target runner")
        if binding.profile.default_target_profile_id != profile_id:
            raise ValueError("bound profile default target runtime differs from SolveSpec")

        target_relpath = Path(binding.target_relpath).as_posix()
        expected_sha = binding.profile.expected_target_sha256.get(target_relpath)
        if expected_sha != spec.target.target_sha256:
            raise ValueError("bound profile expected target SHA-256 differs from SolveSpec")
        launch = runner.build_launch(
            workspace=workspace,
            target_relpath=target_relpath,
            expected_target_sha256=spec.target.target_sha256,
        )
        if launch.target_sha256 != spec.target.target_sha256:
            raise ValueError("prepared target launch differs from SolveSpec target identity")
        return {
            "kind": "local",
            "artifact_ref": spec.target.artifact_ref,
            "target_relpath": target_relpath,
            "target_sha256": launch.target_sha256,
            "runtime_profile_id": profile_id,
            "runtime_kind": spec.target.runtime_kind.value,
            "runtime_fingerprint": launch.runtime_fingerprint(),
            "launch_fingerprint": launch.launch_fingerprint(),
        }

    @staticmethod
    def _validate_remote_binding(spec: SolveSpec, binding: SolveRuntimeBinding) -> dict:
        if not isinstance(spec.target, RemoteTargetSpec):
            raise TypeError("remote binding validator requires RemoteTargetSpec")
        if spec.target.transport is not RemoteTransport.TCP:
            raise ValueError("current SolveEngine remote binding supports admitted TCP transport only")
        if binding.target_relpath is not None:
            raise ValueError("remote SolveSpec must not bind a local target_relpath")
        runner = binding.profile.remote_tcp_runner
        if runner is None or binding.profile.remote_tcp_tool_runtime is None:
            raise ValueError("remote SolveSpec requires a bound RemoteTcpRunner tool")
        if runner.challenge.manifest_fingerprint != spec.challenge.manifest_fingerprint:
            raise ValueError("remote runner challenge identity differs from SolveSpec")
        if runner.target != spec.target:
            raise ValueError("remote runner target differs from SolveSpec")
        if runner.network_policy != spec.network_policy:
            raise ValueError("remote runner network policy differs from SolveSpec")
        if "remote_tcp" not in binding.profile.tools():
            raise ValueError("bound profile does not expose admitted remote_tcp capability")
        description = runner.describe()
        return {
            "kind": "remote",
            "endpoint": spec.target.endpoint,
            "transport": spec.target.transport.value,
            "endpoint_id": description["endpoint_id"],
            "challenge_manifest_fingerprint": description["challenge_manifest_fingerprint"],
            "pinned_ips": description["pinned_ips"],
            "max_send_bytes": description["max_send_bytes"],
            "max_read_bytes": description["max_read_bytes"],
        }

    @classmethod
    def _validate_binding(cls, spec: SolveSpec, binding: SolveRuntimeBinding) -> dict:
        cls._validate_common_binding(spec, binding)
        if isinstance(spec.target, LocalTargetSpec):
            return cls._validate_local_binding(spec, binding)
        if isinstance(spec.target, RemoteTargetSpec):
            return cls._validate_remote_binding(spec, binding)
        raise ValueError("unsupported SolveSpec target type")

    def execute(self, spec: SolveSpec) -> SolveRunReceipt:
        if not isinstance(spec, SolveSpec):
            raise ValueError("spec must be SolveSpec")
        if spec.budget.max_tokens is not None:
            raise ValueError(
                "token-bounded SolveSpec requires a token-enforcing production model adapter; "
                "SolveEngine fails closed instead of post-hoc accounting"
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
        metrics = load_durable_runtime_metrics(run_dir / "metrics.json", runtime=runtime, state=state)

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
            "network_policy": spec.network_policy.descriptor(),
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
        atomic_write_json(run_dir / "solve_execution_evidence.json", {"body": evidence_body, "body_sha256": evidence_sha256})
        return SolveRunReceipt(
            schema_version=self.schema_version,
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
