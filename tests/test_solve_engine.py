from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.core.contracts import GoalContract
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend
from harness.core.storage import canonical_hash

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    AgentSpec,
    LocalTargetSpec,
    NetworkPolicy,
    OperationalChallengeRef,
    OraclePolicy,
    RunIntent,
    RuntimeKind,
    SolveBudget,
    SolveSpec,
)
from ctf_harness.operational.solve_engine import (
    SolveEngine,
    SolveRuntimeBinding,
)
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.target.runners import NativeRunner


TARGET_SHA = "a" * 64
RUNNER_IMAGE = "sha256:" + "f" * 64
CONTROLLER_REVISION = CTFLLMController.revision


class SequenceModel:
    def __init__(self, outputs: list[dict]):
        self.outputs = [json.dumps(item, sort_keys=True) for item in outputs]
        self.calls = 0

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        if not self.outputs:
            raise RuntimeError("model fixture exhausted")
        return self.outputs.pop(0)


def _hypothesis() -> dict:
    return {
        "id": "H1",
        "category": "pwn",
        "target": "chal",
        "vulnerability_class": "unknown",
        "primitive": "controlled_surface",
        "claim": "controlled target should be executed once",
        "evidence_refs": [],
    }


def _tool() -> dict:
    return {
        "kind": "tool",
        "payload": {
            "tool": "argv",
            "args": {"argv": ["./chal", "open-sesame"]},
            "ctf_hypothesis": _hypothesis(),
        },
    }


def _complete(reason: str = "request independent acceptance") -> dict:
    return {"kind": "complete", "payload": {"reason": reason}}


def _challenge() -> OperationalChallengeRef:
    manifest = ChallengeManifest(
        challenge_id="solve-engine-fixture",
        event="controlled",
        description="WP13 SolveEngine fixture",
        artifact_refs=("chal",),
        remote_endpoints=(),
        category_hint="pwn",
        flag_format="flag{...}",
        allowed_network=False,
        allowed_tools=("argv", "pwn_recon", "pwn_crash_probe", "pwn_control_probe"),
        runner_image_digest=RUNNER_IMAGE,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    return OperationalChallengeRef.from_manifest(manifest, {"chal": TARGET_SHA})


def _agent(**changes) -> AgentSpec:
    values = {
        "provider": "controlled",
        "model_id": "fixture-model",
        "model_revision": "model-r1",
        "controller_revision": CONTROLLER_REVISION,
    }
    values.update(changes)
    return AgentSpec(**values)


def _spec(*, intent: RunIntent = RunIntent.SOLVE, budget: SolveBudget | None = None, agent: AgentSpec | None = None, network: NetworkPolicy | None = None) -> SolveSpec:
    return SolveSpec(
        challenge=_challenge(),
        target=LocalTargetSpec(
            artifact_ref="chal",
            target_sha256=TARGET_SHA,
            architecture="x86_64",
            runtime_kind=RuntimeKind.NATIVE,
            runtime_profile_id="fixture-native",
        ),
        agent=agent or _agent(),
        budget=budget or SolveBudget(20, 60.0, None),
        network_policy=network or NetworkPolicy(False, False, False),
        oracle_policy=OraclePolicy("fixture-oracle"),
        run_intent=intent,
    )


def _prepare_files(root: Path) -> tuple[Path, Path]:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    target = workspace / "chal"
    # Bytes deliberately chosen to match the fixture SHA only through the profile
    # binding helper below, where tests may override the expected identity.
    target.write_bytes(b"controlled-target")
    target.chmod(0o755)
    return workspace, target


def _actual_sha(path: Path) -> str:
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bound_spec(root: Path, *, intent: RunIntent = RunIntent.SOLVE, budget: SolveBudget | None = None, agent: AgentSpec | None = None, network: NetworkPolicy | None = None):
    workspace, target = _prepare_files(root)
    actual = _actual_sha(target)
    manifest = ChallengeManifest(
        challenge_id="solve-engine-fixture",
        event="controlled",
        description="WP13 SolveEngine fixture",
        artifact_refs=("chal",),
        remote_endpoints=(),
        category_hint="pwn",
        flag_format="flag{...}",
        allowed_network=False,
        allowed_tools=("argv", "pwn_recon", "pwn_crash_probe", "pwn_control_probe"),
        runner_image_digest=RUNNER_IMAGE,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    challenge = OperationalChallengeRef.from_manifest(manifest, {"chal": actual})
    spec = SolveSpec(
        challenge=challenge,
        target=LocalTargetSpec(
            artifact_ref="chal",
            target_sha256=actual,
            architecture="x86_64",
            runtime_kind=RuntimeKind.NATIVE,
            runtime_profile_id="fixture-native",
        ),
        agent=agent or _agent(),
        budget=budget or SolveBudget(20, 60.0, None),
        network_policy=network or NetworkPolicy(False, False, False),
        oracle_policy=OraclePolicy("fixture-oracle"),
        run_intent=intent,
    )
    return spec, workspace, actual


class Factory:
    def __init__(self, *, root: Path, spec: SolveSpec, model: SequenceModel, backend=None, oracle=None, agent=None, oracle_policy_id="fixture-oracle", profile_id="fixture-native", expected_sha=None):
        self.root = root
        self.spec = spec
        self.model = model
        self.backend = backend or RecordingIsolatedTestBackend({
            ("./chal", "open-sesame"): ExecutionResult(0, "CONTROLLED_OK\n", ""),
        })
        self.oracle = oracle or (lambda *, goal, state, workspace: True)
        self.agent = agent or spec.agent
        self.oracle_policy_id = oracle_policy_id
        self.profile_id = profile_id
        self.expected_sha = expected_sha or spec.target.target_sha256
        self.prepare_calls = 0

    def prepare(self, spec: SolveSpec) -> SolveRuntimeBinding:
        self.prepare_calls += 1
        profile = VerifiedCTFProfile(
            workspace=self.root / "workspace",
            execution_backend=self.backend,
            external_oracle=self.oracle,
            target_runners={self.profile_id: NativeRunner(self.profile_id)},
            default_target_profile_id=self.profile_id,
            expected_target_sha256={"chal": self.expected_sha},
        )
        return SolveRuntimeBinding(
            profile=profile,
            goal=GoalContract(
                goal="solve controlled native challenge",
                acceptance=["external oracle acceptance only"],
                task_id=spec.challenge.challenge_id,
            ),
            controller=CTFLLMController(self.model),
            workspace=self.root / "workspace",
            run_dir=self.root / "run",
            agent=self.agent,
            oracle_policy_id=self.oracle_policy_id,
        )


def test_solve_engine_binds_spec_runs_tool_and_accepts_only_via_oracle(tmp_path: Path) -> None:
    spec, workspace, actual = _bound_spec(tmp_path)
    model = SequenceModel([_tool(), _complete()])
    oracle_calls = {"count": 0}

    def oracle(*, goal, state, workspace):
        oracle_calls["count"] += 1
        return any(
            observation.ok
            and isinstance(observation.preview, dict)
            and observation.preview.get("stdout") == "CONTROLLED_OK\n"
            for observation in state.observations
        )

    factory = Factory(root=tmp_path, spec=spec, model=model, oracle=oracle)
    receipt = SolveEngine(binding_factory=factory).execute(spec)

    assert receipt.completed
    assert receipt.completion_requested
    assert not receipt.halted
    assert receipt.tool_calls == 1
    assert receipt.steps == 2
    assert oracle_calls["count"] == 1
    assert model.calls == 2
    assert receipt.solve_spec_fingerprint == spec.fingerprint()
    assert receipt.verified_fact_keys == ()

    evidence_path = tmp_path / "run" / "solve_execution_evidence.json"
    envelope = json.loads(evidence_path.read_text())
    assert canonical_hash(envelope["body"]) == envelope["body_sha256"]
    assert envelope["body_sha256"] == receipt.run_evidence_sha256
    body = envelope["body"]
    assert body["target_binding"]["target_sha256"] == actual
    assert body["target_binding"]["runtime_profile_id"] == "fixture-native"
    assert body["agent_identity_attestation"] == "operator_bound_only"
    assert body["outcome"]["completion_authority"] == "base_runtime_external_oracle"
    assert body["base_budget"] == {"hard_max_steps": 20, "hard_wall_seconds": 60.0}
    assert body["metrics_sha256"]
    assert body["events_sha256"]
    assert body["run_manifest_sha256"]


def test_solve_engine_smoke_complete_stays_incomplete_and_skips_oracle(tmp_path: Path) -> None:
    spec, _, _ = _bound_spec(tmp_path, intent=RunIntent.SMOKE)
    model = SequenceModel([_complete("smoke boundary")])
    calls = {"count": 0}

    def oracle(*, goal, state, workspace):
        calls["count"] += 1
        return True

    receipt = SolveEngine(binding_factory=Factory(root=tmp_path, spec=spec, model=model, oracle=oracle)).execute(spec)
    assert not receipt.completed
    assert not receipt.completion_requested
    assert receipt.halted
    assert calls["count"] == 0


def test_solve_engine_rejects_agent_binding_mismatch_before_model_call(tmp_path: Path) -> None:
    spec, _, _ = _bound_spec(tmp_path)
    model = SequenceModel([_complete()])
    factory = Factory(root=tmp_path, spec=spec, model=model, agent=_agent(model_revision="other"))
    with pytest.raises(ValueError, match="AgentSpec differs"):
        SolveEngine(binding_factory=factory).execute(spec)
    assert model.calls == 0


def test_solve_engine_rejects_controller_revision_mismatch(tmp_path: Path) -> None:
    spec, _, _ = _bound_spec(tmp_path, agent=_agent(controller_revision="wrong-controller"))
    model = SequenceModel([_complete()])
    with pytest.raises(ValueError, match="controller_revision"):
        SolveEngine(binding_factory=Factory(root=tmp_path, spec=spec, model=model)).execute(spec)
    assert model.calls == 0


def test_solve_engine_rejects_runtime_profile_and_target_hash_binding_mismatch(tmp_path: Path) -> None:
    spec, _, _ = _bound_spec(tmp_path)
    model = SequenceModel([_complete()])
    wrong_profile = Factory(root=tmp_path, spec=spec, model=model, profile_id="different-native")
    with pytest.raises(ValueError, match="runtime profile"):
        SolveEngine(binding_factory=wrong_profile).execute(spec)
    assert model.calls == 0

    wrong_hash = Factory(root=tmp_path, spec=spec, model=model, expected_sha="0" * 64)
    with pytest.raises(ValueError, match="expected target SHA-256"):
        SolveEngine(binding_factory=wrong_hash).execute(spec)
    assert model.calls == 0


def test_solve_engine_fails_closed_on_token_budget_without_enforcing_adapter(tmp_path: Path) -> None:
    spec, _, _ = _bound_spec(tmp_path, budget=SolveBudget(20, 60.0, 1000))

    class NeverPrepare:
        def __init__(self):
            self.calls = 0
        def prepare(self, spec):
            self.calls += 1
            raise AssertionError("must fail before binding preparation")

    factory = NeverPrepare()
    with pytest.raises(ValueError, match="token-enforcing"):
        SolveEngine(binding_factory=factory).execute(spec)
    assert factory.calls == 0


def test_solve_engine_fails_closed_on_network_enabled_minimal_spec(tmp_path: Path) -> None:
    spec, _, _ = _bound_spec(
        tmp_path,
        network=NetworkPolicy(challenge_transport=False, general_internet=True, external_retrieval=False),
    )
    model = SequenceModel([_complete()])
    with pytest.raises(ValueError, match="network-isolated local runs"):
        SolveEngine(binding_factory=Factory(root=tmp_path, spec=spec, model=model)).execute(spec)
    assert model.calls == 0


def test_solve_runtime_binding_rejects_nonempty_run_dir(tmp_path: Path) -> None:
    spec, _, _ = _bound_spec(tmp_path)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "stale").write_text("x")
    profile = VerifiedCTFProfile(
        workspace=tmp_path / "workspace",
        execution_backend=RecordingIsolatedTestBackend(),
        external_oracle=lambda *, goal, state, workspace: False,
        target_runners={"fixture-native": NativeRunner("fixture-native")},
        default_target_profile_id="fixture-native",
        expected_target_sha256={"chal": spec.target.target_sha256},
    )
    with pytest.raises(ValueError, match="run_dir must be empty"):
        SolveRuntimeBinding(
            profile=profile,
            goal=GoalContract(goal="x", acceptance=["y"]),
            controller=CTFLLMController(SequenceModel([_complete()])),
            workspace=tmp_path / "workspace",
            run_dir=run_dir,
            agent=spec.agent,
            oracle_policy_id="fixture-oracle",
        )
