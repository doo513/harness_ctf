from __future__ import annotations

from pathlib import Path

import pytest
from harness.core.contracts import GoalContract
from harness.core.sandbox import RecordingIsolatedTestBackend

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    AgentSpec,
    NetworkPolicy,
    OperationalChallengeRef,
    OraclePolicy,
    RemoteTargetSpec,
    RemoteTransport,
    RunIntent,
    SolveBudget,
    SolveSpec,
)
from ctf_harness.operational.solve_engine import SolveEngine, SolveRuntimeBinding
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.target.remote import RemoteTcpRunner


class CompleteModel:
    def complete(self, *, system: str, user: str) -> str:
        return '{"kind":"complete","payload":{"reason":"controlled"}}'


def _challenge(endpoint: str) -> OperationalChallengeRef:
    manifest = ChallengeManifest(
        challenge_id="remote-bind-fixture",
        event="controlled",
        description="remote binding fixture",
        artifact_refs=(),
        remote_endpoints=(endpoint,),
        category_hint="pwn",
        flag_format="flag{...}",
        allowed_network=True,
        allowed_tools=("remote_tcp",),
        runner_image_digest="sha256:" + "8" * 64,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    return OperationalChallengeRef.from_manifest(manifest, {})


def _spec(endpoint: str, *, policy: NetworkPolicy | None = None) -> SolveSpec:
    challenge = _challenge(endpoint)
    agent = AgentSpec(
        provider="controlled",
        model_id="fixture",
        model_revision="r1",
        controller_revision=CTFLLMController.revision,
    )
    return SolveSpec(
        challenge=challenge,
        target=RemoteTargetSpec(endpoint=endpoint, transport=RemoteTransport.TCP),
        agent=agent,
        budget=SolveBudget(4, 10.0),
        network_policy=policy or NetworkPolicy(True, False, False),
        oracle_policy=OraclePolicy("fixture-oracle"),
        run_intent=RunIntent.COMPETITION,
    )


class Factory:
    def __init__(self, root: Path, spec: SolveSpec, *, runner_target: RemoteTargetSpec | None = None, target_relpath=None):
        self.root = root
        self.spec = spec
        self.runner_target = runner_target or spec.target
        self.target_relpath = target_relpath

    def prepare(self, spec: SolveSpec) -> SolveRuntimeBinding:
        runner = RemoteTcpRunner(
            spec.challenge,
            self.runner_target,
            network_policy=spec.network_policy,
            resolver=lambda host, port: ("127.0.0.1",),
        )
        profile = VerifiedCTFProfile(
            workspace=self.root / "workspace",
            execution_backend=RecordingIsolatedTestBackend(),
            external_oracle=lambda **kwargs: False,
            remote_tcp_runner=runner,
        )
        return SolveRuntimeBinding(
            profile=profile,
            goal=GoalContract(goal="remote", acceptance=["oracle"], task_id=spec.challenge.challenge_id),
            controller=CTFLLMController(CompleteModel()),
            workspace=self.root / "workspace",
            run_dir=self.root / "run",
            target_relpath=self.target_relpath,
            agent=spec.agent,
            oracle_policy_id=spec.oracle_policy.policy_id,
        )


def _root(tmp_path: Path):
    (tmp_path / "workspace").mkdir()
    return tmp_path


def test_remote_solve_rejects_general_internet_before_binding_execution(tmp_path: Path) -> None:
    endpoint = "tcp://fixture.invalid:31337"
    policy = NetworkPolicy(True, True, False)
    spec = _spec(endpoint, policy=policy)
    with pytest.raises(ValueError, match="general_internet=false"):
        SolveEngine(binding_factory=Factory(_root(tmp_path), spec)).execute(spec)


def test_remote_solve_rejects_local_target_path_binding(tmp_path: Path) -> None:
    endpoint = "tcp://fixture.invalid:31337"
    spec = _spec(endpoint)
    root = _root(tmp_path)
    (root / "workspace" / "chal").write_bytes(b"x")
    with pytest.raises(ValueError, match="must not bind a local target_relpath"):
        SolveEngine(binding_factory=Factory(root, spec, target_relpath="chal")).execute(spec)


def test_remote_solve_rejects_runner_target_identity_mismatch(tmp_path: Path) -> None:
    endpoint = "tcp://fixture.invalid:31337"
    spec = _spec(endpoint)
    wrong = RemoteTargetSpec(endpoint="tcp://fixture.invalid:31338", transport=RemoteTransport.TCP)
    # The wrong endpoint is not admitted by the challenge, so the runner itself
    # must fail closed even before SolveEngine can accept the binding.
    with pytest.raises(ValueError):
        SolveEngine(binding_factory=Factory(_root(tmp_path), spec, runner_target=wrong)).execute(spec)
