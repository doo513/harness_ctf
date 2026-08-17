from __future__ import annotations

import pytest

from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    ActorCompleteBehavior,
    AgentSpec,
    LocalTargetSpec,
    NetworkPolicy,
    OperationalChallengeRef,
    OraclePolicy,
    RunIntent,
    RuntimeKind,
    SolveBudget,
    SolveSpec,
    TerminationPolicy,
    UnsupportedCapabilityBehavior,
)

CHAL_SHA = "a" * 64
RUNNER = "sha256:" + "f" * 64


def _challenge() -> OperationalChallengeRef:
    manifest = ChallengeManifest(
        challenge_id="run-intent-fixture",
        event="controlled",
        description="WP12 run intent fixture",
        artifact_refs=("chal",),
        remote_endpoints=(),
        category_hint="pwn",
        flag_format="flag{...}",
        allowed_network=False,
        allowed_tools=("pwn_recon",),
        runner_image_digest=RUNNER,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    return OperationalChallengeRef.from_manifest(manifest, {"chal": CHAL_SHA})


def _spec(**changes) -> SolveSpec:
    values = {
        "challenge": _challenge(),
        "target": LocalTargetSpec(
            artifact_ref="chal",
            target_sha256=CHAL_SHA,
            architecture="x86_64",
            runtime_kind=RuntimeKind.NATIVE,
            runtime_profile_id="native-default",
        ),
        "agent": AgentSpec("fixture", "model", "r1", "controller-r1"),
        "budget": SolveBudget(20, 60.0, 10000),
        "network_policy": NetworkPolicy(False, False, False),
        "oracle_policy": OraclePolicy("external-v1"),
    }
    values.update(changes)
    return SolveSpec(**values)


def test_default_solve_intent_keeps_external_oracle_completion() -> None:
    spec = _spec()
    assert spec.run_intent is RunIntent.SOLVE
    assert spec.termination_policy is not None
    assert spec.termination_policy.actor_complete is ActorCompleteBehavior.CHECK_EXTERNAL_ORACLE
    assert spec.termination_policy.unsupported_capability is UnsupportedCapabilityBehavior.RECOVER
    assert spec.descriptor()["termination_policy"]["completion_authority"] == "external_oracle_only"


def test_smoke_intent_halts_actor_complete_without_redefining_completion() -> None:
    spec = _spec(run_intent=RunIntent.SMOKE)
    assert spec.termination_policy is not None
    assert spec.termination_policy.actor_complete is ActorCompleteBehavior.HALT_INCOMPLETE
    assert spec.termination_policy.unsupported_capability is UnsupportedCapabilityBehavior.HALT_INCOMPLETE
    assert spec.descriptor()["termination_policy"]["completion_authority"] == "external_oracle_only"


def test_solve_and_competition_cannot_replace_external_oracle_with_actor_halt() -> None:
    weakening = TerminationPolicy(
        ActorCompleteBehavior.HALT_INCOMPLETE,
        UnsupportedCapabilityBehavior.RECOVER,
    )
    for intent in (RunIntent.SOLVE, RunIntent.COMPETITION):
        with pytest.raises(ValueError, match="cannot weaken or redefine completion authority"):
            _spec(run_intent=intent, termination_policy=weakening)


def test_smoke_cannot_convert_actor_complete_into_external_success_check() -> None:
    wrong = TerminationPolicy(
        ActorCompleteBehavior.CHECK_EXTERNAL_ORACLE,
        UnsupportedCapabilityBehavior.HALT_INCOMPLETE,
    )
    with pytest.raises(ValueError, match="cannot weaken or redefine completion authority"):
        _spec(run_intent=RunIntent.SMOKE, termination_policy=wrong)


def test_unsupported_capability_behavior_is_control_only_and_fingerprint_bound() -> None:
    default = _spec()
    stop_on_missing = _spec(
        termination_policy=TerminationPolicy(
            ActorCompleteBehavior.CHECK_EXTERNAL_ORACLE,
            UnsupportedCapabilityBehavior.HALT_INCOMPLETE,
        )
    )
    assert default.fingerprint() != stop_on_missing.fingerprint()
    assert stop_on_missing.descriptor()["termination_policy"]["completion_authority"] == "external_oracle_only"


def test_run_intent_changes_solve_fingerprint() -> None:
    assert _spec(run_intent=RunIntent.SOLVE).fingerprint() != _spec(run_intent=RunIntent.SMOKE).fingerprint()
    assert _spec(run_intent=RunIntent.SOLVE).fingerprint() != _spec(run_intent=RunIntent.COMPETITION).fingerprint()
