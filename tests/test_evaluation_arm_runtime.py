from __future__ import annotations

import pytest

from harness.core.contracts import GoalContract
from harness.core.controller import Decision, ScriptedController
from harness.core.failures import Failure, FailureKind
from harness.core.runtime import HarnessRuntime
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend

from ctf_harness.evaluation.arm_runtime import (
    MinimalCTFBenchmarkRuntime,
    VerifiedCTFBenchmarkRuntime,
    build_runtime_for_arm,
    canonical_arm_selection,
)
from ctf_harness.evaluation.models import ArmConfig, BenchmarkArm
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.runtime import VerifiedCTFRuntime


def _goal():
    return GoalContract(goal="controlled benchmark arm runtime test", acceptance=["external oracle only"])


def _runtime(tmp_path, arm, *, run_name):
    backend = RecordingIsolatedTestBackend({
        ("probe", "arm"): ExecutionResult(0, "arm-ok", ""),
    })
    workspace = tmp_path / f"workspace-{run_name}"
    workspace.mkdir()
    profile = VerifiedCTFProfile(workspace=workspace, execution_backend=backend)
    runtime = build_runtime_for_arm(
        arm=arm,
        profile=profile,
        goal=_goal(),
        controller=ScriptedController([]),
        run_dir=tmp_path / run_name,
    )
    return runtime, backend


def test_canonical_selection_maps_only_two_first_ab_arms():
    minimal = canonical_arm_selection(ArmConfig.minimal())
    verified = canonical_arm_selection(ArmConfig.verified())
    assert minimal.arm is BenchmarkArm.MINIMAL
    assert minimal.semantic_verification_enabled is False
    assert minimal.ctf_hypothesis_guard_enabled is False
    assert minimal.ctf_typed_recovery_enabled is False
    assert minimal.ctf_task_progress_enabled is False
    assert minimal.proof_projection_enabled is False
    assert verified.arm is BenchmarkArm.VERIFIED
    assert verified.semantic_verification_enabled is True
    assert verified.ctf_hypothesis_guard_enabled is True
    assert verified.ctf_typed_recovery_enabled is True
    assert verified.ctf_task_progress_enabled is True
    assert verified.proof_projection_enabled is True

    partial = ArmConfig(
        arm=BenchmarkArm.VERIFIED,
        semantic_verification=True,
        proof_gate=True,
        hypothesis_guard=False,
        typed_recovery=True,
        task_progress=True,
    )
    with pytest.raises(ValueError, match="only canonical"):
        canonical_arm_selection(partial)


def test_minimal_uses_base_runtime_while_verified_uses_existing_ctf_runtime(tmp_path):
    minimal, _ = _runtime(tmp_path, ArmConfig.minimal(), run_name="minimal")
    verified, _ = _runtime(tmp_path, ArmConfig.verified(), run_name="verified")

    assert type(minimal) is MinimalCTFBenchmarkRuntime
    assert isinstance(minimal, HarnessRuntime)
    assert not isinstance(minimal, VerifiedCTFRuntime)
    assert type(verified) is VerifiedCTFBenchmarkRuntime
    assert isinstance(verified, VerifiedCTFRuntime)

    assert minimal.profile.task_progress_snapshot(minimal.state) is None
    assert not hasattr(minimal, "ctf_hypotheses")
    assert hasattr(verified, "ctf_hypotheses")


def test_minimal_tool_path_has_no_ctf_hypothesis_guard_but_verified_does(tmp_path):
    minimal, minimal_backend = _runtime(tmp_path, ArmConfig.minimal(), run_name="minimal-tool")
    verified, verified_backend = _runtime(tmp_path, ArmConfig.verified(), run_name="verified-tool")

    decision = Decision("tool", {"tool": "argv", "args": {"argv": ["probe", "arm"]}})
    minimal._dispatch_decision(decision)
    assert len(minimal_backend.calls) == 1
    assert minimal.metrics["tool_calls"] == 1

    verified._dispatch_decision(decision)
    assert len(verified_backend.calls) == 0
    assert verified.metrics["tool_calls"] == 0
    assert verified.metrics["ctf_hypothesis_guard_blocks"] == 1


def test_minimal_semantic_verification_cannot_commit_verified_fact(tmp_path):
    minimal, _ = _runtime(tmp_path, ArmConfig.minimal(), run_name="minimal-verify")
    claim_key = "ctf.pwn.crash_reproducible"
    minimal._dispatch_decision(Decision("propose", {
        "key": claim_key,
        "value": {"claimed": True},
        "evidence_refs": [],
    }))
    assert claim_key in minimal.state.hypotheses

    minimal._dispatch_decision(Decision("verify_claim", {"key": claim_key}))
    assert claim_key not in minimal.state.facts
    failure_record = minimal.state.failures[-1]
    assert failure_record["kind"] == "no_progress"
    assert failure_record["target"] == claim_key
    assert failure_record["message"] == "semantic verification is disabled in the canonical Minimal CTF Loop"
    expected = Failure(
        FailureKind.NO_PROGRESS,
        "semantic verification is disabled in the canonical Minimal CTF Loop",
        action=claim_key,
        signature_key="benchmark:minimal:semantic_verification_disabled",
    )
    assert failure_record["signature"] == expected.signature
