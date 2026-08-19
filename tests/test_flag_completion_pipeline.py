from __future__ import annotations

import hashlib
import json

from harness.core.contracts import GoalContract
from harness.core.controller import Decision, ScriptedController
from harness.core.runtime import HarnessRuntime
from harness.core.sandbox import RecordingIsolatedTestBackend
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.proof.flag_oracle import ExternalFlagOracle, FlagReceiptCompletionOracle, FlagSubmissionReceipt
from ctf_harness.proof.ladder import proof_level_from_verified_keys
from ctf_harness.proof.models import ProofLevel


def _goal(task_id="pwn-final"):
    return GoalContract(
        goal="Obtain an externally accepted CTF flag.",
        acceptance=["task-native external acceptance"],
        constraints=["do not infer success from flag shape"],
        task_id=task_id,
    )


def _accepted_receipt(candidate="FLAG{never_persist_513}"):
    oracle = ExternalFlagOracle(lambda supplied: (supplied == candidate, "ctfd:submission:accepted:513"))
    return oracle.submit(
        "pwn-final",
        "tcp://challenge.example:31337",
        candidate,
        challenge_revision="rev-2026-08-17",
    )


def _completion(receipt):
    return FlagReceiptCompletionOracle(
        challenge_id="pwn-final",
        challenge_revision="rev-2026-08-17",
        target="tcp://challenge.example:31337",
        receipt_provider=lambda: receipt,
        provider_id="synthetic-ctfd-adapter-v1",
    )


def test_flag_submission_receipt_hashes_candidate_and_response_reference():
    candidate = "FLAG{never_persist_513}"
    response_ref = "ctfd:submission:accepted:513"
    receipt = _accepted_receipt(candidate)
    assert receipt.accepted
    assert receipt.candidate_hash == hashlib.sha256(candidate.encode()).hexdigest()
    assert receipt.oracle_response_ref_hash == hashlib.sha256(response_ref.encode()).hexdigest()
    rendered = repr(receipt)
    assert candidate not in rendered
    assert response_ref not in rendered


def test_p6_completion_oracle_binds_task_revision_target_and_acceptance():
    receipt = _accepted_receipt()
    oracle = _completion(receipt)
    result = oracle.evaluate(goal=_goal(), state=None, workspace=None)
    assert result.accepted
    assert result.independence_level == "external_task_oracle_receipt"
    assert result.coverage["external_acceptance"] == 1

    assert not oracle.evaluate(goal=_goal("different-task"), state=None, workspace=None).accepted
    assert not FlagReceiptCompletionOracle(
        challenge_id="pwn-final",
        challenge_revision="different-revision",
        target="tcp://challenge.example:31337",
        receipt_provider=lambda: receipt,
        provider_id="synthetic-ctfd-adapter-v1",
    ).evaluate(goal=_goal(), state=None, workspace=None).accepted
    assert not FlagReceiptCompletionOracle(
        challenge_id="pwn-final",
        challenge_revision="rev-2026-08-17",
        target="tcp://other.example:31337",
        receipt_provider=lambda: receipt,
        provider_id="synthetic-ctfd-adapter-v1",
    ).evaluate(goal=_goal(), state=None, workspace=None).accepted

    rejected = FlagSubmissionReceipt(
        candidate_hash=receipt.candidate_hash,
        challenge_id=receipt.challenge_id,
        target=receipt.target,
        submitted_at_ns=receipt.submitted_at_ns,
        accepted=False,
        challenge_revision=receipt.challenge_revision,
        oracle_response_ref_hash=None,
    )
    assert not _completion(rejected).evaluate(goal=_goal(), state=None, workspace=None).accepted


def test_p6_runtime_completion_requires_external_receipt_and_persists_no_plain_flag(tmp_path):
    candidate = "FLAG{never_persist_513}"
    response_ref = "ctfd:submission:accepted:513"
    receipt = _accepted_receipt(candidate)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    profile = VerifiedCTFProfile(
        workspace=workspace,
        execution_backend=RecordingIsolatedTestBackend(),
        flag_completion_oracle=_completion(receipt),
    )
    runtime = HarnessRuntime(
        goal=_goal(),
        profile=profile,
        controller=ScriptedController([Decision("complete", {"reason": "candidate submitted externally"})]),
        run_dir=tmp_path / "run",
    )
    runtime.step_once()
    assert runtime.state.completed
    assert proof_level_from_verified_keys(set(), completed=runtime.state.completed) == ProofLevel.P6_ACCEPTED
    assert runtime.metrics["oracle_checks"] == 1
    assert runtime.metrics["completion_requests"] == 1

    artifact_ref = runtime.state.artifacts[-1]
    payload = runtime.artifacts.verified_read_bytes(artifact_ref).decode("utf-8")
    parsed = json.loads(payload)
    assert parsed["accepted"] is True
    assert parsed["independence_level"] == "external_task_oracle_receipt"
    assert candidate not in payload
    assert response_ref not in payload
    assert receipt.candidate_hash in payload
    assert receipt.oracle_response_ref_hash in payload


def test_p6_runtime_rejected_receipt_does_not_complete(tmp_path):
    base = _accepted_receipt()
    rejected = FlagSubmissionReceipt(
        candidate_hash=base.candidate_hash,
        challenge_id=base.challenge_id,
        target=base.target,
        submitted_at_ns=base.submitted_at_ns,
        accepted=False,
        challenge_revision=base.challenge_revision,
        oracle_response_ref_hash=None,
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    runtime = HarnessRuntime(
        goal=_goal(),
        profile=VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=RecordingIsolatedTestBackend(),
            flag_completion_oracle=_completion(rejected),
        ),
        controller=ScriptedController([Decision("complete", {"reason": "unverified candidate"})]),
        run_dir=tmp_path / "run",
    )
    runtime.step_once()
    assert not runtime.state.completed
    assert runtime.metrics["oracle_checks"] == 1
    assert proof_level_from_verified_keys(set(), completed=False) is None
