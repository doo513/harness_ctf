from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.controller import Decision, ScriptedController
from harness.core.runtime import HarnessRuntime
from harness.core.sandbox import RecordingIsolatedTestBackend
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.proof.flag_oracle import ExternalFlagOracle, FlagReceiptCompletionOracle, FlagSubmissionReceipt
from ctf_harness.proof.ladder import proof_level_from_verified_keys
from ctf_harness.proof.models import ProofLevel

CHALLENGE_ID = "synthetic-pwn-final"
REVISION = "rev-2026-08-17"
TARGET = "tcp://challenge.invalid:31337"
CANDIDATE = "FLAG{p6_plaintext_must_not_persist_513}"
RESPONSE_REF = "synthetic-ctfd:submission:accepted:513"


def goal() -> GoalContract:
    return GoalContract(
        goal="Obtain an externally accepted task-native flag.",
        acceptance=["external acceptance"],
        constraints=["flag shape is not success"],
        pinned_constraints=["only the configured external receipt can complete the task"],
        task_id=CHALLENGE_ID,
    )


def completion_for(receipt):
    return FlagReceiptCompletionOracle(
        challenge_id=CHALLENGE_ID,
        challenge_revision=REVISION,
        target=TARGET,
        receipt_provider=lambda: receipt,
        provider_id="controlled-platform-adapter-v1",
    )


def runtime_for(root: Path, receipt, name: str) -> HarnessRuntime:
    workspace = root / f"workspace-{name}"
    workspace.mkdir()
    profile = VerifiedCTFProfile(
        workspace=workspace,
        execution_backend=RecordingIsolatedTestBackend(),
        flag_completion_oracle=completion_for(receipt),
    )
    return HarnessRuntime(
        goal=goal(),
        profile=profile,
        controller=ScriptedController([Decision("complete", {"reason": "external submission receipt available"})]),
        run_dir=root / f"run-{name}",
    )


def main() -> int:
    submission = ExternalFlagOracle(lambda candidate: (candidate == CANDIDATE, RESPONSE_REF))
    accepted = submission.submit(
        CHALLENGE_ID,
        TARGET,
        CANDIDATE,
        challenge_revision=REVISION,
    )
    assert accepted.accepted
    assert accepted.candidate_hash == hashlib.sha256(CANDIDATE.encode()).hexdigest()
    assert accepted.oracle_response_ref_hash == hashlib.sha256(RESPONSE_REF.encode()).hexdigest()

    with tempfile.TemporaryDirectory(prefix="ctf-p6-completion-") as td:
        root = Path(td)
        good = runtime_for(root, accepted, "accepted")
        good.step_once()
        assert good.state.completed
        assert proof_level_from_verified_keys(set(), completed=True) == ProofLevel.P6_ACCEPTED
        completion_ref = good.state.artifacts[-1]
        completion_bytes = good.artifacts.verified_read_bytes(completion_ref)
        completion_text = completion_bytes.decode("utf-8")
        completion_data = json.loads(completion_text)
        assert completion_data["accepted"] is True
        assert completion_data["independence_level"] == "external_task_oracle_receipt"
        assert CANDIDATE not in completion_text
        assert RESPONSE_REF not in completion_text
        assert accepted.candidate_hash in completion_text
        assert accepted.oracle_response_ref_hash in completion_text

        rejected = FlagSubmissionReceipt(
            candidate_hash=accepted.candidate_hash,
            challenge_id=accepted.challenge_id,
            target=accepted.target,
            submitted_at_ns=accepted.submitted_at_ns,
            accepted=False,
            challenge_revision=accepted.challenge_revision,
            oracle_response_ref_hash=None,
        )
        bad = runtime_for(root, rejected, "rejected")
        bad.step_once()
        assert not bad.state.completed

        wrong_revision = FlagReceiptCompletionOracle(
            challenge_id=CHALLENGE_ID,
            challenge_revision="other-revision",
            target=TARGET,
            receipt_provider=lambda: accepted,
            provider_id="controlled-platform-adapter-v1",
        ).evaluate(goal=goal(), state=None, workspace=None)
        assert not wrong_revision.accepted

        wrong_target = FlagReceiptCompletionOracle(
            challenge_id=CHALLENGE_ID,
            challenge_revision=REVISION,
            target="tcp://other.invalid:31337",
            receipt_provider=lambda: accepted,
            provider_id="controlled-platform-adapter-v1",
        ).evaluate(goal=goal(), state=None, workspace=None)
        assert not wrong_target.accepted

        wrong_task = completion_for(accepted).evaluate(
            goal=GoalContract(goal="x", acceptance=["external acceptance"], task_id="other-task"),
            state=None,
            workspace=None,
        )
        assert not wrong_task.accepted

        no_revision = submission.submit(CHALLENGE_ID, TARGET, CANDIDATE)
        malformed_revision = completion_for(no_revision).evaluate(goal=goal(), state=None, workspace=None)
        assert not malformed_revision.accepted

        print(json.dumps({
            "probe": "pwn-flag-completion-core-integrated",
            "all_passed": True,
            "runtime_completed": good.state.completed,
            "rejected_receipt_completed": bad.state.completed,
            "proof_level": ProofLevel.P6_ACCEPTED.value,
            "oracle_checks": good.metrics["oracle_checks"],
            "completion_requests": good.metrics["completion_requests"],
            "candidate_hash": accepted.candidate_hash,
            "response_ref_hash": accepted.oracle_response_ref_hash,
            "challenge_id": accepted.challenge_id,
            "challenge_revision": accepted.challenge_revision,
            "target": accepted.target,
            "oracle_id": completion_data["oracle_id"],
            "independence_level": completion_data["independence_level"],
            "plaintext_candidate_persisted": False,
            "plaintext_response_ref_persisted": False,
            "wrong_revision_rejected": True,
            "wrong_target_rejected": True,
            "wrong_task_id_rejected": True,
            "missing_revision_rejected": True,
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
