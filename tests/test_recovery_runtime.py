from __future__ import annotations

import pytest

from harness.core.contracts import GoalContract
from harness.core.controller import ScriptedController
from harness.core.failures import FailureKind, RecoveryAction
from harness.core.sandbox import RecordingIsolatedTestBackend
from harness.core.state import Observation
from harness.core.storage import IntegrityError

from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.recovery.adapter import CTFFailureKind, map_failure, mappings_descriptor
from ctf_harness.runtime import VerifiedCTFRuntime


def _runtime(tmp_path, *, name="run"):
    workspace = tmp_path / f"workspace-{name}"
    workspace.mkdir()
    runtime = VerifiedCTFRuntime(
        goal=GoalContract(goal="exercise CTF recovery adapter", acceptance=["controlled assertions"]),
        profile=VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=RecordingIsolatedTestBackend(),
        ),
        controller=ScriptedController([]),
        run_dir=tmp_path / name,
    )
    return runtime


def _evidence(runtime, *, name="failure.json", payload=None, source="ctf_control_probe"):
    payload = payload or {"observed": "controlled failure"}
    ref = runtime.artifacts.put_json(name, payload)
    runtime.state.artifacts.append(ref)
    runtime.state.evidence_refs.append(ref)
    runtime.state.observations.append(Observation(
        step=runtime.state.step,
        source=source,
        ok=True,
        preview=payload,
        artifact_ref=ref,
    ))
    return ref


def test_failure_taxonomy_covers_roadmap_and_is_typed():
    descriptor = mappings_descriptor()
    assert set(descriptor) == {kind.value for kind in CTFFailureKind}
    assert map_failure("ENVIRONMENT_MISMATCH").core_failure is FailureKind.ENV_ERROR
    assert map_failure("FLAG_REJECTED").core_failure is FailureKind.VERIFICATION_FAILED
    assert map_failure("FLAG_REJECTED").target == "return_to_proof"
    assert map_failure("TOOL_MISSING").target == "install_or_substitute_tool"
    # These are CTF sidecar/routing states, not Core logical hypothesis keys;
    # routing them to Core HYPOTHESIS_REFUTED would misuse ROLLBACK target semantics.
    assert map_failure("HYPOTHESIS_REFUTED").core_failure is FailureKind.NO_PROGRESS
    assert map_failure("HYPOTHESIS_REFUTED").target == "close_branch"
    assert map_failure("CATEGORY_MISCLASSIFIED").core_failure is FailureKind.NO_PROGRESS
    assert map_failure("CATEGORY_MISCLASSIFIED").target == "category_switch"
    with pytest.raises(ValueError, match="unknown CTF failure kind"):
        map_failure("UNKNOWN")


def test_recon_incomplete_maps_to_base_observe_and_preserves_facts(tmp_path):
    runtime = _runtime(tmp_path)
    facts_before = runtime.state.facts.copy()
    ref = _evidence(runtime, payload={"missing": "protocol framing"})

    transition = runtime.report_ctf_failure(
        CTFFailureKind.RECON_INCOMPLETE,
        message="protocol framing is not yet determined",
        subject="remote_protocol",
        evidence_refs=[ref],
    )
    assert transition.failure_kind is FailureKind.MISSING_INFO
    assert transition.action is RecoveryAction.OBSERVE
    assert transition.target == "targeted_recon"
    assert runtime.state.failures[-1]["kind"] == FailureKind.MISSING_INFO.value
    assert runtime.state.facts == facts_before

    assert runtime.step_once() is True
    directive = runtime.state.recovery_directive
    assert directive is not None
    assert directive["action"] == RecoveryAction.OBSERVE.value
    assert directive["target"] == "targeted_recon"
    assert runtime.state.facts == facts_before


def test_ctf_sidecar_branch_change_maps_to_replan_not_core_rollback(tmp_path):
    runtime = _runtime(tmp_path, name="branch")
    transition = runtime.report_ctf_failure(
        "HYPOTHESIS_REFUTED",
        message="controlled sidecar hypothesis was refuted",
        subject="overflow_branch",
    )
    assert transition.failure_kind is FailureKind.NO_PROGRESS
    assert transition.action is RecoveryAction.REPLAN
    assert transition.target == "close_branch"
    runtime.step_once()
    assert runtime.state.recovery_directive["action"] == RecoveryAction.REPLAN.value
    assert runtime.state.recovery_directive["target"] == "close_branch"


def test_environment_mismatch_defaults_to_observe_not_unsafe_retry(tmp_path):
    runtime = _runtime(tmp_path)
    transition = runtime.report_ctf_failure(
        "ENVIRONMENT_MISMATCH",
        message="remote libc digest differs from local proof environment",
        subject="libc_sha256",
    )
    assert transition.failure_kind is FailureKind.ENV_ERROR
    assert transition.retry_safe is False
    assert transition.action is RecoveryAction.OBSERVE
    assert transition.target == "environment_adaptation"

    runtime.step_once()
    assert runtime.state.recovery_directive["action"] == RecoveryAction.OBSERVE.value
    assert runtime.state.recovery_directive["target"] == "environment_adaptation"


def test_explicit_retry_safe_environment_failure_uses_core_retry_route(tmp_path):
    runtime = _runtime(tmp_path)
    transition = runtime.report_ctf_failure(
        "TOOL_MISSING",
        message="controlled tool discovery service was temporarily unavailable",
        subject="tool_inventory",
        retry_safe=True,
    )
    assert transition.failure_kind is FailureKind.ENV_ERROR
    assert transition.retry_safe is True
    assert transition.action is RecoveryAction.RETRY
    runtime.step_once()
    assert runtime.state.recovery_directive["action"] == RecoveryAction.RETRY.value


def test_flag_rejected_maps_to_verification_replan_return_to_proof(tmp_path):
    runtime = _runtime(tmp_path)
    transition = runtime.report_ctf_failure(
        "FLAG_REJECTED",
        message="external task oracle rejected candidate",
        subject="flag_submission",
    )
    assert transition.failure_kind is FailureKind.VERIFICATION_FAILED
    assert transition.action is RecoveryAction.REPLAN
    assert transition.target == "return_to_proof"
    runtime.step_once()
    assert runtime.state.recovery_directive["action"] == RecoveryAction.REPLAN.value
    assert runtime.state.recovery_directive["target"] == "return_to_proof"


def test_repeat_threshold_and_strategy_generation_remain_base_owned(tmp_path):
    runtime = _runtime(tmp_path)
    actions = []
    generations = []
    for _ in range(3):
        transition = runtime.report_ctf_failure(
            "NO_INFORMATION_GAIN",
            message="controlled exploration produced no information gain",
            subject="overflow_branch",
        )
        actions.append(transition.action)
        runtime.step_once()
        generations.append(runtime.state.strategy_generation)

    assert actions == [
        RecoveryAction.REPLAN,
        RecoveryAction.REPLAN,
        RecoveryAction.SWITCH_STRATEGY,
    ]
    assert generations == [0, 0, 1]
    assert runtime.metrics["strategy_switches"] == 1
    assert runtime.metrics["ctf_mapped_failures"] == 3


def test_budget_exhausted_uses_base_terminal_checkpoint_stop(tmp_path):
    runtime = _runtime(tmp_path, name="budget")
    transition = runtime.report_ctf_failure(
        "BUDGET_EXHAUSTED",
        message="controlled CTF budget exhausted",
        subject="challenge_budget",
    )
    assert transition.failure_kind is FailureKind.BUDGET_EXCEEDED
    assert transition.action is RecoveryAction.CHECKPOINT_STOP
    assert transition.target == "checkpoint_stop"
    assert runtime.step_once() is True
    assert runtime.halted
    assert runtime.state.recovery_halted
    assert runtime.state.recovery_directive["action"] == RecoveryAction.CHECKPOINT_STOP.value


def test_unknown_kind_and_unregistered_evidence_fail_before_core_failure_mutation(tmp_path):
    runtime = _runtime(tmp_path)
    before = list(runtime.state.failures)
    with pytest.raises(ValueError, match="unknown CTF failure kind"):
        runtime.report_ctf_failure("UNKNOWN", message="not admissible")
    assert runtime.state.failures == before

    fake = "artifact://" + "0" * 64 + "_missing.json"
    with pytest.raises(IntegrityError):
        runtime.report_ctf_failure(
            "REMOTE_PROOF_FAILED",
            message="controlled failure with forged evidence ref",
            evidence_refs=[fake],
        )
    assert runtime.state.failures == before


def test_mapping_event_is_hash_chained_and_has_no_truth_authority(tmp_path):
    runtime = _runtime(tmp_path)
    ref = _evidence(runtime)
    runtime.report_ctf_failure(
        "LOCAL_PROOF_FAILED",
        message="controlled local proof failed",
        subject="exploit_v1",
        evidence_refs=[ref],
    )

    mapped = [event for event in runtime.events.verify_chain() if event.get("kind") == "ctf.failure.mapped"]
    assert len(mapped) == 1
    payload = mapped[0]["payload"]
    assert payload["ctf_failure_kind"] == "LOCAL_PROOF_FAILED"
    assert payload["core_failure_kind"] == FailureKind.VERIFICATION_FAILED.value
    assert payload["base_recovery_action"] == RecoveryAction.REPLAN.value
    assert payload["recovery_target"] == "proof_strategy_switch"
    assert payload["evidence_refs"] == [ref]
    assert payload["truth_authority"] == "none"
    assert runtime.state.facts == {}
