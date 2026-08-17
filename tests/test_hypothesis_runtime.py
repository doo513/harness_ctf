from __future__ import annotations

import json

import pytest

from harness.core.contracts import GoalContract
from harness.core.controller import Decision, ScriptedController
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend
from harness.core.state import Observation
from harness.core.storage import IntegrityError, canonical_hash

from ctf_harness.hypotheses.models import AttemptStatus, Hypothesis, HypothesisStatus
from ctf_harness.hypotheses.pool import DurableHypothesisLedger, HypothesisPool, fingerprint
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.runtime import VerifiedCTFRuntime


def _goal():
    return GoalContract(goal="exercise hypothesis guard", acceptance=["controlled test"])


def _accept_completion(*, goal, state, workspace):
    return True


def _meta(*, evidence_refs=None, hypothesis_id="h-overflow"):
    return {
        "id": hypothesis_id,
        "category": "pwn",
        "target": "bin/challenge",
        "vulnerability_class": "stack_overflow",
        "primitive": "rip_control",
        "claim": "input may control saved RIP",
        "evidence_refs": list(evidence_refs or []),
    }


def _decision(*, evidence_refs=None, action="same-action"):
    return Decision("tool", {
        "tool": "argv",
        "args": {"argv": ["probe", action]},
        "ctf_hypothesis": _meta(evidence_refs=evidence_refs),
    })


def _backend():
    return RecordingIsolatedTestBackend({
        ("probe", "same-action"): ExecutionResult(1, "", "deterministic failure"),
        ("probe", "evidence-action"): ExecutionResult(0, "evidence-v1", ""),
        ("probe", "evidence-new"): ExecutionResult(0, "evidence-v2", ""),
        ("probe", "adapted-action"): ExecutionResult(1, "", "adapted deterministic failure"),
        ("probe", "adapted-after-refute"): ExecutionResult(0, "should-not-run", ""),
    })


def _runtime(tmp_path, backend=None, *, run_name="run", controller=None, external_oracle=None):
    backend = backend or _backend()
    workspace = tmp_path / f"workspace-{run_name}"
    workspace.mkdir(exist_ok=True)
    runtime = VerifiedCTFRuntime(
        goal=_goal(),
        profile=VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=backend,
            external_oracle=external_oracle,
        ),
        controller=controller or ScriptedController([]),
        run_dir=tmp_path / run_name,
    )
    return runtime, backend


def _register_evidence(runtime, *, name, payload, source="pwn_recon"):
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


def _latest_stdout_ref(state, marker: str) -> str:
    for observation in reversed(state.observations):
        preview = observation.preview
        if isinstance(preview, dict) and preview.get("stdout") == marker and observation.artifact_ref:
            return observation.artifact_ref
    raise AssertionError(f"missing observation marker: {marker}")


class RecoveryAwareHypothesisController:
    """Deterministic Actor script that relies on Base recovery not consuming decisions."""

    def __init__(self):
        self.index = 0

    def snapshot_state(self):
        return {"index": self.index}

    def restore_state(self, raw):
        self.index = int(raw["index"])

    def decide(self, goal, state, context):
        stage = self.index
        self.index += 1
        if stage == 0:
            return _decision(action="same-action")
        if stage == 1:
            return _decision(action="same-action")
        if stage == 2:
            return _decision(action="evidence-action")
        if stage == 3:
            return _decision(
                action="adapted-action",
                evidence_refs=[_latest_stdout_ref(state, "evidence-v1")],
            )
        if stage == 4:
            return _decision(action="evidence-action")
        if stage == 5:
            return _decision(
                action="adapted-action",
                evidence_refs=[_latest_stdout_ref(state, "evidence-v1")],
            )
        if stage == 6:
            return _decision(action="evidence-new")
        if stage == 7:
            return _decision(
                action="adapted-action",
                evidence_refs=[_latest_stdout_ref(state, "evidence-v2")],
            )
        if stage == 8:
            contradiction = state.observations[-1].artifact_ref
            assert contradiction
            return Decision("refute", {
                "key": "h-overflow",
                "reason": "latest controlled execution contradicts this branch",
                "ctf_hypothesis": _meta(evidence_refs=[contradiction]),
            })
        if stage == 9:
            return _decision(
                action="adapted-after-refute",
                evidence_refs=[state.observations[-1].artifact_ref],
            )
        return Decision("complete", {"reason": "controlled integration assertions reached"})


def test_stable_hypothesis_fingerprint_excludes_evidence_state():
    one = Hypothesis(
        "h1", "pwn", "bin", "overflow", "rip", "control",
        evidence_refs=["artifact://one"], evidence_state_digest="1" * 64,
    )
    two = Hypothesis(
        "h2", "pwn", "bin", "overflow", "rip", "control",
        evidence_refs=["artifact://two"], evidence_state_digest="2" * 64,
    )
    assert fingerprint(one) == fingerprint(two)


def test_runtime_blocks_same_failed_action_before_second_backend_call(tmp_path):
    runtime, backend = _runtime(tmp_path)
    runtime._dispatch_decision(_decision())
    assert runtime.metrics["tool_calls"] == 1
    assert len(backend.calls) == 1
    assert runtime.ctf_hypotheses.pool.attempts[-1].status == AttemptStatus.FAILED

    runtime._dispatch_decision(_decision())
    assert runtime.metrics["tool_calls"] == 1
    assert len(backend.calls) == 1
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 1
    assert runtime.state.failures[-1]["kind"] == "no_progress"


def test_novel_evidence_reopens_guard_but_does_not_bypass_core_exact_receipt_dedupe(tmp_path):
    runtime, backend = _runtime(tmp_path)
    runtime._dispatch_decision(_decision())
    assert len(backend.calls) == 1

    ref = _register_evidence(runtime, name="recon-new.json", payload={"offset_candidate": 72})
    blocks_before = runtime.metrics["ctf_hypothesis_guard_blocks"]
    attempts_before = runtime.metrics["ctf_hypothesis_attempts"]
    receipt_dedup_before = runtime.metrics["receipt_deduplications"]
    runtime._dispatch_decision(_decision(evidence_refs=[ref]))

    # Evidence can reopen only the CTF guard. At the same Base step, the exact
    # non-idempotent execution is still governed by Core receipt replay.
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == blocks_before
    assert runtime.metrics["ctf_hypothesis_attempts"] == attempts_before + 1
    assert runtime.metrics["receipt_deduplications"] == receipt_dedup_before + 1
    assert len(backend.calls) == 1


def test_same_content_same_source_under_new_artifact_name_does_not_reopen(tmp_path):
    runtime, backend = _runtime(tmp_path)
    ref1 = _register_evidence(runtime, name="first.json", payload={"finding": "same"})
    runtime._dispatch_decision(_decision(evidence_refs=[ref1]))
    assert len(backend.calls) == 1

    ref2 = _register_evidence(runtime, name="second.json", payload={"finding": "same"})
    assert ref1 != ref2
    assert runtime._evidence_state([ref1]) == runtime._evidence_state([ref2])
    runtime._dispatch_decision(_decision(evidence_refs=[ref2]))
    assert len(backend.calls) == 1
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 1


def test_missing_or_unregistered_hypothesis_evidence_fails_before_execution(tmp_path):
    runtime, backend = _runtime(tmp_path)
    runtime._dispatch_decision(Decision("tool", {"tool": "argv", "args": {"argv": ["probe", "same-action"]}}))
    assert len(backend.calls) == 0
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 1

    bad = _decision(evidence_refs=["artifact://" + "0" * 64 + "_fake.json"])
    runtime._dispatch_decision(bad)
    assert len(backend.calls) == 0
    assert runtime.state.failures[-1]["kind"] == "persistence_error"


def test_explicit_ctf_refutation_requires_registered_evidence_and_closes_branch(tmp_path):
    runtime, backend = _runtime(tmp_path)
    runtime._dispatch_decision(_decision(action="evidence-action"))
    evidence_ref = runtime.state.observations[-1].artifact_ref
    assert evidence_ref

    runtime._dispatch_decision(Decision("refute", {
        "key": "h-overflow",
        "reason": "controlled contradiction",
        "ctf_hypothesis": _meta(evidence_refs=[evidence_ref]),
    }))
    fp, _ = runtime._parse_hypothesis(_meta(evidence_refs=[evidence_ref]))
    assert runtime.ctf_hypotheses.pool.hypotheses[fp].status == HypothesisStatus.REFUTED
    assert runtime.metrics["ctf_hypothesis_refutations"] == 1

    runtime._dispatch_decision(_decision(evidence_refs=[evidence_ref], action="adapted-after-refute"))
    assert len(backend.calls) == 1
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 1


def test_base_run_path_applies_recovery_and_blocks_duplicate_evidence_and_refuted_branch(tmp_path):
    controller = RecoveryAwareHypothesisController()
    runtime, backend = _runtime(
        tmp_path,
        controller=controller,
        external_oracle=_accept_completion,
        run_name="integration",
    )
    state = runtime.run()

    assert state.completed
    calls = [tuple(item["argv"]) for item in backend.calls]
    assert calls == [
        ("probe", "same-action"),
        ("probe", "evidence-action"),
        ("probe", "adapted-action"),
        ("probe", "evidence-action"),
        ("probe", "evidence-new"),
        ("probe", "adapted-action"),
    ]
    assert ("probe", "adapted-after-refute") not in calls
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 3
    assert runtime.metrics["ctf_hypothesis_refutations"] == 1
    assert runtime.metrics["ctf_hypothesis_attempts"] == 6
    assert runtime.metrics["recovery_transitions"] >= 6
    assert controller.index == 11

    body = runtime.ctf_hypotheses.pool.dump()
    assert len(body["hypotheses"]) == 1
    assert len(body["attempts"]) == 6
    only = next(iter(runtime.ctf_hypotheses.pool.hypotheses.values()))
    assert only.status == HypothesisStatus.REFUTED
    assert state.facts == {}


def test_durable_ledger_detects_tamper_and_marks_inflight_ambiguous(tmp_path):
    path = tmp_path / "ledger.json"
    pool = HypothesisPool()
    h = Hypothesis("h", "pwn", "bin", "overflow", "rip", "control", evidence_state_digest="e" * 64)
    fp = pool.add(h)
    attempt_id = pool.begin_attempt(fp, action_digest="a" * 64, evidence_state_digest="e" * 64, step=3)
    ledger = DurableHypothesisLedger(path, pool)
    source_hash = ledger.save()

    loaded = DurableHypothesisLedger.load(path)
    assert loaded.source_body_sha256 == source_hash
    attempt = next(item for item in loaded.pool.attempts if item.attempt_id == attempt_id)
    assert attempt.status == AttemptStatus.AMBIGUOUS
    assert canonical_hash(loaded.pool.dump()) != source_hash
    assert not loaded.pool.guard(fp, action_digest="a" * 64, evidence_state_digest="e" * 64).allowed

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["body"]["hypotheses"][fp]["claim"] = "tampered"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(IntegrityError, match="integrity mismatch"):
        DurableHypothesisLedger.load(path)


def test_resume_rejects_rollback_to_older_valid_hypothesis_ledger(tmp_path):
    backend = _backend()
    runtime, _ = _runtime(tmp_path, backend=backend, run_name="rollback")
    old_valid_envelope = runtime._ctf_hypothesis_ledger_path.read_text(encoding="utf-8")

    # The failure creates a Base checkpoint and newer hash-chained CTF ledger anchors.
    runtime._dispatch_decision(_decision())
    assert runtime.checkpoints.load_verified() is not None
    runtime._ctf_hypothesis_ledger_path.write_text(old_valid_envelope, encoding="utf-8")

    with pytest.raises(IntegrityError, match="rollback or unanchored"):
        VerifiedCTFRuntime.resume(
            goal=_goal(),
            profile=VerifiedCTFProfile(workspace=runtime.workspace, execution_backend=backend),
            controller=ScriptedController([]),
            run_dir=runtime.run_dir,
        )
