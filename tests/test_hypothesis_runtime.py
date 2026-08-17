from __future__ import annotations

import json

import pytest

from harness.core.contracts import GoalContract
from harness.core.controller import Decision, ScriptedController
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend
from harness.core.state import Observation
from harness.core.storage import IntegrityError

from ctf_harness.hypotheses.models import AttemptStatus, Hypothesis
from ctf_harness.hypotheses.pool import DurableHypothesisLedger, HypothesisPool, fingerprint
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.runtime import VerifiedCTFRuntime


def _goal():
    return GoalContract(goal="exercise hypothesis guard", acceptance=["controlled test"])


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


def _runtime(tmp_path, backend=None, *, run_name="run"):
    backend = backend or RecordingIsolatedTestBackend({
        ("probe", "same-action"): ExecutionResult(1, "", "deterministic failure"),
        ("probe", "adapted-action"): ExecutionResult(1, "", "adapted deterministic failure"),
    })
    workspace = tmp_path / f"workspace-{run_name}"
    workspace.mkdir()
    runtime = VerifiedCTFRuntime(
        goal=_goal(),
        profile=VerifiedCTFProfile(workspace=workspace, execution_backend=backend),
        controller=ScriptedController([]),
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

    # The CTF guard reopened the attempt because evidence changed, but the exact
    # tool+args execution identity is still governed by the stronger Base receipt
    # dedupe. WP06 must never bypass that Core side-effect/idempotency boundary.
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == blocks_before
    assert runtime.metrics["ctf_hypothesis_attempts"] == attempts_before + 1
    assert runtime.metrics["receipt_deduplications"] == receipt_dedup_before + 1
    assert len(backend.calls) == 1

    # A materially adapted action is a distinct Core execution identity and is
    # therefore allowed to execute under the new evidence state.
    runtime._dispatch_decision(_decision(evidence_refs=[ref], action="adapted-action"))
    assert len(backend.calls) == 2


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


def test_refuted_hypothesis_blocks_even_with_new_evidence(tmp_path):
    runtime, backend = _runtime(tmp_path)
    fp, hypothesis = runtime._parse_hypothesis(_meta())
    runtime.ctf_hypotheses.pool.add(hypothesis)
    runtime.ctf_hypotheses.pool.mark_refuted(fp)
    runtime.ctf_hypotheses.save()

    ref = _register_evidence(runtime, name="new.json", payload={"new": True})
    runtime._dispatch_decision(_decision(evidence_refs=[ref]))
    assert len(backend.calls) == 0
    assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 1


def test_durable_ledger_detects_tamper_and_marks_inflight_ambiguous(tmp_path):
    path = tmp_path / "ledger.json"
    pool = HypothesisPool()
    h = Hypothesis("h", "pwn", "bin", "overflow", "rip", "control", evidence_state_digest="e" * 64)
    fp = pool.add(h)
    attempt_id = pool.begin_attempt(fp, action_digest="a" * 64, evidence_state_digest="e" * 64, step=3)
    ledger = DurableHypothesisLedger(path, pool)
    ledger.save()

    loaded = DurableHypothesisLedger.load(path)
    attempt = next(item for item in loaded.pool.attempts if item.attempt_id == attempt_id)
    assert attempt.status == AttemptStatus.AMBIGUOUS
    assert not loaded.pool.guard(fp, action_digest="a" * 64, evidence_state_digest="e" * 64).allowed

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["body"]["hypotheses"][fp]["claim"] = "tampered"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(IntegrityError, match="integrity mismatch"):
        DurableHypothesisLedger.load(path)
