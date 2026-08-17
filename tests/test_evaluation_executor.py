from __future__ import annotations

from dataclasses import replace

import pytest

from ctf_harness.evaluation.corpus import case_from_manifest, freeze_corpus
from ctf_harness.evaluation.executor import (
    BenchmarkExecutorDescriptor,
    ExecutionBoundaryAttestation,
    ExecutorRunReceipt,
    execute_planned_run,
)
from ctf_harness.evaluation.models import (
    EvaluationMode,
    ExperimentContract,
    IndependentAdjudication,
    RawRunOutcome,
)
from ctf_harness.evaluation.policy import LeakagePolicy
from ctf_harness.evaluation.runner import BenchmarkPlan, paired_specs
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.proof.models import ProofLevel


RUNNER = "sha256:" + "a" * 64
RUN_EVIDENCE_SHA = "c" * 64


def _case(*, mode="research"):
    manifest = ChallengeManifest(
        challenge_id="executor-fixture",
        event="private-pilot",
        description="controlled executor fixture",
        runner_image_digest=RUNNER,
        challenge_revision="r1",
        category_hint="pwn",
        benchmark_policy=mode,
    )
    return case_from_manifest(manifest, {}, case_id="case-1", category="pwn")


def _experiment(*, mode=EvaluationMode.RESEARCH, max_steps=20, max_wall=30.0, max_tokens=100):
    return ExperimentContract(
        mode=mode,
        model_id="model-fixed",
        model_revision="model-r1",
        controller_revision="controller-r1",
        tool_inventory=("argv", "session"),
        sandbox_id="sandbox-r1",
        oracle_policy_id="oracle-r1",
        max_steps=max_steps,
        max_wall_seconds=max_wall,
        max_tokens=max_tokens,
        seed=1,
    )


def _plan(*, mode=EvaluationMode.RESEARCH):
    case = _case(mode=mode.value)
    experiment = _experiment(mode=mode)
    minimal, verified = paired_specs(case=case, experiment=experiment)
    corpus = freeze_corpus(
        name="executor-fixture",
        revision="r1",
        mode=mode,
        cases=(case,),
        unpublished=(mode is EvaluationMode.RESEARCH),
    )
    policy = LeakagePolicy.research() if mode is EvaluationMode.RESEARCH else LeakagePolicy.competition()
    return BenchmarkPlan(corpus, policy, (minimal, verified)), minimal, verified


def _descriptor(**changes):
    values = dict(
        executor_id="fixture-executor",
        model_id="model-fixed",
        model_revision="model-r1",
        controller_revision="controller-r1",
        tool_inventory=("argv", "session"),
        sandbox_id="sandbox-r1",
        oracle_policy_id="oracle-r1",
        web_search_enabled=False,
        external_retrieval_enabled=False,
        general_internet_egress_enabled=False,
        challenge_transport_only=True,
    )
    values.update(changes)
    return BenchmarkExecutorDescriptor(**values)


def _attestation(descriptor, **changes):
    values = dict(
        issuer_id="fixture-boundary-attestor",
        evidence_sha256="b" * 64,
        executor_fingerprint=descriptor.fingerprint(),
        sandbox_id=descriptor.sandbox_id,
        web_search_blocked=not descriptor.web_search_enabled,
        external_retrieval_blocked=not descriptor.external_retrieval_enabled,
        general_internet_egress_blocked=not descriptor.general_internet_egress_enabled,
        challenge_transport_scoped=descriptor.challenge_transport_only,
    )
    values.update(changes)
    return ExecutionBoundaryAttestation(**values)


def _outcome(**changes):
    values = dict(
        completed_claimed=True,
        verified_fact_keys=(),
        failure_signatures=(),
        tool_calls=3,
        steps=5,
        wall_seconds=4.0,
        input_tokens=20,
        output_tokens=10,
    )
    values.update(changes)
    return RawRunOutcome(**values)


class FakeExecutor:
    def __init__(self, descriptor, outcome=None, *, receipt_executor_id=None, receipt_run_id=None):
        self._descriptor = descriptor
        self.outcome = outcome or _outcome()
        self.receipt_executor_id = receipt_executor_id or descriptor.executor_id
        self.receipt_run_id = receipt_run_id
        self.calls = 0

    def descriptor(self):
        return self._descriptor

    def execute(self, spec):
        self.calls += 1
        return ExecutorRunReceipt(
            executor_id=self.receipt_executor_id,
            run_id=self.receipt_run_id or spec.run_id(),
            run_evidence_sha256=RUN_EVIDENCE_SHA,
            outcome=self.outcome,
        )


class FakeAdjudicator:
    def __init__(self, *, accepted=False, override_run_id=None, override_run_evidence=None):
        self.accepted = accepted
        self.override_run_id = override_run_id
        self.override_run_evidence = override_run_evidence
        self.calls = 0
        self.run_evidence_seen = None

    def adjudicate(self, spec, outcome, *, run_evidence_sha256):
        self.calls += 1
        self.run_evidence_seen = run_evidence_sha256
        return IndependentAdjudication(
            adjudicator_id="fixture-independent-adjudicator",
            evidence_sha256="d" * 64,
            run_id=self.override_run_id or spec.run_id(),
            run_evidence_sha256=self.override_run_evidence or run_evidence_sha256,
            oracle_accepted=self.accepted,
            highest_proof_level=(ProofLevel.P6_ACCEPTED if self.accepted else ProofLevel.P2_CONTROL),
        )


def test_valid_research_run_requires_attested_boundary_and_preserves_evidence_chain():
    plan, spec, _ = _plan()
    descriptor = _descriptor()
    executor = FakeExecutor(descriptor)
    adjudicator = FakeAdjudicator(accepted=False)
    record = execute_planned_run(
        plan=plan,
        spec=spec,
        executor=executor,
        boundary_attestation=_attestation(descriptor),
        adjudicator=adjudicator,
    )
    assert executor.calls == 1 and adjudicator.calls == 1
    assert adjudicator.run_evidence_seen == RUN_EVIDENCE_SHA
    assert record.run_id == spec.run_id()
    assert record.executor_id == descriptor.executor_id
    assert record.executor_fingerprint == descriptor.fingerprint()
    assert record.boundary_attestor_id == "fixture-boundary-attestor"
    assert record.boundary_evidence_sha256 == "b" * 64
    assert record.run_evidence_sha256 == RUN_EVIDENCE_SHA
    assert record.adjudicator_id == "fixture-independent-adjudicator"
    assert not record.success
    assert record.false_completion


@pytest.mark.parametrize(
    "descriptor",
    [
        _descriptor(model_revision="wrong-model"),
        _descriptor(tool_inventory=("argv",)),
        _descriptor(sandbox_id="wrong-sandbox"),
        _descriptor(oracle_policy_id="wrong-oracle"),
    ],
)
def test_executor_contract_mismatch_blocks_before_execute(descriptor):
    plan, spec, _ = _plan()
    executor = FakeExecutor(descriptor)
    adjudicator = FakeAdjudicator()
    with pytest.raises(ValueError, match="executor differs"):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=executor,
            boundary_attestation=_attestation(descriptor),
            adjudicator=adjudicator,
        )
    assert executor.calls == 0 and adjudicator.calls == 0


def test_wrong_boundary_fingerprint_blocks_before_execute():
    plan, spec, _ = _plan()
    descriptor = _descriptor()
    executor = FakeExecutor(descriptor)
    with pytest.raises(ValueError, match="different executor descriptor"):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=executor,
            boundary_attestation=_attestation(descriptor, executor_fingerprint="e" * 64),
            adjudicator=FakeAdjudicator(),
        )
    assert executor.calls == 0


@pytest.mark.parametrize(
    "descriptor,error",
    [
        (_descriptor(web_search_enabled=True), "web-search blocking"),
        (_descriptor(external_retrieval_enabled=True), "external-retrieval blocking"),
        (
            _descriptor(general_internet_egress_enabled=True, challenge_transport_only=False),
            "general-internet egress blocking",
        ),
        (_descriptor(challenge_transport_only=False), "scoped to challenge transport"),
    ],
)
def test_research_boundary_capabilities_block_before_execute(descriptor, error):
    plan, spec, _ = _plan()
    executor = FakeExecutor(descriptor)
    with pytest.raises(ValueError, match=error):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=executor,
            boundary_attestation=_attestation(descriptor),
            adjudicator=FakeAdjudicator(),
        )
    assert executor.calls == 0


@pytest.mark.parametrize(
    "outcome,error",
    [
        (_outcome(steps=21), "max_steps"),
        (_outcome(wall_seconds=31.0), "max_wall_seconds"),
        (_outcome(input_tokens=None, output_tokens=None), "requires measured"),
        (_outcome(input_tokens=80, output_tokens=30), "max_tokens"),
    ],
)
def test_budget_violation_blocks_before_adjudication(outcome, error):
    plan, spec, _ = _plan()
    descriptor = _descriptor()
    executor = FakeExecutor(descriptor, outcome)
    adjudicator = FakeAdjudicator()
    with pytest.raises(ValueError, match=error):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=executor,
            boundary_attestation=_attestation(descriptor),
            adjudicator=adjudicator,
        )
    assert executor.calls == 1 and adjudicator.calls == 0


def test_wrong_receipt_executor_identity_rejected_before_adjudication():
    plan, spec, _ = _plan()
    descriptor = _descriptor()
    executor = FakeExecutor(descriptor, receipt_executor_id="different-executor")
    adjudicator = FakeAdjudicator()
    with pytest.raises(ValueError, match="receipt identity"):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=executor,
            boundary_attestation=_attestation(descriptor),
            adjudicator=adjudicator,
        )
    assert executor.calls == 1 and adjudicator.calls == 0


def test_wrong_receipt_run_id_rejected_before_adjudication():
    plan, spec, _ = _plan()
    descriptor = _descriptor()
    executor = FakeExecutor(descriptor, receipt_run_id="e" * 64)
    adjudicator = FakeAdjudicator()
    with pytest.raises(ValueError, match="different benchmark run"):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=executor,
            boundary_attestation=_attestation(descriptor),
            adjudicator=adjudicator,
        )
    assert executor.calls == 1 and adjudicator.calls == 0


def test_wrong_adjudication_run_binding_is_rejected():
    plan, spec, _ = _plan()
    descriptor = _descriptor()
    with pytest.raises(ValueError, match="different benchmark run"):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=FakeExecutor(descriptor),
            boundary_attestation=_attestation(descriptor),
            adjudicator=FakeAdjudicator(override_run_id="e" * 64),
        )
    with pytest.raises(ValueError, match="different run evidence"):
        execute_planned_run(
            plan=plan,
            spec=spec,
            executor=FakeExecutor(descriptor),
            boundary_attestation=_attestation(descriptor),
            adjudicator=FakeAdjudicator(override_run_evidence="f" * 64),
        )


def test_unplanned_spec_is_rejected_before_executor_call():
    plan, _, verified = _plan()
    descriptor = _descriptor()
    executor = FakeExecutor(descriptor)
    unplanned = replace(verified, repeat_index=1)
    with pytest.raises(ValueError, match="not present"):
        execute_planned_run(
            plan=plan,
            spec=unplanned,
            executor=executor,
            boundary_attestation=_attestation(descriptor),
            adjudicator=FakeAdjudicator(),
        )
    assert executor.calls == 0


def test_competition_mode_can_declare_open_internet_when_attestation_matches():
    plan, spec, _ = _plan(mode=EvaluationMode.COMPETITION)
    descriptor = _descriptor(
        web_search_enabled=True,
        external_retrieval_enabled=True,
        general_internet_egress_enabled=True,
        challenge_transport_only=False,
    )
    executor = FakeExecutor(descriptor)
    adjudicator = FakeAdjudicator(accepted=True)
    record = execute_planned_run(
        plan=plan,
        spec=spec,
        executor=executor,
        boundary_attestation=_attestation(descriptor),
        adjudicator=adjudicator,
    )
    assert record.mode is EvaluationMode.COMPETITION
    assert record.success
