from __future__ import annotations

import json

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


def case():
    manifest = ChallengeManifest(
        challenge_id="executor-boundary-fixture",
        event="controlled",
        description="executor boundary fixture only",
        runner_image_digest=RUNNER,
        challenge_revision="r1",
        category_hint="pwn",
        benchmark_policy="research",
    )
    return case_from_manifest(manifest, {}, case_id="case-1", category="pwn")


def experiment():
    return ExperimentContract(
        mode=EvaluationMode.RESEARCH,
        model_id="fixed-model",
        model_revision="model-r1",
        controller_revision="controller-r1",
        tool_inventory=("argv", "session"),
        sandbox_id="sandbox-r1",
        oracle_policy_id="oracle-r1",
        max_steps=20,
        max_wall_seconds=30.0,
        max_tokens=100,
        seed=1,
    )


def descriptor(**changes):
    values = dict(
        executor_id="controlled-executor",
        model_id="fixed-model",
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


def attestation(desc):
    return ExecutionBoundaryAttestation(
        issuer_id="controlled-boundary-attestor",
        evidence_sha256="b" * 64,
        executor_fingerprint=desc.fingerprint(),
        sandbox_id=desc.sandbox_id,
        web_search_blocked=not desc.web_search_enabled,
        external_retrieval_blocked=not desc.external_retrieval_enabled,
        general_internet_egress_blocked=not desc.general_internet_egress_enabled,
        challenge_transport_scoped=desc.challenge_transport_only,
    )


class Executor:
    def __init__(self, desc, outcome):
        self.desc = desc
        self.outcome = outcome
        self.calls = 0

    def descriptor(self):
        return self.desc

    def execute(self, spec):
        self.calls += 1
        return ExecutorRunReceipt(
            executor_id=self.desc.executor_id,
            run_id=spec.run_id(),
            run_evidence_sha256=RUN_EVIDENCE_SHA,
            outcome=self.outcome,
        )


class Adjudicator:
    def __init__(self):
        self.calls = 0

    def adjudicate(self, spec, outcome, *, run_evidence_sha256):
        self.calls += 1
        assert run_evidence_sha256 == RUN_EVIDENCE_SHA
        return IndependentAdjudication(
            adjudicator_id="controlled-independent-adjudicator",
            evidence_sha256="d" * 64,
            run_id=spec.run_id(),
            run_evidence_sha256=run_evidence_sha256,
            oracle_accepted=False,
            highest_proof_level=ProofLevel.P2_CONTROL,
        )


def valid_outcome(**changes):
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


def main() -> int:
    c = case()
    exp = experiment()
    minimal, verified = paired_specs(case=c, experiment=exp)
    corpus = freeze_corpus(
        name="executor-boundary-fixture",
        revision="r1",
        mode=EvaluationMode.RESEARCH,
        cases=(c,),
        unpublished=True,
    )
    plan = BenchmarkPlan(corpus, LeakagePolicy.research(), (minimal, verified))

    desc = descriptor()
    executor = Executor(desc, valid_outcome())
    adjudicator = Adjudicator()
    record = execute_planned_run(
        plan=plan,
        spec=minimal,
        executor=executor,
        boundary_attestation=attestation(desc),
        adjudicator=adjudicator,
    )
    assert executor.calls == 1 and adjudicator.calls == 1
    assert not record.success and record.false_completion
    assert record.run_id == minimal.run_id()
    assert record.executor_fingerprint == desc.fingerprint()
    assert record.boundary_evidence_sha256 == "b" * 64
    assert record.run_evidence_sha256 == RUN_EVIDENCE_SHA
    assert record.adjudication_evidence_sha256 == "d" * 64

    open_desc = descriptor(web_search_enabled=True)
    blocked_executor = Executor(open_desc, valid_outcome())
    web_rejected_before_execute = False
    try:
        execute_planned_run(
            plan=plan,
            spec=minimal,
            executor=blocked_executor,
            boundary_attestation=attestation(open_desc),
            adjudicator=Adjudicator(),
        )
    except ValueError as exc:
        web_rejected_before_execute = "web-search blocking" in str(exc)
    assert web_rejected_before_execute and blocked_executor.calls == 0

    internet_desc = descriptor(
        general_internet_egress_enabled=True,
        challenge_transport_only=False,
    )
    internet_executor = Executor(internet_desc, valid_outcome())
    internet_rejected_before_execute = False
    try:
        execute_planned_run(
            plan=plan,
            spec=minimal,
            executor=internet_executor,
            boundary_attestation=attestation(internet_desc),
            adjudicator=Adjudicator(),
        )
    except ValueError as exc:
        internet_rejected_before_execute = "general-internet egress blocking" in str(exc)
    assert internet_rejected_before_execute and internet_executor.calls == 0

    over_budget_executor = Executor(desc, valid_outcome(input_tokens=80, output_tokens=30))
    over_budget_adjudicator = Adjudicator()
    budget_rejected_before_adjudication = False
    try:
        execute_planned_run(
            plan=plan,
            spec=verified,
            executor=over_budget_executor,
            boundary_attestation=attestation(desc),
            adjudicator=over_budget_adjudicator,
        )
    except ValueError as exc:
        budget_rejected_before_adjudication = "max_tokens" in str(exc)
    assert over_budget_executor.calls == 1
    assert over_budget_adjudicator.calls == 0
    assert budget_rejected_before_adjudication

    print(json.dumps({
        "probe": "ctf-evaluation-executor-boundary-controlled-v2",
        "all_passed": True,
        "actual_llm_executed": False,
        "actual_private_corpus": False,
        "research_web_search_block_required": True,
        "research_external_retrieval_block_required": True,
        "research_general_internet_block_required": True,
        "challenge_transport_distinct_from_general_internet": True,
        "web_misconfiguration_rejected_before_execute": web_rejected_before_execute,
        "internet_misconfiguration_rejected_before_execute": internet_rejected_before_execute,
        "budget_contract_enforced_before_adjudication": budget_rejected_before_adjudication,
        "executor_receipt_run_id_bound": True,
        "boundary_attestation_evidence_bound": True,
        "run_evidence_bound": True,
        "adjudication_run_id_bound": True,
        "adjudication_run_evidence_bound": True,
        "independent_adjudication_required": True,
        "executor_self_completion_is_not_success_authority": True,
        "effectiveness_measured": False,
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
