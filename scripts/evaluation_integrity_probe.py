from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ctf_harness.evaluation.corpus import case_from_manifest, freeze_corpus, validate_first_pwn_pilot
from ctf_harness.evaluation.metrics import build_run_record, compare_paired_ab
from ctf_harness.evaluation.models import (
    EvaluationMode,
    ExperimentContract,
    IndependentAdjudication,
    RawRunOutcome,
    RunExecutionEvidence,
)
from ctf_harness.evaluation.policy import LeakagePolicy
from ctf_harness.evaluation.results import BenchmarkResultBundle
from ctf_harness.evaluation.runner import BenchmarkPlan, paired_specs
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.proof.models import ProofLevel


RUNNER_IMAGE = "sha256:" + "a" * 64
RUN_EVIDENCE_SHA = "c" * 64


def fixture_case(index: int):
    manifest = ChallengeManifest(
        challenge_id=f"fixture-pwn-{index}",
        event="controlled-evaluation-fixture",
        description=f"synthetic evaluation metadata fixture {index}",
        runner_image_digest=RUNNER_IMAGE,
        challenge_revision="fixture-r1",
        category_hint="pwn",
        benchmark_policy="research",
    )
    return case_from_manifest(
        manifest,
        {},
        case_id=f"fixture-case-{index}",
        category="pwn",
        difficulty="fixture",
    )


def experiment():
    return ExperimentContract(
        mode=EvaluationMode.RESEARCH,
        model_id="fixture-fixed-model",
        model_revision="fixture-model-r1",
        controller_revision="fixture-controller-r1",
        tool_inventory=("argv", "session"),
        sandbox_id="fixture-sandbox-r1",
        oracle_policy_id="external-flag-oracle-r1",
        max_steps=50,
        max_wall_seconds=300.0,
        max_tokens=100_000,
        seed=11,
    )


def adjudication(spec, *, evidence_byte: str, accepted: bool, proof, invalid=()):
    return IndependentAdjudication(
        adjudicator_id="controlled-fixture-adjudicator",
        evidence_sha256=evidence_byte * 64,
        run_id=spec.run_id(),
        run_evidence_sha256=RUN_EVIDENCE_SHA,
        oracle_accepted=accepted,
        highest_proof_level=proof,
        invalid_verified_fact_keys=tuple(invalid),
    )


def execution_evidence(*, executor_byte: str) -> RunExecutionEvidence:
    return RunExecutionEvidence(
        executor_id="controlled-fixture-executor",
        executor_fingerprint=executor_byte * 64,
        boundary_attestor_id="controlled-fixture-boundary-attestor",
        boundary_evidence_sha256="b" * 64,
        run_evidence_sha256=RUN_EVIDENCE_SHA,
    )


def main() -> int:
    cases = tuple(fixture_case(index) for index in range(10))
    corpus = freeze_corpus(
        name="shape-only-pwn-pilot-fixture",
        revision="fixture-corpus-r1",
        mode=EvaluationMode.RESEARCH,
        cases=cases,
        unpublished=True,
    )
    # Shape-only qualification: these are metadata fixtures, not a real private corpus.
    validate_first_pwn_pilot(corpus)

    exp = experiment()
    runs = []
    for case in cases:
        runs.extend(paired_specs(case=case, experiment=exp))
    policy = LeakagePolicy.research()
    plan = BenchmarkPlan(corpus=corpus, leakage_policy=policy, runs=tuple(runs))
    reversed_plan = BenchmarkPlan(
        corpus=freeze_corpus(
            name=corpus.name,
            revision=corpus.revision,
            mode=corpus.mode,
            cases=tuple(reversed(cases)),
            unpublished=True,
        ),
        leakage_policy=policy,
        runs=tuple(reversed(runs)),
    )
    assert plan.fingerprint() == reversed_plan.fingerprint()

    minimal_spec, verified_spec = paired_specs(case=cases[0], experiment=exp)
    minimal_record = build_run_record(
        minimal_spec,
        RawRunOutcome(
            completed_claimed=True,
            verified_fact_keys=("ctf.pwn.arch",),
            failure_signatures=("repeat", "repeat", "repeat"),
            tool_calls=7,
            steps=10,
            wall_seconds=12.0,
        ),
        adjudication(
            minimal_spec,
            evidence_byte="1",
            accepted=False,
            proof=ProofLevel.P0_SURFACE,
            invalid=("ctf.pwn.arch",),
        ),
        execution_evidence(executor_byte="a"),
    )
    verified_record = build_run_record(
        verified_spec,
        RawRunOutcome(
            completed_claimed=False,
            verified_fact_keys=(),
            failure_signatures=(),
            tool_calls=5,
            steps=8,
            wall_seconds=10.0,
        ),
        adjudication(verified_spec, evidence_byte="2", accepted=False, proof=None),
        execution_evidence(executor_byte="d"),
    )
    paired = compare_paired_ab((minimal_record, verified_record))
    assert paired.minimal_success_rate == 0.0
    assert paired.verified_success_rate == 0.0
    assert paired.verified_minus_minimal_success_rate == 0.0
    assert minimal_record.false_completion is True
    assert minimal_record.false_fact_count == 1
    assert minimal_record.repeated_failure_count == 2
    assert len(minimal_record.executor_fingerprint) == 64
    assert len(minimal_record.boundary_evidence_sha256) == 64
    assert len(minimal_record.run_evidence_sha256) == 64
    assert len(minimal_record.adjudication_evidence_sha256) == 64

    one_case_corpus = freeze_corpus(
        name="result-bundle-fixture",
        revision="fixture-result-r1",
        mode=EvaluationMode.RESEARCH,
        cases=(cases[0],),
        unpublished=True,
    )
    one_case_plan = BenchmarkPlan(
        corpus=one_case_corpus,
        leakage_policy=policy,
        runs=(minimal_spec, verified_spec),
    )
    bundle = BenchmarkResultBundle.finalize(one_case_plan, (minimal_record, verified_record))
    with tempfile.TemporaryDirectory(prefix="ctf-evaluation-probe-") as td:
        path = Path(td) / "results.json"
        result_digest = bundle.save(path)
        loaded = BenchmarkResultBundle.verify_saved(
            path,
            expected_plan_fingerprint=one_case_plan.fingerprint(),
        )
        assert len(loaded["records"]) == 2
        assert all(record["executor_id"] for record in loaded["records"])
        assert all(record["boundary_attestor_id"] for record in loaded["records"])
        assert all(record["adjudicator_id"] for record in loaded["records"])
        assert all(len(record["run_evidence_sha256"]) == 64 for record in loaded["records"])
        assert all(len(record["adjudication_evidence_sha256"]) == 64 for record in loaded["records"])

    print(json.dumps({
        "probe": "ctf-evaluation-integrity-controlled-v4",
        "all_passed": True,
        "fixture_only": True,
        "actual_private_challenge_corpus_supplied": False,
        "freshness_independently_proven": False,
        "pilot_shape_gate_passed": True,
        "pilot_shape_case_count": len(cases),
        "first_ab_plan_run_count": len(plan.runs),
        "plan_identity_order_independent": True,
        "research_web_enabled": policy.web_enabled,
        "research_exact_name_search_allowed": policy.exact_challenge_name_search_allowed,
        "research_writeup_search_allowed": policy.writeup_search_allowed,
        "research_direct_flag_search_allowed": policy.direct_flag_search_allowed,
        "permanent_reject_success_rates": {
            "minimal": paired.minimal_success_rate,
            "verified": paired.verified_success_rate,
            "delta": paired.verified_minus_minimal_success_rate,
        },
        "false_completion_detected": minimal_record.false_completion,
        "independently_invalid_fact_counted": minimal_record.false_fact_count,
        "repeated_failure_counted": minimal_record.repeated_failure_count,
        "execution_evidence_bound": True,
        "boundary_attestation_evidence_bound": True,
        "adjudication_run_id_bound": True,
        "adjudication_run_evidence_bound": True,
        "result_bundle_bound_to_plan": True,
        "result_bundle_sha256": result_digest,
        "effectiveness_measured": False,
        "solve_rate_improvement_claimed": False,
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
