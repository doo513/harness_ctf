from __future__ import annotations

from dataclasses import replace

import pytest

from harness.core.storage import IntegrityError

from ctf_harness.evaluation.corpus import (
    CorpusLock,
    case_from_manifest,
    freeze_corpus,
    validate_first_pwn_pilot,
)
from ctf_harness.evaluation.metrics import aggregate, build_run_record, compare_paired_ab
from ctf_harness.evaluation.models import (
    ArmConfig,
    BenchmarkArm,
    BenchmarkCase,
    BenchmarkRunSpec,
    EvaluationMode,
    ExperimentContract,
    IndependentAdjudication,
    RawRunOutcome,
    RunExecutionEvidence,
)
from ctf_harness.evaluation.policy import LeakagePolicy, assert_mode_policy
from ctf_harness.evaluation.results import BenchmarkResultBundle
from ctf_harness.evaluation.runner import BenchmarkPlan, assert_comparable_pair, paired_specs
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.proof.models import ProofLevel


RUNNER = "sha256:" + "a" * 64
ADJUDICATION_SHA = "1" * 64
RUN_EVIDENCE_SHA = "c" * 64


def _manifest(index: int, *, mode="research", revision="r1") -> ChallengeManifest:
    return ChallengeManifest(
        challenge_id=f"pwn-{index}",
        event="private-pilot",
        description=f"private pwn fixture {index}",
        runner_image_digest=RUNNER,
        challenge_revision=revision,
        category_hint="pwn",
        benchmark_policy=mode,
    )


def _case(index: int, *, mode="research", revision="r1", category="pwn") -> BenchmarkCase:
    return case_from_manifest(
        _manifest(index, mode=mode, revision=revision),
        {},
        case_id=f"case-{index}",
        category=category,
        difficulty="controlled",
    )


def _experiment(*, mode=EvaluationMode.RESEARCH, max_steps=50, seed=7) -> ExperimentContract:
    return ExperimentContract(
        mode=mode,
        model_id="fixed-model",
        model_revision="model-r1",
        controller_revision="controller-r1",
        tool_inventory=("argv", "session"),
        sandbox_id="sandbox-r1",
        oracle_policy_id="external-flag-oracle-r1",
        max_steps=max_steps,
        max_wall_seconds=300.0,
        max_tokens=100_000,
        seed=seed,
    )


def _research_corpus(cases):
    return freeze_corpus(
        name="private-pwn-pilot",
        revision="corpus-r1",
        mode=EvaluationMode.RESEARCH,
        cases=cases,
        unpublished=True,
    )


def _outcome(*, completed=False, facts=(), failures=(), tools=0, steps=0, wall=1.0):
    return RawRunOutcome(
        completed_claimed=completed,
        verified_fact_keys=tuple(facts),
        failure_signatures=tuple(failures),
        tool_calls=tools,
        steps=steps,
        wall_seconds=wall,
    )


def _adjudication(
    spec: BenchmarkRunSpec,
    *,
    accepted=False,
    proof=None,
    invalid=(),
    evidence_sha=ADJUDICATION_SHA,
    adjudicator_id="fixture-independent-adjudicator",
    run_evidence_sha=RUN_EVIDENCE_SHA,
):
    return IndependentAdjudication(
        adjudicator_id=adjudicator_id,
        evidence_sha256=evidence_sha,
        run_id=spec.run_id(),
        run_evidence_sha256=run_evidence_sha,
        oracle_accepted=accepted,
        highest_proof_level=proof,
        invalid_verified_fact_keys=tuple(invalid),
    )


def _execution_evidence(byte="a", *, run_evidence_sha=RUN_EVIDENCE_SHA):
    return RunExecutionEvidence(
        executor_id="fixture-executor",
        executor_fingerprint=byte * 64,
        boundary_attestor_id="fixture-boundary-attestor",
        boundary_evidence_sha256="b" * 64,
        run_evidence_sha256=run_evidence_sha,
    )


def test_research_leakage_policy_is_fail_closed():
    policy = LeakagePolicy.research()
    assert not policy.web_enabled and not policy.exact_challenge_name_search_allowed
    assert not policy.writeup_search_allowed and not policy.direct_flag_search_allowed
    assert_mode_policy(EvaluationMode.RESEARCH, policy)
    with pytest.raises(ValueError, match="web disabled"):
        LeakagePolicy(EvaluationMode.RESEARCH, True, False, False, False, True)
    with pytest.raises(ValueError, match="mode must match"):
        assert_mode_policy(EvaluationMode.COMPETITION, policy)
    with pytest.raises(ValueError, match="must be EvaluationMode"):
        LeakagePolicy("research", False, False, False, False, True)


def test_case_identity_is_derived_from_manifest_revision_and_frozen():
    one = _case(1, revision="r1")
    changed = _case(1, revision="r2")
    assert one.manifest_fingerprint != changed.manifest_fingerprint
    corpus = _research_corpus([one])
    assert corpus.require_case(one.case_id, one.manifest_fingerprint) == one
    with pytest.raises(ValueError, match="fingerprint differs"):
        corpus.require_case(one.case_id, changed.manifest_fingerprint)


def test_corpus_and_plan_require_immutable_tuple_collections():
    case = _case(1)
    with pytest.raises(ValueError, match="immutable tuple"):
        CorpusLock("mutable", "r1", EvaluationMode.RESEARCH, [case], True)
    corpus = _research_corpus([case])
    minimal, verified = paired_specs(case=case, experiment=_experiment())
    with pytest.raises(ValueError, match="immutable tuple"):
        BenchmarkPlan(corpus, LeakagePolicy.research(), [minimal, verified])


def test_first_pwn_pilot_qualification_requires_10_to_15_unpublished_research_pwn_cases():
    with pytest.raises(ValueError, match="10-15"):
        validate_first_pwn_pilot(_research_corpus([_case(i) for i in range(9)]))
    ten = _research_corpus([_case(i) for i in range(10)])
    validate_first_pwn_pilot(ten)
    mixed = list(ten.cases)
    mixed[-1] = _case(99, category="reverse")
    with pytest.raises(ValueError, match="only Pwn"):
        validate_first_pwn_pilot(_research_corpus(mixed))


def test_ab_comparison_key_requires_same_case_model_tools_sandbox_oracle_budget_and_seed():
    case = _case(1)
    experiment = _experiment()
    minimal, verified = paired_specs(case=case, experiment=experiment)
    assert minimal.comparison_key() == verified.comparison_key()
    assert minimal.run_id() != verified.run_id()
    assert_comparable_pair(minimal, verified)
    changed_budget = BenchmarkRunSpec(case, _experiment(max_steps=51), ArmConfig.verified())
    with pytest.raises(ValueError, match="differs"):
        assert_comparable_pair(minimal, changed_budget)


def test_first_ab_plan_requires_exact_frozen_case_and_canonical_two_arms():
    case = _case(1)
    corpus = _research_corpus([case])
    minimal, verified = paired_specs(case=case, experiment=_experiment())
    plan = BenchmarkPlan(corpus, LeakagePolicy.research(), (minimal, verified))
    assert len(plan.fingerprint()) == 64
    with pytest.raises(ValueError, match="exactly two"):
        BenchmarkPlan(corpus, LeakagePolicy.research(), (minimal,))
    altered = BenchmarkRunSpec(
        replace(case, difficulty="different-label"),
        _experiment(),
        ArmConfig.verified(),
    )
    with pytest.raises(ValueError, match="exact frozen"):
        BenchmarkPlan(corpus, LeakagePolicy.research(), (minimal, altered))
    noncanonical = BenchmarkRunSpec(
        case,
        _experiment(),
        ArmConfig(BenchmarkArm.VERIFIED, True, True, True, False, True),
    )
    with pytest.raises(ValueError, match="canonical"):
        BenchmarkPlan(corpus, LeakagePolicy.research(), (minimal, noncanonical))


def test_independent_adjudication_and_execution_evidence_require_identity_hashes():
    _, verified = paired_specs(case=_case(1), experiment=_experiment())
    with pytest.raises(ValueError, match="adjudicator_id"):
        _adjudication(verified, adjudicator_id="")
    with pytest.raises(ValueError, match="evidence_sha256"):
        _adjudication(verified, evidence_sha="not-a-sha")
    with pytest.raises(ValueError, match="non-P6"):
        _adjudication(verified, accepted=True, proof=ProofLevel.P5_REMOTE)
    with pytest.raises(ValueError, match="without oracle acceptance"):
        _adjudication(verified, accepted=False, proof=ProofLevel.P6_ACCEPTED)
    with pytest.raises(ValueError, match="executor_fingerprint"):
        RunExecutionEvidence("x", "bad", "attestor", "b" * 64, RUN_EVIDENCE_SHA)


def test_independent_oracle_is_success_authority_and_false_completion_is_counted():
    case = _case(1)
    minimal, verified = paired_specs(case=case, experiment=_experiment())
    minimal_record = build_run_record(
        minimal,
        _outcome(
            completed=True,
            failures=("same", "same", "other", "same"),
            tools=8,
            steps=12,
            wall=20.0,
        ),
        _adjudication(minimal, accepted=False, proof=ProofLevel.P2_CONTROL),
        _execution_evidence("a"),
    )
    assert not minimal_record.success and minimal_record.false_completion
    assert minimal_record.repeated_failure_count == 2
    assert minimal_record.executor_id == "fixture-executor"
    assert minimal_record.adjudicator_id == "fixture-independent-adjudicator"

    verified_record = build_run_record(
        verified,
        _outcome(completed=True, tools=5, steps=9, wall=14.0),
        _adjudication(
            verified,
            accepted=True,
            proof=ProofLevel.P6_ACCEPTED,
            evidence_sha="2" * 64,
        ),
        _execution_evidence("d"),
    )
    comparison = compare_paired_ab((minimal_record, verified_record))
    assert comparison.pair_count == 1
    assert comparison.minimal_success_rate == 0.0
    assert comparison.verified_success_rate == 1.0
    assert comparison.verified_minus_minimal_success_rate == 1.0
    assert comparison.verified_minus_minimal_mean_tool_calls == -3.0
    assert comparison.verified_minus_minimal_false_completions == -1
    assert comparison.verified_minus_minimal_repeated_failures == -2


def test_false_fact_metric_requires_independent_labels_to_reference_reported_facts():
    _, verified = paired_specs(case=_case(1), experiment=_experiment())
    record = build_run_record(
        verified,
        _outcome(facts=("ctf.pwn.arch", "ctf.pwn.control_flow")),
        _adjudication(
            verified,
            proof=ProofLevel.P1_PRIMITIVE,
            invalid=("ctf.pwn.control_flow",),
        ),
        _execution_evidence(),
    )
    assert record.false_fact_count == 1
    with pytest.raises(ValueError, match="reported by the run"):
        build_run_record(
            verified,
            _outcome(facts=("ctf.pwn.arch",)),
            _adjudication(
                verified,
                proof=ProofLevel.P0_SURFACE,
                invalid=("ctf.pwn.remote_behavior",),
            ),
            _execution_evidence(),
        )


def test_research_and_competition_results_cannot_be_aggregated_or_compared():
    _, research_spec = paired_specs(case=_case(1), experiment=_experiment())
    research_record = build_run_record(
        research_spec,
        _outcome(),
        _adjudication(research_spec),
        _execution_evidence(),
    )
    competition_spec = BenchmarkRunSpec(
        _case(2, mode="competition"),
        _experiment(mode=EvaluationMode.COMPETITION),
        ArmConfig.verified(),
    )
    competition_record = build_run_record(
        competition_spec,
        _outcome(),
        _adjudication(competition_spec, evidence_sha="3" * 64),
        _execution_evidence("d"),
    )
    with pytest.raises(ValueError, match="must not be aggregated"):
        aggregate((research_record, competition_record))
    with pytest.raises(ValueError, match="must not be compared"):
        compare_paired_ab((research_record, competition_record))


def test_result_bundle_requires_exact_plan_complete_evidence_and_detects_tamper(tmp_path):
    case = _case(1)
    corpus = _research_corpus([case])
    minimal, verified = paired_specs(case=case, experiment=_experiment())
    plan = BenchmarkPlan(corpus, LeakagePolicy.research(), (minimal, verified))
    records = (
        build_run_record(
            minimal,
            _outcome(),
            _adjudication(minimal, evidence_sha="4" * 64),
            _execution_evidence("a"),
        ),
        build_run_record(
            verified,
            _outcome(),
            _adjudication(verified, evidence_sha="5" * 64),
            _execution_evidence("d"),
        ),
    )
    bundle = BenchmarkResultBundle.finalize(plan, records)
    path = tmp_path / "results.json"
    digest = bundle.save(path)
    assert len(digest) == 64
    body = BenchmarkResultBundle.verify_saved(
        path, expected_plan_fingerprint=plan.fingerprint()
    )
    assert len(body["records"]) == 2
    for row in body["records"]:
        assert row["executor_id"] and row["boundary_attestor_id"] and row["adjudicator_id"]
        assert len(row["run_evidence_sha256"]) == 64
    with pytest.raises(ValueError, match="exactly match plan"):
        BenchmarkResultBundle.finalize(plan, records[:1])
    with pytest.raises(ValueError, match="immutable tuple"):
        BenchmarkResultBundle(plan.fingerprint(), list(records))
    raw = path.read_text(encoding="utf-8")
    path.write_text(
        raw.replace('"tool_calls": 0', '"tool_calls": 1', 1),
        encoding="utf-8",
    )
    with pytest.raises(IntegrityError, match="integrity mismatch"):
        BenchmarkResultBundle.verify_saved(
            path, expected_plan_fingerprint=plan.fingerprint()
        )


def test_fixture_corpus_does_not_qualify_as_first_pwn_pilot_by_default():
    with pytest.raises(ValueError, match="10-15"):
        validate_first_pwn_pilot(_research_corpus([_case(1)]))
