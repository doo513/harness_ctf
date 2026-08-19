from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from statistics import mean
from typing import Iterable

from .models import (
    BenchmarkArm,
    BenchmarkRunSpec,
    EvaluationMode,
    IndependentAdjudication,
    RawRunOutcome,
    RunExecutionEvidence,
)


@dataclass(frozen=True)
class BenchmarkRunRecord:
    run_id: str
    comparison_key: str
    case_id: str
    manifest_fingerprint: str
    mode: EvaluationMode
    arm: BenchmarkArm
    repeat_index: int
    executor_id: str
    executor_fingerprint: str
    boundary_attestor_id: str
    boundary_evidence_sha256: str
    run_evidence_sha256: str
    adjudicator_id: str
    adjudication_evidence_sha256: str
    oracle_accepted: bool
    completed_claimed: bool
    highest_proof_level: int | None
    false_completion: bool
    false_fact_count: int
    repeated_failure_count: int
    tool_calls: int
    steps: int
    wall_seconds: float
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    terminal_reason: str | None

    @property
    def success(self) -> bool:
        return self.oracle_accepted


def repeated_failure_count(signatures: Iterable[str]) -> int:
    counts = Counter(signatures)
    return sum(max(0, count - 1) for count in counts.values())


def build_run_record(
    spec: BenchmarkRunSpec,
    outcome: RawRunOutcome,
    adjudication: IndependentAdjudication,
    execution_evidence: RunExecutionEvidence,
) -> BenchmarkRunRecord:
    if not isinstance(adjudication, IndependentAdjudication):
        raise ValueError("adjudication must be IndependentAdjudication")
    if not isinstance(execution_evidence, RunExecutionEvidence):
        raise ValueError("execution_evidence must be RunExecutionEvidence")
    if adjudication.run_id != spec.run_id():
        raise ValueError("independent adjudication is bound to a different benchmark run")
    if adjudication.run_evidence_sha256 != execution_evidence.run_evidence_sha256:
        raise ValueError("independent adjudication is bound to different run evidence")

    invalid = set(adjudication.invalid_verified_fact_keys)
    reported = set(outcome.verified_fact_keys)
    if not invalid.issubset(reported):
        raise ValueError("independent invalid-fact labels must refer to facts reported by the run")

    return BenchmarkRunRecord(
        run_id=spec.run_id(),
        comparison_key=spec.comparison_key(),
        case_id=spec.case.case_id,
        manifest_fingerprint=spec.case.manifest_fingerprint,
        mode=spec.experiment.mode,
        arm=spec.arm.arm,
        repeat_index=spec.repeat_index,
        executor_id=execution_evidence.executor_id.strip(),
        executor_fingerprint=execution_evidence.executor_fingerprint,
        boundary_attestor_id=execution_evidence.boundary_attestor_id.strip(),
        boundary_evidence_sha256=execution_evidence.boundary_evidence_sha256,
        run_evidence_sha256=execution_evidence.run_evidence_sha256,
        adjudicator_id=adjudication.adjudicator_id.strip(),
        adjudication_evidence_sha256=adjudication.evidence_sha256,
        oracle_accepted=adjudication.oracle_accepted,
        completed_claimed=outcome.completed_claimed,
        highest_proof_level=(int(adjudication.highest_proof_level) if adjudication.highest_proof_level is not None else None),
        false_completion=bool(outcome.completed_claimed and not adjudication.oracle_accepted),
        false_fact_count=len(invalid),
        repeated_failure_count=repeated_failure_count(outcome.failure_signatures),
        tool_calls=outcome.tool_calls,
        steps=outcome.steps,
        wall_seconds=float(outcome.wall_seconds),
        input_tokens=outcome.input_tokens,
        output_tokens=outcome.output_tokens,
        cost_usd=(float(outcome.cost_usd) if outcome.cost_usd is not None else None),
        terminal_reason=outcome.terminal_reason,
    )


@dataclass(frozen=True)
class AggregateMetrics:
    mode: EvaluationMode
    arm: BenchmarkArm
    run_count: int
    success_rate: float
    false_completion_count: int
    false_fact_count: int
    repeated_failure_count: int
    mean_highest_proof_level: float | None
    mean_tool_calls: float
    mean_steps: float
    mean_wall_seconds: float
    total_input_tokens: int | None
    total_output_tokens: int | None
    total_cost_usd: float | None


def aggregate(records: Iterable[BenchmarkRunRecord]) -> AggregateMetrics:
    rows = tuple(records)
    if not rows:
        raise ValueError("cannot aggregate an empty benchmark result set")
    modes = {row.mode for row in rows}
    arms = {row.arm for row in rows}
    if len(modes) != 1:
        raise ValueError("research and competition results must not be aggregated together")
    if len(arms) != 1:
        raise ValueError("different benchmark arms must be aggregated separately")

    proof_values = [row.highest_proof_level for row in rows if row.highest_proof_level is not None]
    input_known = all(row.input_tokens is not None for row in rows)
    output_known = all(row.output_tokens is not None for row in rows)
    cost_known = all(row.cost_usd is not None for row in rows)

    return AggregateMetrics(
        mode=next(iter(modes)),
        arm=next(iter(arms)),
        run_count=len(rows),
        success_rate=sum(1 for row in rows if row.success) / len(rows),
        false_completion_count=sum(1 for row in rows if row.false_completion),
        false_fact_count=sum(row.false_fact_count for row in rows),
        repeated_failure_count=sum(row.repeated_failure_count for row in rows),
        mean_highest_proof_level=(mean(proof_values) if proof_values else None),
        mean_tool_calls=mean(row.tool_calls for row in rows),
        mean_steps=mean(row.steps for row in rows),
        mean_wall_seconds=mean(row.wall_seconds for row in rows),
        total_input_tokens=(sum(int(row.input_tokens) for row in rows) if input_known else None),
        total_output_tokens=(sum(int(row.output_tokens) for row in rows) if output_known else None),
        total_cost_usd=(sum(float(row.cost_usd) for row in rows) if cost_known else None),
    )


@dataclass(frozen=True)
class PairedABMetrics:
    mode: EvaluationMode
    pair_count: int
    minimal_success_rate: float
    verified_success_rate: float
    verified_minus_minimal_success_rate: float
    verified_minus_minimal_mean_tool_calls: float
    verified_minus_minimal_mean_steps: float
    verified_minus_minimal_mean_wall_seconds: float
    verified_minus_minimal_repeated_failures: int
    verified_minus_minimal_false_completions: int
    verified_minus_minimal_false_facts: int


def compare_paired_ab(records: Iterable[BenchmarkRunRecord]) -> PairedABMetrics:
    rows = tuple(records)
    if not rows:
        raise ValueError("cannot compare an empty benchmark result set")
    modes = {row.mode for row in rows}
    if len(modes) != 1:
        raise ValueError("research and competition results must not be compared together")

    grouped: dict[str, list[BenchmarkRunRecord]] = {}
    seen_run_ids: set[str] = set()
    for row in rows:
        if row.run_id in seen_run_ids:
            raise ValueError("duplicate benchmark run_id in paired comparison")
        seen_run_ids.add(row.run_id)
        grouped.setdefault(row.comparison_key, []).append(row)

    minimal_rows: list[BenchmarkRunRecord] = []
    verified_rows: list[BenchmarkRunRecord] = []
    for key, pair in grouped.items():
        if len(pair) != 2:
            raise ValueError(f"comparison key {key} does not contain exactly two records")
        by_arm = {row.arm: row for row in pair}
        if set(by_arm) != {BenchmarkArm.MINIMAL, BenchmarkArm.VERIFIED}:
            raise ValueError("paired comparison requires exactly one minimal and one verified record")
        minimal = by_arm[BenchmarkArm.MINIMAL]
        verified = by_arm[BenchmarkArm.VERIFIED]
        if (
            minimal.case_id != verified.case_id
            or minimal.manifest_fingerprint != verified.manifest_fingerprint
            or minimal.repeat_index != verified.repeat_index
        ):
            raise ValueError("paired records disagree on frozen case identity")
        minimal_rows.append(minimal)
        verified_rows.append(verified)

    minimal_agg = aggregate(minimal_rows)
    verified_agg = aggregate(verified_rows)
    return PairedABMetrics(
        mode=next(iter(modes)),
        pair_count=len(grouped),
        minimal_success_rate=minimal_agg.success_rate,
        verified_success_rate=verified_agg.success_rate,
        verified_minus_minimal_success_rate=verified_agg.success_rate - minimal_agg.success_rate,
        verified_minus_minimal_mean_tool_calls=verified_agg.mean_tool_calls - minimal_agg.mean_tool_calls,
        verified_minus_minimal_mean_steps=verified_agg.mean_steps - minimal_agg.mean_steps,
        verified_minus_minimal_mean_wall_seconds=verified_agg.mean_wall_seconds - minimal_agg.mean_wall_seconds,
        verified_minus_minimal_repeated_failures=verified_agg.repeated_failure_count - minimal_agg.repeated_failure_count,
        verified_minus_minimal_false_completions=verified_agg.false_completion_count - minimal_agg.false_completion_count,
        verified_minus_minimal_false_facts=verified_agg.false_fact_count - minimal_agg.false_fact_count,
    )
