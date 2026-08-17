from __future__ import annotations

from dataclasses import dataclass

from harness.core.storage import canonical_hash

from .corpus import CorpusLock
from .models import ArmConfig, BenchmarkArm, BenchmarkRunSpec
from .policy import LeakagePolicy, assert_mode_policy


@dataclass(frozen=True)
class BenchmarkPlan:
    """Frozen first A/B plan: Minimal CTF Loop vs Verified CTF Harness.

    Drop-one ablations intentionally require a later explicit plan contract so
    they cannot be silently mixed into the first two-arm benchmark.
    """

    corpus: CorpusLock
    leakage_policy: LeakagePolicy
    runs: tuple[BenchmarkRunSpec, ...]

    def __post_init__(self) -> None:
        if not self.runs:
            raise ValueError("benchmark plan must contain at least one run")
        assert_mode_policy(self.corpus.mode, self.leakage_policy)

        run_ids: set[str] = set()
        grouped: dict[str, list[BenchmarkRunSpec]] = {}
        for spec in self.runs:
            if spec.experiment.mode is not self.corpus.mode:
                raise ValueError("run experiment mode differs from frozen corpus mode")
            frozen_case = self.corpus.require_case(
                spec.case.case_id,
                spec.case.manifest_fingerprint,
            )
            if spec.case != frozen_case:
                raise ValueError("run case metadata differs from the exact frozen corpus case")
            run_id = spec.run_id()
            if run_id in run_ids:
                raise ValueError("benchmark plan contains a duplicate run identity")
            run_ids.add(run_id)
            grouped.setdefault(spec.comparison_key(), []).append(spec)

        expected_configs = {
            BenchmarkArm.MINIMAL: ArmConfig.minimal(),
            BenchmarkArm.VERIFIED: ArmConfig.verified(),
        }
        for rows in grouped.values():
            if len(rows) != 2:
                raise ValueError("each first A/B comparison key must contain exactly two runs")
            by_arm = {row.arm.arm: row for row in rows}
            if set(by_arm) != {BenchmarkArm.MINIMAL, BenchmarkArm.VERIFIED}:
                raise ValueError("each A/B comparison must contain minimal and verified arms")
            for arm, expected in expected_configs.items():
                if by_arm[arm].arm != expected:
                    raise ValueError("first A/B benchmark requires canonical arm feature toggles")

    def fingerprint(self) -> str:
        return canonical_hash({
            "plan_schema": "ctf-first-ab-v1",
            "corpus_fingerprint": self.corpus.fingerprint(),
            "leakage_policy": self.leakage_policy.descriptor(),
            "runs": [
                {
                    "comparison_key": spec.comparison_key(),
                    "run_id": spec.run_id(),
                    "arm": spec.arm.descriptor(),
                }
                for spec in sorted(self.runs, key=lambda item: item.run_id())
            ],
        })


def assert_comparable_pair(left: BenchmarkRunSpec, right: BenchmarkRunSpec) -> None:
    if left.comparison_key() != right.comparison_key():
        raise ValueError("A/B pair differs in challenge, experiment contract, or repeat index")
    expected = {
        BenchmarkArm.MINIMAL: ArmConfig.minimal(),
        BenchmarkArm.VERIFIED: ArmConfig.verified(),
    }
    rows = {left.arm.arm: left, right.arm.arm: right}
    if set(rows) != set(expected):
        raise ValueError("A/B pair must contain one minimal and one verified arm")
    for arm, config in expected.items():
        if rows[arm].arm != config:
            raise ValueError("A/B pair uses non-canonical arm feature toggles")


def paired_specs(*, case, experiment, repeat_index: int = 0) -> tuple[BenchmarkRunSpec, BenchmarkRunSpec]:
    minimal = BenchmarkRunSpec(
        case=case,
        experiment=experiment,
        arm=ArmConfig.minimal(),
        repeat_index=repeat_index,
    )
    verified = BenchmarkRunSpec(
        case=case,
        experiment=experiment,
        arm=ArmConfig.verified(),
        repeat_index=repeat_index,
    )
    return minimal, verified
