from __future__ import annotations

from dataclasses import dataclass

from harness.core.storage import canonical_hash

from .corpus import CorpusLock
from .models import BenchmarkArm, BenchmarkRunSpec
from .policy import LeakagePolicy, assert_mode_policy


@dataclass(frozen=True)
class BenchmarkPlan:
    corpus: CorpusLock
    leakage_policy: LeakagePolicy
    runs: tuple[BenchmarkRunSpec, ...]

    def __post_init__(self) -> None:
        if not self.runs:
            raise ValueError("benchmark plan must contain at least one run")
        assert_mode_policy(self.corpus.mode, self.leakage_policy)

        run_ids: set[str] = set()
        comparison_arms: dict[str, set[BenchmarkArm]] = {}
        comparison_contracts: dict[str, str] = {}
        for spec in self.runs:
            if spec.experiment.mode is not self.corpus.mode:
                raise ValueError("run experiment mode differs from frozen corpus mode")
            self.corpus.require_case(spec.case.case_id, spec.case.manifest_fingerprint)
            run_id = spec.run_id()
            if run_id in run_ids:
                raise ValueError("benchmark plan contains a duplicate run identity")
            run_ids.add(run_id)
            key = spec.comparison_key()
            comparison_arms.setdefault(key, set()).add(spec.arm.arm)
            comparison_contracts.setdefault(key, spec.experiment.fingerprint())
            if comparison_contracts[key] != spec.experiment.fingerprint():
                raise ValueError("comparison group contains different experiment contracts")

        for key, arms in comparison_arms.items():
            if arms != {BenchmarkArm.MINIMAL, BenchmarkArm.VERIFIED}:
                raise ValueError(
                    "each A/B comparison key must contain exactly minimal and verified arms"
                )

    def fingerprint(self) -> str:
        return canonical_hash({
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
    if {left.arm.arm, right.arm.arm} != {BenchmarkArm.MINIMAL, BenchmarkArm.VERIFIED}:
        raise ValueError("A/B pair must contain one minimal and one verified arm")


def paired_specs(*, case, experiment, repeat_index: int = 0) -> tuple[BenchmarkRunSpec, BenchmarkRunSpec]:
    minimal = BenchmarkRunSpec(
        case=case,
        experiment=experiment,
        arm=__import__("ctf_harness.evaluation.models", fromlist=["ArmConfig"]).ArmConfig.minimal(),
        repeat_index=repeat_index,
    )
    verified = BenchmarkRunSpec(
        case=case,
        experiment=experiment,
        arm=__import__("ctf_harness.evaluation.models", fromlist=["ArmConfig"]).ArmConfig.verified(),
        repeat_index=repeat_index,
    )
    return minimal, verified
