from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from harness.core.storage import canonical_hash


class AblationFeature(str, Enum):
    PLAYBOOK = "playbook"
    ANALYSIS_SANDBOX = "analysis_sandbox"
    SEMANTIC_VERIFICATION = "semantic_verification"
    HYPOTHESIS_GUARD = "hypothesis_guard"
    TYPED_RECOVERY = "typed_recovery"
    TASK_PROGRESS = "task_progress"


@dataclass(frozen=True)
class OperationalFeatureSet:
    playbook: bool = True
    analysis_sandbox: bool = True
    semantic_verification: bool = True
    hypothesis_guard: bool = True
    typed_recovery: bool = True
    task_progress: bool = True

    def __post_init__(self) -> None:
        for name in AblationFeature:
            if not isinstance(getattr(self, name.value), bool):
                raise ValueError(f"{name.value} must be boolean")

    def without(self, feature: AblationFeature) -> "OperationalFeatureSet":
        if not isinstance(feature, AblationFeature):
            raise ValueError("feature must be AblationFeature")
        values = self.descriptor()
        values[feature.value] = False
        return OperationalFeatureSet(**values)

    def descriptor(self) -> dict[str, bool]:
        return {feature.value: getattr(self, feature.value) for feature in AblationFeature}

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())


@dataclass(frozen=True)
class AblationArm:
    arm_id: str
    features: OperationalFeatureSet
    ablated_feature: AblationFeature | None

    def descriptor(self) -> dict:
        return {
            "arm_id": self.arm_id,
            "features": self.features.descriptor(),
            "ablated_feature": None if self.ablated_feature is None else self.ablated_feature.value,
        }


@dataclass(frozen=True)
class AblationPlan:
    baseline: OperationalFeatureSet
    arms: tuple[AblationArm, ...]

    @classmethod
    def single_factor(
        cls,
        *,
        baseline: OperationalFeatureSet | None = None,
        features: tuple[AblationFeature, ...] = tuple(AblationFeature),
    ) -> "AblationPlan":
        base = baseline or OperationalFeatureSet()
        if not isinstance(features, tuple) or any(not isinstance(item, AblationFeature) for item in features):
            raise ValueError("features must be a tuple of AblationFeature")
        if len(set(features)) != len(features):
            raise ValueError("ablation features must be unique")
        arms = [AblationArm("full", base, None)]
        for feature in features:
            if not getattr(base, feature.value):
                raise ValueError(f"cannot ablate disabled baseline feature: {feature.value}")
            arms.append(AblationArm(f"without-{feature.value}", base.without(feature), feature))
        return cls(base, tuple(arms))

    def __post_init__(self) -> None:
        if not isinstance(self.baseline, OperationalFeatureSet):
            raise ValueError("baseline must be OperationalFeatureSet")
        if not isinstance(self.arms, tuple) or not self.arms:
            raise ValueError("ablation plan requires arms")
        ids = [arm.arm_id for arm in self.arms]
        if len(set(ids)) != len(ids):
            raise ValueError("ablation arm IDs must be unique")
        full = [arm for arm in self.arms if arm.ablated_feature is None]
        if len(full) != 1 or full[0].features != self.baseline:
            raise ValueError("ablation plan requires one exact baseline arm")
        for arm in self.arms:
            if arm.ablated_feature is None:
                continue
            baseline = self.baseline.descriptor()
            candidate = arm.features.descriptor()
            changed = [name for name in baseline if baseline[name] != candidate[name]]
            if changed != [arm.ablated_feature.value] or candidate[arm.ablated_feature.value] is not False:
                raise ValueError("ablation arm must differ from baseline by exactly one disabled feature")

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-ablation-plan-v1",
            "baseline": self.baseline.descriptor(),
            "arms": [arm.descriptor() for arm in self.arms],
            "interpretation": "single_factor_only",
            "effectiveness_claim": "none_until_empirical_runs",
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())
