from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import math
from typing import Any

from harness.core.storage import canonical_hash

from ctf_harness.proof.models import ProofLevel


class EvaluationMode(str, Enum):
    RESEARCH = "research"
    COMPETITION = "competition"


class BenchmarkArm(str, Enum):
    MINIMAL = "minimal_ctf_loop"
    VERIFIED = "verified_ctf_harness"


def _lower_sha256(value: str, *, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex")


@dataclass(frozen=True)
class ArmConfig:
    arm: BenchmarkArm
    semantic_verification: bool
    proof_gate: bool
    hypothesis_guard: bool
    typed_recovery: bool
    task_progress: bool

    def __post_init__(self) -> None:
        if not isinstance(self.arm, BenchmarkArm):
            raise ValueError("arm must be BenchmarkArm")
        for field_name in (
            "semantic_verification",
            "proof_gate",
            "hypothesis_guard",
            "typed_recovery",
            "task_progress",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise ValueError(f"{field_name} must be boolean")

    @classmethod
    def minimal(cls) -> "ArmConfig":
        return cls(BenchmarkArm.MINIMAL, False, False, False, False, False)

    @classmethod
    def verified(cls) -> "ArmConfig":
        return cls(BenchmarkArm.VERIFIED, True, True, True, True, True)

    def descriptor(self) -> dict[str, Any]:
        body = asdict(self)
        body["arm"] = self.arm.value
        return body


@dataclass(frozen=True)
class ExperimentContract:
    mode: EvaluationMode
    model_id: str
    model_revision: str
    controller_revision: str
    tool_inventory: tuple[str, ...]
    sandbox_id: str
    oracle_policy_id: str
    max_steps: int
    max_wall_seconds: float
    max_tokens: int | None = None
    seed: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, EvaluationMode):
            raise ValueError("mode must be EvaluationMode")
        for field_name in (
            "model_id",
            "model_revision",
            "controller_revision",
            "sandbox_id",
            "oracle_policy_id",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        if not isinstance(self.tool_inventory, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.tool_inventory
        ):
            raise ValueError("tool_inventory must be a tuple of non-empty strings")
        if len(set(self.tool_inventory)) != len(self.tool_inventory):
            raise ValueError("tool_inventory must be unique")
        if not isinstance(self.max_steps, int) or isinstance(self.max_steps, bool) or self.max_steps <= 0:
            raise ValueError("max_steps must be a positive integer")
        if (
            not isinstance(self.max_wall_seconds, (int, float))
            or isinstance(self.max_wall_seconds, bool)
            or not math.isfinite(float(self.max_wall_seconds))
            or self.max_wall_seconds <= 0
        ):
            raise ValueError("max_wall_seconds must be finite and positive")
        if self.max_tokens is not None and (
            not isinstance(self.max_tokens, int)
            or isinstance(self.max_tokens, bool)
            or self.max_tokens <= 0
        ):
            raise ValueError("max_tokens must be a positive integer when provided")
        if self.seed is not None and (not isinstance(self.seed, int) or isinstance(self.seed, bool)):
            raise ValueError("seed must be an integer when provided")

    def descriptor(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "controller_revision": self.controller_revision,
            "tool_inventory": sorted(self.tool_inventory),
            "sandbox_id": self.sandbox_id,
            "oracle_policy_id": self.oracle_policy_id,
            "max_steps": self.max_steps,
            "max_wall_seconds": float(self.max_wall_seconds),
            "max_tokens": self.max_tokens,
            "seed": self.seed,
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    challenge_id: str
    challenge_revision: str
    manifest_fingerprint: str
    mode: EvaluationMode
    category: str
    difficulty: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.mode, EvaluationMode):
            raise ValueError("case mode must be EvaluationMode")
        for field_name in ("case_id", "challenge_id", "challenge_revision", "category"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        _lower_sha256(self.manifest_fingerprint, field_name="manifest_fingerprint")
        if self.difficulty is not None and (
            not isinstance(self.difficulty, str) or not self.difficulty.strip()
        ):
            raise ValueError("difficulty must be a non-empty string when provided")

    def descriptor(self) -> dict[str, Any]:
        body = asdict(self)
        body["mode"] = self.mode.value
        return body


@dataclass(frozen=True)
class BenchmarkRunSpec:
    case: BenchmarkCase
    experiment: ExperimentContract
    arm: ArmConfig
    repeat_index: int = 0

    def __post_init__(self) -> None:
        if self.case.mode is not self.experiment.mode:
            raise ValueError("case mode and experiment mode must match")
        if (
            not isinstance(self.repeat_index, int)
            or isinstance(self.repeat_index, bool)
            or self.repeat_index < 0
        ):
            raise ValueError("repeat_index must be a non-negative integer")

    def comparison_key(self) -> str:
        return canonical_hash(
            {
                "case": self.case.descriptor(),
                "experiment": self.experiment.descriptor(),
                "repeat_index": self.repeat_index,
            }
        )

    def run_id(self) -> str:
        return canonical_hash(
            {"comparison_key": self.comparison_key(), "arm": self.arm.descriptor()}
        )


@dataclass(frozen=True)
class RunExecutionEvidence:
    """Identity chain for the mechanism that produced one RawRunOutcome."""

    executor_id: str
    executor_fingerprint: str
    boundary_attestor_id: str
    boundary_evidence_sha256: str
    run_evidence_sha256: str

    def __post_init__(self) -> None:
        for field_name in ("executor_id", "boundary_attestor_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        _lower_sha256(self.executor_fingerprint, field_name="executor_fingerprint")
        _lower_sha256(self.boundary_evidence_sha256, field_name="boundary_evidence_sha256")
        _lower_sha256(self.run_evidence_sha256, field_name="run_evidence_sha256")


@dataclass(frozen=True)
class IndependentAdjudication:
    adjudicator_id: str
    evidence_sha256: str
    run_id: str
    run_evidence_sha256: str
    oracle_accepted: bool
    highest_proof_level: ProofLevel | None
    invalid_verified_fact_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.adjudicator_id, str) or not self.adjudicator_id.strip():
            raise ValueError("adjudicator_id must be a non-empty string")
        _lower_sha256(self.evidence_sha256, field_name="evidence_sha256")
        _lower_sha256(self.run_id, field_name="adjudication run_id")
        _lower_sha256(
            self.run_evidence_sha256,
            field_name="adjudication run_evidence_sha256",
        )
        if not isinstance(self.oracle_accepted, bool):
            raise ValueError("oracle_accepted must be boolean")
        if self.highest_proof_level is not None and not isinstance(
            self.highest_proof_level, ProofLevel
        ):
            raise ValueError("highest_proof_level must be ProofLevel or None")
        if not isinstance(self.invalid_verified_fact_keys, tuple):
            raise ValueError("invalid_verified_fact_keys must be a tuple")
        if any(
            not isinstance(key, str) or not key
            for key in self.invalid_verified_fact_keys
        ):
            raise ValueError("invalid_verified_fact_keys must contain non-empty strings")
        if len(set(self.invalid_verified_fact_keys)) != len(self.invalid_verified_fact_keys):
            raise ValueError("invalid_verified_fact_keys must be unique")
        if self.oracle_accepted and self.highest_proof_level not in {
            None,
            ProofLevel.P6_ACCEPTED,
        }:
            raise ValueError(
                "oracle acceptance cannot be paired with a non-P6 highest proof level"
            )
        if (
            self.highest_proof_level is ProofLevel.P6_ACCEPTED
            and not self.oracle_accepted
        ):
            raise ValueError("P6 accepted proof cannot exist without oracle acceptance")


@dataclass(frozen=True)
class RawRunOutcome:
    completed_claimed: bool
    verified_fact_keys: tuple[str, ...]
    failure_signatures: tuple[str, ...]
    tool_calls: int
    steps: int
    wall_seconds: float
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    terminal_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.completed_claimed, bool):
            raise ValueError("completed_claimed must be boolean")
        if not isinstance(self.verified_fact_keys, tuple):
            raise ValueError("verified_fact_keys must be a tuple")
        if not isinstance(self.failure_signatures, tuple):
            raise ValueError("failure_signatures must be a tuple")
        if len(set(self.verified_fact_keys)) != len(self.verified_fact_keys):
            raise ValueError("verified_fact_keys must be unique")
        if any(
            not isinstance(key, str) or not key for key in self.verified_fact_keys
        ):
            raise ValueError("verified_fact_keys must contain non-empty strings")
        if any(
            not isinstance(sig, str) or not sig for sig in self.failure_signatures
        ):
            raise ValueError("failure_signatures must contain non-empty strings")
        for name in ("tool_calls", "steps"):
            value = getattr(self, name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer")
        if (
            not isinstance(self.wall_seconds, (int, float))
            or isinstance(self.wall_seconds, bool)
            or not math.isfinite(float(self.wall_seconds))
            or self.wall_seconds < 0
        ):
            raise ValueError("wall_seconds must be finite and non-negative")
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(
                    f"{name} must be a non-negative integer when provided"
                )
        if self.cost_usd is not None and (
            not isinstance(self.cost_usd, (int, float))
            or isinstance(self.cost_usd, bool)
            or not math.isfinite(float(self.cost_usd))
            or self.cost_usd < 0
        ):
            raise ValueError("cost_usd must be finite and non-negative when provided")
        if self.terminal_reason is not None and not isinstance(
            self.terminal_reason, str
        ):
            raise ValueError("terminal_reason must be a string when provided")
