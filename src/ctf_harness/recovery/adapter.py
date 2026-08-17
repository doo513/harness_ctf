from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from harness.core.failures import Failure, FailureKind


class CTFFailureKind(str, Enum):
    RECON_INCOMPLETE = "RECON_INCOMPLETE"
    CATEGORY_MISCLASSIFIED = "CATEGORY_MISCLASSIFIED"
    TOOL_MISSING = "TOOL_MISSING"
    TOOL_FAILURE = "TOOL_FAILURE"
    INTERACTIVE_STALL = "INTERACTIVE_STALL"
    HYPOTHESIS_REFUTED = "HYPOTHESIS_REFUTED"
    PRIMITIVE_NOT_REPRODUCIBLE = "PRIMITIVE_NOT_REPRODUCIBLE"
    LOCAL_PROOF_FAILED = "LOCAL_PROOF_FAILED"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    REMOTE_PROOF_FAILED = "REMOTE_PROOF_FAILED"
    FLAG_REJECTED = "FLAG_REJECTED"
    NO_INFORMATION_GAIN = "NO_INFORMATION_GAIN"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


@dataclass(frozen=True)
class RecoveryMapping:
    core_failure: FailureKind
    target: str
    retry_safe_default: bool = False

    def dump(self) -> dict[str, object]:
        return {
            "core_failure": self.core_failure.value,
            "target": self.target,
            "retry_safe_default": self.retry_safe_default,
        }


_MAP: dict[CTFFailureKind, RecoveryMapping] = {
    CTFFailureKind.RECON_INCOMPLETE: RecoveryMapping(FailureKind.MISSING_INFO, "targeted_recon"),
    # CTF category assessments and sidecar hypotheses are not Core logical
    # hypotheses. Core HYPOTHESIS_REFUTED would make ROLLBACK interpret the
    # recovery label as a Core hypothesis key, so these use Base REPLAN.
    CTFFailureKind.CATEGORY_MISCLASSIFIED: RecoveryMapping(FailureKind.NO_PROGRESS, "category_switch"),
    CTFFailureKind.TOOL_MISSING: RecoveryMapping(FailureKind.ENV_ERROR, "install_or_substitute_tool"),
    CTFFailureKind.TOOL_FAILURE: RecoveryMapping(FailureKind.TOOL_ERROR, "repair_or_substitute"),
    CTFFailureKind.INTERACTIVE_STALL: RecoveryMapping(FailureKind.NO_PROGRESS, "restart_or_switch_session"),
    CTFFailureKind.HYPOTHESIS_REFUTED: RecoveryMapping(FailureKind.NO_PROGRESS, "close_branch"),
    CTFFailureKind.PRIMITIVE_NOT_REPRODUCIBLE: RecoveryMapping(FailureKind.VERIFICATION_FAILED, "alternate_primitive"),
    CTFFailureKind.LOCAL_PROOF_FAILED: RecoveryMapping(FailureKind.VERIFICATION_FAILED, "proof_strategy_switch"),
    CTFFailureKind.ENVIRONMENT_MISMATCH: RecoveryMapping(FailureKind.ENV_ERROR, "environment_adaptation"),
    CTFFailureKind.REMOTE_PROOF_FAILED: RecoveryMapping(FailureKind.VERIFICATION_FAILED, "inspect_environment_diff"),
    CTFFailureKind.FLAG_REJECTED: RecoveryMapping(FailureKind.VERIFICATION_FAILED, "return_to_proof"),
    CTFFailureKind.NO_INFORMATION_GAIN: RecoveryMapping(FailureKind.NO_PROGRESS, "strategy_switch"),
    CTFFailureKind.BUDGET_EXHAUSTED: RecoveryMapping(FailureKind.BUDGET_EXCEEDED, "checkpoint_stop"),
}


def normalize_ctf_failure_kind(kind: CTFFailureKind | str) -> CTFFailureKind:
    if isinstance(kind, CTFFailureKind):
        return kind
    if not isinstance(kind, str):
        raise ValueError("CTF failure kind must be a CTFFailureKind or string")
    try:
        return CTFFailureKind(kind)
    except ValueError as exc:
        raise ValueError(f"unknown CTF failure kind: {kind!r}") from exc


def map_failure(kind: CTFFailureKind | str) -> RecoveryMapping:
    return _MAP[normalize_ctf_failure_kind(kind)]


def mappings_descriptor() -> dict[str, dict[str, object]]:
    return {
        kind.value: mapping.dump()
        for kind, mapping in sorted(_MAP.items(), key=lambda item: item[0].value)
    }


def to_core_failure(
    kind: CTFFailureKind | str,
    *,
    message: str,
    subject: str | None = None,
    retry_safe: bool | None = None,
) -> tuple[CTFFailureKind, RecoveryMapping, Failure]:
    ctf_kind = normalize_ctf_failure_kind(kind)
    mapping = _MAP[ctf_kind]
    if not isinstance(message, str) or not message.strip():
        raise ValueError("CTF failure message must be a non-empty string")
    if subject is not None and (not isinstance(subject, str) or not subject.strip()):
        raise ValueError("CTF failure subject must be a non-empty string when provided")
    if retry_safe is not None and not isinstance(retry_safe, bool):
        raise ValueError("CTF failure retry_safe must be a boolean when provided")

    safe = mapping.retry_safe_default if retry_safe is None else retry_safe
    normalized_subject = subject.strip() if isinstance(subject, str) else ""
    core = Failure(
        mapping.core_failure,
        message.strip(),
        action=mapping.target,
        retry_safe=safe,
        signature_key=f"ctf:{ctf_kind.value}:{normalized_subject}",
    )
    return ctf_kind, mapping, core
