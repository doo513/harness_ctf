from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Callable

from harness.core.oracles import CompletionResult
from harness.core.storage import canonical_hash


def _nonempty(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty")
    return value.strip()


def _sha256(value: str, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{field} must be a 64-character SHA-256 hex string")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be hexadecimal") from exc
    if value.lower() != value:
        raise ValueError(f"{field} must use lowercase hex")
    return value


@dataclass(frozen=True)
class FlagSubmissionReceipt:
    candidate_hash: str
    challenge_id: str
    target: str
    submitted_at_ns: int
    accepted: bool
    challenge_revision: str | None = None
    oracle_response_ref_hash: str | None = None

    def validate_for_completion(self) -> None:
        _sha256(self.candidate_hash, field="candidate_hash")
        _nonempty(self.challenge_id, field="challenge_id")
        _nonempty(self.target, field="target")
        if not isinstance(self.submitted_at_ns, int) or isinstance(self.submitted_at_ns, bool) or self.submitted_at_ns <= 0:
            raise ValueError("submitted_at_ns must be a positive integer")
        if not isinstance(self.accepted, bool):
            raise ValueError("accepted must be bool")
        _nonempty(self.challenge_revision or "", field="challenge_revision")
        if self.accepted:
            _sha256(self.oracle_response_ref_hash or "", field="oracle_response_ref_hash")
        elif self.oracle_response_ref_hash is not None:
            _sha256(self.oracle_response_ref_hash, field="oracle_response_ref_hash")

    def evidence(self) -> dict:
        return {
            "candidate_hash": self.candidate_hash,
            "challenge_id": self.challenge_id,
            "challenge_revision": self.challenge_revision,
            "target": self.target,
            "submitted_at_ns": self.submitted_at_ns,
            "accepted": self.accepted,
            "oracle_response_ref_hash": self.oracle_response_ref_hash,
        }


class ExternalFlagOracle:
    """Submission adapter that stores hashes only; Core completion is separate."""

    def __init__(self, submit: Callable[[str], tuple[bool, str | None]]):
        self._submit = submit

    def submit(self, challenge_id: str, target: str, candidate: str, *, challenge_revision: str | None = None) -> FlagSubmissionReceipt:
        challenge_id = _nonempty(challenge_id, field="challenge_id")
        target = _nonempty(target, field="target")
        if not isinstance(candidate, str) or not candidate:
            raise ValueError("candidate must be non-empty")
        if challenge_revision is not None:
            challenge_revision = _nonempty(challenge_revision, field="challenge_revision")
        accepted, response_ref = self._submit(candidate)
        if not isinstance(accepted, bool):
            raise TypeError("external flag submit callback must return bool acceptance")
        if accepted and (not isinstance(response_ref, str) or not response_ref.strip()):
            raise ValueError("accepted external flag submission requires a non-empty response reference")
        response_hash = None
        if response_ref is not None:
            if not isinstance(response_ref, str):
                raise TypeError("external flag response reference must be str or None")
            response_hash = hashlib.sha256(response_ref.encode()).hexdigest()
        return FlagSubmissionReceipt(
            candidate_hash=hashlib.sha256(candidate.encode()).hexdigest(),
            challenge_id=challenge_id,
            target=target,
            submitted_at_ns=time.time_ns(),
            accepted=accepted,
            challenge_revision=challenge_revision,
            oracle_response_ref_hash=response_hash,
        )


class FlagReceiptCompletionOracle:
    """Core completion oracle backed by an operator/control-plane receipt provider."""

    name = "ctf_flag_receipt_completion"

    def __init__(self, *, challenge_id: str, challenge_revision: str, target: str, receipt_provider: Callable[[], FlagSubmissionReceipt | None], provider_id: str):
        self.challenge_id = _nonempty(challenge_id, field="challenge_id")
        self.challenge_revision = _nonempty(challenge_revision, field="challenge_revision")
        self.target = _nonempty(target, field="target")
        self.receipt_provider = receipt_provider
        self.provider_id = _nonempty(provider_id, field="provider_id")
        descriptor = {
            "schema_version": 1,
            "challenge_id": self.challenge_id,
            "challenge_revision": self.challenge_revision,
            "target": self.target,
            "provider_id": self.provider_id,
        }
        self.oracle_id = f"{self.name}:{canonical_hash(descriptor)[:16]}"

    def _result(self, *, accepted: bool, reason: str, evidence: list[dict]) -> CompletionResult:
        return CompletionResult(
            accepted=accepted,
            reason=reason,
            evidence=evidence,
            oracle_id=self.oracle_id,
            independence_level="external_task_oracle_receipt",
            evidence_hash=canonical_hash(evidence),
            coverage={
                "challenge_id": 1,
                "challenge_revision": 1,
                "target": 1,
                "external_acceptance": 1 if accepted else 0,
            },
        )

    def evaluate(self, *, goal, state, workspace) -> CompletionResult:
        del state, workspace
        if getattr(goal, "task_id", None) != self.challenge_id:
            return self._result(accepted=False, reason="goal task_id does not match configured external challenge", evidence=[])
        try:
            receipt = self.receipt_provider()
        except Exception as exc:
            return self._result(accepted=False, reason=f"external receipt provider failed: {type(exc).__name__}", evidence=[])
        if receipt is None:
            return self._result(accepted=False, reason="no external flag submission receipt is available", evidence=[])
        if not isinstance(receipt, FlagSubmissionReceipt):
            return self._result(accepted=False, reason="external receipt provider returned an unsupported receipt type", evidence=[])
        try:
            receipt.validate_for_completion()
        except Exception as exc:
            return self._result(accepted=False, reason=f"external receipt is malformed: {type(exc).__name__}", evidence=[])

        evidence = [receipt.evidence()]
        if receipt.challenge_id != self.challenge_id:
            return self._result(accepted=False, reason="external receipt challenge_id mismatch", evidence=evidence)
        if receipt.challenge_revision != self.challenge_revision:
            return self._result(accepted=False, reason="external receipt challenge revision mismatch", evidence=evidence)
        if receipt.target != self.target:
            return self._result(accepted=False, reason="external receipt target mismatch", evidence=evidence)
        if not receipt.accepted:
            return self._result(accepted=False, reason="external task oracle rejected the submitted candidate", evidence=evidence)
        return self._result(
            accepted=True,
            reason="external task oracle accepted the submitted candidate for this exact challenge revision and target",
            evidence=evidence,
        )
