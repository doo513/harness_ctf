from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class SubmissionMode(str, Enum):
    MANUAL = "manual"
    CONFIRM = "confirm"
    AUTO = "auto"


@dataclass(frozen=True)
class SubmissionReceipt:
    challenge_id: str
    candidate_sha256: str
    accepted: bool
    attempt_number: int

    def descriptor(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "candidate_sha256": self.candidate_sha256,
            "accepted": self.accepted,
            "attempt_number": self.attempt_number,
            "raw_candidate_persisted": False,
        }


class SubmissionGuard:
    def __init__(self, mode: SubmissionMode = SubmissionMode.CONFIRM, *, budget: int = 3):
        if not isinstance(mode, SubmissionMode):
            raise ValueError("submission mode must be SubmissionMode")
        if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
            raise ValueError("submission budget must be a positive integer")
        self.mode = mode
        self.budget = budget
        self._attempted: set[str] = set()
        self._rejected: set[str] = set()
        self._attempt_count = 0

    @staticmethod
    def candidate_sha256(candidate: str) -> str:
        if not isinstance(candidate, str) or not candidate:
            raise ValueError("flag candidate must be non-empty")
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest()

    def authorize(self, candidate: str, *, confirmed: bool = False) -> str:
        digest = self.candidate_sha256(candidate)
        if digest in self._attempted:
            raise ValueError("candidate was already submitted")
        if self._attempt_count >= self.budget:
            raise RuntimeError("submission budget exhausted")
        if self.mode is SubmissionMode.MANUAL:
            raise PermissionError("manual submission mode does not authorize automatic submission")
        if self.mode is SubmissionMode.CONFIRM and not confirmed:
            raise PermissionError("submission confirmation is required")
        return digest

    def submit(self, adapter, challenge_id: str, candidate: str, *, confirmed: bool = False) -> SubmissionReceipt:
        digest = self.authorize(candidate, confirmed=confirmed)
        accepted = bool(adapter.submit_flag(challenge_id, candidate))
        self._attempt_count += 1
        self._attempted.add(digest)
        if not accepted:
            self._rejected.add(digest)
        return SubmissionReceipt(challenge_id, digest, accepted, self._attempt_count)

    def was_rejected(self, candidate: str) -> bool:
        return self.candidate_sha256(candidate) in self._rejected

    def descriptor(self) -> dict:
        return {
            "mode": self.mode.value,
            "budget": self.budget,
            "attempt_count": self._attempt_count,
            "attempted_candidate_hashes": sorted(self._attempted),
            "rejected_candidate_hashes": sorted(self._rejected),
            "raw_candidates_persisted": False,
        }
