from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class HypothesisStatus(str, Enum):
    OPEN = "open"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    PROVED = "proved"


class AttemptStatus(str, Enum):
    INFLIGHT = "inflight"
    FAILED = "failed"
    SUCCEEDED = "succeeded"
    AMBIGUOUS = "ambiguous"


@dataclass
class Hypothesis:
    id: str
    category: str
    target: str
    vulnerability_class: str
    primitive: str
    claim: str
    evidence_refs: list[str] = field(default_factory=list)
    evidence_state_digest: str = ""
    support_evidence: list[str] = field(default_factory=list)
    contradiction_evidence: list[str] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.OPEN
    attempt_count: int = 0
    last_failure_signature: str | None = None

    def dump(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "Hypothesis":
        data = dict(raw)
        data["status"] = HypothesisStatus(data.get("status", HypothesisStatus.OPEN.value))
        data["evidence_refs"] = list(data.get("evidence_refs", []))
        data["support_evidence"] = list(data.get("support_evidence", []))
        data["contradiction_evidence"] = list(data.get("contradiction_evidence", []))
        return cls(**data)


@dataclass
class AttemptRecord:
    attempt_id: str
    hypothesis_fingerprint: str
    action_digest: str
    evidence_state_digest: str
    step: int
    status: AttemptStatus = AttemptStatus.INFLIGHT
    failure_signature: str | None = None
    failure_kind: str | None = None
    retry_safe: bool = False

    def dump(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "AttemptRecord":
        data = dict(raw)
        data["status"] = AttemptStatus(data.get("status", AttemptStatus.INFLIGHT.value))
        return cls(**data)
