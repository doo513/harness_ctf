from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable


class FindingTrust(str, Enum):
    VERIFIED = "verified"
    TENTATIVE = "tentative"


@dataclass(frozen=True)
class FindingEnvelope:
    finding_id: str
    source_agent: str
    trust: FindingTrust
    summary: str
    fact_key: str | None = None
    hypothesis_fingerprint: str | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field in ("finding_id", "source_agent", "summary"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be non-empty")
        if not isinstance(self.trust, FindingTrust):
            raise ValueError("trust must be FindingTrust")
        if not isinstance(self.evidence_refs, tuple) or any(not isinstance(ref, str) or not ref for ref in self.evidence_refs):
            raise ValueError("evidence_refs must be an immutable tuple of non-empty strings")
        if self.trust is FindingTrust.VERIFIED:
            if not isinstance(self.fact_key, str) or not self.fact_key.strip():
                raise ValueError("verified finding requires fact_key")
            if self.hypothesis_fingerprint is not None:
                raise ValueError("verified finding must not masquerade as a hypothesis")
        else:
            if not isinstance(self.hypothesis_fingerprint, str) or not self.hypothesis_fingerprint.strip():
                raise ValueError("tentative finding requires hypothesis_fingerprint")

    def descriptor(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "source_agent": self.source_agent,
            "trust": self.trust.value,
            "summary": self.summary,
            "fact_key": self.fact_key,
            "hypothesis_fingerprint": self.hypothesis_fingerprint,
            "evidence_refs": list(self.evidence_refs),
            "truth_authority": "none",
        }


class EvidenceBus:
    """Optional multi-agent exchange with provenance-aware trust channels.

    The bus cannot create facts. A VERIFIED publication is accepted only if the
    caller-provided Harness fact resolver confirms that the fact already exists.
    TENTATIVE findings remain explicitly speculative.
    """

    def __init__(self, *, verified_fact_exists: Callable[[str], bool]):
        if not callable(verified_fact_exists):
            raise ValueError("verified_fact_exists must be callable")
        self._verified_fact_exists = verified_fact_exists
        self._records: list[FindingEnvelope] = []
        self._ids: set[str] = set()

    def publish(self, finding: FindingEnvelope) -> None:
        if not isinstance(finding, FindingEnvelope):
            raise ValueError("finding must be FindingEnvelope")
        if finding.finding_id in self._ids:
            raise ValueError("duplicate finding_id")
        if finding.trust is FindingTrust.VERIFIED and not self._verified_fact_exists(finding.fact_key or ""):
            raise ValueError("verified channel requires an already verified Harness fact")
        self._records.append(finding)
        self._ids.add(finding.finding_id)

    def snapshot(self) -> dict:
        verified = [record.descriptor() for record in self._records if record.trust is FindingTrust.VERIFIED]
        tentative = [record.descriptor() for record in self._records if record.trust is FindingTrust.TENTATIVE]
        return {
            "schema_version": "ctf-evidence-bus-v1",
            "verified": verified,
            "tentative": tentative,
            "bus_truth_authority": "none",
            "verified_source": "existing_harness_facts_only",
            "multi_agent_execution": "optional_not_enabled_by_bus",
        }
