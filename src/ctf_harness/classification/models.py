from dataclasses import dataclass
@dataclass(frozen=True)
class CategoryCandidate:
    category: str
    score: float
@dataclass(frozen=True)
class CategoryAssessment:
    candidates: tuple[CategoryCandidate, ...]
    evidence_refs: tuple[str, ...] = ()
    @property
    def authoritative(self) -> bool: return False
