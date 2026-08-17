from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from harness.core.storage import canonical_hash

from .models import BenchmarkCase, EvaluationMode


@dataclass(frozen=True)
class CorpusLock:
    name: str
    revision: str
    mode: EvaluationMode
    cases: tuple[BenchmarkCase, ...]
    unpublished: bool

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("corpus name is required")
        if not isinstance(self.revision, str) or not self.revision.strip():
            raise ValueError("corpus revision is required")
        if not isinstance(self.unpublished, bool):
            raise ValueError("unpublished must be boolean")
        if not self.cases:
            raise ValueError("corpus must contain at least one case")
        case_ids = [case.case_id for case in self.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("corpus case_id values must be unique")
        manifest_ids = [case.manifest_fingerprint for case in self.cases]
        if len(set(manifest_ids)) != len(manifest_ids):
            raise ValueError("corpus manifest fingerprints must be unique")
        if self.mode is EvaluationMode.RESEARCH and not self.unpublished:
            raise ValueError("fresh/private research corpus must be marked unpublished")

    def descriptor(self) -> dict[str, object]:
        return {
            "name": self.name,
            "revision": self.revision,
            "mode": self.mode.value,
            "unpublished": self.unpublished,
            "cases": [
                case.descriptor()
                for case in sorted(self.cases, key=lambda item: item.case_id)
            ],
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())

    def require_case(self, case_id: str, manifest_fingerprint: str) -> BenchmarkCase:
        matches = [case for case in self.cases if case.case_id == case_id]
        if len(matches) != 1:
            raise ValueError(f"case is not in frozen corpus: {case_id!r}")
        case = matches[0]
        if case.manifest_fingerprint != manifest_fingerprint:
            raise ValueError("case manifest fingerprint differs from frozen corpus")
        return case


def freeze_corpus(
    *,
    name: str,
    revision: str,
    mode: EvaluationMode,
    cases: Iterable[BenchmarkCase],
    unpublished: bool,
) -> CorpusLock:
    return CorpusLock(
        name=name,
        revision=revision,
        mode=mode,
        cases=tuple(cases),
        unpublished=unpublished,
    )
