from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from harness.core.storage import canonical_hash

from ctf_harness.manifest.fingerprint import manifest_fingerprint
from ctf_harness.manifest.models import ChallengeManifest

from .models import BenchmarkCase, EvaluationMode


FIRST_PWN_PILOT_MIN_CASES = 10
FIRST_PWN_PILOT_MAX_CASES = 15


@dataclass(frozen=True)
class CorpusLock:
    name: str
    revision: str
    mode: EvaluationMode
    cases: tuple[BenchmarkCase, ...]
    unpublished: bool

    def __post_init__(self) -> None:
        if not isinstance(self.mode, EvaluationMode):
            raise ValueError("corpus mode must be EvaluationMode")
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("corpus name is required")
        if not isinstance(self.revision, str) or not self.revision.strip():
            raise ValueError("corpus revision is required")
        if not isinstance(self.unpublished, bool):
            raise ValueError("unpublished must be boolean")
        if not isinstance(self.cases, tuple):
            raise ValueError("corpus cases must be an immutable tuple")
        if not self.cases:
            raise ValueError("corpus must contain at least one case")
        if any(not isinstance(case, BenchmarkCase) for case in self.cases):
            raise ValueError("corpus cases must contain BenchmarkCase values")
        if any(case.mode is not self.mode for case in self.cases):
            raise ValueError("every benchmark case mode must match the corpus mode")
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
            "cases": [case.descriptor() for case in sorted(self.cases, key=lambda item: item.case_id)],
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())

    def require_case(self, case_id: str, manifest_fingerprint_value: str) -> BenchmarkCase:
        matches = [case for case in self.cases if case.case_id == case_id]
        if len(matches) != 1:
            raise ValueError(f"case is not in frozen corpus: {case_id!r}")
        case = matches[0]
        if case.manifest_fingerprint != manifest_fingerprint_value:
            raise ValueError("case manifest fingerprint differs from frozen corpus")
        return case


def case_from_manifest(
    manifest: ChallengeManifest,
    artifact_hashes: dict[str, str],
    *,
    case_id: str,
    category: str,
    difficulty: str | None = None,
) -> BenchmarkCase:
    try:
        mode = EvaluationMode(manifest.benchmark_policy)
    except ValueError as exc:
        raise ValueError("challenge manifest has unsupported benchmark policy") from exc
    return BenchmarkCase(
        case_id=case_id,
        challenge_id=manifest.challenge_id,
        challenge_revision=manifest.challenge_revision,
        manifest_fingerprint=manifest_fingerprint(manifest, artifact_hashes),
        mode=mode,
        category=category,
        difficulty=difficulty,
    )


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


def validate_first_pwn_pilot(corpus: CorpusLock) -> None:
    """Fail closed unless a corpus qualifies for the first meaningful Pwn pilot.

    Passing this function establishes only declared corpus shape/identity policy;
    it does not independently prove that challenge authors have never published
    the material or that contamination is impossible.
    """
    if corpus.mode is not EvaluationMode.RESEARCH:
        raise ValueError("first Pwn pilot requires research mode")
    if not corpus.unpublished:
        raise ValueError("first Pwn pilot requires an unpublished/private corpus declaration")
    if not (FIRST_PWN_PILOT_MIN_CASES <= len(corpus.cases) <= FIRST_PWN_PILOT_MAX_CASES):
        raise ValueError(
            f"first Pwn pilot requires {FIRST_PWN_PILOT_MIN_CASES}-{FIRST_PWN_PILOT_MAX_CASES} frozen cases"
        )
    if any(case.category.strip().lower() != "pwn" for case in corpus.cases):
        raise ValueError("first Pwn pilot must contain only Pwn cases")
