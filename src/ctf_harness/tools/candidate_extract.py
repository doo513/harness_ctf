from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable


_DEFAULT_PATTERNS = (
    re.compile(r"flag\{[^\r\n{}]{1,512}\}", re.IGNORECASE),
    re.compile(r"ctf\{[^\r\n{}]{1,512}\}", re.IGNORECASE),
)


@dataclass(frozen=True)
class FlagCandidate:
    candidate: str
    candidate_sha256: str
    source_ref: str

    def descriptor(self, *, expose_candidate: bool = False) -> dict:
        data = {
            "candidate_sha256": self.candidate_sha256,
            "source_ref": self.source_ref,
            "authority": "candidate_observation_only",
            "accepted": False,
        }
        if expose_candidate:
            data["candidate"] = self.candidate
        return data


class FlagCandidateExtractor:
    """Find flag-shaped strings only; acceptance remains External Oracle authority."""

    def __init__(self, patterns: Iterable[re.Pattern[str]] = _DEFAULT_PATTERNS):
        self.patterns = tuple(patterns)
        if not self.patterns:
            raise ValueError("at least one flag candidate pattern is required")

    def extract(self, text: str, *, source_ref: str) -> tuple[FlagCandidate, ...]:
        if not isinstance(text, str):
            raise ValueError("candidate source text must be a string")
        if not isinstance(source_ref, str) or not source_ref.strip():
            raise ValueError("source_ref must be non-empty")
        found: dict[str, FlagCandidate] = {}
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                candidate = match.group(0)
                digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
                found.setdefault(digest, FlagCandidate(candidate, digest, source_ref))
        return tuple(found[key] for key in sorted(found))
