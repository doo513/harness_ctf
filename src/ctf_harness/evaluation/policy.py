from __future__ import annotations

from dataclasses import dataclass

from harness.core.storage import canonical_hash

from .models import EvaluationMode


@dataclass(frozen=True)
class LeakagePolicy:
    mode: EvaluationMode
    web_enabled: bool
    exact_challenge_name_search_allowed: bool
    writeup_search_allowed: bool
    direct_flag_search_allowed: bool
    external_provenance_required: bool

    @classmethod
    def research(cls) -> "LeakagePolicy":
        return cls(
            mode=EvaluationMode.RESEARCH,
            web_enabled=False,
            exact_challenge_name_search_allowed=False,
            writeup_search_allowed=False,
            direct_flag_search_allowed=False,
            external_provenance_required=True,
        )

    @classmethod
    def competition(cls) -> "LeakagePolicy":
        return cls(
            mode=EvaluationMode.COMPETITION,
            web_enabled=True,
            exact_challenge_name_search_allowed=True,
            writeup_search_allowed=True,
            direct_flag_search_allowed=True,
            external_provenance_required=True,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.mode, EvaluationMode):
            raise ValueError("leakage policy mode must be EvaluationMode")
        values = (
            self.web_enabled,
            self.exact_challenge_name_search_allowed,
            self.writeup_search_allowed,
            self.direct_flag_search_allowed,
            self.external_provenance_required,
        )
        if any(not isinstance(value, bool) for value in values):
            raise ValueError("leakage policy switches must be boolean")
        if self.mode is EvaluationMode.RESEARCH:
            if self.web_enabled:
                raise ValueError("research benchmark policy requires web disabled")
            if any((
                self.exact_challenge_name_search_allowed,
                self.writeup_search_allowed,
                self.direct_flag_search_allowed,
            )):
                raise ValueError("research benchmark policy forbids challenge/writeup/flag search")
            if not self.external_provenance_required:
                raise ValueError("research benchmark policy requires provenance accounting")

    def descriptor(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "web_enabled": self.web_enabled,
            "exact_challenge_name_search_allowed": self.exact_challenge_name_search_allowed,
            "writeup_search_allowed": self.writeup_search_allowed,
            "direct_flag_search_allowed": self.direct_flag_search_allowed,
            "external_provenance_required": self.external_provenance_required,
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())


def assert_mode_policy(mode: EvaluationMode, policy: LeakagePolicy) -> None:
    if not isinstance(mode, EvaluationMode):
        raise ValueError("mode must be EvaluationMode")
    if policy.mode is not mode:
        raise ValueError("experiment mode and leakage policy mode must match")
