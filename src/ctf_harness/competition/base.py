from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from .models import CompetitionChallengeSnapshot, DownloadedArtifact


class CompetitionAdapter(Protocol):
    """Platform metadata/file/submission boundary; never solve/truth authority."""

    def validate_session(self) -> bool: ...
    def list_challenges(self) -> Sequence[CompetitionChallengeSnapshot]: ...
    def get_challenge(self, challenge_id: str) -> CompetitionChallengeSnapshot: ...
    def download(self, file_url: str) -> DownloadedArtifact: ...
    def submit_flag(self, challenge_id: str, candidate: str) -> bool: ...


class InstanceProvider(Protocol):
    """Optional dynamic instance lifecycle independent from platform metadata."""

    def start(self, challenge_id: str) -> str: ...
    def status(self, challenge_id: str) -> dict: ...
    def stop(self, challenge_id: str) -> None: ...


@dataclass(frozen=True)
class StaticConnectionProvider:
    """No-lifecycle provider for challenges with a pre-declared endpoint."""

    endpoint: str

    def __post_init__(self) -> None:
        if not isinstance(self.endpoint, str) or not self.endpoint.strip():
            raise ValueError("static endpoint must be non-empty")

    def start(self, challenge_id: str) -> str:
        if not isinstance(challenge_id, str) or not challenge_id.strip():
            raise ValueError("challenge_id must be non-empty")
        return self.endpoint

    def status(self, challenge_id: str) -> dict:
        return {"challenge_id": challenge_id, "state": "static", "endpoint": self.endpoint}

    def stop(self, challenge_id: str) -> None:
        return None
