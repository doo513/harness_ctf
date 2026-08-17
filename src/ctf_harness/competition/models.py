from __future__ import annotations

import hashlib
from dataclasses import dataclass


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty")
    return value.strip()


@dataclass(frozen=True)
class CompetitionChallengeSnapshot:
    """Normalized platform data only; not challenge identity authority."""

    platform: str
    challenge_id: str
    name: str
    description: str
    category: str | None = None
    file_urls: tuple[str, ...] = ()
    connection_info: str | None = None

    def __post_init__(self) -> None:
        _text(self.platform, "platform")
        _text(self.challenge_id, "challenge_id")
        _text(self.name, "name")
        if not isinstance(self.description, str):
            raise ValueError("description must be a string")
        if self.category is not None and not isinstance(self.category, str):
            raise ValueError("category must be a string when provided")
        if not isinstance(self.file_urls, tuple) or any(not isinstance(item, str) or not item for item in self.file_urls):
            raise ValueError("file_urls must be an immutable tuple of non-empty strings")
        if self.connection_info is not None and not isinstance(self.connection_info, str):
            raise ValueError("connection_info must be a string when provided")

    def descriptor(self) -> dict:
        return {
            "platform": self.platform,
            "challenge_id": self.challenge_id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "file_urls": list(self.file_urls),
            "connection_info": self.connection_info,
            "authority": "platform_snapshot_only",
            "truth_authority": "none",
        }


@dataclass(frozen=True)
class DownloadedArtifact:
    ref: str
    content: bytes
    source_url: str

    def __post_init__(self) -> None:
        _text(self.ref, "artifact ref")
        if not isinstance(self.content, bytes):
            raise ValueError("artifact content must be bytes")
        _text(self.source_url, "source_url")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def descriptor(self) -> dict:
        return {
            "ref": self.ref,
            "sha256": self.sha256,
            "bytes": len(self.content),
            "source_url": self.source_url,
            "authority": "download_observation",
        }
