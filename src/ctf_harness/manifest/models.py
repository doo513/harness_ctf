from __future__ import annotations

from dataclasses import dataclass
import re

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

@dataclass(frozen=True)
class ChallengeManifest:
    challenge_id: str
    event: str
    description: str
    artifact_refs: tuple[str, ...] = ()
    remote_endpoints: tuple[str, ...] = ()
    category_hint: str | None = None
    flag_format: str | None = None
    allowed_network: bool = False
    allowed_tools: tuple[str, ...] = ()
    runner_image_digest: str = ""
    challenge_revision: str = ""
    oracle_type: str = "external"
    benchmark_policy: str = "research"

    def __post_init__(self) -> None:
        if not isinstance(self.challenge_id, str) or not self.challenge_id.strip():
            raise ValueError("challenge_id is required")
        if not isinstance(self.event, str) or not self.event.strip():
            raise ValueError("event is required")
        if not isinstance(self.challenge_revision, str) or not self.challenge_revision.strip():
            raise ValueError("challenge_revision is required")
        if not isinstance(self.runner_image_digest, str) or not _DIGEST_RE.fullmatch(self.runner_image_digest):
            raise ValueError("runner_image_digest must be sha256:<64 lowercase hex>")
        if self.benchmark_policy not in {"research", "competition"}:
            raise ValueError("benchmark_policy must be research or competition")
        if self.oracle_type != "external":
            raise ValueError("initial CTF profile requires external oracle authority")
        if len(set(self.artifact_refs)) != len(self.artifact_refs):
            raise ValueError("artifact_refs must be unique")
        if len(set(self.remote_endpoints)) != len(self.remote_endpoints):
            raise ValueError("remote_endpoints must be unique")
        if len(set(self.allowed_tools)) != len(self.allowed_tools):
            raise ValueError("allowed_tools must be unique")
