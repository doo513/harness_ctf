from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .models import ChallengeManifest


def _valid_sha256(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def manifest_fingerprint(manifest: ChallengeManifest, artifact_hashes: dict[str, str]) -> str:
    expected = set(manifest.artifact_refs)
    supplied = set(artifact_hashes)
    if supplied != expected:
        missing = sorted(expected - supplied)
        extra = sorted(supplied - expected)
        raise ValueError(f"artifact hash set does not match manifest: missing={missing}, extra={extra}")
    if any(not _valid_sha256(value) for value in artifact_hashes.values()):
        raise ValueError("artifact hashes must be lowercase SHA-256 hex digests")
    body = {"manifest": asdict(manifest), "artifact_hashes": dict(sorted(artifact_hashes.items()))}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()
