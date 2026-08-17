from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.core.storage import IntegrityError, canonical_hash

from ctf_harness.admission.artifact import admit_artifact
from ctf_harness.manifest.models import ChallengeManifest

from .corpus import CorpusLock, case_from_manifest, freeze_corpus
from .models import EvaluationMode


_INDEX_KEYS = {"schema_version", "name", "revision", "mode", "unpublished", "cases"}
_CASE_KEYS = {"case_id", "category", "difficulty", "manifest", "artifact_sha256"}
_MANIFEST_KEYS = {
    "challenge_id",
    "event",
    "description",
    "artifact_refs",
    "remote_endpoints",
    "category_hint",
    "flag_format",
    "allowed_network",
    "allowed_tools",
    "runner_image_digest",
    "challenge_revision",
    "oracle_type",
    "benchmark_policy",
}
_TUPLE_MANIFEST_FIELDS = {"artifact_refs", "remote_endpoints", "allowed_tools"}


def _sha256(value: str, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field} must be lowercase SHA-256 hex")
    return value


def _safe_relative_regular_file(root: Path, relative: str, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative.strip():
        raise ValueError(f"{label} must be a non-empty relative path")
    rel = Path(relative)
    if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        raise ValueError(f"{label} must be a normalized relative path")

    root_resolved = root.resolve(strict=True)
    current = root_resolved
    for part in rel.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"{label} path rejects symbolic links")

    resolved = (root_resolved / rel).resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"{label} escapes corpus root") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} must resolve to a regular file")
    return resolved


def _read_json_regular(path: Path, *, label: str) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{label} must be a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        if len(raw) != info.st_size:
            raise IntegrityError(f"{label} changed while being read")
    finally:
        os.close(fd)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} must contain UTF-8 JSON") from exc


def _strict_object(raw: Any, *, allowed: set[str], required: set[str], label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{label} must be a JSON object")
    extras = set(raw) - allowed
    missing = required - set(raw)
    if extras:
        raise ValueError(f"{label} contains unsupported fields: {', '.join(sorted(extras))}")
    if missing:
        raise ValueError(f"{label} is missing fields: {', '.join(sorted(missing))}")
    return dict(raw)


def load_challenge_manifest_json(path: Path) -> ChallengeManifest:
    raw = _strict_object(
        _read_json_regular(path, label="challenge manifest"),
        allowed=_MANIFEST_KEYS,
        required={"challenge_id", "event", "description", "runner_image_digest", "challenge_revision"},
        label="challenge manifest",
    )
    for field in _TUPLE_MANIFEST_FIELDS:
        value = raw.get(field, [])
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"challenge manifest {field} must be a JSON string array")
        raw[field] = tuple(value)
    if "allowed_network" in raw and not isinstance(raw["allowed_network"], bool):
        raise ValueError("challenge manifest allowed_network must be boolean")
    return ChallengeManifest(**raw)


@dataclass(frozen=True)
class IngestedCorpus:
    corpus: CorpusLock
    index_sha256: str
    admitted_manifest_sha256: tuple[tuple[str, str], ...]
    admitted_artifact_sha256: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _sha256(self.index_sha256, field="index_sha256")
        if not isinstance(self.admitted_manifest_sha256, tuple):
            raise ValueError("admitted_manifest_sha256 must be an immutable tuple")
        if not isinstance(self.admitted_artifact_sha256, tuple):
            raise ValueError("admitted_artifact_sha256 must be an immutable tuple")

    def descriptor(self) -> dict[str, object]:
        return {
            "corpus_fingerprint": self.corpus.fingerprint(),
            "index_sha256": self.index_sha256,
            "admitted_manifest_sha256": [list(item) for item in self.admitted_manifest_sha256],
            "admitted_artifact_sha256": [list(item) for item in self.admitted_artifact_sha256],
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())


def ingest_corpus_index(corpus_root: str | Path, index_relative: str = "corpus.json") -> IngestedCorpus:
    root = Path(corpus_root)
    if not root.exists() or not root.is_dir():
        raise ValueError("corpus_root must be an existing directory")
    index_path = _safe_relative_regular_file(root, index_relative, label="corpus index")
    index_admission = admit_artifact(index_path)
    raw = _strict_object(
        _read_json_regular(index_path, label="corpus index"),
        allowed=_INDEX_KEYS,
        required=_INDEX_KEYS,
        label="corpus index",
    )
    if raw["schema_version"] != 1:
        raise ValueError("unsupported corpus index schema_version")
    try:
        mode = EvaluationMode(raw["mode"])
    except (TypeError, ValueError) as exc:
        raise ValueError("corpus index mode must be research or competition") from exc
    if not isinstance(raw["unpublished"], bool):
        raise ValueError("corpus index unpublished must be boolean")
    if not isinstance(raw["cases"], list) or not raw["cases"]:
        raise ValueError("corpus index cases must be a non-empty array")

    cases = []
    artifact_pairs: list[tuple[str, str]] = []
    manifest_pairs: list[tuple[str, str]] = []
    manifest_paths: set[str] = set()
    for position, item in enumerate(raw["cases"]):
        case_raw = _strict_object(
            item,
            allowed=_CASE_KEYS,
            required={"case_id", "category", "manifest", "artifact_sha256"},
            label=f"corpus case[{position}]",
        )
        manifest_rel = case_raw["manifest"]
        manifest_path = _safe_relative_regular_file(root, manifest_rel, label="challenge manifest")
        if manifest_rel in manifest_paths:
            raise ValueError("corpus cases must not reuse the same manifest path")
        manifest_paths.add(manifest_rel)
        manifest_admission = admit_artifact(manifest_path)
        manifest_pairs.append((manifest_rel, manifest_admission.sha256))

        manifest = load_challenge_manifest_json(manifest_path)
        if manifest.benchmark_policy != mode.value:
            raise ValueError("challenge manifest benchmark_policy differs from corpus mode")

        expected = case_raw["artifact_sha256"]
        if not isinstance(expected, dict):
            raise ValueError("artifact_sha256 must be an object keyed by manifest artifact_refs")
        if set(expected) != set(manifest.artifact_refs):
            raise ValueError("artifact_sha256 keys must exactly match manifest artifact_refs")

        artifact_hashes: dict[str, str] = {}
        for artifact_ref in manifest.artifact_refs:
            digest = _sha256(expected[artifact_ref], field=f"artifact_sha256[{artifact_ref!r}]")
            artifact_path = _safe_relative_regular_file(root, artifact_ref, label="challenge artifact")
            admitted = admit_artifact(artifact_path, expected_sha256=digest)
            artifact_hashes[artifact_ref] = admitted.sha256
            artifact_pairs.append((artifact_ref, admitted.sha256))

        cases.append(case_from_manifest(
            manifest,
            artifact_hashes,
            case_id=case_raw["case_id"],
            category=case_raw["category"],
            difficulty=case_raw.get("difficulty"),
        ))

    corpus = freeze_corpus(
        name=raw["name"],
        revision=raw["revision"],
        mode=mode,
        cases=cases,
        unpublished=raw["unpublished"],
    )
    return IngestedCorpus(
        corpus=corpus,
        index_sha256=index_admission.sha256,
        admitted_manifest_sha256=tuple(sorted(manifest_pairs)),
        admitted_artifact_sha256=tuple(sorted(set(artifact_pairs))),
    )
