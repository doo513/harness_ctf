from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ctf_harness.evaluation.ingest import ingest_corpus_index
from ctf_harness.evaluation.models import EvaluationMode


RUNNER = "sha256:" + "a" * 64


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_fixture(root: Path, *, mode="research", artifact_bytes=b"ELF-fixture", extra_manifest=None):
    (root / "manifests").mkdir(parents=True)
    (root / "artifacts").mkdir(parents=True)
    artifact_rel = "artifacts/challenge.bin"
    artifact = root / artifact_rel
    artifact.write_bytes(artifact_bytes)

    manifest = {
        "challenge_id": "private-pwn-1",
        "event": "private-pilot",
        "description": "controlled ingestion fixture",
        "artifact_refs": [artifact_rel],
        "remote_endpoints": [],
        "category_hint": "pwn",
        "flag_format": "FLAG{...}",
        "allowed_network": False,
        "allowed_tools": ["argv", "session"],
        "runner_image_digest": RUNNER,
        "challenge_revision": "r1",
        "oracle_type": "external",
        "benchmark_policy": mode,
    }
    if extra_manifest:
        manifest.update(extra_manifest)
    manifest_rel = "manifests/challenge.json"
    (root / manifest_rel).write_text(json.dumps(manifest), encoding="utf-8")

    index = {
        "schema_version": 1,
        "name": "controlled-private-corpus",
        "revision": "corpus-r1",
        "mode": mode,
        "unpublished": True,
        "cases": [{
            "case_id": "case-1",
            "category": "pwn",
            "difficulty": "fixture",
            "manifest": manifest_rel,
            "artifact_sha256": {artifact_rel: _sha(artifact_bytes)},
        }],
    }
    (root / "corpus.json").write_text(json.dumps(index), encoding="utf-8")
    return index, manifest, artifact


def test_valid_ingestion_hashes_index_manifest_and_artifact(tmp_path):
    _write_fixture(tmp_path)
    one = ingest_corpus_index(tmp_path)
    two = ingest_corpus_index(tmp_path)

    assert one.corpus.mode is EvaluationMode.RESEARCH
    assert len(one.corpus.cases) == 1
    assert len(one.index_sha256) == 64
    assert one.admitted_manifest_sha256 == two.admitted_manifest_sha256
    assert one.admitted_artifact_sha256 == two.admitted_artifact_sha256
    assert one.fingerprint() == two.fingerprint()
    assert one.corpus.cases[0].challenge_revision == "r1"


def test_artifact_tamper_is_rejected_against_index_hash(tmp_path):
    _, _, artifact = _write_fixture(tmp_path)
    artifact.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        ingest_corpus_index(tmp_path)


def test_manifest_mode_must_match_corpus_mode(tmp_path):
    index, _, _ = _write_fixture(tmp_path, mode="research")
    manifest_path = tmp_path / index["cases"][0]["manifest"]
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw["benchmark_policy"] = "competition"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="benchmark_policy differs"):
        ingest_corpus_index(tmp_path)


def test_artifact_hash_keys_must_exactly_match_manifest_refs(tmp_path):
    index, _, _ = _write_fixture(tmp_path)
    index["cases"][0]["artifact_sha256"] = {}
    (tmp_path / "corpus.json").write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly match"):
        ingest_corpus_index(tmp_path)


def test_path_traversal_is_rejected_before_file_read(tmp_path):
    index, _, _ = _write_fixture(tmp_path)
    index["cases"][0]["manifest"] = "../outside.json"
    (tmp_path / "corpus.json").write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ValueError, match="normalized relative path"):
        ingest_corpus_index(tmp_path)


def test_manifest_symlink_is_rejected(tmp_path):
    index, _, _ = _write_fixture(tmp_path)
    original = tmp_path / index["cases"][0]["manifest"]
    target = tmp_path / "real-manifest.json"
    target.write_bytes(original.read_bytes())
    original.unlink()
    try:
        original.symlink_to(target)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError, match="rejects symbolic links"):
        ingest_corpus_index(tmp_path)


def test_artifact_symlink_is_rejected(tmp_path):
    index, _, artifact = _write_fixture(tmp_path)
    target = tmp_path / "real-artifact.bin"
    target.write_bytes(artifact.read_bytes())
    artifact.unlink()
    try:
        artifact.symlink_to(target)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(ValueError, match="rejects symbolic links"):
        ingest_corpus_index(tmp_path)


def test_unknown_index_or_manifest_fields_fail_closed(tmp_path):
    index, _, _ = _write_fixture(tmp_path)
    index["unexpected"] = True
    (tmp_path / "corpus.json").write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        ingest_corpus_index(tmp_path)

    index.pop("unexpected")
    (tmp_path / "corpus.json").write_text(json.dumps(index), encoding="utf-8")
    manifest_path = tmp_path / index["cases"][0]["manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["unexpected"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        ingest_corpus_index(tmp_path)


def test_manifest_allowed_network_requires_real_boolean(tmp_path):
    _write_fixture(tmp_path, extra_manifest={"allowed_network": "false"})
    with pytest.raises(ValueError, match="allowed_network must be boolean"):
        ingest_corpus_index(tmp_path)


def test_duplicate_manifest_path_is_rejected(tmp_path):
    index, _, _ = _write_fixture(tmp_path)
    duplicate = dict(index["cases"][0])
    duplicate["case_id"] = "case-2"
    index["cases"].append(duplicate)
    (tmp_path / "corpus.json").write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ValueError, match="reuse the same manifest path"):
        ingest_corpus_index(tmp_path)
