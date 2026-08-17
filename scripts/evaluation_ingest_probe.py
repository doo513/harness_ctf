from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from ctf_harness.evaluation.ingest import ingest_corpus_index


RUNNER = "sha256:" + "a" * 64


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_fixture(root: Path) -> Path:
    (root / "manifests").mkdir()
    (root / "artifacts").mkdir()
    artifact_rel = "artifacts/challenge.bin"
    artifact = root / artifact_rel
    artifact.write_bytes(b"controlled-private-corpus-fixture")
    manifest_rel = "manifests/challenge.json"
    manifest = {
        "challenge_id": "fixture-pwn-1",
        "event": "controlled-private-ingestion",
        "description": "metadata fixture only",
        "artifact_refs": [artifact_rel],
        "remote_endpoints": [],
        "category_hint": "pwn",
        "allowed_network": False,
        "allowed_tools": ["argv", "session"],
        "runner_image_digest": RUNNER,
        "challenge_revision": "r1",
        "oracle_type": "external_flag",
        "benchmark_policy": "research",
    }
    (root / manifest_rel).write_text(json.dumps(manifest), encoding="utf-8")
    index = {
        "schema_version": 1,
        "name": "controlled-ingestion-fixture",
        "revision": "r1",
        "mode": "research",
        "unpublished": True,
        "cases": [{
            "case_id": "case-1",
            "category": "pwn",
            "difficulty": "fixture",
            "manifest": manifest_rel,
            "artifact_sha256": {artifact_rel: sha(artifact.read_bytes())},
        }],
    }
    (root / "corpus.json").write_text(json.dumps(index), encoding="utf-8")
    return artifact


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-evaluation-ingest-") as td:
        root = Path(td)
        artifact = write_fixture(root)
        first = ingest_corpus_index(root)
        second = ingest_corpus_index(root)
        assert first.fingerprint() == second.fingerprint()
        assert len(first.index_sha256) == 64
        assert len(first.admitted_manifest_sha256) == 1
        assert len(first.admitted_artifact_sha256) == 1

        original = artifact.read_bytes()
        artifact.write_bytes(b"tampered")
        tamper_rejected = False
        try:
            ingest_corpus_index(root)
        except ValueError as exc:
            tamper_rejected = "SHA-256 mismatch" in str(exc)
        assert tamper_rejected
        artifact.write_bytes(original)

        traversal = json.loads((root / "corpus.json").read_text(encoding="utf-8"))
        traversal["cases"][0]["manifest"] = "../outside.json"
        (root / "corpus.json").write_text(json.dumps(traversal), encoding="utf-8")
        traversal_rejected = False
        try:
            ingest_corpus_index(root)
        except ValueError as exc:
            traversal_rejected = "normalized relative path" in str(exc)
        assert traversal_rejected

        print(json.dumps({
            "probe": "ctf-evaluation-corpus-ingestion-controlled-v1",
            "all_passed": True,
            "fixture_only": True,
            "actual_private_corpus": False,
            "index_hash_bound": True,
            "manifest_hash_bound": True,
            "artifact_expected_hash_enforced": True,
            "artifact_tamper_rejected": tamper_rejected,
            "path_traversal_rejected": traversal_rejected,
            "stable_ingestion_fingerprint": True,
            "freshness_independently_proven": False,
            "effectiveness_measured": False,
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
