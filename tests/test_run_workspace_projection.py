from __future__ import annotations

import json
from pathlib import Path

from ctf_harness.operational.workspace import RunWorkspaceProjection


def test_run_workspace_projection_contains_refs_hashes_not_fact_state(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "run_manifest.json").write_text(json.dumps({"run_id": "run-513"}), encoding="utf-8")
    (run / "metrics.json").write_text(json.dumps({"steps": 3, "tool_calls": 2, "wall_seconds": 1.25, "secret": "do-not-project"}), encoding="utf-8")
    (run / "events.jsonl").write_text('{"fact":"do-not-copy"}\n', encoding="utf-8")
    (run / "tool_calls.jsonl").write_text('{"token":"do-not-copy"}\n', encoding="utf-8")

    projection = RunWorkspaceProjection.prepare(tmp_path / "projection")
    rendered = projection.refresh_from_run(run)
    assert rendered["run_id"] == "run-513"
    assert rendered["projection_authority"] == "none"
    assert rendered["raw_fact_state_copied"] is False
    assert rendered["raw_secrets_copied"] is False
    assert rendered["metrics"] == {"steps": 3, "tool_calls": 2, "wall_seconds": 1.25}
    persisted = (projection.root / "run.json").read_text(encoding="utf-8")
    assert "do-not-copy" not in persisted
    assert "do-not-project" not in persisted
    assert "events.jsonl" in rendered["durable_artifacts"]
    assert len(rendered["durable_artifacts"]["events.jsonl"]["sha256"]) == 64


def test_projection_requires_complete_durable_run_shape(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "run_manifest.json").write_text(json.dumps({"run_id": "x"}))
    projection = RunWorkspaceProjection.prepare(tmp_path / "projection")
    try:
        projection.refresh_from_run(run)
    except ValueError as exc:
        assert "durable run is incomplete" in str(exc)
    else:
        raise AssertionError("incomplete durable run must be rejected")
