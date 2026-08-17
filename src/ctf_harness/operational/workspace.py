from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from harness.core.storage import atomic_write_json


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class RunWorkspaceProjection:
    """Human/agent-readable projection over authoritative runtime artifacts.

    This layout never becomes the source of truth. It stores only IDs, relative
    paths, hashes, and selected outcome counters from the existing durable run.
    """

    root: Path
    input_dir: Path
    work_dir: Path
    generated_dir: Path
    evidence_dir: Path
    logs_dir: Path
    reports_dir: Path

    @classmethod
    def prepare(cls, root: str | Path) -> "RunWorkspaceProjection":
        base = Path(root).resolve()
        base.mkdir(parents=True, exist_ok=True)
        if not base.is_dir():
            raise ValueError("workspace projection root must be a directory")
        names = {
            "input_dir": base / "input",
            "work_dir": base / "work",
            "generated_dir": base / "generated",
            "evidence_dir": base / "evidence",
            "logs_dir": base / "logs",
            "reports_dir": base / "reports",
        }
        for path in names.values():
            path.mkdir(exist_ok=True)
            if not path.is_dir():
                raise ValueError("workspace projection path must be a directory")
        return cls(base, **names)

    def refresh_from_run(self, run_dir: str | Path) -> dict:
        run = Path(run_dir).resolve(strict=True)
        if not run.is_dir():
            raise ValueError("run_dir must be a directory")
        required = ("run_manifest.json", "metrics.json", "events.jsonl", "tool_calls.jsonl")
        missing = [name for name in required if not (run / name).is_file()]
        if missing:
            raise ValueError("durable run is incomplete: " + ", ".join(missing))

        try:
            manifest = json.loads((run / "run_manifest.json").read_text(encoding="utf-8"))
            metrics = json.loads((run / "metrics.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read durable run projection source: {exc}") from exc

        run_id = manifest.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("run manifest lacks run_id")

        authoritative_files = {}
        for name in required:
            path = run / name
            authoritative_files[name] = {
                "source": f"run/{name}",
                "sha256": _file_sha256(path),
            }
        solve_evidence = run / "solve_execution_evidence.json"
        if solve_evidence.is_file():
            authoritative_files[solve_evidence.name] = {
                "source": f"run/{solve_evidence.name}",
                "sha256": _file_sha256(solve_evidence),
            }

        projection = {
            "schema_version": "ctf-run-workspace-projection-v1",
            "run_id": run_id,
            "authoritative_state_location": "durable_run",
            "projection_authority": "none",
            "raw_fact_state_copied": False,
            "raw_secrets_copied": False,
            "paths": {
                "input": "input/",
                "work": "work/",
                "generated": "generated/",
                "evidence": "evidence/",
                "logs": "logs/",
                "reports": "reports/",
            },
            "durable_artifacts": authoritative_files,
            "metrics": {
                key: metrics.get(key)
                for key in ("steps", "tool_calls", "wall_seconds")
                if key in metrics
            },
        }
        atomic_write_json(self.root / "run.json", projection)
        return projection

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-run-workspace-layout-v1",
            "root": self.root.name,
            "projection_authority": "none",
            "authoritative_state_location": "durable_run",
        }
