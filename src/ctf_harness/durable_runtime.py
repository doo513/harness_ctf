from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path


def file_sha256(path: Path) -> str | None:
    path = Path(path)
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_durable_runtime_metrics(path: Path, *, runtime, state) -> dict:
    """Validate Base-produced metrics.json against runtime and returned state.

    Base computes final wall time in the persisted metrics snapshot, so callers
    must not substitute the mutable `runtime.metrics` dictionary as final
    execution evidence.
    """

    path = Path(path)
    if not path.exists() or not path.is_file():
        raise ValueError("runtime did not persist metrics.json")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime metrics.json is unreadable or invalid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError("runtime metrics.json must contain an object")

    required = ("run_id", "steps", "tool_calls", "completed", "wall_seconds")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError("runtime metrics.json missing required fields: " + ", ".join(missing))

    if raw["run_id"] != getattr(runtime, "run_id", None):
        raise ValueError("runtime metrics.json is bound to a different Base runtime run_id")
    if not isinstance(raw["steps"], int) or isinstance(raw["steps"], bool) or raw["steps"] < 0:
        raise ValueError("runtime metrics steps must be a non-negative integer")
    if not isinstance(raw["tool_calls"], int) or isinstance(raw["tool_calls"], bool) or raw["tool_calls"] < 0:
        raise ValueError("runtime metrics tool_calls must be a non-negative integer")
    if not isinstance(raw["completed"], bool):
        raise ValueError("runtime metrics completed must be boolean")
    if (
        not isinstance(raw["wall_seconds"], (int, float))
        or isinstance(raw["wall_seconds"], bool)
        or not math.isfinite(float(raw["wall_seconds"]))
        or float(raw["wall_seconds"]) < 0
    ):
        raise ValueError("runtime metrics wall_seconds must be finite and non-negative")

    if raw["steps"] != int(state.step):
        raise ValueError("runtime metrics steps disagree with returned HarnessState")
    if raw["completed"] is not bool(state.completed):
        raise ValueError("runtime metrics completed disagrees with returned HarnessState")
    return raw
