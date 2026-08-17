from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from harness.core.storage import IntegrityError, atomic_write_json, canonical_hash

from .metrics import BenchmarkRunRecord
from .runner import BenchmarkPlan


def record_descriptor(record: BenchmarkRunRecord) -> dict[str, object]:
    return {
        "run_id": record.run_id,
        "comparison_key": record.comparison_key,
        "case_id": record.case_id,
        "manifest_fingerprint": record.manifest_fingerprint,
        "mode": record.mode.value,
        "arm": record.arm.value,
        "repeat_index": record.repeat_index,
        "oracle_accepted": record.oracle_accepted,
        "completed_claimed": record.completed_claimed,
        "highest_proof_level": record.highest_proof_level,
        "false_completion": record.false_completion,
        "false_fact_count": record.false_fact_count,
        "repeated_failure_count": record.repeated_failure_count,
        "tool_calls": record.tool_calls,
        "steps": record.steps,
        "wall_seconds": record.wall_seconds,
        "input_tokens": record.input_tokens,
        "output_tokens": record.output_tokens,
        "cost_usd": record.cost_usd,
        "terminal_reason": record.terminal_reason,
    }


@dataclass(frozen=True)
class BenchmarkResultBundle:
    plan_fingerprint: str
    records: tuple[BenchmarkRunRecord, ...]

    @classmethod
    def finalize(
        cls,
        plan: BenchmarkPlan,
        records: Iterable[BenchmarkRunRecord],
    ) -> "BenchmarkResultBundle":
        rows = tuple(records)
        expected = {spec.run_id(): spec for spec in plan.runs}
        observed_ids = [row.run_id for row in rows]
        if len(set(observed_ids)) != len(observed_ids):
            raise ValueError("result bundle contains duplicate run IDs")
        if set(observed_ids) != set(expected):
            missing = sorted(set(expected) - set(observed_ids))
            extra = sorted(set(observed_ids) - set(expected))
            raise ValueError(f"result set does not exactly match plan: missing={missing}, extra={extra}")

        for row in rows:
            spec = expected[row.run_id]
            if row.comparison_key != spec.comparison_key():
                raise ValueError("result comparison key differs from planned run")
            if row.case_id != spec.case.case_id or row.manifest_fingerprint != spec.case.manifest_fingerprint:
                raise ValueError("result case identity differs from planned run")
            if row.mode is not spec.experiment.mode or row.arm is not spec.arm.arm:
                raise ValueError("result mode/arm differs from planned run")
            if row.repeat_index != spec.repeat_index:
                raise ValueError("result repeat index differs from planned run")

        return cls(
            plan_fingerprint=plan.fingerprint(),
            records=tuple(sorted(rows, key=lambda item: item.run_id)),
        )

    def body(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "plan_fingerprint": self.plan_fingerprint,
            "records": [record_descriptor(row) for row in self.records],
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.body())

    def save(self, path: str | Path) -> str:
        body = self.body()
        digest = canonical_hash(body)
        atomic_write_json(path, {"body": body, "body_sha256": digest})
        return digest

    @staticmethod
    def verify_saved(path: str | Path, *, expected_plan_fingerprint: str) -> dict[str, object]:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise IntegrityError("benchmark result bundle is missing") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"cannot read benchmark result bundle: {exc}") from exc
        if not isinstance(raw, dict) or set(raw) != {"body", "body_sha256"}:
            raise IntegrityError("malformed benchmark result envelope")
        if canonical_hash(raw["body"]) != raw.get("body_sha256"):
            raise IntegrityError("benchmark result bundle integrity mismatch")
        body = raw["body"]
        if not isinstance(body, dict) or body.get("schema_version") != 1:
            raise IntegrityError("unsupported benchmark result schema")
        if body.get("plan_fingerprint") != expected_plan_fingerprint:
            raise IntegrityError("benchmark result bundle belongs to a different plan")
        return body
