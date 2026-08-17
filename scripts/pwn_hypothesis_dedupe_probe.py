from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.controller import Decision
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend

from ctf_harness.hypotheses.models import HypothesisStatus
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.runtime import VerifiedCTFRuntime


def accept_completion(*, goal, state, workspace):
    return True


def meta(refs=None):
    return {
        "id": "overflow-control",
        "category": "pwn",
        "target": "bin/challenge",
        "vulnerability_class": "stack_overflow",
        "primitive": "rip_control",
        "claim": "saved RIP may be controlled",
        "evidence_refs": list(refs or []),
    }


def tool(action: str, refs=None):
    return Decision("tool", {
        "tool": "argv",
        "args": {"argv": ["probe", action]},
        "ctf_hypothesis": meta(refs),
    })


def latest_stdout_ref(state, marker: str) -> str:
    for observation in reversed(state.observations):
        preview = observation.preview
        if isinstance(preview, dict) and preview.get("stdout") == marker and observation.artifact_ref:
            return observation.artifact_ref
    raise AssertionError(f"missing controlled evidence marker: {marker}")


class Controller:
    def __init__(self):
        self.index = 0

    def snapshot_state(self):
        return {"index": self.index}

    def restore_state(self, raw):
        self.index = int(raw["index"])

    def decide(self, goal, state, context):
        stage = self.index
        self.index += 1
        if stage == 0:
            return tool("same-action")
        if stage == 1:
            return tool("same-action")
        if stage == 2:
            return tool("evidence-action")
        if stage == 3:
            return tool("adapted-action", [latest_stdout_ref(state, "evidence-v1")])
        if stage == 4:
            return tool("evidence-action")
        if stage == 5:
            return tool("adapted-action", [latest_stdout_ref(state, "evidence-v1")])
        if stage == 6:
            return tool("evidence-new")
        if stage == 7:
            return tool("adapted-action", [latest_stdout_ref(state, "evidence-v2")])
        if stage == 8:
            contradiction = state.observations[-1].artifact_ref
            assert contradiction
            return Decision("refute", {
                "key": "overflow-control",
                "reason": "controlled contradiction evidence",
                "ctf_hypothesis": meta([contradiction]),
            })
        if stage == 9:
            contradiction = state.observations[-1].artifact_ref
            return tool("adapted-after-refute", [contradiction])
        return Decision("complete", {"reason": "controlled WP06 probe complete"})


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-hypothesis-dedupe-") as td:
        root = Path(td)
        workspace = root / "workspace"
        workspace.mkdir()
        backend = RecordingIsolatedTestBackend({
            ("probe", "same-action"): ExecutionResult(9, "", "deterministic probe failure"),
            ("probe", "evidence-action"): ExecutionResult(0, "evidence-v1", ""),
            ("probe", "evidence-new"): ExecutionResult(0, "evidence-v2", ""),
            ("probe", "adapted-action"): ExecutionResult(9, "", "adapted deterministic failure"),
            ("probe", "adapted-after-refute"): ExecutionResult(0, "must-not-execute", ""),
        })
        controller = Controller()
        runtime = VerifiedCTFRuntime(
            goal=GoalContract(goal="controlled hypothesis dedupe probe", acceptance=["probe assertions"]),
            profile=VerifiedCTFProfile(
                workspace=workspace,
                execution_backend=backend,
                external_oracle=accept_completion,
            ),
            controller=controller,
            run_dir=root / "run",
        )
        state = runtime.run()

        calls = [tuple(item["argv"]) for item in backend.calls]
        expected = [
            ("probe", "same-action"),
            ("probe", "evidence-action"),
            ("probe", "adapted-action"),
            ("probe", "evidence-action"),
            ("probe", "evidence-new"),
            ("probe", "adapted-action"),
        ]
        assert state.completed
        assert calls == expected
        assert ("probe", "adapted-after-refute") not in calls
        assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 3
        assert runtime.metrics["ctf_hypothesis_refutations"] == 1
        assert runtime.metrics["ctf_hypothesis_attempts"] == 6
        assert runtime.metrics["recovery_transitions"] >= 6
        assert controller.index == 11

        ledger_body = runtime.ctf_hypotheses.pool.dump()
        assert len(ledger_body["hypotheses"]) == 1
        assert len(ledger_body["attempts"]) == 6
        only = next(iter(runtime.ctf_hypotheses.pool.hypotheses.values()))
        assert only.status == HypothesisStatus.REFUTED
        assert state.facts == {}

        print(json.dumps({
            "probe": "pwn-hypothesis-runtime-dedupe-controlled-v2",
            "all_passed": True,
            "base_run_loop_exercised": True,
            "backend_execution_calls": len(calls),
            "backend_calls": [list(item) for item in calls],
            "hypothesis_attempts": runtime.metrics["ctf_hypothesis_attempts"],
            "guard_blocks": runtime.metrics["ctf_hypothesis_guard_blocks"],
            "explicit_refutations": runtime.metrics["ctf_hypothesis_refutations"],
            "recovery_transitions": runtime.metrics["recovery_transitions"],
            "same_failure_same_evidence_blocked": True,
            "novel_evidence_plus_adapted_action_executed": True,
            "duplicate_ref_same_content_provenance_blocked": True,
            "refuted_hypothesis_blocked_before_backend": True,
            "stable_hypothesis_count": len(ledger_body["hypotheses"]),
            "durable_attempt_count": len(ledger_body["attempts"]),
            "ledger_anchor_policy": "latest Base hash-chained event must match sidecar body hash",
            "truth_authority": "none",
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
