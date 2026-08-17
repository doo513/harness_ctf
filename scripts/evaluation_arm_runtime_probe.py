from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.controller import Decision, ScriptedController
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend

from ctf_harness.evaluation.arm_runtime import build_runtime_for_arm, canonical_arm_selection
from ctf_harness.evaluation.models import ArmConfig
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.runtime import VerifiedCTFRuntime


def make_runtime(root: Path, arm, name: str):
    backend = RecordingIsolatedTestBackend({
        ("probe", "arm"): ExecutionResult(0, "arm-ok", ""),
    })
    workspace = root / f"workspace-{name}"
    workspace.mkdir()
    profile = VerifiedCTFProfile(workspace=workspace, execution_backend=backend)
    runtime = build_runtime_for_arm(
        arm=arm,
        profile=profile,
        goal=GoalContract(goal="controlled benchmark arm probe", acceptance=["controlled probe"]),
        controller=ScriptedController([]),
        run_dir=root / f"run-{name}",
    )
    return runtime, backend


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-arm-runtime-") as td:
        root = Path(td)
        minimal, minimal_backend = make_runtime(root, ArmConfig.minimal(), "minimal")
        verified, verified_backend = make_runtime(root, ArmConfig.verified(), "verified")

        assert not isinstance(minimal, VerifiedCTFRuntime)
        assert isinstance(verified, VerifiedCTFRuntime)
        assert minimal.profile.task_progress_snapshot(minimal.state) is None
        assert not hasattr(minimal, "ctf_hypotheses")
        assert hasattr(verified, "ctf_hypotheses")

        tool = Decision("tool", {"tool": "argv", "args": {"argv": ["probe", "arm"]}})
        minimal._dispatch_decision(tool)
        verified._dispatch_decision(tool)
        assert len(minimal_backend.calls) == 1
        assert len(verified_backend.calls) == 0
        assert verified.metrics["ctf_hypothesis_guard_blocks"] == 1

        minimal._dispatch_decision(Decision("propose", {
            "key": "ctf.pwn.crash_reproducible",
            "value": {"claimed": True},
            "evidence_refs": [],
        }))
        minimal._dispatch_decision(Decision("verify_claim", {"key": "ctf.pwn.crash_reproducible"}))
        assert "ctf.pwn.crash_reproducible" not in minimal.state.facts

        min_sel = canonical_arm_selection(ArmConfig.minimal())
        ver_sel = canonical_arm_selection(ArmConfig.verified())
        print(json.dumps({
            "probe": "ctf-evaluation-canonical-arm-runtime-controlled-v1",
            "all_passed": True,
            "actual_llm_executed": False,
            "actual_private_corpus": False,
            "minimal_runtime_uses_base_kernel": True,
            "verified_runtime_uses_existing_verified_ctf_runtime": True,
            "same_profile_tool_backend_used": True,
            "minimal_tool_without_ctf_hypothesis_executed": len(minimal_backend.calls) == 1,
            "verified_same_tool_blocked_by_ctf_hypothesis_guard": len(verified_backend.calls) == 0,
            "minimal_semantic_fact_commit_blocked": True,
            "minimal_ctf_task_progress_authority_disabled": True,
            "minimal_selection": min_sel.__dict__,
            "verified_selection": ver_sel.__dict__,
            "partial_ablation_configs_allowed": False,
            "effectiveness_measured": False,
        }, default=lambda value: value.value if hasattr(value, "value") else str(value), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
