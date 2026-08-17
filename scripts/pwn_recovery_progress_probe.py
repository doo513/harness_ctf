from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.controller import ScriptedController
from harness.core.failures import RecoveryAction
from harness.core.sandbox import RecordingIsolatedTestBackend

from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.progress.pwn import pwn_progress_snapshot
from ctf_harness.runtime import VerifiedCTFRuntime


def runtime_at(root: Path, name: str) -> VerifiedCTFRuntime:
    workspace = root / f"workspace-{name}"
    workspace.mkdir()
    return VerifiedCTFRuntime(
        goal=GoalContract(goal=f"controlled WP07 recovery probe {name}", acceptance=["probe assertions"]),
        profile=VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=RecordingIsolatedTestBackend(),
        ),
        controller=ScriptedController([]),
        run_dir=root / f"run-{name}",
    )


def apply(runtime: VerifiedCTFRuntime) -> dict:
    assert runtime.step_once() is True
    assert runtime.state.recovery_directive is not None
    return dict(runtime.state.recovery_directive)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-recovery-progress-") as td:
        root = Path(td)

        recon = runtime_at(root, "recon")
        recon_transition = recon.report_ctf_failure(
            "RECON_INCOMPLETE",
            message="controlled protocol information is incomplete",
            subject="protocol",
        )
        recon_directive = apply(recon)
        assert recon_transition.action is RecoveryAction.OBSERVE
        assert recon_directive["target"] == "targeted_recon"

        env = runtime_at(root, "environment")
        env_transition = env.report_ctf_failure(
            "ENVIRONMENT_MISMATCH",
            message="controlled target environment mismatch",
            subject="libc_sha256",
        )
        env_directive = apply(env)
        assert env_transition.action is RecoveryAction.OBSERVE
        assert env_directive["target"] == "environment_adaptation"

        flag = runtime_at(root, "flag")
        flag_transition = flag.report_ctf_failure(
            "FLAG_REJECTED",
            message="controlled external oracle rejection",
            subject="flag_submission",
        )
        flag_directive = apply(flag)
        assert flag_transition.action is RecoveryAction.REPLAN
        assert flag_directive["target"] == "return_to_proof"

        repeat = runtime_at(root, "repeat")
        repeat_actions = []
        repeat_generations = []
        for _ in range(3):
            transition = repeat.report_ctf_failure(
                "NO_INFORMATION_GAIN",
                message="controlled branch made no information gain",
                subject="same_branch",
            )
            repeat_actions.append(transition.action.value)
            apply(repeat)
            repeat_generations.append(repeat.state.strategy_generation)
        assert repeat_actions == ["replan", "replan", "switch_strategy"]
        assert repeat_generations == [0, 0, 1]

        budget = runtime_at(root, "budget")
        budget_transition = budget.report_ctf_failure(
            "BUDGET_EXHAUSTED",
            message="controlled challenge budget exhausted",
            subject="budget",
        )
        budget_directive = apply(budget)
        assert budget_transition.action is RecoveryAction.CHECKPOINT_STOP
        assert budget.halted and budget.state.recovery_halted
        assert budget_directive["action"] == "checkpoint_stop"

        # Progress remains a projection over verified keys/completion; a later
        # milestone does not invent the missing intermediate chain.
        sparse_progress = pwn_progress_snapshot([
            "ctf.pwn.arch",
            "ctf.pwn.remote_behavior",
        ])
        assert sparse_progress == {
            "milestones": ["artifact_profiled", "remote_behavior_verified"],
            "score": 2.0,
        }
        assert pwn_progress_snapshot([], completed=True) == {
            "milestones": ["flag_accepted"],
            "score": 1.0,
        }

        assert recon.state.facts == {}
        assert env.state.facts == {}
        assert flag.state.facts == {}
        assert repeat.state.facts == {}
        assert budget.state.facts == {}

        print(json.dumps({
            "probe": "pwn-ctf-recovery-progress-controlled-v1",
            "all_passed": True,
            "recon_incomplete": {
                "core_failure": recon_transition.failure_kind.value,
                "base_action": recon_transition.action.value,
                "target": recon_transition.target,
            },
            "environment_mismatch": {
                "core_failure": env_transition.failure_kind.value,
                "retry_safe": env_transition.retry_safe,
                "base_action": env_transition.action.value,
                "target": env_transition.target,
            },
            "flag_rejected": {
                "core_failure": flag_transition.failure_kind.value,
                "base_action": flag_transition.action.value,
                "target": flag_transition.target,
            },
            "repeat_no_information_gain_actions": repeat_actions,
            "repeat_strategy_generations": repeat_generations,
            "budget_exhausted": {
                "base_action": budget_transition.action.value,
                "halted": budget.halted,
            },
            "sparse_progress": sparse_progress,
            "facts_mutated": False,
            "routing_authority": "base_failure_router",
            "recovery_authority": "base_runtime_recovery",
            "truth_authority": "none",
            "solve_rate_measured": False,
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
