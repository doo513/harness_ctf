from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.controller import Decision, ScriptedController
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend
from harness.core.state import Observation

from ctf_harness.hypotheses.pool import fingerprint
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.runtime import VerifiedCTFRuntime


def meta(refs=None, *, claim="saved RIP may be controlled"):
    return {
        "id": "overflow-control",
        "category": "pwn",
        "target": "bin/challenge",
        "vulnerability_class": "stack_overflow",
        "primitive": "rip_control",
        "claim": claim,
        "evidence_refs": list(refs or []),
    }


def decision(refs=None, *, action="same-action"):
    return Decision("tool", {
        "tool": "argv",
        "args": {"argv": ["probe", action]},
        "ctf_hypothesis": meta(refs),
    })


def register(runtime, name, payload):
    ref = runtime.artifacts.put_json(name, payload)
    runtime.state.artifacts.append(ref)
    runtime.state.evidence_refs.append(ref)
    runtime.state.observations.append(Observation(
        step=runtime.state.step,
        source="pwn_recon",
        ok=True,
        preview=payload,
        artifact_ref=ref,
    ))
    return ref


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-hypothesis-dedupe-") as td:
        root = Path(td)
        workspace = root / "workspace"
        workspace.mkdir()
        backend = RecordingIsolatedTestBackend({
            ("probe", "same-action"): ExecutionResult(9, "", "deterministic probe failure"),
            ("probe", "adapted-action"): ExecutionResult(9, "", "adapted deterministic failure"),
            ("probe", "second-adaptation"): ExecutionResult(9, "", "second adapted failure"),
        })
        runtime = VerifiedCTFRuntime(
            goal=GoalContract(goal="controlled hypothesis dedupe probe", acceptance=["probe assertions"]),
            profile=VerifiedCTFProfile(workspace=workspace, execution_backend=backend),
            controller=ScriptedController([]),
            run_dir=root / "run",
        )

        runtime._dispatch_decision(decision())
        assert len(backend.calls) == 1
        first_failure = runtime.ctf_hypotheses.pool.attempts[-1].failure_signature
        assert first_failure

        # Same semantic hypothesis + exact action + same evidence state is blocked
        # by the CTF guard before Core/ActionRuntime execution.
        runtime._dispatch_decision(decision())
        assert len(backend.calls) == 1
        assert runtime.metrics["ctf_hypothesis_guard_blocks"] == 1

        # Novel registered evidence reopens the *hypothesis guard*. It must not
        # bypass the stronger Core receipt identity for exactly identical tool
        # arguments, so the backend still does not execute a duplicate action.
        ref1 = register(runtime, "recon-1.json", {"offset": 72})
        state1 = runtime._evidence_state([ref1])
        attempts_before = runtime.metrics["ctf_hypothesis_attempts"]
        dedup_before = runtime.metrics["receipt_deduplications"]
        runtime._dispatch_decision(decision([ref1]))
        assert runtime.metrics["ctf_hypothesis_attempts"] == attempts_before + 1
        assert runtime.metrics["receipt_deduplications"] == dedup_before + 1
        assert len(backend.calls) == 1

        # A materially adapted action under the new evidence state is a distinct
        # Core execution identity and therefore reaches the backend.
        runtime._dispatch_decision(decision([ref1], action="adapted-action"))
        assert len(backend.calls) == 2

        # A different ref with identical content and stable provenance has the
        # same evidence identity. It cannot manufacture novelty for the already
        # failed adapted action.
        ref2 = register(runtime, "recon-duplicate.json", {"offset": 72})
        state2 = runtime._evidence_state([ref2])
        assert ref1 != ref2 and state1 == state2
        runtime._dispatch_decision(decision([ref2], action="adapted-action"))
        assert len(backend.calls) == 2

        # Genuine new evidence plus a second material adaptation executes once.
        ref3 = register(runtime, "recon-2.json", {"offset": 80})
        state3 = runtime._evidence_state([ref3])
        assert state3 != state1
        runtime._dispatch_decision(decision([ref3], action="second-adaptation"))
        assert len(backend.calls) == 3

        # Refutation blocks the semantic strategy even with newer evidence and a
        # newly adapted action.
        fp, parsed = runtime._parse_hypothesis(meta([ref3]))
        assert fingerprint(parsed) == fp
        runtime.ctf_hypotheses.pool.mark_refuted(fp, contradiction_evidence=[ref3])
        runtime.ctf_hypotheses.save()
        ref4 = register(runtime, "recon-3.json", {"offset": 88})
        runtime._dispatch_decision(decision([ref4], action="post-refutation-action"))
        assert len(backend.calls) == 3

        ledger_body = runtime.ctf_hypotheses.pool.dump()
        assert len(ledger_body["hypotheses"]) == 1

        print(json.dumps({
            "probe": "pwn-hypothesis-runtime-dedupe-controlled",
            "all_passed": True,
            "backend_execution_calls": len(backend.calls),
            "hypothesis_attempts": runtime.metrics["ctf_hypothesis_attempts"],
            "guard_blocks": runtime.metrics["ctf_hypothesis_guard_blocks"],
            "core_receipt_deduplications": runtime.metrics["receipt_deduplications"],
            "first_failure_signature": first_failure,
            "same_failure_same_evidence_blocked_before_core": True,
            "novel_evidence_reopened_hypothesis_guard": True,
            "exact_action_still_core_deduplicated": True,
            "materially_adapted_action_executed": True,
            "duplicate_ref_same_content_provenance_blocked": True,
            "refuted_hypothesis_blocked": True,
            "stable_hypothesis_count": len(ledger_body["hypotheses"]),
            "durable_attempt_count": len(ledger_body["attempts"]),
            "truth_authority": "none",
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
