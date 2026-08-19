from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harness.core.failures import Failure, FailureKind
from harness.core.runtime import HarnessRuntime

from ctf_harness.runtime import VerifiedCTFRuntime

from .models import ArmConfig, BenchmarkArm


@dataclass(frozen=True)
class RuntimeArmSelection:
    arm: BenchmarkArm
    runtime_class: str
    semantic_verification_enabled: bool
    ctf_hypothesis_guard_enabled: bool
    ctf_typed_recovery_enabled: bool
    ctf_task_progress_enabled: bool
    proof_projection_enabled: bool


class MinimalBenchmarkProfile:
    """Delegate execution/oracle/tool policy while removing CTF task authority.

    This wrapper is benchmark-only. It intentionally does not become another
    production CTF profile or truth store. All non-task profile behavior is
    delegated to the exact underlying profile used by the Verified arm.
    """

    def __init__(self, base_profile: Any):
        self._base_profile = base_profile
        self.name = f"{getattr(base_profile, 'name', type(base_profile).__name__)}:benchmark-minimal"

    def __getattr__(self, name: str):
        return getattr(self._base_profile, name)

    def task_progress_snapshot(self, state):
        return None


class MinimalCTFBenchmarkRuntime(HarnessRuntime):
    """Canonical Minimal CTF Loop on the frozen Base runtime.

    CTF-specific runtime extensions are absent because this class inherits
    directly from HarnessRuntime rather than VerifiedCTFRuntime. Intermediate
    semantic verification is additionally blocked so a Minimal run cannot
    acquire Verified CTF facts through the shared profile's verifier registry.
    Final success still uses the same Core completion oracle.
    """

    benchmark_arm = BenchmarkArm.MINIMAL

    def _dispatch_decision(self, decision) -> None:
        if decision.kind == "verify_claim":
            key = decision.payload.get("key", "")
            self.log("benchmark.feature.blocked", {
                "arm": self.benchmark_arm.value,
                "feature": "semantic_verification",
                "decision": "verify_claim",
                "claim": key,
            })
            self.fail(Failure(
                FailureKind.NO_PROGRESS,
                "semantic verification is disabled in the canonical Minimal CTF Loop",
                action=key or "verify_claim",
                signature_key="benchmark:minimal:semantic_verification_disabled",
            ))
            return
        super()._dispatch_decision(decision)


class VerifiedCTFBenchmarkRuntime(VerifiedCTFRuntime):
    """Named benchmark binding for the existing production Verified CTF runtime."""

    benchmark_arm = BenchmarkArm.VERIFIED


def canonical_arm_selection(arm: ArmConfig) -> RuntimeArmSelection:
    if arm == ArmConfig.minimal():
        return RuntimeArmSelection(
            arm=BenchmarkArm.MINIMAL,
            runtime_class="ctf_harness.evaluation.arm_runtime.MinimalCTFBenchmarkRuntime",
            semantic_verification_enabled=False,
            ctf_hypothesis_guard_enabled=False,
            ctf_typed_recovery_enabled=False,
            ctf_task_progress_enabled=False,
            proof_projection_enabled=False,
        )
    if arm == ArmConfig.verified():
        return RuntimeArmSelection(
            arm=BenchmarkArm.VERIFIED,
            runtime_class="ctf_harness.evaluation.arm_runtime.VerifiedCTFBenchmarkRuntime",
            semantic_verification_enabled=True,
            ctf_hypothesis_guard_enabled=True,
            ctf_typed_recovery_enabled=True,
            ctf_task_progress_enabled=True,
            proof_projection_enabled=True,
        )
    raise ValueError("first A/B runtime adapter accepts only canonical Minimal or Verified ArmConfig")


def build_runtime_for_arm(*, arm: ArmConfig, profile, **runtime_kwargs):
    """Instantiate the actual runtime path for one canonical first A/B arm."""
    selection = canonical_arm_selection(arm)
    if selection.arm is BenchmarkArm.MINIMAL:
        return MinimalCTFBenchmarkRuntime(
            profile=MinimalBenchmarkProfile(profile),
            **runtime_kwargs,
        )
    return VerifiedCTFBenchmarkRuntime(profile=profile, **runtime_kwargs)
