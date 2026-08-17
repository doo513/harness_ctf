from __future__ import annotations

import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.controller import Decision
from harness.core.sandbox import ExecutionResult, RecordingIsolatedTestBackend
from harness.core.storage import canonical_hash

from ctf_harness.evaluation.executor import BenchmarkExecutorDescriptor
from ctf_harness.evaluation.models import ArmConfig, BenchmarkCase, BenchmarkRunSpec, EvaluationMode, ExperimentContract
from ctf_harness.evaluation.runtime_executor import RuntimeBenchmarkExecutor, RuntimeBinding
from ctf_harness.profile import VerifiedCTFProfile


class Controller:
    def decide(self, goal, state, context):
        return Decision("tool", {
            "tool": "argv",
            "args": {"argv": ["probe", "runtime-executor"]},
            "ctf_hypothesis": {
                "id": "controlled-runtime-executor",
                "category": "pwn",
                "target": "fixture",
                "vulnerability_class": "controlled",
                "primitive": "probe",
                "claim": "controlled execution probe",
                "evidence_refs": [],
            },
        })


class Factory:
    def __init__(self, root: Path):
        self.root = root
        self.bindings = []
        self.backends = []

    def prepare(self, spec):
        suffix = f"{spec.arm.arm.value}-{len(self.bindings)}"
        workspace = self.root / f"workspace-{suffix}"
        workspace.mkdir()
        backend = RecordingIsolatedTestBackend({
            ("probe", "runtime-executor"): ExecutionResult(1, "", "controlled failure"),
        })
        binding = RuntimeBinding(
            profile=VerifiedCTFProfile(workspace=workspace, execution_backend=backend),
            goal=GoalContract(goal="controlled runtime executor probe", acceptance=["never accepted"]),
            controller=Controller(),
            workspace=workspace,
            run_dir=self.root / f"run-{suffix}",
        )
        self.bindings.append(binding)
        self.backends.append(backend)
        return binding


def descriptor():
    return BenchmarkExecutorDescriptor(
        executor_id="controlled-runtime-executor",
        model_id="fixture-model",
        model_revision="fixture-model-r1",
        controller_revision="fixture-controller-r1",
        tool_inventory=("argv", "session"),
        sandbox_id="fixture-sandbox-r1",
        oracle_policy_id="fixture-oracle-r1",
        web_search_enabled=False,
        external_retrieval_enabled=False,
        general_internet_egress_enabled=False,
        challenge_transport_only=True,
    )


def spec(arm):
    case = BenchmarkCase(
        case_id="runtime-executor-fixture",
        challenge_id="runtime-executor-fixture",
        challenge_revision="r1",
        manifest_fingerprint="a" * 64,
        mode=EvaluationMode.RESEARCH,
        category="pwn",
    )
    experiment = ExperimentContract(
        mode=EvaluationMode.RESEARCH,
        model_id="fixture-model",
        model_revision="fixture-model-r1",
        controller_revision="fixture-controller-r1",
        tool_inventory=("argv", "session"),
        sandbox_id="fixture-sandbox-r1",
        oracle_policy_id="fixture-oracle-r1",
        max_steps=6,
        max_wall_seconds=30.0,
        max_tokens=None,
        seed=1,
    )
    return BenchmarkRunSpec(case=case, experiment=experiment, arm=arm)


def verify_receipt(receipt, run_spec, binding):
    assert receipt.run_id == run_spec.run_id()
    assert len(receipt.run_evidence_sha256) == 64
    metrics = json.loads((binding.run_dir / "metrics.json").read_text(encoding="utf-8"))
    assert receipt.outcome.steps == metrics["steps"]
    assert receipt.outcome.tool_calls == metrics["tool_calls"]
    assert receipt.outcome.wall_seconds == metrics["wall_seconds"]
    envelope = json.loads((binding.run_dir / "benchmark_execution_evidence.json").read_text(encoding="utf-8"))
    assert canonical_hash(envelope["body"]) == envelope["body_sha256"] == receipt.run_evidence_sha256
    assert envelope["body"]["run_id"] == run_spec.run_id()
    assert envelope["body"]["manifest_fingerprint"] == run_spec.case.manifest_fingerprint
    return envelope["body"]["runtime_class"]


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-runtime-executor-") as td:
        root = Path(td)
        factory = Factory(root)
        executor = RuntimeBenchmarkExecutor(descriptor=descriptor(), binding_factory=factory)

        minimal_spec = spec(ArmConfig.minimal())
        verified_spec = spec(ArmConfig.verified())
        minimal_receipt = executor.execute(minimal_spec)
        verified_receipt = executor.execute(verified_spec)

        minimal_class = verify_receipt(minimal_receipt, minimal_spec, factory.bindings[0])
        verified_class = verify_receipt(verified_receipt, verified_spec, factory.bindings[1])
        assert minimal_class.endswith("MinimalCTFBenchmarkRuntime")
        assert verified_class.endswith("VerifiedCTFBenchmarkRuntime")

        print(json.dumps({
            "probe": "ctf-evaluation-runtime-executor-controlled-v1",
            "all_passed": True,
            "actual_llm_executed": False,
            "actual_private_corpus": False,
            "canonical_minimal_runtime_executed": True,
            "canonical_verified_runtime_executed": True,
            "persisted_metrics_used_for_outcome": True,
            "run_id_bound": True,
            "manifest_fingerprint_bound": True,
            "state_and_runtime_logs_hashed_into_run_evidence": True,
            "execution_evidence_self_hash_valid": True,
            "token_usage_provider_exercised": False,
            "production_model_identity_attestation": False,
            "production_network_boundary_attestation": False,
            "effectiveness_measured": False,
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
