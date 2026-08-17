from __future__ import annotations

import base64
import hashlib
import json
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.sandbox import LinuxNamespaceSandboxBackend, NetworkPolicy as BaseNetworkPolicy
from harness.core.storage import canonical_hash

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    AgentSpec,
    LocalTargetSpec,
    NetworkPolicy,
    OperationalChallengeRef,
    OraclePolicy,
    RunIntent,
    RuntimeKind,
    SolveBudget,
    SolveSpec,
)
from ctf_harness.operational.solve_engine import SolveEngine, SolveRuntimeBinding
from ctf_harness.profile import VerifiedCTFProfile
from ctf_harness.target.runners import NativeRunner

TARGET = """#!/bin/sh
read value
if [ "$value" = "open-sesame-513" ]; then
    printf 'CONTROLLED_SOLVE_OK_513\\n'
    exit 0
fi
exit 13
"""
INPUT = b"open-sesame-513\n"
EXPECTED = b"CONTROLLED_SOLVE_OK_513\n"


class ControlledModel:
    def __init__(self):
        self.calls = 0
        self.outputs = [
            {
                "kind": "tool",
                "payload": {
                    "tool": "target_exec",
                    "args": {
                        "argv": [
                            "chal",
                            base64.b64encode(INPUT).decode("ascii"),
                            "controlled-native",
                        ]
                    },
                    "ctf_hypothesis": {
                        "id": "H-wp13",
                        "category": "pwn",
                        "target": "chal",
                        "vulnerability_class": "controlled",
                        "primitive": "execute_fixture",
                        "claim": "runtime-bound controlled target output should be observed",
                        "evidence_refs": [],
                    },
                },
            },
            {"kind": "complete", "payload": {"reason": "request external acceptance"}},
        ]

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        if not self.outputs:
            raise RuntimeError("controlled solve model exhausted")
        return json.dumps(self.outputs.pop(0), sort_keys=True)


class BindingFactory:
    def __init__(self, *, root: Path, backend, model, oracle):
        self.root = root
        self.backend = backend
        self.model = model
        self.oracle = oracle

    def prepare(self, spec: SolveSpec) -> SolveRuntimeBinding:
        profile_id = spec.target.runtime_profile_id
        profile = VerifiedCTFProfile(
            workspace=self.root / "workspace",
            execution_backend=self.backend,
            external_oracle=self.oracle,
            target_runners={profile_id: NativeRunner(profile_id)},
            default_target_profile_id=profile_id,
            expected_target_sha256={spec.target.artifact_ref: spec.target.target_sha256},
        )
        return SolveRuntimeBinding(
            profile=profile,
            goal=GoalContract(
                goal="execute the controlled target through target_exec and request independent acceptance",
                acceptance=["only the configured external oracle establishes completion"],
                task_id=spec.challenge.challenge_id,
            ),
            controller=CTFLLMController(self.model),
            workspace=self.root / "workspace",
            run_dir=self.root / "run",
            target_relpath="chal",
            agent=spec.agent,
            oracle_policy_id=spec.oracle_policy.policy_id,
        )


def _observed_expected_output(state) -> bool:
    for observation in state.observations:
        if not observation.ok or not isinstance(observation.preview, dict):
            continue
        wrapper_stdout = observation.preview.get("stdout")
        if not isinstance(wrapper_stdout, str):
            continue
        try:
            record = json.loads(wrapper_stdout.strip())
        except json.JSONDecodeError:
            continue
        if record.get("kind") != "ctf_target_execution":
            continue
        if record.get("timed_out") is not False or record.get("returncode") != 0:
            continue
        if record.get("runtime", {}).get("runtime_kind") != "native":
            continue
        try:
            stdout = base64.b64decode(record.get("stdout_b64", ""), validate=True)
        except Exception:
            continue
        if stdout == EXPECTED:
            return True
    return False


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-solve-engine-") as td:
        root = Path(td)
        workspace = root / "workspace"
        workspace.mkdir()
        target = workspace / "chal"
        target.write_text(TARGET, encoding="utf-8")
        target.chmod(0o755)
        target_sha = hashlib.sha256(target.read_bytes()).hexdigest()

        manifest = ChallengeManifest(
            challenge_id="controlled-wp13-solve",
            event="controlled",
            description="minimal live SolveEngine vertical fixture",
            artifact_refs=("chal",),
            remote_endpoints=(),
            category_hint="pwn",
            flag_format="flag{...}",
            allowed_network=False,
            allowed_tools=("target_exec",),
            runner_image_digest="sha256:" + "f" * 64,
            challenge_revision="r1",
            oracle_type="external",
            benchmark_policy="research",
        )
        challenge = OperationalChallengeRef.from_manifest(manifest, {"chal": target_sha})
        agent = AgentSpec(
            provider="controlled",
            model_id="deterministic-model-adapter",
            model_revision="fixture-r1",
            controller_revision=CTFLLMController.revision,
        )
        spec = SolveSpec(
            challenge=challenge,
            target=LocalTargetSpec(
                artifact_ref="chal",
                target_sha256=target_sha,
                architecture="x86_64",
                runtime_kind=RuntimeKind.NATIVE,
                runtime_profile_id="controlled-native",
            ),
            agent=agent,
            budget=SolveBudget(max_steps=10, max_wall_seconds=30.0, max_tokens=None),
            network_policy=NetworkPolicy(False, False, False),
            oracle_policy=OraclePolicy("controlled-observation-oracle"),
            run_intent=RunIntent.SOLVE,
        )

        backend = LinuxNamespaceSandboxBackend(network_policy=BaseNetworkPolicy.DENY)
        attestation = backend.isolation_attestation(workspace=workspace)
        if attestation.source != "runtime_probe":
            raise RuntimeError(f"live namespace unavailable: {attestation.evidence}")

        oracle_calls = {"count": 0}

        def oracle(*, goal, state, workspace):
            oracle_calls["count"] += 1
            return _observed_expected_output(state)

        model = ControlledModel()
        receipt = SolveEngine(
            binding_factory=BindingFactory(
                root=root,
                backend=backend,
                model=model,
                oracle=oracle,
            )
        ).execute(spec)

        if not receipt.completed or not receipt.completion_requested:
            raise AssertionError(receipt)
        if receipt.tool_calls != 1 or receipt.steps != 2:
            raise AssertionError(receipt)
        if oracle_calls["count"] != 1 or model.calls != 2:
            raise AssertionError("unexpected controlled model/oracle calls")

        evidence = json.loads((root / "run" / "solve_execution_evidence.json").read_text())
        if canonical_hash(evidence["body"]) != evidence["body_sha256"]:
            raise AssertionError("solve execution evidence integrity mismatch")
        body = evidence["body"]
        if body["solve_spec_fingerprint"] != spec.fingerprint():
            raise AssertionError("SolveSpec fingerprint not bound")
        if body["target_binding"]["target_sha256"] != target_sha:
            raise AssertionError("target identity not bound")
        if body["outcome"]["completion_authority"] != "base_runtime_external_oracle":
            raise AssertionError("completion authority changed")

        print(json.dumps({
            "probe": "ctf-solve-engine-live-controlled-v2",
            "all_passed": True,
            "actual_production_llm_executed": False,
            "live_namespace_target_execution": True,
            "target_exec_runtime_bound": True,
            "solve_spec_fingerprint": spec.fingerprint(),
            "target_sha256": target_sha,
            "runtime_profile_id": spec.target.runtime_profile_id,
            "model_calls": model.calls,
            "tool_calls": receipt.tool_calls,
            "steps": receipt.steps,
            "oracle_calls": oracle_calls["count"],
            "completed": receipt.completed,
            "completion_authority": "base_runtime_external_oracle",
            "solve_evidence_sha256": receipt.run_evidence_sha256,
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
