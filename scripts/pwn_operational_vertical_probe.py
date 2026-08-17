from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from harness.core.contracts import GoalContract
from harness.core.sandbox import LinuxNamespaceSandboxBackend, NetworkPolicy as BaseNetworkPolicy

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
from ctf_harness.sandbox import AnalysisSandbox, AnalysisSandboxLayout
from ctf_harness.target.runners import NativeRunner


MAGIC = 0x5131337CAFEBABE
FLAG = b"flag{controlled_pwn_vertical_513}\n"
SOURCE = r'''
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
struct frame { char buf[64]; uint64_t gate; };
int main(void) {
    struct frame f = {{0}, 0};
    (void)read(0, &f, 72);
    if (f.gate == 0x05131337cafebabeULL) {
        puts("flag{controlled_pwn_vertical_513}");
        return 0;
    }
    puts("nope");
    return 7;
}
'''


def _hypothesis(identifier: str, primitive: str, claim: str) -> dict:
    return {
        "id": identifier,
        "category": "pwn",
        "target": "chal",
        "vulnerability_class": "stack-overflow",
        "primitive": primitive,
        "claim": claim,
        "evidence_refs": [],
    }


class AdaptiveControlledPwnModel:
    """Deterministic actor used to prove the operational wiring, not intelligence."""

    def __init__(self):
        self.calls = 0

    @staticmethod
    def _analysis_stdout(context: dict) -> str:
        observations = context.get("untrusted", {}).get("observations", [])
        for item in observations:
            if item.get("source") != "analysis_exec":
                continue
            preview = item.get("preview", {})
            try:
                rendered = json.loads(preview.get("text", "{}"))
            except json.JSONDecodeError:
                continue
            stdout = rendered.get("stdout")
            if isinstance(stdout, str) and stdout.strip():
                return stdout.strip()
        raise RuntimeError("analysis payload output not visible in governed context")

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        request = json.loads(user)
        context = request["context"]
        if self.calls == 1:
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "pwn_recon",
                    "args": {"relative_path": "chal"},
                    "ctf_hypothesis": _hypothesis(
                        "H-recon", "surface_recon", "profile target architecture and hardening first"
                    ),
                },
            }
        elif self.calls == 2:
            payload_script = (
                "import base64,struct; "
                f"p=b'A'*64+struct.pack('<Q',{MAGIC}); "
                "open('generated/payload.bin','wb').write(p); "
                "print(base64.b64encode(p).decode())"
            )
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "analysis_exec",
                    "args": {"argv": ["/usr/bin/python3", "-c", payload_script]},
                    "ctf_hypothesis": _hypothesis(
                        "H-payload", "stack_data_overwrite", "64-byte buffer is followed by gate word"
                    ),
                },
            }
        elif self.calls == 3:
            payload_b64 = self._analysis_stdout(context)
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "target_exec",
                    "args": {"argv": ["chal", payload_b64, "controlled-native"]},
                    "ctf_hypothesis": _hypothesis(
                        "H-execute", "controlled_gate_overwrite", "generated payload should trigger accepted target behavior"
                    ),
                },
            }
        elif self.calls == 4:
            decision = {"kind": "complete", "payload": {"reason": "request independent flag acceptance"}}
        else:
            raise RuntimeError("controlled Pwn model exceeded expected decisions")
        return json.dumps(decision, sort_keys=True)


class BindingFactory:
    def __init__(self, *, root: Path, target_backend, model, oracle):
        self.root = root
        self.target_backend = target_backend
        self.model = model
        self.oracle = oracle

    def prepare(self, spec: SolveSpec) -> SolveRuntimeBinding:
        workspace = self.root / "workspace"
        analysis_layout = AnalysisSandboxLayout.prepare(
            self.root / "analysis",
            admitted_inputs={"chal": workspace / "chal"},
            expected_sha256={"chal": spec.target.target_sha256},
        )
        analysis = AnalysisSandbox(analysis_layout)
        profile_id = spec.target.runtime_profile_id
        profile = VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=self.target_backend,
            external_oracle=self.oracle,
            target_runners={profile_id: NativeRunner(profile_id)},
            default_target_profile_id=profile_id,
            expected_target_sha256={"chal": spec.target.target_sha256},
            analysis_sandbox=analysis,
        )
        return SolveRuntimeBinding(
            profile=profile,
            goal=GoalContract(
                goal="solve controlled native Pwn stack overwrite through governed tools",
                acceptance=["only configured external oracle establishes completion"],
                task_id=spec.challenge.challenge_id,
            ),
            controller=CTFLLMController(self.model),
            workspace=workspace,
            run_dir=self.root / "run",
            target_relpath="chal",
            agent=spec.agent,
            oracle_policy_id=spec.oracle_policy.policy_id,
        )


def _oracle(*, goal, state, workspace) -> bool:
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
        if record.get("kind") != "ctf_target_execution" or record.get("returncode") != 0:
            continue
        try:
            stdout = base64.b64decode(record.get("stdout_b64", ""), validate=True)
        except Exception:
            continue
        if FLAG in stdout:
            return True
    return False


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-pwn-vertical-") as td:
        root = Path(td)
        workspace = root / "workspace"
        workspace.mkdir()
        source = root / "chal.c"
        source.write_text(SOURCE, encoding="utf-8")
        target = workspace / "chal"
        subprocess.run(
            ["gcc", "-O0", "-fno-stack-protector", "-no-pie", "-o", str(target), str(source)],
            check=True,
        )
        target_hash = hashlib.sha256(target.read_bytes()).hexdigest()

        manifest = ChallengeManifest(
            challenge_id="controlled-pwn-vertical",
            event="controlled",
            description="native stack overwrite vertical fixture",
            artifact_refs=("chal",),
            remote_endpoints=(),
            category_hint="pwn",
            flag_format="flag{...}",
            allowed_network=False,
            allowed_tools=("pwn_recon", "analysis_exec", "target_exec"),
            runner_image_digest="sha256:" + "d" * 64,
            challenge_revision="r1",
            oracle_type="external",
            benchmark_policy="research",
        )
        challenge = OperationalChallengeRef.from_manifest(manifest, {"chal": target_hash})
        model = AdaptiveControlledPwnModel()
        spec = SolveSpec(
            challenge=challenge,
            target=LocalTargetSpec(
                artifact_ref="chal",
                target_sha256=target_hash,
                architecture="x86_64",
                runtime_kind=RuntimeKind.NATIVE,
                runtime_profile_id="controlled-native",
            ),
            agent=AgentSpec(
                provider="controlled",
                model_id="adaptive-pwn-fixture",
                model_revision="fixture-r1",
                controller_revision=CTFLLMController.revision,
            ),
            budget=SolveBudget(max_steps=12, max_wall_seconds=60.0),
            network_policy=NetworkPolicy(False, False, False),
            oracle_policy=OraclePolicy("controlled-pwn-flag-oracle"),
            run_intent=RunIntent.SOLVE,
        )
        target_backend = LinuxNamespaceSandboxBackend(network_policy=BaseNetworkPolicy.DENY)
        receipt = SolveEngine(
            binding_factory=BindingFactory(
                root=root,
                target_backend=target_backend,
                model=model,
                oracle=_oracle,
            )
        ).execute(spec)
        if not receipt.completed or not receipt.completion_requested:
            raise AssertionError(receipt)
        if model.calls != 4 or receipt.tool_calls != 3:
            raise AssertionError((model.calls, receipt))
        generated = root / "analysis" / "work" / "generated" / "payload.bin"
        if not generated.is_file() or generated.read_bytes() != b"A" * 64 + MAGIC.to_bytes(8, "little"):
            raise AssertionError("analysis-generated exploit payload mismatch")
        if hashlib.sha256(target.read_bytes()).hexdigest() != target_hash:
            raise AssertionError("admitted target mutated during solve")

        print(json.dumps({
            "probe": "pwn-operational-vertical-v1",
            "all_passed": True,
            "native_x86_64": True,
            "deterministic_recon": True,
            "analysis_sandbox_used": True,
            "target_runner_used": True,
            "external_oracle_acceptance": True,
            "actual_production_llm_executed": False,
            "model_calls": model.calls,
            "tool_calls": receipt.tool_calls,
            "completed": receipt.completed,
            "target_sha256": target_hash,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
