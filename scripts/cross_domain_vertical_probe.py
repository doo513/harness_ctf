from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
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


CRYPTO_FLAG = "flag{crypto_vertical_513}"
REVERSE_FLAG = "flag{reverse_vertical_513}"
CRYPTO_SOURCE = f'''#!/usr/bin/env python3
KEY = 0x23
CIPHERTEXT_HEX = "{bytes(b ^ 0x23 for b in CRYPTO_FLAG.encode()).hex()}"
print("decode the challenge data")
'''
REVERSE_SOURCE = r'''
#include <stdio.h>
static const char answer[] = "flag{reverse_vertical_513}";
int main(void) {
    puts("validate_me");
    return answer[0] == 'f' ? 0 : 1;
}
'''


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hypothesis(domain: str, identifier: str, primitive: str, claim: str) -> dict:
    return {
        "id": identifier,
        "category": domain,
        "target": "chal",
        "vulnerability_class": "controlled-challenge",
        "primitive": primitive,
        "claim": claim,
        "evidence_refs": [],
    }


class CryptoModel:
    def __init__(self):
        self.calls = 0

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        if self.calls == 1:
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "domain_recon",
                    "args": {"relative_path": "chal"},
                    "ctf_hypothesis": _hypothesis(
                        "crypto", "H-crypto-recon", "parameter_inventory", "extract exact crypto parameters before choosing an attack"
                    ),
                },
            }
        elif self.calls == 2:
            code = (
                "import re; "
                "t=open('input/chal','r',encoding='utf-8').read(); "
                "k=int(re.search(r'KEY\\s*=\\s*(0x[0-9a-fA-F]+)',t).group(1),16); "
                "c=bytes.fromhex(re.search(r'CIPHERTEXT_HEX\\s*=\\s*\"([0-9a-f]+)\"',t).group(1)); "
                "print(bytes(b^k for b in c).decode())"
            )
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "analysis_exec",
                    "args": {"argv": ["/usr/bin/python3", "-c", code]},
                    "ctf_hypothesis": _hypothesis(
                        "crypto", "H-crypto-xor", "xor_decode", "declared single-byte key should decode the ciphertext"
                    ),
                },
            }
        elif self.calls == 3:
            decision = {"kind": "complete", "payload": {"reason": "request external acceptance of crypto result"}}
        else:
            raise RuntimeError("crypto fixture model exhausted")
        return json.dumps(decision, sort_keys=True)


class ReverseModel:
    def __init__(self):
        self.calls = 0

    def complete(self, *, system: str, user: str) -> str:
        self.calls += 1
        if self.calls == 1:
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "domain_recon",
                    "args": {"relative_path": "chal"},
                    "ctf_hypothesis": _hypothesis(
                        "reverse", "H-rev-recon", "binary_profile", "profile the native binary before targeted extraction"
                    ),
                },
            }
        elif self.calls == 2:
            decision = {
                "kind": "tool",
                "payload": {
                    "tool": "analysis_exec",
                    "args": {"argv": ["/usr/bin/strings", "input/chal"]},
                    "ctf_hypothesis": _hypothesis(
                        "reverse", "H-rev-strings", "targeted_strings", "a validation constant may be recoverable from admitted binary strings"
                    ),
                },
            }
        elif self.calls == 3:
            decision = {"kind": "complete", "payload": {"reason": "request external acceptance of reverse result"}}
        else:
            raise RuntimeError("reverse fixture model exhausted")
        return json.dumps(decision, sort_keys=True)


@dataclass
class BindingFactory:
    root: Path
    spec: SolveSpec
    model: object
    domain: str
    oracle: object

    def prepare(self, spec: SolveSpec) -> SolveRuntimeBinding:
        workspace = self.root / "workspace"
        layout = AnalysisSandboxLayout.prepare(
            self.root / "analysis",
            admitted_inputs={"chal": workspace / "chal"},
            expected_sha256={"chal": spec.target.target_sha256},
        )
        analysis = AnalysisSandbox(layout)
        profile_id = spec.target.runtime_profile_id
        profile = VerifiedCTFProfile(
            workspace=workspace,
            execution_backend=LinuxNamespaceSandboxBackend(network_policy=BaseNetworkPolicy.DENY),
            external_oracle=self.oracle,
            target_runners={profile_id: NativeRunner(profile_id)},
            default_target_profile_id=profile_id,
            expected_target_sha256={"chal": spec.target.target_sha256},
            active_domains=(self.domain,),
            analysis_sandbox=analysis,
        )
        return SolveRuntimeBinding(
            profile=profile,
            goal=GoalContract(
                goal=f"solve controlled {self.domain} challenge through governed tools",
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


def _observation_contains(state, needle: str) -> bool:
    for observation in state.observations:
        if not observation.ok or not isinstance(observation.preview, dict):
            continue
        preview_text = json.dumps(observation.preview, ensure_ascii=False)
        if needle in preview_text:
            return True
    return False


def _run_case(root: Path, *, domain: str, model, expected_flag: str) -> dict:
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    target = workspace / "chal"
    if domain == "crypto":
        target.write_text(CRYPTO_SOURCE, encoding="utf-8")
        target.chmod(0o755)
    elif domain == "reverse":
        source = root / "chal.c"
        source.write_text(REVERSE_SOURCE, encoding="utf-8")
        subprocess.run(["gcc", "-O0", "-o", str(target), str(source)], check=True)
    else:
        raise ValueError(domain)
    target_hash = _sha(target)
    manifest = ChallengeManifest(
        challenge_id=f"controlled-{domain}-vertical",
        event="controlled",
        description=f"controlled {domain} operational vertical fixture",
        artifact_refs=("chal",),
        remote_endpoints=(),
        category_hint=domain,
        flag_format="flag{...}",
        allowed_network=False,
        allowed_tools=("domain_recon", "analysis_exec"),
        runner_image_digest="sha256:" + ("c" if domain == "crypto" else "b") * 64,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    challenge = OperationalChallengeRef.from_manifest(manifest, {"chal": target_hash})
    agent = AgentSpec(
        provider="controlled",
        model_id=f"{domain}-vertical-fixture",
        model_revision="fixture-r1",
        controller_revision=CTFLLMController.revision,
    )
    spec = SolveSpec(
        challenge=challenge,
        target=LocalTargetSpec(
            artifact_ref="chal",
            target_sha256=target_hash,
            architecture="x86_64" if domain == "reverse" else "script",
            runtime_kind=RuntimeKind.NATIVE,
            runtime_profile_id=f"controlled-{domain}-native",
        ),
        agent=agent,
        budget=SolveBudget(max_steps=8, max_wall_seconds=45.0),
        network_policy=NetworkPolicy(False, False, False),
        oracle_policy=OraclePolicy(f"controlled-{domain}-oracle"),
        run_intent=RunIntent.SOLVE,
    )

    oracle_calls = {"count": 0}
    def oracle(*, goal, state, workspace):
        oracle_calls["count"] += 1
        return _observation_contains(state, expected_flag)

    receipt = SolveEngine(
        binding_factory=BindingFactory(root, spec, model, domain, oracle)
    ).execute(spec)
    if not receipt.completed or not receipt.completion_requested:
        raise AssertionError((domain, receipt))
    if receipt.tool_calls != 2 or receipt.steps != 3 or model.calls != 3 or oracle_calls["count"] != 1:
        raise AssertionError((domain, receipt, model.calls, oracle_calls))
    if _sha(target) != target_hash:
        raise AssertionError(f"{domain} target mutated")
    return {
        "domain": domain,
        "completed": receipt.completed,
        "tool_calls": receipt.tool_calls,
        "steps": receipt.steps,
        "model_calls": model.calls,
        "oracle_calls": oracle_calls["count"],
        "target_sha256": target_hash,
    }


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-cross-domain-") as td:
        base = Path(td)
        crypto = _run_case(base / "crypto", domain="crypto", model=CryptoModel(), expected_flag=CRYPTO_FLAG)
        reverse = _run_case(base / "reverse", domain="reverse", model=ReverseModel(), expected_flag=REVERSE_FLAG)
        print(json.dumps({
            "probe": "cross-domain-controlled-vertical-v1",
            "all_passed": True,
            "actual_production_llm_executed": False,
            "semantic_fact_authority_added": False,
            "cases": [crypto, reverse],
            "completion_authority": "external_oracle_only",
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
