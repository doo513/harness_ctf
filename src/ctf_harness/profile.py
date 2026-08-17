from harness.core.claim_contracts import ClaimContractRegistry, ClaimContractRule
from harness.core.tools import SideEffect, ToolSpec, make_argv_tool, make_session_tool
from harness.core.verification import VerificationContract, VerificationLevel, VerificationRequirement
from harness.profiles.ctf import CTFProfile
from ctf_harness.claims.pwn import PWN_CLAIM_SPECS
from ctf_harness.domains.pwn import PwnPlaybook
from ctf_harness.domains.registry import DomainRegistry
from ctf_harness.domains.standard import CryptoPlaybook, ForensicsPlaybook, MiscPlaybook, ReversePlaybook, WebPlaybook
from ctf_harness.progress.pwn import pwn_progress_snapshot
from ctf_harness.sandbox import AnalysisSandbox
from ctf_harness.target.runners import NativeRunner, TargetRunner
from ctf_harness.tools.domain_recon import make_domain_recon_handler
from ctf_harness.tools.recon import make_pwn_recon_handler
from ctf_harness.tools.crash import make_crash_probe_tool
from ctf_harness.tools.control import make_control_probe_tool
from ctf_harness.tools.target_exec import make_target_exec_tool
from ctf_harness.verifiers.pwn.core import static_pwn_verifiers
from ctf_harness.verifiers.pwn.crash import CrashReproducibleVerifier
from ctf_harness.verifiers.pwn.control import ControlFlowVerifier
from ctf_harness.verifiers.pwn.local import LocalExploitVerifier
from ctf_harness.verifiers.pwn.environment import EnvironmentCompatibilityVerifier
from ctf_harness.verifiers.pwn.remote import RemoteBehaviorVerifier

_LEVEL = {name: getattr(VerificationLevel, name) for name in ("LOGICAL", "EXECUTION", "EXTERNAL_ORACLE")}


def _default_domain_registry() -> DomainRegistry:
    return DomainRegistry((
        PwnPlaybook(),
        ReversePlaybook(),
        CryptoPlaybook(),
        WebPlaybook(),
        ForensicsPlaybook(),
        MiscPlaybook(),
    ))


class VerifiedCTFProfile(CTFProfile):
    name = "verified_ctf"

    def __init__(
        self,
        *,
        workspace=".",
        external_oracle=None,
        execution_backend=None,
        flag_completion_oracle=None,
        target_runners: dict[str, TargetRunner] | None = None,
        default_target_profile_id: str = "native-default",
        expected_target_sha256: dict[str, str] | None = None,
        domain_registry: DomainRegistry | None = None,
        active_domains: tuple[str, ...] = ("pwn",),
        analysis_sandbox: AnalysisSandbox | None = None,
    ):
        super().__init__(workspace=workspace, external_oracle=external_oracle, execution_backend=execution_backend)
        self.flag_completion_oracle = flag_completion_oracle
        configured = dict(target_runners or {"native-default": NativeRunner("native-default")})
        if not configured:
            raise ValueError("VerifiedCTFProfile requires at least one target runner")
        for profile_id, runner in configured.items():
            if not isinstance(profile_id, str) or not profile_id.strip():
                raise ValueError("target runner profile id must be a non-empty string")
            if getattr(runner, "profile_id", None) != profile_id:
                raise ValueError("target runner registry key must equal runner.profile_id")
        if default_target_profile_id not in configured:
            raise ValueError("default target runner profile is not registered")
        self.target_runners = configured
        self.default_target_profile_id = default_target_profile_id
        self.expected_target_sha256 = dict(expected_target_sha256 or {})

        registry = domain_registry or _default_domain_registry()
        if not isinstance(registry, DomainRegistry):
            raise ValueError("domain_registry must be DomainRegistry")
        if not isinstance(active_domains, tuple) or not active_domains:
            raise ValueError("active_domains must be a non-empty tuple")
        if len(set(active_domains)) != len(active_domains):
            raise ValueError("active_domains must be unique")
        for domain in active_domains:
            registry.require(domain)
        self.domain_registry = registry
        self.active_domains = active_domains

        if analysis_sandbox is not None and not isinstance(analysis_sandbox, AnalysisSandbox):
            raise ValueError("analysis_sandbox must be AnalysisSandbox when provided")
        self.analysis_sandbox = analysis_sandbox

    def tools(self):
        tools = super().tools()
        tools["argv"] = make_argv_tool(self.workspace, backend=self.execution_backend)
        tools["session"] = make_session_tool(self.workspace, backend=self.execution_backend)
        tools["target_exec"] = make_target_exec_tool(
            self.workspace,
            backend=self.execution_backend,
            runners=self.target_runners,
            default_profile_id=self.default_target_profile_id,
            expected_target_sha256=self.expected_target_sha256,
        )
        tools["pwn_crash_probe"] = make_crash_probe_tool(
            self.workspace,
            backend=self.execution_backend,
            runners=self.target_runners,
            default_profile_id=self.default_target_profile_id,
            expected_target_sha256=self.expected_target_sha256,
        )
        tools["pwn_control_probe"] = make_control_probe_tool(
            self.workspace,
            backend=self.execution_backend,
            runners=self.target_runners,
            default_profile_id=self.default_target_profile_id,
            expected_target_sha256=self.expected_target_sha256,
        )
        tools["pwn_recon"] = ToolSpec(
            name="pwn_recon",
            description="Deterministically inspect one workspace-relative ELF artifact.",
            handler=make_pwn_recon_handler(self.workspace),
            side_effect=SideEffect.READ,
            idempotent=True,
            permission="auto",
            failure_modes=["invalid_path", "non_elf", "truncated_elf"],
            provenance={"kind":"deterministic_domain_probe", "domain":"pwn", "schema":"pwn_recon_snapshot.v1"},
        )
        tools["domain_recon"] = ToolSpec(
            name="domain_recon",
            description="Create a bounded deterministic cross-domain ReconDigest for one workspace-relative artifact; raw artifact remains preserved.",
            handler=make_domain_recon_handler(self.workspace),
            side_effect=SideEffect.READ,
            idempotent=True,
            permission="auto",
            failure_modes=["invalid_path", "unreadable_artifact"],
            provenance={"kind":"deterministic_domain_probe", "domain":"cross-domain", "schema":"ctf-recon-digest-v1"},
        )
        if self.analysis_sandbox is not None:
            tools["analysis_exec"] = self.analysis_sandbox.tool()
        return tools

    def verifiers(self):
        return [
            *super().verifiers(),
            *static_pwn_verifiers(),
            CrashReproducibleVerifier(),
            ControlFlowVerifier(),
            LocalExploitVerifier(),
            EnvironmentCompatibilityVerifier(),
            RemoteBehaviorVerifier(),
        ]

    def claim_verification_registry(self):
        rules = []
        for spec in PWN_CLAIM_SPECS:
            level = _LEVEL[spec.verification_level]
            contract = VerificationContract(
                minimum_level=level,
                requirements=(VerificationRequirement("ctf_semantic", level, description="claim-specific CTF semantic evidence", require_evidence=True),),
            )
            rules.append(ClaimContractRule(claim_class=spec.key_prefix, key_prefix=spec.key_prefix, contract=contract, allowed_verifiers=(spec.verifier,)))
        return ClaimContractRegistry(tuple(rules))

    def completion_oracle(self):
        if self.flag_completion_oracle is not None:
            return self.flag_completion_oracle
        return super().completion_oracle()

    def task_progress_snapshot(self, *, goal, state):
        facts = getattr(state, "facts", {})
        keys = facts.keys() if hasattr(facts, "keys") else (getattr(item, "key", "") for item in facts)
        return pwn_progress_snapshot(keys, completed=bool(getattr(state, "completed", False)))
