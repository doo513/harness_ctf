from harness.core.claim_contracts import ClaimContractRegistry, ClaimContractRule
from harness.core.tools import SideEffect, ToolSpec, make_argv_tool, make_session_tool
from harness.core.verification import VerificationContract, VerificationLevel, VerificationRequirement
from harness.profiles.ctf import CTFProfile
from ctf_harness.claims.pwn import PWN_CLAIM_SPECS
from ctf_harness.progress.pwn import pwn_progress_snapshot
from ctf_harness.tools.recon import make_pwn_recon_handler
from ctf_harness.verifiers.pwn.core import static_pwn_verifiers
_LEVEL={name:getattr(VerificationLevel,name) for name in ("LOGICAL","EXECUTION","EXTERNAL_ORACLE")}
class VerifiedCTFProfile(CTFProfile):
    name="verified_ctf"
    def tools(self):
        tools=super().tools(); tools["argv"]=make_argv_tool(self.workspace,backend=self.execution_backend); tools["session"]=make_session_tool(self.workspace,backend=self.execution_backend)
        tools["pwn_recon"]=ToolSpec(name="pwn_recon",description="Deterministically inspect one workspace-relative ELF artifact.",handler=make_pwn_recon_handler(self.workspace),side_effect=SideEffect.READ,idempotent=True,permission="auto",failure_modes=["invalid_path","non_elf","truncated_elf"],provenance={"kind":"deterministic_domain_probe","domain":"pwn","schema":"pwn_recon_snapshot.v1"})
        return tools
    def verifiers(self):return [*super().verifiers(),*static_pwn_verifiers()]
    def claim_verification_registry(self):
        rules=[]
        for spec in PWN_CLAIM_SPECS:
            level=_LEVEL[spec.verification_level]
            contract=VerificationContract(minimum_level=level,requirements=(VerificationRequirement("ctf_semantic",level,description="claim-specific CTF semantic evidence",require_evidence=True),))
            rules.append(ClaimContractRule(claim_class=spec.key_prefix,key_prefix=spec.key_prefix,contract=contract,allowed_verifiers=(spec.verifier,)))
        return ClaimContractRegistry(tuple(rules))
    def task_progress_snapshot(self,*,goal,state):
        facts=getattr(state,"facts",{}); keys=facts.keys() if hasattr(facts,"keys") else (getattr(item,"key","") for item in facts)
        return pwn_progress_snapshot(keys,completed=bool(getattr(state,"completed",False)))
