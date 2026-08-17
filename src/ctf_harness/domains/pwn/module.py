from __future__ import annotations

from ctf_harness.claims.pwn import PWN_CLAIM_SPECS
from ctf_harness.progress.pwn import pwn_progress_snapshot
from ctf_harness.verifiers.pwn.control import ControlFlowVerifier
from ctf_harness.verifiers.pwn.core import static_pwn_verifiers
from ctf_harness.verifiers.pwn.crash import CrashReproducibleVerifier
from ctf_harness.verifiers.pwn.environment import EnvironmentCompatibilityVerifier
from ctf_harness.verifiers.pwn.local import LocalExploitVerifier
from ctf_harness.verifiers.pwn.remote import RemoteBehaviorVerifier

from .playbook import PwnPlaybook


class PwnDomainModule:
    """Cohesive Pwn registration boundary over the existing verified assets."""

    domain = "pwn"
    revision = "pwn-domain-module-v1"

    def __init__(self) -> None:
        self.playbook = PwnPlaybook()

    def claim_specs(self):
        return PWN_CLAIM_SPECS

    def build_verifiers(self):
        return (
            *static_pwn_verifiers(),
            CrashReproducibleVerifier(),
            ControlFlowVerifier(),
            LocalExploitVerifier(),
            EnvironmentCompatibilityVerifier(),
            RemoteBehaviorVerifier(),
        )

    def progress_snapshot(self, verified_keys, *, completed: bool = False) -> dict:
        return pwn_progress_snapshot(verified_keys, completed=completed)

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-domain-module-v1",
            "domain": self.domain,
            "revision": self.revision,
            "playbook_revision": self.playbook.revision,
            "claim_key_prefixes": [spec.key_prefix for spec in self.claim_specs()],
            "verifier_names": [verifier.name for verifier in self.build_verifiers()],
            "authority": "registration_only",
            "truth_authority": "existing_verifiers_only",
            "completion_authority": "none",
        }
