from __future__ import annotations

from collections.abc import Sequence

from ctf_harness.domains.base import PlaybookQuestion, PlaybookStage


class PwnPlaybook:
    domain = "pwn"
    revision = "pwn-playbook-v1"

    def __init__(self) -> None:
        self._stages = {
            "surface": PlaybookStage(
                "surface",
                "Reduce target, architecture, hardening, runtime, and input-path uncertainty before committing to an exploit theory.",
                (
                    PlaybookQuestion(
                        "pwn.surface.profile",
                        "What architecture/runtime and hardening properties constrain later analysis?",
                        "environment_and_binary_profile",
                        "high",
                        "Architecture or runtime mistakes invalidate later exploit assumptions.",
                        ("pwn_recon",),
                    ),
                    PlaybookQuestion(
                        "pwn.surface.input",
                        "Where does attacker-controlled input enter and which path is most promising to test first?",
                        "input_surface_localization",
                        "high",
                        "Locating the controllable input path reduces the exploit search space.",
                        ("pwn_recon", "analysis_exec"),
                    ),
                ),
                ("ctf.pwn.arch verified", "input path localized"),
                ("non-native architecture", "source available", "stripped target", "runtime mismatch"),
            ),
            "primitive": PlaybookStage(
                "primitive",
                "Turn an observed fault or unsafe input path into a reproducible exploit primitive without overclaiming control.",
                (
                    PlaybookQuestion(
                        "pwn.primitive.crash",
                        "Can a candidate input reproduce a stable crash under the admitted runtime?",
                        "confirm_or_refute_crash_primitive",
                        "high",
                        "A reproducible primitive is a stronger branch point than speculative exploit construction.",
                        ("pwn_crash_probe", "analysis_exec"),
                    ),
                    PlaybookQuestion(
                        "pwn.primitive.control",
                        "Which saved control datum or control-flow target is affected by the input?",
                        "control_surface_localization",
                        "medium",
                        "This distinguishes a generic crash from a useful control primitive.",
                        ("pwn_control_probe", "analysis_exec"),
                    ),
                ),
                ("ctf.pwn.crash_reproducible verified", "supported control observation"),
                ("crash is non-deterministic", "runtime differs", "input cannot reach control data"),
            ),
            "control": PlaybookStage(
                "control",
                "Verify the candidate control primitive and identify the shortest path to a local exploit.",
                (
                    PlaybookQuestion(
                        "pwn.control.verify",
                        "Can the suspected control primitive be demonstrated under the architecture-specific verifier?",
                        "confirm_or_refute_control",
                        "high",
                        "Formal control proof prevents later exploit work from resting on a false primitive.",
                        ("pwn_control_probe",),
                    ),
                    PlaybookQuestion(
                        "pwn.control.tactic",
                        "If formal verification is not yet supported, what bounded experiment can still use the supported observation tactically?",
                        "tactical_exploit_direction",
                        "medium",
                        "Supported observations may guide experiments without becoming Proof facts.",
                        ("analysis_exec", "target_exec"),
                    ),
                ),
                ("ctf.pwn.control_flow verified", "local exploit candidate created"),
                ("architecture verifier unsupported", "mitigation blocks primitive", "candidate control contradicted"),
            ),
            "local_exploit": PlaybookStage(
                "local_exploit",
                "Produce a repeatable local exploit artifact and separate exploit success from target-environment compatibility.",
                (
                    PlaybookQuestion(
                        "pwn.local.build",
                        "What minimal generated artifact exercises the verified or tactically supported primitive?",
                        "local_exploit_candidate",
                        "high",
                        "A small reproducible artifact is easier to verify and port to remote execution.",
                        ("analysis_exec", "target_exec"),
                    ),
                    PlaybookQuestion(
                        "pwn.local.verify",
                        "Does the local exploit satisfy the claim-specific local proof under immutable target identity?",
                        "local_exploit_verification",
                        "high",
                        "Command success alone is not semantic exploit proof.",
                        ("target_exec",),
                    ),
                ),
                ("ctf.pwn.local_exploit verified",),
                ("target mutation required", "local runtime mismatch", "exploit depends on accidental state"),
            ),
            "environment": PlaybookStage(
                "environment",
                "Resolve local-versus-remote environment differences before treating transport failures as exploit failures.",
                (
                    PlaybookQuestion(
                        "pwn.environment.compat",
                        "Which runtime, library, loader, architecture, or protocol differences can invalidate the local exploit remotely?",
                        "environment_compatibility",
                        "high",
                        "Separating environment drift from exploit logic avoids unproductive exploit rewrites.",
                        ("analysis_exec",),
                    ),
                ),
                ("ctf.environment.compatible verified",),
                ("different libc/loader", "different architecture", "remote protocol requires staging"),
            ),
            "remote": PlaybookStage(
                "remote",
                "Exercise the admitted remote endpoint with bounded stateful transport and collect evidence for final acceptance.",
                (
                    PlaybookQuestion(
                        "pwn.remote.behavior",
                        "Does the exploit produce the expected remote behavior on the admitted endpoint?",
                        "remote_behavior_confirmation",
                        "high",
                        "Remote behavior must be separated from local proof and final flag acceptance.",
                        ("target_exec",),
                    ),
                    PlaybookQuestion(
                        "pwn.remote.flag",
                        "Is there a flag-shaped candidate that should be sent to the external acceptance oracle under submission policy?",
                        "flag_candidate_for_external_acceptance",
                        "high",
                        "A candidate string is not completion until an external oracle accepts it.",
                        (),
                    ),
                ),
                ("ctf.pwn.remote_behavior verified", "external flag accepted"),
                ("remote protocol drift", "endpoint unavailable", "candidate rejected"),
            ),
            "complete": PlaybookStage(
                "complete",
                "Preserve the accepted proof/evidence chain; no further solving action is required.",
                (
                    PlaybookQuestion(
                        "pwn.complete.preserve",
                        "Which verified artifacts and receipts must be preserved for reproducibility?",
                        "reproducibility_projection",
                        "low",
                        "Completion is externally established; reporting must project existing evidence rather than invent new truth.",
                        (),
                    ),
                ),
                ("external flag accepted",),
                (),
            ),
        }

    @staticmethod
    def _select_stage(keys: set[str], *, completed: bool) -> str:
        if completed:
            return "complete"
        if "ctf.pwn.remote_behavior" in keys:
            return "remote"
        if "ctf.environment.compatible" in keys:
            return "remote"
        if "ctf.pwn.local_exploit" in keys:
            return "environment"
        if "ctf.pwn.control_flow" in keys:
            return "local_exploit"
        if "ctf.pwn.crash_reproducible" in keys:
            return "control"
        if "ctf.pwn.arch" in keys:
            return "primitive"
        return "surface"

    def snapshot(
        self,
        *,
        verified_fact_keys: Sequence[str],
        hypothesis_statuses: Sequence[str],
        available_tools: Sequence[str],
        completed: bool,
    ) -> dict:
        keys = set(str(key) for key in verified_fact_keys)
        stage_id = self._select_stage(keys, completed=bool(completed))
        stage = self._stages[stage_id]
        status_counts = {name: 0 for name in ("open", "supported", "refuted", "proved")}
        for status in hypothesis_statuses:
            if status in status_counts:
                status_counts[status] += 1
        return {
            "schema_version": "ctf-domain-playbook-v1",
            "domain": self.domain,
            "revision": self.revision,
            "authority": "advisory_policy",
            "instruction_authority": "advisory",
            "truth_authority": "none",
            "completion_authority": "none",
            "hard_sequence": False,
            "current": stage.descriptor(available_tools=set(available_tools)),
            "tactical_hypothesis_counts": status_counts,
        }
