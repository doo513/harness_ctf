from __future__ import annotations

import hashlib
from typing import Any

from harness.core.controller import Decision
from harness.core.storage import canonical_hash

from ctf_harness.operational.models import (
    ActorCompleteBehavior,
    RunIntent,
    TerminationPolicy,
    UnsupportedCapabilityBehavior,
)
from ctf_harness.recovery.adapter import CTFFailureKind
from ctf_harness.runtime import VerifiedCTFRuntime


AGENT_CONTROL_SCHEMA = "ctf-agent-control-v1"
CTF_CONTEXT_SCHEMA = "ctf-context-extension-v2"
_STOP_REASON_PREVIEW_LIMIT = 512
_STOP_SUBJECT_PREVIEW_LIMIT = 128


def _bounded_untrusted_text(value: object, *, limit: int) -> tuple[str, str]:
    text = str(value)
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
    preview = text[:limit]
    return preview, digest


class AgentCTFRuntime(VerifiedCTFRuntime):
    """CTF run-policy/context adapter over the existing verified Base runtime.

    This class intentionally does not replace Base ContextProjector,
    LLMController, Decision, tool execution, verification, recovery, or
    completion. It only adds CTF-specific control projection and incomplete-stop
    semantics needed by a model-driven operational run.
    """

    def __init__(
        self,
        *,
        run_intent: RunIntent = RunIntent.SOLVE,
        termination_policy: TerminationPolicy | None = None,
        **kwargs,
    ):
        if not isinstance(run_intent, RunIntent):
            raise ValueError("run_intent must be RunIntent")
        policy = termination_policy or TerminationPolicy.for_intent(run_intent)
        if not isinstance(policy, TerminationPolicy):
            raise ValueError("termination_policy must be TerminationPolicy")
        policy.validate_for_intent(run_intent)
        self.run_intent = run_intent
        self.termination_policy = policy
        self._ctf_policy_stop: dict[str, Any] | None = None
        super().__init__(**kwargs)
        self.metrics.setdefault("ctf_policy_stops", 0)
        self.metrics.setdefault("ctf_missing_capabilities", 0)

    def _config_descriptor(self) -> dict[str, Any]:
        descriptor = super()._config_descriptor()
        descriptor["ctf_agent_control"] = {
            "schema_version": AGENT_CONTROL_SCHEMA,
            "run_intent": self.run_intent.value,
            "termination_policy": self.termination_policy.descriptor(),
            "base_context_projector_reused": True,
            "base_decision_contract_reused": True,
            "base_llm_controller_compatible": True,
            "domain_registry_revision": "ctf-domain-registry-v1",
            "active_domains": list(self.profile.active_domains),
            "playbook_behavior": "advisory_not_mandatory",
            "truth_authority": "none",
            "completion_authority": "external_oracle_only",
            "available_tools": sorted(self.actions.tools),
        }
        return descriptor

    def _restore_run(self) -> None:
        super()._restore_run()
        latest = None
        for record in self.events.verify_chain():
            if record.get("kind") == "ctf.run.stop":
                latest = dict(record.get("payload") or {})
        if latest is not None:
            if latest.get("run_intent") != self.run_intent.value:
                raise ValueError("persisted CTF run stop intent differs from configured run intent")
            self._ctf_policy_stop = latest
            self.halted = True

    def _capability_projection(self) -> dict[str, Any]:
        return {
            "authority": "kernel_control",
            "instruction_authority": "none",
            "inventory_source": "base_action_runtime",
            "available_tools": sorted(self.actions.tools),
            "unsupported_capability_behavior": self.termination_policy.unsupported_capability.value,
        }

    def _hypothesis_projection(self) -> list[dict[str, Any]]:
        projected: list[dict[str, Any]] = []
        for fp, hypothesis in sorted(self.ctf_hypotheses.pool.hypotheses.items()):
            projected.append({
                "fingerprint": fp,
                "id": hypothesis.id,
                "category": hypothesis.category,
                "target": hypothesis.target,
                "vulnerability_class": hypothesis.vulnerability_class,
                "primitive": hypothesis.primitive,
                "claim": hypothesis.claim,
                "status": hypothesis.status.value,
                "evidence_refs": list(hypothesis.evidence_refs[:8]),
                "support_evidence": list(hypothesis.support_evidence[:8]),
                "trust": "untrusted_speculation",
                "instruction_authority": "none",
                "truth_authority": "none",
            })
        return projected[:32]

    def _playbook_projection(self) -> dict[str, Any]:
        facts = getattr(self.state, "facts", {})
        verified_keys = list(facts.keys()) if hasattr(facts, "keys") else []
        statuses = [
            hypothesis.status.value
            for hypothesis in self.ctf_hypotheses.pool.hypotheses.values()
        ]
        return self.profile.domain_registry.project(
            active_domains=self.profile.active_domains,
            verified_fact_keys=verified_keys,
            hypothesis_statuses=statuses,
            available_tools=sorted(self.actions.tools),
            completed=bool(self.state.completed),
        )

    def _context(self) -> dict:
        context = super()._context()
        context["ctf"] = {
            "schema_version": CTF_CONTEXT_SCHEMA,
            "run": {
                "intent": self.run_intent.value,
                "termination_policy": self.termination_policy.descriptor(),
                "authority": "kernel_control",
                "instruction_authority": "none",
                "completion_authority": "external_oracle_only",
            },
            "capabilities": self._capability_projection(),
            "playbook": self._playbook_projection(),
            "hypotheses": self._hypothesis_projection(),
        }
        return context

    def _stop_incomplete(self, *, reason: str, source: str, subject: str | None = None) -> None:
        facts_before = canonical_hash({key: value.dump() for key, value in self.state.facts.items()})
        reason_preview, reason_sha256 = _bounded_untrusted_text(
            reason,
            limit=_STOP_REASON_PREVIEW_LIMIT,
        )
        subject_preview = None
        subject_sha256 = None
        if subject is not None:
            subject_preview, subject_sha256 = _bounded_untrusted_text(
                subject,
                limit=_STOP_SUBJECT_PREVIEW_LIMIT,
            )
        payload = {
            "schema_version": AGENT_CONTROL_SCHEMA,
            "run_intent": self.run_intent.value,
            "reason_preview": reason_preview,
            "reason_sha256": reason_sha256,
            "source": str(source),
            "subject_preview": subject_preview,
            "subject_sha256": subject_sha256,
            "completed": False,
            "completion_requested": bool(self.state.completion_requested),
            "completion_authority": "external_oracle_only",
            "truth_authority": "none",
        }
        self._ctf_policy_stop = payload
        self.halted = True
        self.metrics["ctf_policy_stops"] = int(self.metrics.get("ctf_policy_stops", 0)) + 1
        self.log("ctf.run.stop", payload)
        facts_after = canonical_hash({key: value.dump() for key, value in self.state.facts.items()})
        if facts_after != facts_before:
            raise RuntimeError("CTF run stop mutated verified facts")
        if self.state.completed:
            raise RuntimeError("incomplete CTF run stop cannot mark completion")
        self._persist_state("ctf.run.stop")

    def _dispatch_decision(self, decision: Decision) -> None:
        if decision.kind == "complete" and self.termination_policy.actor_complete is ActorCompleteBehavior.HALT_INCOMPLETE:
            self._stop_incomplete(
                reason=decision.payload.get("reason", "actor requested smoke stop"),
                source="actor_complete",
            )
            return

        if decision.kind == "tool":
            tool = decision.payload.get("tool", "")
            if tool not in self.actions.tools:
                self.metrics["ctf_missing_capabilities"] = int(self.metrics.get("ctf_missing_capabilities", 0)) + 1
                if self.termination_policy.unsupported_capability is UnsupportedCapabilityBehavior.HALT_INCOMPLETE:
                    self._stop_incomplete(
                        reason=f"requested tool/capability is unavailable: {tool}",
                        source="unsupported_capability",
                        subject=tool,
                    )
                    return
                self.report_ctf_failure(
                    CTFFailureKind.TOOL_MISSING,
                    message=f"requested tool/capability is unavailable: {tool}",
                    subject=tool,
                    retry_safe=False,
                )
                return

        return super()._dispatch_decision(decision)
