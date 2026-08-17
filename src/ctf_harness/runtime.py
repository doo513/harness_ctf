from __future__ import annotations

from pathlib import Path
from typing import Any

from harness.core.controller import Decision
from harness.core.failures import Failure, FailureKind
from harness.core.runtime import HarnessRuntime
from harness.core.storage import IntegrityError, canonical_hash

from ctf_harness.hypotheses.models import Hypothesis
from ctf_harness.hypotheses.pool import DurableHypothesisLedger, fingerprint
from ctf_harness.recovery.adapter import (
    CTFFailureKind,
    mappings_descriptor,
    to_core_failure,
)


HYPOTHESIS_GUARD_SCHEMA = "ctf-hypothesis-guard-v1"
CTF_RECOVERY_ADAPTER_SCHEMA = "ctf-recovery-adapter-v1"
_LEDGER_ANCHOR_EVENT = "ctf.hypothesis.ledger_anchor"
_HYPOTHESIS_FIELDS = {
    "id",
    "category",
    "target",
    "vulnerability_class",
    "primitive",
    "claim",
    "evidence_refs",
}


class VerifiedCTFRuntime(HarnessRuntime):
    """Base runtime plus CTF-specific speculative/control adapters.

    CTF extensions may deny duplicate speculative actions and classify domain
    failures, but never write verified facts or completion state. Base
    HarnessRuntime remains the authority for tool execution, receipts, failure
    routing, recovery transitions, progress and completion.
    """

    def __init__(self, *, require_hypothesis_for_tools: bool = True, **kwargs):
        if "run_dir" not in kwargs:
            raise TypeError("VerifiedCTFRuntime requires the Base keyword argument run_dir")
        run_dir = Path(kwargs["run_dir"]).resolve()
        self.require_hypothesis_for_tools = bool(require_hypothesis_for_tools)
        self._ctf_hypothesis_ledger_path = run_dir / "ctf_hypotheses.json"
        super().__init__(**kwargs)

        if self.resume_mode:
            self.ctf_hypotheses = DurableHypothesisLedger.load(self._ctf_hypothesis_ledger_path)
            source_hash = self.ctf_hypotheses.source_body_sha256
            if not source_hash:
                raise IntegrityError("CTF hypothesis ledger has no source body hash")
            self._verify_ctf_hypothesis_anchor(source_hash)
            normalized_hash = canonical_hash(self.ctf_hypotheses.pool.dump())
            if normalized_hash != source_hash:
                self._save_ctf_hypotheses("resume_inflight_to_ambiguous")
        else:
            self.ctf_hypotheses = DurableHypothesisLedger(self._ctf_hypothesis_ledger_path)
            self._save_ctf_hypotheses("init")

        self.metrics.setdefault("ctf_hypothesis_attempts", 0)
        self.metrics.setdefault("ctf_hypothesis_guard_blocks", 0)
        self.metrics.setdefault("ctf_hypothesis_refutations", 0)
        self.metrics.setdefault("ctf_mapped_failures", 0)

    def _config_descriptor(self) -> dict[str, Any]:
        descriptor = super()._config_descriptor()
        descriptor["ctf_hypothesis_guard"] = {
            "schema_version": HYPOTHESIS_GUARD_SCHEMA,
            "required_for_tools": self.require_hypothesis_for_tools,
            "identity_fields": [
                "category", "target", "vulnerability_class", "primitive", "claim"
            ],
            "evidence_identity": "core_registered_content_digest_plus_stable_provenance",
            "ambiguous_resume_policy": "block_same_action_same_evidence",
            "ledger_integrity": "self_hash_plus_latest_base_event_anchor",
            "explicit_refutation": "registered_contradiction_evidence_required",
            "truth_authority": "none",
        }
        descriptor["ctf_recovery_adapter"] = {
            "schema_version": CTF_RECOVERY_ADAPTER_SCHEMA,
            "mappings": mappings_descriptor(),
            "routing_authority": "base_failure_router",
            "recovery_authority": "base_runtime_recovery",
            "truth_authority": "none",
        }
        return descriptor

    @staticmethod
    def _require_nonempty_text(raw: dict, field: str) -> str:
        value = raw.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"ctf_hypothesis.{field} must be a non-empty string")
        return value.strip()

    def _evidence_state(self, refs: list[str]) -> str:
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise ValueError("ctf_hypothesis.evidence_refs must be a list of artifact refs")
        identities = sorted({self._evidence_novelty_identity(ref) for ref in refs})
        return canonical_hash({"evidence_identities": identities})

    def report_ctf_failure(
        self,
        kind: CTFFailureKind | str,
        *,
        message: str,
        subject: str | None = None,
        evidence_refs: list[str] | tuple[str, ...] = (),
        retry_safe: bool | None = None,
    ):
        """Map one domain failure into Core failure/recovery without new authority.

        This is a trusted runtime/domain-adapter API, not an Actor decision kind.
        Evidence refs, when supplied, must already be registered durable Core
        evidence. The returned object is the Base pending RecoveryTransition.
        """
        if not isinstance(evidence_refs, (list, tuple)) or any(
            not isinstance(ref, str) for ref in evidence_refs
        ):
            raise ValueError("CTF failure evidence_refs must be a list/tuple of strings")

        refs = list(dict.fromkeys(evidence_refs))
        identities = sorted(self._evidence_novelty_identity(ref) for ref in refs)
        evidence_state_digest = canonical_hash({"evidence_identities": identities})
        facts_before = canonical_hash({k: v.dump() for k, v in self.state.facts.items()})

        ctf_kind, mapping, core_failure = to_core_failure(
            kind,
            message=message,
            subject=subject,
            retry_safe=retry_safe,
        )
        self.fail(core_failure)
        transition = self.state.pending_recovery
        if transition is None:
            raise IntegrityError("CTF failure mapping did not schedule a Base recovery transition")

        facts_after = canonical_hash({k: v.dump() for k, v in self.state.facts.items()})
        if facts_after != facts_before:
            raise IntegrityError("CTF failure adapter mutated verified facts")

        self.metrics["ctf_mapped_failures"] = int(self.metrics.get("ctf_mapped_failures", 0)) + 1
        self.log("ctf.failure.mapped", {
            "schema_version": CTF_RECOVERY_ADAPTER_SCHEMA,
            "ctf_failure_kind": ctf_kind.value,
            "core_failure_kind": mapping.core_failure.value,
            "recovery_target": mapping.target,
            "subject": subject,
            "retry_safe": bool(core_failure.retry_safe),
            "evidence_refs": refs,
            "evidence_state_digest": evidence_state_digest,
            "base_transition_id": transition.transition_id,
            "base_recovery_action": transition.action.value,
            "base_repeat_count": transition.repeat_count,
            "truth_authority": "none",
        })
        self._persist_state("ctf.failure.mapped")
        return transition

    def _parse_hypothesis(self, raw: Any) -> tuple[str, Hypothesis]:
        if not isinstance(raw, dict):
            raise ValueError("tool decision requires ctf_hypothesis object")
        extras = set(raw) - _HYPOTHESIS_FIELDS
        if extras:
            raise ValueError("unsupported ctf_hypothesis fields: " + ", ".join(sorted(extras)))
        refs = raw.get("evidence_refs", [])
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise ValueError("ctf_hypothesis.evidence_refs must be a list of strings")
        evidence_state = self._evidence_state(refs)
        hypothesis = Hypothesis(
            id=self._require_nonempty_text(raw, "id"),
            category=self._require_nonempty_text(raw, "category"),
            target=self._require_nonempty_text(raw, "target"),
            vulnerability_class=self._require_nonempty_text(raw, "vulnerability_class"),
            primitive=self._require_nonempty_text(raw, "primitive"),
            claim=self._require_nonempty_text(raw, "claim"),
            evidence_refs=list(dict.fromkeys(refs)),
            evidence_state_digest=evidence_state,
        )
        return fingerprint(hypothesis), hypothesis

    @staticmethod
    def _action_digest(decision: Decision) -> str:
        return canonical_hash({
            "tool": decision.payload["tool"],
            "args": decision.payload.get("args", {}),
        })

    def _save_ctf_hypotheses(self, reason: str) -> str:
        body_sha256 = self.ctf_hypotheses.save()
        self.log(_LEDGER_ANCHOR_EVENT, {
            "schema_version": HYPOTHESIS_GUARD_SCHEMA,
            "body_sha256": body_sha256,
            "reason": reason,
        })
        return body_sha256

    def _verify_ctf_hypothesis_anchor(self, source_body_sha256: str) -> None:
        latest = None
        for record in self.events.verify_chain():
            if record.get("kind") == _LEDGER_ANCHOR_EVENT:
                latest = record
        if latest is None:
            raise IntegrityError("CTF hypothesis ledger has no Base event-log anchor")
        payload = latest.get("payload", {})
        anchored = payload.get("body_sha256")
        if anchored != source_body_sha256:
            raise IntegrityError(
                "CTF hypothesis ledger rollback or unanchored sidecar state detected"
            )

    def _block_tool(self, *, tool: str, message: str, signature_key: str, payload: dict) -> None:
        self.metrics["ctf_hypothesis_guard_blocks"] = self.metrics.get("ctf_hypothesis_guard_blocks", 0) + 1
        self.log("ctf.hypothesis.guard_block", payload)
        self.fail(Failure(
            FailureKind.NO_PROGRESS,
            message,
            action=tool,
            signature_key=signature_key,
        ))

    def _dispatch_ctf_refutation(self, decision: Decision) -> bool:
        if decision.kind != "refute" or "ctf_hypothesis" not in decision.payload:
            return False
        raw_hypothesis = decision.payload.get("ctf_hypothesis")
        try:
            fp, hypothesis = self._parse_hypothesis(raw_hypothesis)
        except IntegrityError as exc:
            self.fail(Failure(
                FailureKind.PERSISTENCE_ERROR,
                f"CTF hypothesis refutation evidence integrity failure: {exc}",
                action="ctf_hypothesis_refute",
                signature_key="ctf:hypothesis:refute_evidence_integrity",
            ))
            return True
        except Exception as exc:
            self.fail(Failure(
                FailureKind.IMPLEMENTATION_ERROR,
                f"invalid CTF hypothesis refutation metadata: {type(exc).__name__}: {exc}",
                action="ctf_hypothesis_refute",
                signature_key="ctf:hypothesis:refute_metadata_contract",
            ))
            return True

        if decision.payload.get("key") != hypothesis.id:
            self.fail(Failure(
                FailureKind.IMPLEMENTATION_ERROR,
                "CTF refute.key must match ctf_hypothesis.id",
                action="ctf_hypothesis_refute",
                signature_key="ctf:hypothesis:refute_key_mismatch",
            ))
            return True
        if not hypothesis.evidence_refs:
            self.fail(Failure(
                FailureKind.MISSING_INFO,
                "CTF hypothesis refutation requires registered contradiction evidence",
                action="ctf_hypothesis_refute",
                signature_key="ctf:hypothesis:refute_missing_evidence",
            ))
            return True

        existing = self.ctf_hypotheses.pool.hypotheses.get(fp)
        if existing is None:
            self.fail(Failure(
                FailureKind.MISSING_INFO,
                "cannot refute unknown CTF hypothesis",
                action="ctf_hypothesis_refute",
                signature_key="ctf:hypothesis:refute_unknown",
            ))
            return True

        self.ctf_hypotheses.pool.update_evidence(
            fp,
            evidence_refs=hypothesis.evidence_refs,
            evidence_state_digest=hypothesis.evidence_state_digest,
        )
        self.ctf_hypotheses.pool.mark_refuted(
            fp,
            contradiction_evidence=hypothesis.evidence_refs,
        )
        self.metrics["ctf_hypothesis_refutations"] = self.metrics.get("ctf_hypothesis_refutations", 0) + 1
        self._save_ctf_hypotheses("explicit_refutation")
        self.log("ctf.hypothesis.refuted", {
            "hypothesis_fingerprint": fp,
            "hypothesis_id": hypothesis.id,
            "evidence_state_digest": hypothesis.evidence_state_digest,
            "contradiction_evidence": list(hypothesis.evidence_refs),
            "reason": decision.payload.get("reason", ""),
            "truth_authority": "none",
        })
        return True

    def _dispatch_decision(self, decision) -> None:
        if self._dispatch_ctf_refutation(decision):
            return
        if decision.kind != "tool":
            return super()._dispatch_decision(decision)

        tool = decision.payload.get("tool", "")
        raw_hypothesis = decision.payload.get("ctf_hypothesis")
        if raw_hypothesis is None:
            if not self.require_hypothesis_for_tools:
                return super()._dispatch_decision(decision)
            self._block_tool(
                tool=tool,
                message="CTF tool execution requires hypothesis metadata",
                signature_key="ctf:hypothesis:missing",
                payload={"tool": tool, "reason": "missing_hypothesis_metadata"},
            )
            return

        try:
            fp, hypothesis = self._parse_hypothesis(raw_hypothesis)
        except IntegrityError as exc:
            self.fail(Failure(
                FailureKind.PERSISTENCE_ERROR,
                f"CTF hypothesis evidence integrity failure: {exc}",
                action=tool,
                signature_key="ctf:hypothesis:evidence_integrity",
            ))
            return
        except Exception as exc:
            self.fail(Failure(
                FailureKind.IMPLEMENTATION_ERROR,
                f"invalid CTF hypothesis metadata: {type(exc).__name__}: {exc}",
                action=tool,
                signature_key="ctf:hypothesis:metadata_contract",
            ))
            return

        existing = self.ctf_hypotheses.pool.hypotheses.get(fp)
        if existing is None:
            self.ctf_hypotheses.pool.add(hypothesis)
        else:
            self.ctf_hypotheses.pool.update_evidence(
                fp,
                evidence_refs=hypothesis.evidence_refs,
                evidence_state_digest=hypothesis.evidence_state_digest,
            )
        self._save_ctf_hypotheses("hypothesis_upsert")

        action_digest = self._action_digest(decision)
        guard = self.ctf_hypotheses.pool.guard(
            fp,
            action_digest=action_digest,
            evidence_state_digest=hypothesis.evidence_state_digest,
        )
        if not guard.allowed:
            self._block_tool(
                tool=tool,
                message=guard.reason,
                signature_key=f"ctf:hypothesis:duplicate:{fp}:{action_digest}",
                payload={
                    "tool": tool,
                    "hypothesis_fingerprint": fp,
                    "action_digest": action_digest,
                    "evidence_state_digest": hypothesis.evidence_state_digest,
                    "blocking_attempt_id": guard.blocking_attempt_id,
                    "blocking_failure_signature": guard.blocking_failure_signature,
                    "reason": guard.reason,
                },
            )
            return

        attempt_id = self.ctf_hypotheses.pool.begin_attempt(
            fp,
            action_digest=action_digest,
            evidence_state_digest=hypothesis.evidence_state_digest,
            step=self.state.step,
        )
        self.metrics["ctf_hypothesis_attempts"] = self.metrics.get("ctf_hypothesis_attempts", 0) + 1
        self._save_ctf_hypotheses("attempt_begin")
        self.log("ctf.hypothesis.attempt_begin", {
            "attempt_id": attempt_id,
            "hypothesis_fingerprint": fp,
            "action_digest": action_digest,
            "evidence_state_digest": hypothesis.evidence_state_digest,
            "tool": tool,
        })

        sanitized = Decision("tool", {
            "tool": tool,
            "args": decision.payload.get("args", {}),
        })
        before_failures = len(self.state.failures)
        try:
            super()._dispatch_decision(sanitized)
        except Exception:
            self.ctf_hypotheses.pool.finish_ambiguous(attempt_id)
            self._save_ctf_hypotheses("attempt_ambiguous")
            raise

        new_failures = self.state.failures[before_failures:]
        if new_failures:
            failure = new_failures[-1]
            self.ctf_hypotheses.pool.finish_failure(
                attempt_id,
                failure_signature=str(failure.get("signature", "")),
                failure_kind=str(failure.get("kind", "")),
                retry_safe=bool(failure.get("retry_safe", False)),
            )
            outcome = "failed"
        else:
            self.ctf_hypotheses.pool.finish_success(attempt_id)
            outcome = "succeeded"
        self._save_ctf_hypotheses("attempt_end")
        self.log("ctf.hypothesis.attempt_end", {
            "attempt_id": attempt_id,
            "hypothesis_fingerprint": fp,
            "action_digest": action_digest,
            "evidence_state_digest": hypothesis.evidence_state_digest,
            "tool": tool,
            "outcome": outcome,
            "failure_signature": (
                str(new_failures[-1].get("signature", "")) if new_failures else None
            ),
        })
