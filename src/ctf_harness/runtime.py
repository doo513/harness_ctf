from __future__ import annotations

from pathlib import Path
from typing import Any

from harness.core.controller import Decision
from harness.core.failures import Failure, FailureKind
from harness.core.runtime import HarnessRuntime
from harness.core.storage import IntegrityError, canonical_hash

from ctf_harness.hypotheses.models import Hypothesis
from ctf_harness.hypotheses.pool import DurableHypothesisLedger, fingerprint


HYPOTHESIS_GUARD_SCHEMA = "ctf-hypothesis-guard-v1"
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
    """Base runtime plus a speculative, non-authoritative CTF hypothesis guard.

    The guard never writes verified facts or completion state. It only decides
    whether an Actor-requested tool action may be dispatched again under the
    same speculative hypothesis/evidence state. Base HarnessRuntime still owns
    tool execution, receipts, failures, recovery, progress and completion.
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
        else:
            self.ctf_hypotheses = DurableHypothesisLedger(self._ctf_hypothesis_ledger_path)
            self.ctf_hypotheses.save()
        self.metrics.setdefault("ctf_hypothesis_attempts", 0)
        self.metrics.setdefault("ctf_hypothesis_guard_blocks", 0)

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

    def _block_tool(self, *, tool: str, message: str, signature_key: str, payload: dict) -> None:
        self.metrics["ctf_hypothesis_guard_blocks"] = self.metrics.get("ctf_hypothesis_guard_blocks", 0) + 1
        self.log("ctf.hypothesis.guard_block", payload)
        self.fail(Failure(
            FailureKind.NO_PROGRESS,
            message,
            action=tool,
            signature_key=signature_key,
        ))

    def _dispatch_decision(self, decision) -> None:
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
        self.ctf_hypotheses.save()

        action_digest = self._action_digest(decision)
        guard = self.ctf_hypotheses.pool.guard(
            fp,
            action_digest=action_digest,
            evidence_state_digest=hypothesis.evidence_state_digest,
        )
        if not guard.allowed:
            self.ctf_hypotheses.save()
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
        self.ctf_hypotheses.save()
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
            self.ctf_hypotheses.save()
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
        self.ctf_hypotheses.save()
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
