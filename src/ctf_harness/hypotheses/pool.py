from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path

from harness.core.storage import IntegrityError, atomic_write_json, canonical_hash

from .models import AttemptRecord, AttemptStatus, Hypothesis, HypothesisStatus


LEDGER_SCHEMA_VERSION = 1


def fingerprint(hypothesis: Hypothesis) -> str:
    """Stable semantic/strategy identity; evidence state is deliberately excluded."""
    payload = {
        "category": hypothesis.category,
        "target": hypothesis.target,
        "vulnerability_class": hypothesis.vulnerability_class,
        "primitive": hypothesis.primitive,
        "claim": hypothesis.claim,
    }
    return canonical_hash(payload)


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    reason: str
    blocking_attempt_id: str | None = None
    blocking_failure_signature: str | None = None


class HypothesisPool:
    """Speculative CTF hypothesis sidecar; never a fact/completion authority."""

    def __init__(self):
        self._by_fp: dict[str, Hypothesis] = {}
        self._attempts: list[AttemptRecord] = []

    @property
    def hypotheses(self) -> dict[str, Hypothesis]:
        return dict(self._by_fp)

    @property
    def attempts(self) -> tuple[AttemptRecord, ...]:
        return tuple(self._attempts)

    def add(self, hypothesis: Hypothesis) -> str:
        fp = fingerprint(hypothesis)
        existing = self._by_fp.get(fp)
        if existing is None:
            self._by_fp[fp] = hypothesis
        else:
            # Display IDs are non-authoritative; semantic identity controls dedupe.
            # Evidence is mutable and updated separately from the fingerprint.
            existing.evidence_refs = list(dict.fromkeys(hypothesis.evidence_refs))
            existing.evidence_state_digest = hypothesis.evidence_state_digest
        return fp

    def update_evidence(self, fp: str, *, evidence_refs: list[str], evidence_state_digest: str) -> None:
        hypothesis = self._by_fp[fp]
        hypothesis.evidence_refs = list(dict.fromkeys(evidence_refs))
        hypothesis.evidence_state_digest = evidence_state_digest

    def mark_refuted(self, fp: str, *, contradiction_evidence: list[str] = ()) -> None:
        hypothesis = self._by_fp[fp]
        hypothesis.status = HypothesisStatus.REFUTED
        for ref in contradiction_evidence:
            if ref not in hypothesis.contradiction_evidence:
                hypothesis.contradiction_evidence.append(ref)

    def guard(self, fp: str, *, action_digest: str, evidence_state_digest: str) -> GuardDecision:
        hypothesis = self._by_fp[fp]
        if hypothesis.status == HypothesisStatus.REFUTED:
            return GuardDecision(False, "hypothesis is refuted")

        for attempt in reversed(self._attempts):
            if attempt.hypothesis_fingerprint != fp:
                continue
            if attempt.action_digest != action_digest:
                continue
            if attempt.evidence_state_digest != evidence_state_digest:
                continue
            if attempt.status == AttemptStatus.AMBIGUOUS:
                return GuardDecision(
                    False,
                    "same hypothesis/action has an ambiguous prior execution under the same evidence state",
                    attempt.attempt_id,
                    attempt.failure_signature,
                )
            if attempt.status == AttemptStatus.FAILED and not attempt.retry_safe:
                return GuardDecision(
                    False,
                    "same hypothesis/action already failed under the same evidence state",
                    attempt.attempt_id,
                    attempt.failure_signature,
                )
        return GuardDecision(True, "no blocking prior failure under this evidence state")

    def begin_attempt(self, fp: str, *, action_digest: str, evidence_state_digest: str, step: int) -> str:
        hypothesis = self._by_fp[fp]
        attempt_id = uuid.uuid4().hex
        hypothesis.attempt_count += 1
        self._attempts.append(AttemptRecord(
            attempt_id=attempt_id,
            hypothesis_fingerprint=fp,
            action_digest=action_digest,
            evidence_state_digest=evidence_state_digest,
            step=int(step),
        ))
        return attempt_id

    def _attempt(self, attempt_id: str) -> AttemptRecord:
        for attempt in self._attempts:
            if attempt.attempt_id == attempt_id:
                return attempt
        raise KeyError(attempt_id)

    def finish_success(self, attempt_id: str) -> None:
        self._attempt(attempt_id).status = AttemptStatus.SUCCEEDED

    def finish_failure(
        self,
        attempt_id: str,
        *,
        failure_signature: str,
        failure_kind: str,
        retry_safe: bool,
    ) -> None:
        attempt = self._attempt(attempt_id)
        attempt.status = AttemptStatus.FAILED
        attempt.failure_signature = failure_signature
        attempt.failure_kind = failure_kind
        attempt.retry_safe = bool(retry_safe)
        hypothesis = self._by_fp[attempt.hypothesis_fingerprint]
        hypothesis.last_failure_signature = failure_signature

    def finish_ambiguous(self, attempt_id: str, *, failure_signature: str | None = None) -> None:
        attempt = self._attempt(attempt_id)
        attempt.status = AttemptStatus.AMBIGUOUS
        attempt.failure_signature = failure_signature

    def dump(self) -> dict:
        return {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "hypotheses": {
                fp: hypothesis.dump()
                for fp, hypothesis in sorted(self._by_fp.items())
            },
            "attempts": [attempt.dump() for attempt in self._attempts],
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "HypothesisPool":
        if not isinstance(raw, dict) or raw.get("schema_version") != LEDGER_SCHEMA_VERSION:
            raise IntegrityError("unsupported CTF hypothesis ledger schema")
        hypotheses = raw.get("hypotheses")
        attempts = raw.get("attempts")
        if not isinstance(hypotheses, dict) or not isinstance(attempts, list):
            raise IntegrityError("malformed CTF hypothesis ledger")
        pool = cls()
        for fp, item in hypotheses.items():
            hypothesis = Hypothesis.from_dict(item)
            if fingerprint(hypothesis) != fp:
                raise IntegrityError("CTF hypothesis fingerprint does not match semantic identity")
            pool._by_fp[fp] = hypothesis
        for item in attempts:
            attempt = AttemptRecord.from_dict(item)
            if attempt.hypothesis_fingerprint not in pool._by_fp:
                raise IntegrityError("CTF attempt references unknown hypothesis")
            if attempt.status == AttemptStatus.INFLIGHT:
                # A process crash can leave an execution outcome uncertain. Never
                # silently turn that into a safe retry on resume.
                attempt.status = AttemptStatus.AMBIGUOUS
            pool._attempts.append(attempt)
        return pool


class DurableHypothesisLedger:
    """Integrity-wrapped, atomically replaced speculative sidecar."""

    def __init__(self, path: str | Path, pool: HypothesisPool | None = None):
        self.path = Path(path)
        self.pool = pool or HypothesisPool()

    def save(self) -> None:
        body = self.pool.dump()
        envelope = {
            "body": body,
            "body_sha256": canonical_hash(body),
        }
        atomic_write_json(self.path, envelope)

    @classmethod
    def load(cls, path: str | Path) -> "DurableHypothesisLedger":
        path = Path(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise IntegrityError("CTF hypothesis ledger is missing") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"cannot read CTF hypothesis ledger: {exc}") from exc
        if not isinstance(raw, dict) or set(raw) != {"body", "body_sha256"}:
            raise IntegrityError("malformed CTF hypothesis ledger envelope")
        if canonical_hash(raw["body"]) != raw["body_sha256"]:
            raise IntegrityError("CTF hypothesis ledger integrity mismatch")
        ledger = cls(path, HypothesisPool.from_dict(raw["body"]))
        # Persist conversion of crash-left INFLIGHT records to AMBIGUOUS.
        ledger.save()
        return ledger
