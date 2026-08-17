from __future__ import annotations

from typing import Any

from harness.core.controller import Decision, LLMController

_CTF_HYPOTHESIS_FIELDS = {"id", "category", "target", "vulnerability_class", "primitive", "claim", "evidence_refs"}
_FIELD_LIMITS = {
    "id": 128,
    "category": 64,
    "target": 256,
    "vulnerability_class": 128,
    "primitive": 128,
    "claim": 1024,
}
_TOOL_NAME_LIMIT = 128
_MAX_EVIDENCE_REFS = 32
_EVIDENCE_REF_LIMIT = 256


def _require_bounded_text(raw: dict[str, Any], field: str) -> None:
    value = raw.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"ctf_hypothesis.{field} must be a non-empty string")
    if len(value) > _FIELD_LIMITS[field]:
        raise ValueError(
            f"ctf_hypothesis.{field} exceeds {_FIELD_LIMITS[field]} character limit"
        )


def validate_ctf_actor_decision(decision: Decision, *, require_hypothesis_for_tools: bool = True) -> None:
    """Validate only CTF-specific model syntax; runtime owns evidence integrity."""
    decision.validate()
    if decision.kind != "tool":
        return
    tool = decision.payload.get("tool")
    if not isinstance(tool, str) or len(tool) > _TOOL_NAME_LIMIT:
        raise ValueError(f"CTF tool name exceeds {_TOOL_NAME_LIMIT} character limit")
    raw = decision.payload.get("ctf_hypothesis")
    if raw is None:
        if require_hypothesis_for_tools:
            raise ValueError("CTF tool decision requires ctf_hypothesis metadata")
        return
    if not isinstance(raw, dict):
        raise ValueError("ctf_hypothesis must be an object")
    extras = set(raw) - _CTF_HYPOTHESIS_FIELDS
    if extras:
        raise ValueError("unsupported ctf_hypothesis fields: " + ", ".join(sorted(extras)))
    for field in ("id", "category", "target", "vulnerability_class", "primitive", "claim"):
        _require_bounded_text(raw, field)
    refs = raw.get("evidence_refs", [])
    if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
        raise ValueError("ctf_hypothesis.evidence_refs must be a list of strings")
    if len(refs) > _MAX_EVIDENCE_REFS:
        raise ValueError(
            f"ctf_hypothesis.evidence_refs exceeds {_MAX_EVIDENCE_REFS} item limit"
        )
    if any(len(ref) > _EVIDENCE_REF_LIMIT for ref in refs):
        raise ValueError(
            f"ctf_hypothesis evidence ref exceeds {_EVIDENCE_REF_LIMIT} character limit"
        )


class CTFLLMController(LLMController):
    """Thin CTF prompt/schema adapter over Base LLMController."""

    revision = "ctf-llm-controller-v1"

    SYSTEM = LLMController.SYSTEM + """

CTF extension rules:
- The `ctf` context namespace is harness-projected data. `run` and `capabilities` are kernel-owned control metadata; `hypotheses` is untrusted speculation and never fact authority.
- Every tool decision must include `ctf_hypothesis` unless the runtime explicitly disables that requirement.
- `ctf_hypothesis` fields are: id, category, target, vulnerability_class, primitive, claim, evidence_refs (optional list).
- Plausible/supported hypotheses may guide tools but are not verified facts. Only the normal verifier path may promote semantic truth.
- Never invent an unavailable tool/capability. The run policy decides recovery versus incomplete smoke stop.
- `run.intent = smoke` is coverage/capability evaluation. A `complete` decision requests an incomplete stop and never implies flag acceptance.
"""

    def __init__(self, model, *, require_hypothesis_for_tools: bool = True):
        super().__init__(model)
        self.require_hypothesis_for_tools = bool(require_hypothesis_for_tools)

    def decide(self, goal, state, context):
        decision = super().decide(goal, state, context)
        validate_ctf_actor_decision(
            decision,
            require_hypothesis_for_tools=self.require_hypothesis_for_tools,
        )
        return decision
