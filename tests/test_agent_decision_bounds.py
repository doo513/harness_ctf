from __future__ import annotations

import json

import pytest

from ctf_harness.agent_controller import CTFLLMController


class OneShotModel:
    def __init__(self, decision: dict):
        self.decision = decision

    def complete(self, *, system: str, user: str) -> str:
        return json.dumps(self.decision, sort_keys=True)


def _decision(*, tool: str = "argv", claim: str = "bounded claim", refs=None) -> dict:
    return {
        "kind": "tool",
        "payload": {
            "tool": tool,
            "args": {"argv": ["x"]},
            "ctf_hypothesis": {
                "id": "H1",
                "category": "pwn",
                "target": "chal",
                "vulnerability_class": "unknown",
                "primitive": "recon",
                "claim": claim,
                "evidence_refs": list(refs or []),
            },
        },
    }


def _decide(decision: dict):
    return CTFLLMController(OneShotModel(decision)).decide("goal", object(), {})


def test_rejects_oversized_tool_name() -> None:
    with pytest.raises(ValueError, match="tool name exceeds"):
        _decide(_decision(tool="x" * 129))


def test_rejects_oversized_hypothesis_claim() -> None:
    with pytest.raises(ValueError, match="claim exceeds"):
        _decide(_decision(claim="x" * 1025))


def test_rejects_too_many_evidence_refs() -> None:
    with pytest.raises(ValueError, match="evidence_refs exceeds"):
        _decide(_decision(refs=[f"ref-{i}" for i in range(33)]))


def test_rejects_oversized_evidence_ref() -> None:
    with pytest.raises(ValueError, match="evidence ref exceeds"):
        _decide(_decision(refs=["r" * 257]))


def test_accepts_bounded_ctf_tool_decision() -> None:
    decision = _decide(_decision(refs=["artifact-ref"] * 2))
    assert decision.kind == "tool"
    assert decision.payload["tool"] == "argv"
