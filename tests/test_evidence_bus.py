import pytest

from ctf_harness.coordination import EvidenceBus, FindingEnvelope, FindingTrust


def test_verified_channel_requires_existing_harness_fact() -> None:
    bus = EvidenceBus(verified_fact_exists=lambda key: key == "ctf.pwn.control_flow")
    bus.publish(FindingEnvelope(
        finding_id="F1",
        source_agent="solver-a",
        trust=FindingTrust.VERIFIED,
        summary="control verifier accepted",
        fact_key="ctf.pwn.control_flow",
        evidence_refs=("artifact://e1",),
    ))
    with pytest.raises(ValueError, match="already verified"):
        bus.publish(FindingEnvelope(
            finding_id="F2",
            source_agent="solver-b",
            trust=FindingTrust.VERIFIED,
            summary="model says solved",
            fact_key="ctf.fake.fact",
        ))
    snap = bus.snapshot()
    assert len(snap["verified"]) == 1
    assert snap["bus_truth_authority"] == "none"


def test_tentative_channel_stays_speculative() -> None:
    bus = EvidenceBus(verified_fact_exists=lambda key: False)
    bus.publish(FindingEnvelope(
        finding_id="T1",
        source_agent="solver-a",
        trust=FindingTrust.TENTATIVE,
        summary="input six appears to affect saved LR",
        hypothesis_fingerprint="h" * 64,
        evidence_refs=("artifact://obs",),
    ))
    snap = bus.snapshot()
    assert not snap["verified"]
    assert snap["tentative"][0]["trust"] == "tentative"
    assert snap["tentative"][0]["truth_authority"] == "none"
    assert snap["multi_agent_execution"] == "optional_not_enabled_by_bus"
