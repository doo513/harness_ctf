from __future__ import annotations

from ctf_harness.coordination import EvidenceBus, FindingEnvelope, FindingTrust, MultiAgentCoordinator


class Worker:
    def __init__(self, worker_id: str, finding: FindingEnvelope):
        self.worker_id = worker_id
        self.finding = finding
        self.contexts = []

    def run_round(self, *, round_index, shared_context):
        self.contexts.append(shared_context)
        return (self.finding,)


def test_multi_agent_coordinator_parallelizes_findings_not_harness_state() -> None:
    bus = EvidenceBus(verified_fact_exists=lambda key: key == "ctf.pwn.crash_reproducible")
    a = Worker("a", FindingEnvelope(
        finding_id="A1",
        source_agent="a",
        trust=FindingTrust.TENTATIVE,
        summary="saved control data may be affected",
        hypothesis_fingerprint="a" * 64,
        evidence_refs=("artifact://obs-a",),
    ))
    b = Worker("b", FindingEnvelope(
        finding_id="B1",
        source_agent="b",
        trust=FindingTrust.VERIFIED,
        summary="existing crash fact is useful to both solvers",
        fact_key="ctf.pwn.crash_reproducible",
        evidence_refs=("artifact://obs-b",),
    ))
    coordinator = MultiAgentCoordinator(workers=(b, a), evidence_bus=bus, max_workers=2)
    receipt = coordinator.run_round(shared_context={"challenge_id": "fixture"})
    assert receipt.round_index == 0
    assert receipt.worker_ids == ("a", "b")
    assert receipt.findings_published == 2
    assert len(receipt.bus_snapshot["tentative"]) == 1
    assert len(receipt.bus_snapshot["verified"]) == 1
    assert all(context["mutable_harness_state_available"] is False for context in a.contexts + b.contexts)
    desc = coordinator.descriptor()
    assert desc["fact_write_authority"] == "none"
    assert desc["tool_execution_authority"] == "none"
    assert desc["completion_authority"] == "none"
