from __future__ import annotations

from ctf_harness.domains.pwn import PwnPlaybook
from ctf_harness.domains.registry import DomainRegistry
from ctf_harness.hypotheses.models import Hypothesis, HypothesisStatus
from ctf_harness.hypotheses.pool import HypothesisPool, fingerprint


def test_pwn_playbook_is_question_capability_pivot_not_command_sequence() -> None:
    snap = PwnPlaybook().snapshot(
        verified_fact_keys=[],
        hypothesis_statuses=["open"],
        available_tools=["pwn_recon", "target_exec"],
        completed=False,
    )
    assert snap["domain"] == "pwn"
    assert snap["hard_sequence"] is False
    assert snap["truth_authority"] == "none"
    assert snap["current"]["stage"] == "surface"
    assert snap["current"]["questions"]
    rendered = repr(snap)
    assert "shell_command" not in rendered
    assert "command_sequence" not in rendered
    assert snap["current"]["questions"][0]["available_capabilities"] == ["pwn_recon"]


def test_pwn_playbook_moves_from_verified_facts_only_for_proof_stage() -> None:
    playbook = PwnPlaybook()
    primitive = playbook.snapshot(
        verified_fact_keys=["ctf.pwn.arch"],
        hypothesis_statuses=["supported"],
        available_tools=["pwn_crash_probe", "pwn_control_probe", "analysis_exec"],
        completed=False,
    )
    assert primitive["current"]["stage"] == "primitive"
    assert primitive["tactical_hypothesis_counts"]["supported"] == 1

    control = playbook.snapshot(
        verified_fact_keys=["ctf.pwn.arch", "ctf.pwn.crash_reproducible"],
        hypothesis_statuses=["supported"],
        available_tools=["pwn_control_probe"],
        completed=False,
    )
    assert control["current"]["stage"] == "control"

    # A supported tactical hypothesis alone must not advance a verified proof stage.
    still_surface = playbook.snapshot(
        verified_fact_keys=[],
        hypothesis_statuses=["supported"],
        available_tools=["pwn_control_probe"],
        completed=False,
    )
    assert still_surface["current"]["stage"] == "surface"


def test_domain_registry_has_no_execution_or_truth_authority() -> None:
    registry = DomainRegistry((PwnPlaybook(),))
    projected = registry.project(
        active_domains=("pwn",),
        verified_fact_keys=(),
        hypothesis_statuses=(),
        available_tools=("pwn_recon",),
        completed=False,
    )
    assert projected["behavior"] == "advisory_not_mandatory"
    assert projected["execution_authority"] == "none"
    assert projected["truth_authority"] == "none"
    assert projected["completion_authority"] == "none"


def test_supported_hypothesis_remains_speculative_sidecar() -> None:
    hypothesis = Hypothesis(
        id="H-supported",
        category="pwn",
        target="chal",
        vulnerability_class="stack-overflow",
        primitive="probable-control",
        claim="saved control data appears affected",
    )
    pool = HypothesisPool()
    fp = pool.add(hypothesis)
    assert fp == fingerprint(hypothesis)
    assert pool.mark_supported(fp, support_evidence=["artifact://" + "a" * 64 + "_obs"])
    supported = pool.hypotheses[fp]
    assert supported.status is HypothesisStatus.SUPPORTED
    assert supported.support_evidence
    assert not pool.mark_supported(fp, support_evidence=supported.support_evidence)
    # HypothesisPool has no Fact store or completion state by construction.
    assert not hasattr(pool, "facts")
    assert not hasattr(pool, "completed")
