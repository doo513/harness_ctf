from __future__ import annotations

import pytest

from ctf_harness.evaluation.models import IndependentAdjudication
from ctf_harness.proof.models import ProofLevel


def test_rejected_adjudication_cannot_claim_p6():
    with pytest.raises(ValueError, match="cannot exist without oracle acceptance"):
        IndependentAdjudication(
            adjudicator_id="independent-adjudicator",
            evidence_sha256="a" * 64,
            run_id="b" * 64,
            run_evidence_sha256="c" * 64,
            oracle_accepted=False,
            highest_proof_level=ProofLevel.P6_ACCEPTED,
        )
