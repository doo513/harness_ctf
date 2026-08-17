from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from harness.core.sandbox import LinuxNamespaceSandboxBackend, NetworkPolicy
from harness.core.storage import ArtifactStore
from ctf_harness.proof.local_oracle import (
    ExecutableDigestLocalProofOracle,
    evaluate_local_proof,
    persist_local_proof_receipt,
)
from ctf_harness.proof.ladder import proof_level_from_verified_keys
from ctf_harness.proof.models import ProofLevel
from ctf_harness.verifiers.pwn.local import LocalExploitVerifier

TARGET = """#!/bin/sh
read value
if [ "$value" = "ctf-local-proof-secret-513" ]; then
    printf 'LOCAL_PROOF_OK_513\\n'
    exit 0
fi
exit 7
"""

EXPLOIT = """#!/bin/sh
printf 'ctf-local-proof-secret-513\\n' | "$1"
"""


def _write_exec(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-local-proof-") as td:
        root = Path(td)
        workspace = root / "workspace"
        workspace.mkdir()
        target = workspace / "target.sh"
        exploit = workspace / "exploit.sh"
        _write_exec(target, TARGET)
        _write_exec(exploit, EXPLOIT)

        backend = LinuxNamespaceSandboxBackend(network_policy=NetworkPolicy.DENY)
        att = backend.isolation_attestation(workspace=workspace)
        if att.source != "runtime_probe" or not att.strong_filesystem_boundary:
            raise RuntimeError(f"live filesystem-isolated namespace unavailable: {att.evidence}")

        expected = hashlib.sha256(b"LOCAL_PROOF_OK_513\n").hexdigest()
        env_fp = hashlib.sha256(b"synthetic-local-pwn-environment-v1").hexdigest()
        oracle = ExecutableDigestLocalProofOracle(
            expected_stdout_sha256=expected,
            backend=backend,
            timeout_seconds=3.0,
        )
        receipt = evaluate_local_proof(
            oracle,
            workspace=workspace,
            target_path="target.sh",
            exploit_path="exploit.sh",
            environment_fingerprint=env_fp,
        )
        assert receipt.accepted
        assert receipt.independence_level == "operator_fixed_digest_and_filesystem_isolation"

        store = ArtifactStore(root / "artifacts")
        ref = persist_local_proof_receipt(store, receipt)
        context = {
            "state": {
                "artifacts": [ref],
                "evidence_refs": [ref],
                "observations": [{"source": "pwn_local_proof_oracle", "ok": True, "artifact_ref": ref}],
            },
            "artifact_root": str(store.root),
            "claim_evidence_refs": [ref],
            "claim_key": "ctf.pwn.local_exploit",
        }
        candidate = {
            "target_sha256": receipt.target_sha256,
            "exploit_sha256": receipt.exploit_sha256,
            "environment_fingerprint": receipt.environment_fingerprint,
            "oracle_id": receipt.oracle_id,
        }
        verifier = LocalExploitVerifier()
        accepted = verifier.verify(candidate, context)
        assert accepted.verified, accepted.reason
        assert not verifier.verify({**candidate, "exploit_sha256": "0" * 64}, context).verified

        wrong_source = dict(context)
        wrong_source["state"] = {
            "artifacts": [ref],
            "evidence_refs": [ref],
            "observations": [{"source": "actor_claim", "ok": True, "artifact_ref": ref}],
        }
        assert not verifier.verify(candidate, wrong_source).verified

        bad_oracle = ExecutableDigestLocalProofOracle(
            expected_stdout_sha256=hashlib.sha256(b"wrong\n").hexdigest(),
            backend=backend,
            timeout_seconds=3.0,
        )
        rejected = evaluate_local_proof(
            bad_oracle,
            workspace=workspace,
            target_path="target.sh",
            exploit_path="exploit.sh",
            environment_fingerprint=env_fp,
        )
        assert not rejected.accepted
        bad_ref = persist_local_proof_receipt(store, rejected, name="rejected-local-proof.json")
        bad_context = {
            "state": {
                "artifacts": [bad_ref],
                "evidence_refs": [bad_ref],
                "observations": [{"source": "pwn_local_proof_oracle", "ok": True, "artifact_ref": bad_ref}],
            },
            "artifact_root": str(store.root),
            "claim_evidence_refs": [bad_ref],
            "claim_key": "ctf.pwn.local_exploit",
        }
        assert not verifier.verify(candidate, bad_context).verified

        # The ladder must be contiguous: a later fact alone cannot claim P5.
        assert proof_level_from_verified_keys({"ctf.pwn.remote_behavior"}) is None
        assert proof_level_from_verified_keys({
            "ctf.pwn.arch",
            "ctf.pwn.crash_reproducible",
            "ctf.pwn.control_flow",
            "ctf.pwn.local_exploit",
        }) == ProofLevel.P3_LOCAL

        print(json.dumps({
            "probe": "pwn-local-proof-live",
            "all_passed": True,
            "attestation_source": att.source,
            "filesystem_isolated": att.strong_filesystem_boundary,
            "target_sha256": receipt.target_sha256,
            "exploit_sha256": receipt.exploit_sha256,
            "environment_fingerprint": receipt.environment_fingerprint,
            "oracle_id": receipt.oracle_id,
            "accepted": receipt.accepted,
            "actor_source_rejected": True,
            "rejected_oracle_rejected": True,
            "noncontiguous_p5_blocked": True,
        }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
