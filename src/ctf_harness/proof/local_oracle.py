from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from harness.core.oracles import CompletionResult
from harness.core.sandbox import ExecutionBackend
from harness.core.storage import ArtifactStore, canonical_hash

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class LocalProofReceipt:
    schema_version: int
    kind: str
    proof_level: str
    target_sha256: str
    exploit_sha256: str
    environment_fingerprint: str
    oracle_id: str
    independence_level: str
    oracle_evidence_hash: str
    accepted: bool
    reason_hash: str

    def dump(self) -> dict:
        return asdict(self)


class LocalProofOracle(Protocol):
    name: str

    def evaluate(
        self,
        *,
        workspace: Path,
        target_path: str,
        exploit_path: str,
        environment_fingerprint: str,
    ) -> CompletionResult: ...


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_workspace_file(workspace: Path, value: str, *, label: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty workspace-relative path")
    raw = Path(value)
    if raw.is_absolute():
        raise ValueError(f"{label} must be workspace-relative")
    unresolved = workspace / raw
    if unresolved.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    resolved = unresolved.resolve(strict=True)
    try:
        relative = resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{label} escapes workspace") from exc
    if not resolved.is_file():
        raise ValueError(f"{label} must be a regular file")
    return resolved, relative.as_posix()


class ExecutableDigestLocalProofOracle:
    """Operator-fixed local proof oracle for deterministic exploit outputs.

    The actor controls the exploit file, but not the expected output digest or
    the oracle decision. The exploit is executed only through the supplied
    sandbox backend as ``[./exploit, ./target]``. No raw expected output is
    exposed through the receipt.
    """

    name = "pwn_local_executable_digest"

    def __init__(
        self,
        *,
        expected_stdout_sha256: str,
        backend: ExecutionBackend,
        timeout_seconds: float = 5.0,
    ):
        if not isinstance(expected_stdout_sha256, str) or not _HEX64.fullmatch(expected_stdout_sha256):
            raise ValueError("expected_stdout_sha256 must be 64 lowercase hex characters")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.expected_stdout_sha256 = expected_stdout_sha256
        self.backend = backend
        self.timeout_seconds = float(timeout_seconds)
        contract_hash = hashlib.sha256(
            f"v1|argv=exploit,target|stdout_sha256={expected_stdout_sha256}".encode()
        ).hexdigest()
        self.oracle_id = f"{self.name}:{contract_hash[:16]}"

    def evaluate(
        self,
        *,
        workspace: Path,
        target_path: str,
        exploit_path: str,
        environment_fingerprint: str,
    ) -> CompletionResult:
        workspace = Path(workspace).expanduser().resolve()
        target, target_rel = _safe_workspace_file(workspace, target_path, label="target_path")
        exploit, exploit_rel = _safe_workspace_file(workspace, exploit_path, label="exploit_path")
        attestation = self.backend.isolation_attestation(workspace=workspace)
        trusted_boundary = (
            attestation.source == "runtime_probe"
            and bool(getattr(attestation, "strong_filesystem_boundary", False))
        )
        target_sha = _sha256_file(target)
        exploit_sha = _sha256_file(exploit)
        if not trusted_boundary:
            evidence = [{
                "target_sha256": target_sha,
                "exploit_sha256": exploit_sha,
                "environment_fingerprint": environment_fingerprint,
                "sandbox_source": attestation.source,
                "filesystem_isolated": bool(getattr(attestation, "filesystem_isolated", False)),
            }]
            return CompletionResult(
                accepted=False,
                reason="local proof oracle requires a live filesystem-isolated execution backend",
                evidence=evidence,
                oracle_id=self.oracle_id,
                independence_level="operator_fixed_digest_unisolated",
                evidence_hash=canonical_hash(evidence),
            )

        result = self.backend.run_argv(
            workspace=workspace,
            argv=[f"./{exploit_rel}", f"./{target_rel}"],
            timeout_seconds=self.timeout_seconds,
            env=None,
        )
        stdout_sha = hashlib.sha256(result.stdout.encode()).hexdigest()
        stderr_sha = hashlib.sha256(result.stderr.encode()).hexdigest()
        evidence = [{
            "target_sha256": target_sha,
            "exploit_sha256": exploit_sha,
            "environment_fingerprint": environment_fingerprint,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stdout_sha256": stdout_sha,
            "stderr_sha256": stderr_sha,
            "sandbox_source": attestation.source,
        }]
        accepted = (
            result.returncode == 0
            and result.timed_out is False
            and stdout_sha == self.expected_stdout_sha256
        )
        return CompletionResult(
            accepted=accepted,
            reason="operator-fixed local proof output matched" if accepted else "local proof output did not satisfy the operator-fixed contract",
            evidence=evidence,
            oracle_id=self.oracle_id,
            independence_level="operator_fixed_digest_and_filesystem_isolation",
            evidence_hash=canonical_hash(evidence),
            coverage={"target": 1, "exploit": 1, "stdout_contract": 1},
        )


def evaluate_local_proof(
    oracle: LocalProofOracle,
    *,
    workspace: str | Path,
    target_path: str,
    exploit_path: str,
    environment_fingerprint: str,
) -> LocalProofReceipt:
    if not isinstance(environment_fingerprint, str) or not _HEX64.fullmatch(environment_fingerprint):
        raise ValueError("environment_fingerprint must be 64 lowercase hex characters")
    root = Path(workspace).expanduser().resolve()
    target, _ = _safe_workspace_file(root, target_path, label="target_path")
    exploit, _ = _safe_workspace_file(root, exploit_path, label="exploit_path")
    result = oracle.evaluate(
        workspace=root,
        target_path=target_path,
        exploit_path=exploit_path,
        environment_fingerprint=environment_fingerprint,
    )
    if not isinstance(result.oracle_id, str) or not result.oracle_id:
        raise ValueError("local proof oracle must return a stable oracle_id")
    if not isinstance(result.evidence_hash, str) or not _HEX64.fullmatch(result.evidence_hash):
        raise ValueError("local proof oracle must return a canonical evidence_hash")
    return LocalProofReceipt(
        schema_version=1,
        kind="pwn_local_proof_receipt",
        proof_level="P3_LOCAL",
        target_sha256=_sha256_file(target),
        exploit_sha256=_sha256_file(exploit),
        environment_fingerprint=environment_fingerprint,
        oracle_id=result.oracle_id,
        independence_level=str(result.independence_level),
        oracle_evidence_hash=result.evidence_hash,
        accepted=bool(result.accepted),
        reason_hash=hashlib.sha256(str(result.reason).encode()).hexdigest(),
    )


def persist_local_proof_receipt(
    store: ArtifactStore,
    receipt: LocalProofReceipt,
    *,
    name: str = "pwn-local-proof.json",
) -> str:
    return store.put_json(name, {"ok": True, "output": receipt.dump(), "error": None})
