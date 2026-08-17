from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from harness.core.oracles import CompletionResult
from harness.core.sandbox import ExecutionBackend
from harness.core.storage import ArtifactStore, canonical_hash
from ctf_harness.target.runners import NativeRunner, TargetRunner

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class LocalProofReceipt:
    schema_version: int
    kind: str
    proof_level: str
    target_sha256: str
    exploit_sha256: str
    environment_fingerprint: str
    runtime_fingerprint: str
    launch_fingerprint: str
    oracle_id: str
    independence_level: str
    oracle_evidence_hash: str
    accepted: bool
    reason_hash: str

    def dump(self) -> dict:
        return asdict(self)


class LocalProofOracle(Protocol):
    name: str
    def evaluate(self, *, workspace: Path, target_path: str, exploit_path: str, environment_fingerprint: str) -> CompletionResult: ...


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
    """Operator-fixed P3 oracle using one hash-bound TargetRunner launch.

    The exploit is actor-controlled, so the accepted path requires a live strong
    filesystem boundary *and* a read-only workspace. This prevents the exploit
    from changing the admitted target, loader, or workspace sysroot after their
    identities are checked and before using the supplied RuntimeLaunch argv.
    """

    name = "pwn_local_executable_digest"

    def __init__(
        self,
        *,
        expected_stdout_sha256: str,
        backend: ExecutionBackend,
        timeout_seconds: float = 5.0,
        target_runner: TargetRunner | None = None,
        expected_target_sha256: str | None = None,
    ):
        if not isinstance(expected_stdout_sha256, str) or not _HEX64.fullmatch(expected_stdout_sha256):
            raise ValueError("expected_stdout_sha256 must be 64 lowercase hex characters")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if expected_target_sha256 is not None and not _HEX64.fullmatch(expected_target_sha256):
            raise ValueError("expected_target_sha256 must be 64 lowercase hex characters")
        self.expected_stdout_sha256 = expected_stdout_sha256
        self.backend = backend
        self.timeout_seconds = float(timeout_seconds)
        self.target_runner = target_runner or NativeRunner("native-default")
        self.expected_target_sha256 = expected_target_sha256
        contract_hash = hashlib.sha256(
            ("v2|argv=exploit,target-runtime-argv"
             f"|stdout_sha256={expected_stdout_sha256}"
             f"|runner_profile={self.target_runner.profile_id}"
             "|workspace=read-only").encode()
        ).hexdigest()
        self.oracle_id = f"{self.name}:{contract_hash[:16]}"

    def evaluate(self, *, workspace: Path, target_path: str, exploit_path: str, environment_fingerprint: str) -> CompletionResult:
        workspace = Path(workspace).expanduser().resolve()
        target, target_rel = _safe_workspace_file(workspace, target_path, label="target_path")
        exploit, exploit_rel = _safe_workspace_file(workspace, exploit_path, label="exploit_path")
        launch = self.target_runner.build_launch(
            workspace=workspace,
            target_relpath=target_rel,
            expected_target_sha256=self.expected_target_sha256,
        )
        attestation = self.backend.isolation_attestation(workspace=workspace)
        workspace_read_only = getattr(self.backend, "workspace_writable", None) is False
        trusted_boundary = (
            attestation.source == "runtime_probe"
            and bool(getattr(attestation, "strong_filesystem_boundary", False))
            and workspace_read_only
        )
        target_sha = _sha256_file(target)
        exploit_sha = _sha256_file(exploit)
        runtime = launch.runtime_descriptor()
        runtime_fingerprint = launch.runtime_fingerprint()
        launch_fingerprint = launch.launch_fingerprint()
        base_evidence = {
            "target_sha256": target_sha,
            "exploit_sha256": exploit_sha,
            "environment_fingerprint": environment_fingerprint,
            "runtime": runtime,
            "runtime_fingerprint": runtime_fingerprint,
            "launch_argv": list(launch.argv),
            "launch_fingerprint": launch_fingerprint,
            "workspace_read_only": workspace_read_only,
        }
        if not trusted_boundary:
            evidence = [{
                **base_evidence,
                "sandbox_source": attestation.source,
                "filesystem_isolated": bool(getattr(attestation, "filesystem_isolated", False)),
            }]
            return CompletionResult(
                accepted=False,
                reason="local proof oracle requires a live filesystem-isolated backend with read-only workspace",
                evidence=evidence,
                oracle_id=self.oracle_id,
                independence_level="operator_fixed_digest_unsealed_workspace",
                evidence_hash=canonical_hash(evidence),
            )

        result = self.backend.run_argv(
            workspace=workspace,
            argv=[f"./{exploit_rel}", *launch.argv],
            timeout_seconds=self.timeout_seconds,
            env=None,
        )
        stdout_sha = hashlib.sha256(result.stdout.encode()).hexdigest()
        stderr_sha = hashlib.sha256(result.stderr.encode()).hexdigest()
        evidence = [{
            **base_evidence,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "stdout_sha256": stdout_sha,
            "stderr_sha256": stderr_sha,
            "sandbox_source": attestation.source,
        }]
        accepted = result.returncode == 0 and result.timed_out is False and stdout_sha == self.expected_stdout_sha256
        return CompletionResult(
            accepted=accepted,
            reason="operator-fixed local proof output matched" if accepted else "local proof output did not satisfy the operator-fixed contract",
            evidence=evidence,
            oracle_id=self.oracle_id,
            independence_level="sealed_integrity_and_filesystem_isolation",
            evidence_hash=canonical_hash(evidence),
            coverage={"target": 1, "exploit": 1, "runtime": 1, "launch": 1, "workspace_seal": 1, "stdout_contract": 1},
        )


def _runtime_identity_from_result(result: CompletionResult) -> tuple[str, str]:
    evidence = result.evidence
    if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], dict):
        raise ValueError("local proof oracle did not return runtime-bound evidence")
    first = evidence[0]
    runtime_fp = first.get("runtime_fingerprint")
    launch_fp = first.get("launch_fingerprint")
    if not isinstance(runtime_fp, str) or not _HEX64.fullmatch(runtime_fp):
        raise ValueError("local proof oracle runtime_fingerprint is invalid")
    if not isinstance(launch_fp, str) or not _HEX64.fullmatch(launch_fp):
        raise ValueError("local proof oracle launch_fingerprint is invalid")
    runtime = first.get("runtime")
    argv = first.get("launch_argv")
    if not isinstance(runtime, dict) or canonical_hash(runtime) != runtime_fp:
        raise ValueError("local proof oracle runtime identity is inconsistent")
    if not isinstance(argv, list) or not argv:
        raise ValueError("local proof oracle launch argv is unavailable")
    expected = canonical_hash({"target_sha256": first.get("target_sha256"), "runtime_fingerprint": runtime_fp, "argv": argv})
    if expected != launch_fp:
        raise ValueError("local proof oracle launch identity is inconsistent")
    return runtime_fp, launch_fp


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
    runtime_fp, launch_fp = _runtime_identity_from_result(result)
    return LocalProofReceipt(
        schema_version=2,
        kind="pwn_local_proof_receipt",
        proof_level="P3_LOCAL",
        target_sha256=_sha256_file(target),
        exploit_sha256=_sha256_file(exploit),
        environment_fingerprint=environment_fingerprint,
        runtime_fingerprint=runtime_fp,
        launch_fingerprint=launch_fp,
        oracle_id=result.oracle_id,
        independence_level=str(result.independence_level),
        oracle_evidence_hash=result.evidence_hash,
        accepted=bool(result.accepted),
        reason_hash=hashlib.sha256(str(result.reason).encode()).hexdigest(),
    )


def persist_local_proof_receipt(store: ArtifactStore, receipt: LocalProofReceipt, *, name: str = "pwn-local-proof.json") -> str:
    return store.put_json(name, {"ok": True, "output": receipt.dump(), "error": None})
