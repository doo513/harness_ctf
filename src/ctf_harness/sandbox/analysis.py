from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from harness.core.sandbox import LinuxNamespaceSandboxBackend, NetworkPolicy
from harness.core.tools import SandboxedArgvToolSpec, SideEffect


def _safe_relative_path(value: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("analysis input reference must be non-empty")
    raw = Path(value)
    if raw.is_absolute() or any(part in {"", ".", ".."} for part in raw.parts):
        raise ValueError("analysis input reference must be a normalized relative path")
    return raw


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class AnalysisSandboxLayout:
    root: Path
    input_dir: Path
    work_dir: Path
    generated_dir: Path
    artifacts_dir: Path

    @classmethod
    def prepare(
        cls,
        root: str | Path,
        *,
        admitted_inputs: Mapping[str, str | Path],
        expected_sha256: Mapping[str, str] | None = None,
    ) -> "AnalysisSandboxLayout":
        base = Path(root).resolve()
        if base.exists() and (not base.is_dir() or any(base.iterdir())):
            raise ValueError("analysis sandbox root must be absent or an empty directory")
        base.mkdir(parents=True, exist_ok=True)
        input_dir = base / "input"
        work_dir = base / "work"
        generated_dir = work_dir / "generated"
        artifacts_dir = work_dir / "artifacts"
        input_dir.mkdir()
        work_dir.mkdir()
        generated_dir.mkdir()
        artifacts_dir.mkdir()

        expected = dict(expected_sha256 or {})
        for ref, source_value in admitted_inputs.items():
            relative = _safe_relative_path(ref)
            source = Path(source_value).resolve(strict=True)
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"analysis input must be a regular non-symlink file: {ref}")
            destination = input_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists():
                raise ValueError(f"duplicate analysis input path: {ref}")
            shutil.copyfile(source, destination)
            digest = _sha256(destination)
            required = expected.get(ref)
            if required is not None and digest != required:
                raise ValueError(f"analysis input SHA-256 mismatch: {ref}")
            destination.chmod(0o444)

        # Stable actor-facing path. The absolute target is mounted read-only by
        # the Linux namespace backend, while the symlink itself lives in RW work.
        os.symlink(str(input_dir), str(work_dir / "input"))
        return cls(base, input_dir, work_dir, generated_dir, artifacts_dir)

    def descriptor(self) -> dict:
        inputs = []
        for path in sorted(self.input_dir.rglob("*")):
            if path.is_file() and not path.is_symlink():
                inputs.append({
                    "ref": path.relative_to(self.input_dir).as_posix(),
                    "sha256": _sha256(path),
                })
        return {
            "schema_version": "ctf-analysis-layout-v1",
            "input_mount": "input/",
            "input_mode": "read_only",
            "work_mode": "read_write",
            "generated_dir": "generated/",
            "artifacts_dir": "artifacts/",
            "inputs": inputs,
            "authority": "execution_layout_only",
            "truth_authority": "none",
        }


class AnalysisSandbox:
    """Harness-owned analysis execution environment, separate from TargetRunner."""

    def __init__(self, layout: AnalysisSandboxLayout, *, backend=None):
        if not isinstance(layout, AnalysisSandboxLayout):
            raise ValueError("layout must be AnalysisSandboxLayout")
        self.layout = layout
        self.backend = backend or LinuxNamespaceSandboxBackend(
            network_policy=NetworkPolicy.DENY,
            inherit_env=False,
            workspace_writable=True,
            read_only_paths=(layout.input_dir,),
        )

    def tool(self, *, timeout_seconds: float = 60.0) -> SandboxedArgvToolSpec:
        return SandboxedArgvToolSpec(
            name="analysis_exec",
            description=(
                "Run one structured argv analysis command in an isolated RW work area. "
                "Admitted originals are available through input/ and are read-only; write "
                "generated files under generated/ or artifacts/. Network is denied by the "
                "production analysis backend. This tool does not execute challenge transport."
            ),
            execution_backend=self.backend,
            execution_workspace=self.layout.work_dir,
            timeout_seconds=timeout_seconds,
            argv_arg="argv",
            side_effect=SideEffect.WRITE,
            idempotent=False,
            failure_modes=[
                "invalid_argv",
                "sandbox_violation",
                "input_write_denied",
                "network_denied",
                "execution_timeout",
            ],
            provenance={
                "kind": "ctf_analysis_sandbox",
                "schema": "ctf-analysis-layout-v1",
                "input_mode": "ro",
                "work_mode": "rw",
                "network_mode": "deny",
                "target_execution_authority": "none",
            },
            require_zero_exit=True,
        )
