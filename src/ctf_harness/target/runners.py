from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Protocol

from ctf_harness.operational.models import RuntimeKind

from .models import RuntimeArtifactIdentity, RuntimeLaunch


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_workspace_file(workspace: Path, value: str, *, field_name: str) -> tuple[Path, str]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty workspace-relative path")
    raw = Path(value)
    if raw.is_absolute():
        raise ValueError(f"{field_name} must be workspace-relative")
    workspace = Path(workspace).resolve()
    unresolved = (workspace / raw).resolve(strict=False)
    try:
        unresolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{field_name} escapes workspace") from exc
    resolved = (workspace / raw).resolve(strict=True)
    try:
        relative = resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{field_name} escapes workspace") from exc
    if not resolved.is_file():
        raise ValueError(f"{field_name} must be a regular file")
    return resolved, relative.as_posix()


def _require_sha256(value: str, *, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex")
    return value


def _checked_target(
    workspace: Path,
    target_relpath: str,
    *,
    expected_sha256: str | None,
) -> tuple[Path, str, str]:
    target, relative = _safe_workspace_file(workspace, target_relpath, field_name="target")
    actual = _sha256_file(target)
    if expected_sha256 is not None:
        _require_sha256(expected_sha256, field_name="expected target SHA-256")
        if actual != expected_sha256:
            raise ValueError("target SHA-256 differs from admitted/expected target identity")
    return target, relative, actual


class TargetRunner(Protocol):
    profile_id: str
    runtime_kind: RuntimeKind

    def build_launch(
        self,
        *,
        workspace: Path,
        target_relpath: str,
        expected_target_sha256: str | None = None,
    ) -> RuntimeLaunch: ...


@dataclass(frozen=True)
class NativeRunner:
    profile_id: str = "native-default"
    runtime_kind: RuntimeKind = RuntimeKind.NATIVE

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or not self.profile_id.strip():
            raise ValueError("profile_id must be a non-empty string")
        if self.runtime_kind is not RuntimeKind.NATIVE:
            raise ValueError("NativeRunner runtime_kind is fixed to native")

    def build_launch(
        self,
        *,
        workspace: Path,
        target_relpath: str,
        expected_target_sha256: str | None = None,
    ) -> RuntimeLaunch:
        _, relative, target_sha256 = _checked_target(
            Path(workspace), target_relpath, expected_sha256=expected_target_sha256
        )
        return RuntimeLaunch(
            profile_id=self.profile_id,
            runtime_kind=self.runtime_kind,
            argv=(f"./{relative}",),
            target_sha256=target_sha256,
            runtime_artifacts=(),
            runtime_args=(),
        )


@dataclass(frozen=True)
class QemuUserRunner:
    profile_id: str
    qemu_path: str
    qemu_sha256: str
    qemu_args: tuple[str, ...] = ()
    loader_relpath: str | None = None
    loader_sha256: str | None = None
    loader_args: tuple[str, ...] = ()
    runtime_kind: RuntimeKind = RuntimeKind.QEMU_USER

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or not self.profile_id.strip():
            raise ValueError("profile_id must be a non-empty string")
        if self.runtime_kind is not RuntimeKind.QEMU_USER:
            raise ValueError("QemuUserRunner runtime_kind is fixed to qemu_user")
        path = Path(self.qemu_path)
        if not path.is_absolute():
            raise ValueError("qemu_path must be absolute")
        _require_sha256(self.qemu_sha256, field_name="qemu_sha256")
        for field_name, values in (("qemu_args", self.qemu_args), ("loader_args", self.loader_args)):
            if not isinstance(values, tuple) or any(
                not isinstance(item, str) or not item or "\x00" in item for item in values
            ):
                raise ValueError(f"{field_name} must be an immutable tuple of non-empty NUL-free strings")
        if self.loader_relpath is None:
            if self.loader_sha256 is not None or self.loader_args:
                raise ValueError("loader hash/args require loader_relpath")
        else:
            if not isinstance(self.loader_relpath, str) or not self.loader_relpath.strip():
                raise ValueError("loader_relpath must be a non-empty workspace-relative path")
            if self.loader_sha256 is None:
                raise ValueError("loader_relpath requires loader_sha256")
            _require_sha256(self.loader_sha256, field_name="loader_sha256")

    def _qemu_identity(self) -> RuntimeArtifactIdentity:
        qemu = Path(self.qemu_path).resolve(strict=True)
        if not qemu.is_file():
            raise ValueError("qemu_path must be a regular file")
        actual = _sha256_file(qemu)
        if actual != self.qemu_sha256:
            raise ValueError("QEMU executable SHA-256 differs from pinned runtime identity")
        return RuntimeArtifactIdentity("qemu", str(qemu), actual)

    def build_launch(
        self,
        *,
        workspace: Path,
        target_relpath: str,
        expected_target_sha256: str | None = None,
    ) -> RuntimeLaunch:
        workspace = Path(workspace).resolve()
        _, target_relative, target_sha256 = _checked_target(
            workspace, target_relpath, expected_sha256=expected_target_sha256
        )
        qemu_identity = self._qemu_identity()
        runtime_artifacts: list[RuntimeArtifactIdentity] = [qemu_identity]
        argv: list[str] = [qemu_identity.path, *self.qemu_args]
        runtime_args: list[str] = [*self.qemu_args]

        if self.loader_relpath is not None:
            loader, loader_relative = _safe_workspace_file(
                workspace, self.loader_relpath, field_name="loader"
            )
            actual_loader_sha = _sha256_file(loader)
            if actual_loader_sha != self.loader_sha256:
                raise ValueError("loader SHA-256 differs from pinned runtime identity")
            runtime_artifacts.append(
                RuntimeArtifactIdentity("loader", loader_relative, actual_loader_sha)
            )
            argv.extend([f"./{loader_relative}", *self.loader_args, f"./{target_relative}"])
            runtime_args.extend(["<loader>", *self.loader_args])
        else:
            argv.append(f"./{target_relative}")

        return RuntimeLaunch(
            profile_id=self.profile_id,
            runtime_kind=self.runtime_kind,
            argv=tuple(argv),
            target_sha256=target_sha256,
            runtime_artifacts=tuple(runtime_artifacts),
            runtime_args=tuple(runtime_args),
        )
