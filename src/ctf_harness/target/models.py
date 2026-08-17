from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harness.core.storage import canonical_hash

from ctf_harness.operational.models import RuntimeKind


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_sha256(value: object, *, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex")
    return value


@dataclass(frozen=True)
class RuntimeArtifactIdentity:
    """Hash-bound executable/runtime artifact used to launch a target."""

    role: str
    path: str
    sha256: str

    def __post_init__(self) -> None:
        _require_text(self.role, field_name="runtime artifact role")
        _require_text(self.path, field_name="runtime artifact path")
        _require_sha256(self.sha256, field_name="runtime artifact sha256")

    def descriptor(self) -> dict[str, str]:
        return {"role": self.role, "path": self.path, "sha256": self.sha256}


@dataclass(frozen=True)
class RuntimeLaunch:
    """Trusted argv plus runtime-only provenance for one target execution.

    `target_sha256` is deliberately outside `runtime_descriptor()`: target
    identity and runtime identity remain separate. The launch fingerprint binds
    both only when recording one concrete execution.
    """

    profile_id: str
    runtime_kind: RuntimeKind
    argv: tuple[str, ...]
    target_sha256: str
    runtime_artifacts: tuple[RuntimeArtifactIdentity, ...] = ()
    runtime_args: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.profile_id, field_name="profile_id")
        if not isinstance(self.runtime_kind, RuntimeKind):
            raise ValueError("runtime_kind must be RuntimeKind")
        if not isinstance(self.argv, tuple) or not self.argv or any(
            not isinstance(item, str) or not item or "\x00" in item for item in self.argv
        ):
            raise ValueError("argv must be a non-empty tuple of NUL-free strings")
        _require_sha256(self.target_sha256, field_name="target_sha256")
        if not isinstance(self.runtime_artifacts, tuple) or any(
            not isinstance(item, RuntimeArtifactIdentity) for item in self.runtime_artifacts
        ):
            raise ValueError("runtime_artifacts must be an immutable tuple")
        roles = [item.role for item in self.runtime_artifacts]
        if len(set(roles)) != len(roles):
            raise ValueError("runtime artifact roles must be unique")
        if not isinstance(self.runtime_args, tuple) or any(
            not isinstance(item, str) or "\x00" in item for item in self.runtime_args
        ):
            raise ValueError("runtime_args must be an immutable tuple of NUL-free strings")

    def runtime_descriptor(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "runtime_kind": self.runtime_kind.value,
            "runtime_artifacts": [
                item.descriptor()
                for item in sorted(self.runtime_artifacts, key=lambda artifact: artifact.role)
            ],
            "runtime_args": list(self.runtime_args),
        }

    def runtime_fingerprint(self) -> str:
        return canonical_hash(self.runtime_descriptor())

    def launch_descriptor(self) -> dict[str, Any]:
        return {
            "target_sha256": self.target_sha256,
            "runtime_fingerprint": self.runtime_fingerprint(),
            "argv": list(self.argv),
        }

    def launch_fingerprint(self) -> str:
        return canonical_hash(self.launch_descriptor())
