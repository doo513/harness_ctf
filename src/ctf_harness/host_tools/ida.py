from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol

from ctf_harness.tools.capabilities import CapabilityResult


_IDA_CAPABILITIES = (
    "decompile_function",
    "find_xrefs",
    "list_functions",
    "list_strings",
    "find_callers",
    "find_callees",
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class CapabilityTransport(Protocol):
    def request(self, payload: dict[str, Any]) -> dict[str, Any]: ...
    def available(self) -> bool: ...
    def descriptor(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class JsonProcessCapabilityTransport:
    argv: tuple[str, ...]
    revision: str
    timeout_seconds: float = 60.0
    max_output_bytes: int = 2 * 1024 * 1024
    env: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not self.argv or any(
            not isinstance(item, str) or not item or "\x00" in item for item in self.argv
        ):
            raise ValueError("capability process argv must be a non-empty tuple")
        if not isinstance(self.revision, str) or not self.revision.strip():
            raise ValueError("capability process revision must be non-empty")
        if self.timeout_seconds <= 0:
            raise ValueError("capability process timeout must be positive")
        if not isinstance(self.max_output_bytes, int) or self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")

    def available(self) -> bool:
        executable = Path(self.argv[0])
        if executable.is_absolute():
            return executable.is_file()
        import shutil
        return shutil.which(self.argv[0]) is not None

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.available():
            raise RuntimeError("capability process executable is unavailable")
        request = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            completed = subprocess.run(
                list(self.argv),
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=float(self.timeout_seconds),
                shell=False,
                check=False,
                env=None if self.env is None else dict(self.env),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("capability process timed out") from exc
        if completed.returncode != 0:
            raise RuntimeError(f"capability process exited {completed.returncode}")
        if len(completed.stdout) > self.max_output_bytes:
            raise RuntimeError("capability process output exceeds configured byte limit")
        try:
            result = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("capability process returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise RuntimeError("capability process response must be an object")
        return result

    def descriptor(self) -> dict[str, Any]:
        return {
            "transport": "json_process",
            "argv0": self.argv[0],
            "revision": self.revision,
            "timeout_seconds": float(self.timeout_seconds),
            "max_output_bytes": self.max_output_bytes,
            "environment_names": sorted((self.env or {}).keys()),
        }


class IdaCapabilityProvider:
    """Scoped, provenance-aware IDA provider.

    The provider may inspect only an admitted/provenance-known file under the
    configured workspace and revalidates its expected SHA-256 before each host
    tool invocation. IDA output remains an untrusted Observation.
    """

    provider_id = "ida"
    revision = "ida-capability-provider-v1"
    capabilities = _IDA_CAPABILITIES
    priority = 100

    def __init__(
        self,
        *,
        workspace: str | Path,
        expected_sha256: Mapping[str, str],
        transport: CapabilityTransport,
    ):
        self.workspace = Path(workspace).resolve()
        if not self.workspace.is_dir():
            raise ValueError("IDA provider workspace must exist")
        self.expected_sha256 = dict(expected_sha256)
        if not self.expected_sha256:
            raise ValueError("IDA provider requires admitted/provenance-known artifact hashes")
        for ref, digest in self.expected_sha256.items():
            if not isinstance(ref, str) or not ref or Path(ref).is_absolute() or ".." in Path(ref).parts:
                raise ValueError("IDA artifact refs must be normalized workspace-relative paths")
            if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                raise ValueError("IDA expected SHA-256 must be lowercase hex")
        if not callable(getattr(transport, "request", None)) or not callable(getattr(transport, "available", None)):
            raise ValueError("IDA transport must expose request()/available()")
        self.transport = transport

    def available(self) -> bool:
        return bool(self.transport.available())

    def _artifact(self, ref: str) -> tuple[Path, str]:
        if ref not in self.expected_sha256:
            raise ValueError("IDA artifact is not admitted/provenance-known")
        raw = Path(ref)
        if raw.is_absolute() or ".." in raw.parts:
            raise ValueError("IDA artifact ref must be normalized relative path")
        resolved = (self.workspace / raw).resolve(strict=True)
        try:
            relative = resolved.relative_to(self.workspace).as_posix()
        except ValueError as exc:
            raise ValueError("IDA artifact escapes workspace") from exc
        if resolved.is_symlink() or not resolved.is_file():
            raise ValueError("IDA artifact must be a regular non-symlink file")
        actual = _sha256(resolved)
        if actual != self.expected_sha256[ref]:
            raise ValueError("IDA artifact identity changed since admission")
        return resolved, relative

    def invoke(self, capability: str, args: dict[str, Any]) -> CapabilityResult:
        if capability not in self.capabilities:
            raise ValueError(f"unsupported IDA capability: {capability}")
        if not isinstance(args, dict):
            raise ValueError("IDA capability args must be an object")
        artifact_ref = args.get("artifact_ref")
        if not isinstance(artifact_ref, str) or not artifact_ref:
            raise ValueError("IDA capability requires artifact_ref")
        artifact, relative = self._artifact(artifact_ref)
        provider_args = {key: value for key, value in args.items() if key != "artifact_ref"}
        request = {
            "schema_version": "ctf-ida-capability-request-v1",
            "capability": capability,
            "artifact_path": str(artifact),
            "artifact_ref": relative,
            "artifact_sha256": self.expected_sha256[artifact_ref],
            "args": provider_args,
        }
        response = self.transport.request(request)
        return CapabilityResult(
            capability=capability,
            provider_id=self.provider_id,
            provider_revision=self.revision,
            payload={
                "artifact_ref": relative,
                "artifact_sha256": self.expected_sha256[artifact_ref],
                "provider_output": response,
                "provider_transport": self.transport.descriptor(),
                "output_authority": "observation_only",
            },
        )

    def descriptor(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "revision": self.revision,
            "capabilities": list(self.capabilities),
            "priority": self.priority,
            "transport": self.transport.descriptor(),
            "artifact_scope": sorted(self.expected_sha256),
            "result_authority": "observation_only",
        }
