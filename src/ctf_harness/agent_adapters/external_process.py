from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Mapping, Sequence


class ModelProcessError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExternalProcessModelAdapter:
    """Production-capable ModelAdapter transport over one bounded subprocess.

    The subprocess owns provider SDK/API credentials and receives only the
    Harness-projected system/user prompt. It must return exactly one Decision
    JSON object on stdout. No shell is involved and environment inheritance is
    opt-in so provider secrets do not accidentally enter unrelated child tools.
    """

    argv: tuple[str, ...]
    revision: str
    timeout_seconds: float = 120.0
    max_output_bytes: int = 1_048_576
    env: Mapping[str, str] | None = None
    inherit_env: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.argv, tuple) or not self.argv or any(
            not isinstance(item, str) or not item or "\x00" in item for item in self.argv
        ):
            raise ValueError("external model argv must be a non-empty immutable tuple")
        if not isinstance(self.revision, str) or not self.revision.strip():
            raise ValueError("external model revision must be non-empty")
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise ValueError("external model timeout must be positive")
        if not isinstance(self.max_output_bytes, int) or isinstance(self.max_output_bytes, bool) or self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be a positive integer")
        if self.env is not None and (
            not isinstance(self.env, Mapping)
            or any(not isinstance(k, str) or not isinstance(v, str) for k, v in self.env.items())
        ):
            raise ValueError("external model env must map strings to strings")

    @classmethod
    def from_environment(
        cls,
        *,
        command_var: str = "CTF_MODEL_ADAPTER_CMD",
        revision_var: str = "CTF_MODEL_ADAPTER_REVISION",
        pass_env_names: Sequence[str] = (),
        timeout_seconds: float = 120.0,
        max_output_bytes: int = 1_048_576,
    ) -> "ExternalProcessModelAdapter":
        raw = os.environ.get(command_var, "").strip()
        revision = os.environ.get(revision_var, "").strip()
        if not raw:
            raise ModelProcessError(f"{command_var} is not configured")
        if not revision:
            raise ModelProcessError(f"{revision_var} is not configured")
        argv = tuple(shlex.split(raw))
        if not argv:
            raise ModelProcessError(f"{command_var} resolved to an empty argv")
        forwarded: dict[str, str] = {}
        for name in pass_env_names:
            if not isinstance(name, str) or not name:
                raise ValueError("pass_env_names must contain non-empty strings")
            if name in os.environ:
                forwarded[name] = os.environ[name]
        return cls(
            argv=argv,
            revision=revision,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            env=forwarded,
            inherit_env=False,
        )

    def _child_env(self) -> dict[str, str]:
        child = dict(os.environ) if self.inherit_env else {}
        if self.env:
            child.update({str(k): str(v) for k, v in self.env.items()})
        # A minimal deterministic PATH is useful for wrapper scripts while not
        # copying the rest of the parent environment or provider credentials.
        child.setdefault("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
        child.setdefault("LANG", os.environ.get("LANG", "C.UTF-8"))
        return child

    def complete(self, *, system: str, user: str) -> str:
        if not isinstance(system, str) or not isinstance(user, str):
            raise ValueError("ModelAdapter system/user prompts must be strings")
        request = json.dumps(
            {
                "schema_version": "ctf-model-process-request-v1",
                "system": system,
                "user": user,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            completed = subprocess.run(
                list(self.argv),
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=float(self.timeout_seconds),
                check=False,
                shell=False,
                env=self._child_env(),
            )
        except subprocess.TimeoutExpired as exc:
            raise ModelProcessError("external model process timed out") from exc
        except OSError as exc:
            raise ModelProcessError(f"cannot execute external model process: {exc}") from exc

        if completed.returncode != 0:
            stderr = completed.stderr[:2048].decode("utf-8", errors="replace")
            raise ModelProcessError(
                f"external model process exited {completed.returncode}: {stderr}"
            )
        if len(completed.stdout) > self.max_output_bytes:
            raise ModelProcessError("external model output exceeds configured byte limit")
        try:
            text = completed.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ModelProcessError("external model output is not UTF-8") from exc
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ModelProcessError("external model output is not one JSON object") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str) or not isinstance(raw.get("payload"), dict):
            raise ModelProcessError("external model output must have Decision kind/payload")
        return json.dumps(raw, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-external-process-model-adapter-v1",
            "transport": "json_over_stdin_stdout",
            "argv0": self.argv[0],
            "revision": self.revision,
            "timeout_seconds": float(self.timeout_seconds),
            "max_output_bytes": self.max_output_bytes,
            "inherit_env": self.inherit_env,
            "forwarded_env_names": sorted((self.env or {}).keys()),
            "credential_values_persisted": False,
        }
