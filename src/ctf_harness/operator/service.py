from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.configuration import HarnessConfiguration, build_default_model_gateway, load_configuration
from ctf_harness.doctor import Doctor
from ctf_harness.mcp import build_mcp_registry
from ctf_harness.operational.workspace import RunWorkspaceProjection
from ctf_harness.site_access import SiteAccessError, build_default_site_gateway


class OperatorError(RuntimeError):
    pass


class OperatorService:
    """Stable application-service boundary for CLI/TUI/front-end operators.

    It composes existing gateways and exposes operator actions without becoming
    truth, verification, solve, or completion authority. UI code should depend
    on this service instead of importing provider-specific adapters directly.
    """

    def __init__(
        self,
        config: HarnessConfiguration,
        *,
        environ: Mapping[str, str] | None = None,
        model_gateway=None,
        site_gateway=None,
        mcp_registry=None,
        doctor=None,
    ):
        self.config = config
        self.environ = dict(os.environ if environ is None else environ)
        self.model_gateway = model_gateway or build_default_model_gateway(config, environ=self.environ)
        self.site_gateway = site_gateway or build_default_site_gateway(config, environ=self.environ)
        self.mcp_registry = mcp_registry or build_mcp_registry(config, environ=self.environ)
        self.doctor = doctor or Doctor(config, environ=self.environ)

    @classmethod
    def from_path(
        cls,
        path: str | os.PathLike[str],
        *,
        environ: Mapping[str, str] | None = None,
    ) -> "OperatorService":
        env = dict(os.environ if environ is None else environ)
        return cls(load_configuration(path, environ=env), environ=env)

    def controller(self, model_name: str | None = None) -> CTFLLMController:
        """Bind one configured model to the existing verified CTF controller."""
        return CTFLLMController(self.model_gateway.build(model_name))

    def status(self) -> dict:
        report = self.doctor.run()
        return {
            "schema_version": "ctf-operator-status-v1",
            "configuration": self.config.descriptor(),
            "model_gateway": self.model_gateway.descriptor(),
            "site_gateway": self.site_gateway.descriptor(),
            "mcp_registry": self.mcp_registry.descriptor(),
            "doctor": report.descriptor(),
            "truth_authority": "none",
            "completion_authority": "none",
        }

    def challenges(self) -> list[dict]:
        try:
            session = self.site_gateway.build()
            return [challenge.descriptor() for challenge in session.list_challenges()]
        except Exception as exc:
            raise OperatorError(f"cannot list configured site challenges: {exc}") from exc

    def challenge(self, challenge_id: str) -> dict:
        try:
            session = self.site_gateway.build()
            return session.get_challenge(challenge_id).descriptor()
        except Exception as exc:
            raise OperatorError(f"cannot read challenge {challenge_id!r}: {exc}") from exc

    @staticmethod
    def _safe_artifact_name(name: str) -> str:
        if not isinstance(name, str) or not name or name in {".", ".."}:
            raise OperatorError("downloaded artifact name is unsafe")
        path = Path(name)
        if path.is_absolute() or len(path.parts) != 1 or path.name != name:
            raise OperatorError("downloaded artifact name must be one simple filename")
        return name

    def download_challenge(self, challenge_id: str, workspace: str | os.PathLike[str]) -> dict:
        """Download platform artifacts into a prepared projection input directory.

        The operation validates every download before writing and rolls back any
        newly created artifact if a later write fails. Existing files are never
        overwritten. Downloads remain observations and are not admitted as truth.
        """
        try:
            session = self.site_gateway.build()
            snapshot = session.get_challenge(challenge_id)
        except Exception as exc:
            raise OperatorError(f"cannot read challenge {challenge_id!r}: {exc}") from exc

        projection = RunWorkspaceProjection.prepare(workspace)
        pending: list[tuple[object, str, Path]] = []
        seen_names: set[str] = set()
        for file_url in snapshot.file_urls:
            try:
                artifact = session.download(file_url)
            except Exception as exc:
                raise OperatorError(f"cannot download challenge artifact: {exc}") from exc
            name = self._safe_artifact_name(artifact.ref)
            if name in seen_names:
                raise OperatorError(f"duplicate downloaded artifact name: {name}")
            seen_names.add(name)
            target = projection.input_dir / name
            if target.exists() or target.is_symlink():
                raise OperatorError(f"refusing to overwrite existing artifact: {name}")
            pending.append((artifact, name, target))

        created: list[Path] = []
        try:
            for artifact, _, target in pending:
                with target.open("xb") as handle:
                    handle.write(artifact.content)
                created.append(target)
        except Exception as exc:
            for target in reversed(created):
                try:
                    target.unlink()
                except OSError:
                    pass
            if isinstance(exc, FileExistsError):
                raise OperatorError("artifact appeared concurrently; refusing partial overwrite") from exc
            raise OperatorError(f"cannot persist challenge artifacts: {exc}") from exc

        written = [
            {**artifact.descriptor(), "path": f"input/{name}"}
            for artifact, name, _ in pending
        ]
        return {
            "schema_version": "ctf-operator-download-v2",
            "challenge": snapshot.descriptor(),
            "workspace": projection.descriptor(),
            "artifacts": written,
            "artifact_admission_performed": False,
            "truth_authority": "none",
        }

    def mcp_servers(self) -> dict:
        return self.mcp_registry.descriptor()

    def mcp_tools(self, server: str) -> list[dict]:
        try:
            return [tool.descriptor() for tool in self.mcp_registry.list_tools(server)]
        except Exception as exc:
            raise OperatorError(f"cannot list MCP tools for {server!r}: {exc}") from exc

    def mcp_call(self, server: str, tool: str, arguments: Mapping[str, object]) -> dict:
        """Explicit human/operator invocation; agent calls still use confirm ToolSpec."""
        try:
            return self.mcp_registry.call_tool(server, tool, arguments)
        except Exception as exc:
            raise OperatorError(f"MCP call failed for {server}:{tool}: {exc}") from exc

    def submit_flag(self, challenge_id: str, candidate: str) -> bool:
        try:
            return bool(self.site_gateway.build().submit_flag(challenge_id, candidate))
        except SiteAccessError as exc:
            raise OperatorError(str(exc)) from exc
        except Exception as exc:
            raise OperatorError(f"flag submission failed: {exc}") from exc
