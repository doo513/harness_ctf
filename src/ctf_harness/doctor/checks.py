from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

from ctf_harness.configuration.models import HarnessConfiguration, MCPServerConfig, ModelProviderConfig, SiteProfileConfig


class DoctorStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: DoctorStatus
    detail: str
    category: str

    def descriptor(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status.value, "detail": self.detail, "category": self.category}


@dataclass(frozen=True)
class ToolRequirement:
    command: str
    required: bool = False
    purpose: str = "tool"


@dataclass(frozen=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def ready(self) -> bool:
        return not any(check.status is DoctorStatus.FAIL for check in self.checks)

    def descriptor(self) -> dict:
        counts = {status.value: 0 for status in DoctorStatus}
        for check in self.checks:
            counts[check.status.value] += 1
        return {
            "schema_version": "ctf-doctor-report-v2",
            "ready": self.ready,
            "counts": counts,
            "checks": [check.descriptor() for check in self.checks],
            "mutations_performed": False,
            "credential_values_persisted": False,
        }


_DEFAULT_TOOLS = (
    ToolRequirement("gdb", required=False, purpose="pwn debugging"),
    ToolRequirement("gcc", required=False, purpose="local build/probes"),
    ToolRequirement("strings", required=False, purpose="binary reconnaissance"),
    ToolRequirement("qemu-aarch64-static", required=False, purpose="cross-architecture execution"),
    ToolRequirement("docker", required=False, purpose="isolated challenge environments"),
)


class Doctor:
    """Read-only operational readiness diagnostics.

    Doctor never installs software, mutates configuration, resolves paid model
    calls, submits flags, invokes MCP tools, or writes Harness truth state.
    """

    def __init__(
        self,
        config: HarnessConfiguration,
        *,
        environ: Mapping[str, str] | None = None,
        tool_requirements: Sequence[ToolRequirement] = _DEFAULT_TOOLS,
        which=shutil.which,
    ):
        self.config = config
        self.environ = os.environ if environ is None else environ
        self.tool_requirements = tuple(tool_requirements)
        self.which = which

    def _model_checks(self, cfg: ModelProviderConfig) -> list[DoctorCheck]:
        checks = [DoctorCheck("model.active", DoctorStatus.PASS, f"{cfg.name}:{cfg.provider}:{cfg.model or '-'}", "model")]
        provider = cfg.provider.lower()
        if provider not in {"openai", "anthropic", "gemini", "external_process"}:
            checks.append(DoctorCheck("model.provider", DoctorStatus.FAIL, f"unsupported provider: {cfg.provider}", "model"))
            return checks
        checks.append(DoctorCheck("model.provider", DoctorStatus.PASS, provider, "model"))
        if provider == "external_process":
            if not cfg.command:
                checks.append(DoctorCheck("model.command", DoctorStatus.FAIL, "external_process command is missing", "model"))
            else:
                found = self.which(cfg.command[0])
                checks.append(DoctorCheck("model.command", DoctorStatus.PASS if found else DoctorStatus.FAIL, found or f"command not found: {cfg.command[0]}", "model"))
        else:
            if not cfg.api_key_env:
                checks.append(DoctorCheck("model.credential", DoctorStatus.FAIL, "api_key_env is not configured", "model"))
            elif self.environ.get(cfg.api_key_env):
                checks.append(DoctorCheck("model.credential", DoctorStatus.PASS, f"{cfg.api_key_env} is set", "model"))
            else:
                checks.append(DoctorCheck("model.credential", DoctorStatus.FAIL, f"{cfg.api_key_env} is not set", "model"))
        return checks

    def _site_checks(self, cfg: SiteProfileConfig | None) -> list[DoctorCheck]:
        if cfg is None:
            return [DoctorCheck("site.active", DoctorStatus.SKIP, "no site profile selected", "site")]
        checks = [DoctorCheck("site.active", DoctorStatus.PASS, f"{cfg.name}:{cfg.provider}:{cfg.base_url}", "site")]
        if cfg.provider.lower() != "ctfd":
            checks.append(DoctorCheck("site.provider", DoctorStatus.FAIL, f"unsupported site provider: {cfg.provider}", "site"))
            return checks
        checks.append(DoctorCheck("site.provider", DoctorStatus.PASS, "ctfd", "site"))
        if not cfg.credential_locator:
            checks.append(DoctorCheck("site.credential", DoctorStatus.FAIL, "credential_locator is not configured", "site"))
        elif cfg.credential_kind == "env":
            if self.environ.get(cfg.credential_locator):
                checks.append(DoctorCheck("site.credential", DoctorStatus.PASS, f"{cfg.credential_locator} is set", "site"))
            else:
                checks.append(DoctorCheck("site.credential", DoctorStatus.FAIL, f"{cfg.credential_locator} is not set", "site"))
        else:
            checks.append(DoctorCheck("site.credential", DoctorStatus.WARN, f"{cfg.credential_kind}:{cfg.credential_locator} requires runtime resolver validation", "site"))
        return checks

    def _mcp_check(self, cfg: MCPServerConfig) -> list[DoctorCheck]:
        prefix = f"mcp.{cfg.name}"
        checks: list[DoctorCheck] = []
        if cfg.protocol_version == "2026-07-28":
            checks.append(DoctorCheck(f"{prefix}.protocol", DoctorStatus.PASS, "pinned to current MCP 2026-07-28", "mcp"))
        elif cfg.protocol_version == "auto":
            checks.append(DoctorCheck(f"{prefix}.protocol", DoctorStatus.PASS, "official SDK automatic negotiation", "mcp"))
        elif cfg.protocol_version == "legacy":
            checks.append(DoctorCheck(f"{prefix}.protocol", DoctorStatus.WARN, "legacy MCP mode requested", "mcp"))
        else:
            checks.append(DoctorCheck(f"{prefix}.protocol", DoctorStatus.WARN, f"explicit SDK protocol mode {cfg.protocol_version}; validated on connection", "mcp"))

        if cfg.transport == "stdio":
            found = self.which(cfg.command[0]) if cfg.command else None
            checks.append(DoctorCheck(f"{prefix}.transport", DoctorStatus.PASS if found else DoctorStatus.FAIL, found or f"stdio command not found: {cfg.command[0] if cfg.command else '-'}", "mcp"))
            missing_env = [name for name in cfg.pass_env_names if not self.environ.get(name)]
            if missing_env:
                checks.append(DoctorCheck(f"{prefix}.env", DoctorStatus.WARN, f"forwarded environment variable(s) not set: {', '.join(missing_env)}", "mcp"))
        else:
            checks.append(DoctorCheck(f"{prefix}.transport", DoctorStatus.PASS, cfg.endpoint or "", "mcp"))
            if cfg.auth_env and not self.environ.get(cfg.auth_env):
                checks.append(DoctorCheck(f"{prefix}.credential", DoctorStatus.FAIL, f"{cfg.auth_env} is not set", "mcp"))
            elif cfg.auth_env:
                checks.append(DoctorCheck(f"{prefix}.credential", DoctorStatus.PASS, f"{cfg.auth_env} is set", "mcp"))

        if cfg.allowed_tools:
            checks.append(DoctorCheck(f"{prefix}.allowlist", DoctorStatus.PASS, f"{len(cfg.allowed_tools)} explicit tool rule(s)", "mcp"))
        else:
            checks.append(DoctorCheck(f"{prefix}.allowlist", DoctorStatus.WARN, "no MCP tools are allowlisted; calls will be denied", "mcp"))
        return checks

    def _tool_checks(self) -> list[DoctorCheck]:
        checks = [DoctorCheck("runtime.python", DoctorStatus.PASS, sys.executable, "runtime")]
        for requirement in self.tool_requirements:
            found = self.which(requirement.command)
            if found:
                status, detail = DoctorStatus.PASS, found
            elif requirement.required:
                status, detail = DoctorStatus.FAIL, f"missing required command: {requirement.command} ({requirement.purpose})"
            else:
                status, detail = DoctorStatus.WARN, f"optional command unavailable: {requirement.command} ({requirement.purpose})"
            checks.append(DoctorCheck(f"tool.{requirement.command}", status, detail, "tool"))
        return checks

    def run(self) -> DoctorReport:
        checks: list[DoctorCheck] = []
        checks.extend(self._model_checks(self.config.model()))
        checks.extend(self._site_checks(self.config.site() if self.config.active_site else None))
        for cfg in self.config.mcp_servers.values():
            checks.extend(self._mcp_check(cfg))
        checks.extend(self._tool_checks())
        return DoctorReport(tuple(checks))
