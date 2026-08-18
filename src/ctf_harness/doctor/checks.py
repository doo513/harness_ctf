from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Sequence

from ctf_harness.configuration.models import HarnessConfiguration, ModelProviderConfig, SiteProfileConfig


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
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "category": self.category,
        }


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
            "schema_version": "ctf-doctor-report-v1",
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
    calls, submits flags, or writes Harness truth state.
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
        checks = [
            DoctorCheck(
                name="model.active",
                status=DoctorStatus.PASS,
                detail=f"{cfg.name}:{cfg.provider}:{cfg.model or '-'}",
                category="model",
            )
        ]
        provider = cfg.provider.lower()
        if provider == "external_process":
            if not cfg.command:
                checks.append(DoctorCheck("model.command", DoctorStatus.FAIL, "external_process command is missing", "model"))
            else:
                found = self.which(cfg.command[0])
                checks.append(
                    DoctorCheck(
                        "model.command",
                        DoctorStatus.PASS if found else DoctorStatus.FAIL,
                        found or f"command not found: {cfg.command[0]}",
                        "model",
                    )
                )
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
        if not cfg.credential_locator:
            checks.append(DoctorCheck("site.credential", DoctorStatus.FAIL, "credential_locator is not configured", "site"))
        elif cfg.credential_kind == "env":
            if self.environ.get(cfg.credential_locator):
                checks.append(DoctorCheck("site.credential", DoctorStatus.PASS, f"{cfg.credential_locator} is set", "site"))
            else:
                checks.append(DoctorCheck("site.credential", DoctorStatus.FAIL, f"{cfg.credential_locator} is not set", "site"))
        else:
            checks.append(
                DoctorCheck(
                    "site.credential",
                    DoctorStatus.WARN,
                    f"{cfg.credential_kind}:{cfg.credential_locator} requires runtime resolver validation",
                    "site",
                )
            )
        return checks

    def _tool_checks(self) -> list[DoctorCheck]:
        checks = [DoctorCheck("runtime.python", DoctorStatus.PASS, sys.executable, "runtime")]
        for requirement in self.tool_requirements:
            found = self.which(requirement.command)
            if found:
                status = DoctorStatus.PASS
                detail = found
            elif requirement.required:
                status = DoctorStatus.FAIL
                detail = f"missing required command: {requirement.command} ({requirement.purpose})"
            else:
                status = DoctorStatus.WARN
                detail = f"optional command unavailable: {requirement.command} ({requirement.purpose})"
            checks.append(DoctorCheck(f"tool.{requirement.command}", status, detail, "tool"))
        return checks

    def run(self) -> DoctorReport:
        checks: list[DoctorCheck] = []
        checks.extend(self._model_checks(self.config.model()))
        site_cfg = self.config.site() if self.config.active_site else None
        checks.extend(self._site_checks(site_cfg))
        checks.extend(self._tool_checks())
        return DoctorReport(tuple(checks))
