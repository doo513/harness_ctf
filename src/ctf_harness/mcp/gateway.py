from __future__ import annotations

import subprocess
from typing import Mapping

from ctf_harness.configuration.models import HarnessConfiguration

from .client import MCPClientError, MCPRegistry, build_mcp_registry as _build_mcp_registry


SUPPORTED_MCP_PROTOCOL = "2026-07-28"


class GuardedMCPRegistry(MCPRegistry):
    """Public MCP registry with human approval required for remote tool calls."""

    def tool_specs(self):
        specs = super().tool_specs()
        for spec in specs:
            if spec.name == "mcp_call":
                spec.permission = "confirm"
                spec.provenance = dict(spec.provenance)
                spec.provenance["approval_policy"] = "operator_confirm_required"
        return specs


def build_mcp_registry(
    config: HarnessConfiguration,
    *,
    environ: Mapping[str, str] | None = None,
    http_opener: object | None = None,
    stdio_runner=subprocess.run,
) -> MCPRegistry:
    """Build the public MCP registry only for semantics this client implements.

    Protocol-version checks live at this composition boundary so future MCP
    protocol adapters can coexist without weakening the low-level transport
    implementation or silently claiming compatibility.
    """

    unsupported = sorted(
        (name, cfg.protocol_version)
        for name, cfg in config.mcp_servers.items()
        if cfg.protocol_version != SUPPORTED_MCP_PROTOCOL
    )
    if unsupported:
        rendered = ", ".join(f"{name}:{version}" for name, version in unsupported)
        raise MCPClientError(
            "unsupported MCP protocol version(s): "
            f"{rendered}; built-in client supports {SUPPORTED_MCP_PROTOCOL}"
        )
    registry = _build_mcp_registry(
        config,
        environ=environ,
        http_opener=http_opener,
        stdio_runner=stdio_runner,
    )
    return GuardedMCPRegistry(config, registry.clients)
