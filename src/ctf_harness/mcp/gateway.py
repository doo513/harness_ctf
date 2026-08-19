from __future__ import annotations

from typing import Mapping

from ctf_harness.configuration.models import HarnessConfiguration

from .client import ClientFactory, MCPRegistry, build_sdk_clients


PREFERRED_MCP_PROTOCOL = "2026-07-28"
# Compatibility export for the first operational-readiness draft. The official
# SDK can negotiate earlier revisions; this value is no longer an exclusivity gate.
SUPPORTED_MCP_PROTOCOL = PREFERRED_MCP_PROTOCOL


def build_mcp_registry(
    config: HarnessConfiguration,
    *,
    environ: Mapping[str, str] | None = None,
    client_factory: ClientFactory | None = None,
) -> MCPRegistry:
    """Build the Harness policy layer over official MCP SDK clients.

    Protocol negotiation/validation belongs to the SDK. This boundary keeps
    Harness policy limited to configured servers, tool allowlists, confirmation,
    secret scoping, and trust classification.
    """
    return MCPRegistry(
        config,
        build_sdk_clients(config, environ=environ, client_factory=client_factory),
    )
