from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_harness.configuration import ConfigurationError, load_configuration
from ctf_harness.mcp import MCPClientError, MCPTool, MCPToolResult, build_mcp_registry
from ctf_harness.mcp.client import SDKMCPClient


class _FakeMCPBackend:
    def __init__(self, server: str):
        self.server = server
        self.calls = []

    def list_tools(self):
        return (
            MCPTool(self.server, "search", "search", {"type": "object"}, title="Search"),
            MCPTool(self.server, "not_allowed", "hidden", {"type": "object"}),
        )

    def call_tool(self, name: str, arguments):
        self.calls.append((name, dict(arguments)))
        return MCPToolResult(self.server, name, {"structuredContent": {"ok": True}, "isError": False})

    def descriptor(self):
        return {
            "schema_version": "fake-mcp-client",
            "server": self.server,
            "credential_values_persisted": False,
            "truth_authority": "none",
        }


def _http_config(path: Path, *, protocol_version: str = "2026-07-28") -> Path:
    path.write_text(
        f"""
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"

[mcp_servers.analysis]
transport = "streamable_http"
endpoint = "https://mcp.example/mcp"
protocol_version = "{protocol_version}"
auth_env = "MCP_TOKEN"
allowed_tools = ["search"]
""",
        encoding="utf-8",
    )
    return path


def _registry(cfg):
    backends = {}

    def factory(server_cfg, env):
        backend = _FakeMCPBackend(server_cfg.name)
        backends[server_cfg.name] = backend
        return backend

    return build_mcp_registry(cfg, environ={"MCP_TOKEN": "mcp-secret"}, client_factory=factory), backends


def test_mcp_configuration_rejects_inline_credentials(tmp_path: Path):
    path = tmp_path / "bad.toml"
    path.write_text(
        """
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"
[mcp_servers.analysis]
transport = "streamable_http"
endpoint = "https://mcp.example/mcp"
token = "secret"
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="inline secret"):
        load_configuration(path)


def test_registry_filters_remote_metadata_and_routes_allowlisted_tool(tmp_path: Path):
    cfg = load_configuration(_http_config(tmp_path / "harness.toml"))
    registry, backends = _registry(cfg)
    tools = registry.list_tools("analysis")
    assert [tool.name for tool in tools] == ["search"]
    assert tools[0].descriptor()["trust"] == "untrusted_server_metadata"

    result = registry.call_tool("analysis", "search", {"q": "ctf"})
    assert result["truth_authority"] == "none"
    assert result["trust"] == "untrusted_observation"
    assert backends["analysis"].calls == [("search", {"q": "ctf"})]


def test_mcp_tool_call_is_denied_when_not_allowlisted(tmp_path: Path):
    cfg = load_configuration(_http_config(tmp_path / "harness.toml"))
    registry, backends = _registry(cfg)
    with pytest.raises(MCPClientError, match="not allowlisted"):
        registry.call_tool("analysis", "not_allowed", {})
    assert backends["analysis"].calls == []


def test_official_sdk_client_descriptor_never_contains_auth_value(tmp_path: Path):
    cfg = load_configuration(_http_config(tmp_path / "harness.toml"))
    client = SDKMCPClient(cfg.mcp_server("analysis"), environ={"MCP_TOKEN": "mcp-secret"})
    rendered = json.dumps(client.descriptor())
    assert "mcp-secret" not in rendered
    assert client.descriptor()["sdk"] == "mcp-python-v2"


def test_protocol_mode_is_delegated_to_official_sdk_instead_of_hard_blocked(tmp_path: Path):
    cfg = load_configuration(_http_config(tmp_path / "harness.toml", protocol_version="legacy"))
    registry, _ = _registry(cfg)
    assert registry.server_names == ("analysis",)


def test_registry_exposes_only_harness_owned_mcp_tools_with_call_confirmation(tmp_path: Path):
    cfg = load_configuration(_http_config(tmp_path / "harness.toml"))
    registry, _ = _registry(cfg)
    specs = {spec.name: spec for spec in registry.tool_specs()}
    assert set(specs) == {"mcp_list", "mcp_call"}
    assert specs["mcp_list"].permission == "auto"
    assert specs["mcp_call"].permission == "confirm"
    assert specs["mcp_call"].provenance["approval_policy"] == "operator_confirm_required"
