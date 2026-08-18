from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctf_harness.configuration import ConfigurationError, load_configuration
from ctf_harness.mcp import MCPClientError, build_mcp_registry


class _HTTPResponse:
    def __init__(self, payload: dict, content_type: str = "application/json"):
        self.body = json.dumps(payload).encode("utf-8")
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, limit: int) -> bytes:
        return self.body[:limit]


class _MCPOpener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout: float):
        message = json.loads(request.data.decode("utf-8"))
        self.requests.append((request, message, timeout))
        if message["method"] == "tools/list":
            result = {
                "tools": [
                    {"name": "search", "description": "search", "inputSchema": {"type": "object"}},
                    {"name": "not_allowed", "description": "hidden", "inputSchema": {"type": "object"}},
                ]
            }
        else:
            result = {"structuredContent": {"ok": True}, "isError": False}
        return _HTTPResponse({"jsonrpc": "2.0", "id": message["id"], "result": result})


def _http_config(path: Path) -> Path:
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
protocol_version = "2026-07-28"
auth_env = "MCP_TOKEN"
allowed_tools = ["search"]
""",
        encoding="utf-8",
    )
    return path


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


def test_http_mcp_registry_filters_remote_metadata_and_routes_allowlisted_tool(tmp_path: Path):
    opener = _MCPOpener()
    cfg = load_configuration(_http_config(tmp_path / "harness.toml"))
    registry = build_mcp_registry(cfg, environ={"MCP_TOKEN": "mcp-secret"}, http_opener=opener)
    tools = registry.list_tools("analysis")
    assert [tool.name for tool in tools] == ["search"]
    result = registry.call_tool("analysis", "search", {"q": "ctf"})
    assert result["truth_authority"] == "none"
    assert result["trust"] == "untrusted_observation"
    call_request, call_message, _ = opener.requests[-1]
    assert call_message["method"] == "tools/call"
    assert call_request.get_header("Mcp-method") == "tools/call"
    assert call_request.get_header("Mcp-name") == "search"
    assert call_request.get_header("Mcp-protocol-version") == "2026-07-28"
    assert call_request.get_header("Authorization") == "Bearer mcp-secret"
    assert "mcp-secret" not in json.dumps(registry.descriptor())


def test_mcp_tool_call_is_denied_when_not_allowlisted(tmp_path: Path):
    cfg = load_configuration(_http_config(tmp_path / "harness.toml"))
    registry = build_mcp_registry(cfg, environ={"MCP_TOKEN": "x"}, http_opener=_MCPOpener())
    with pytest.raises(MCPClientError, match="not allowlisted"):
        registry.call_tool("analysis", "not_allowed", {})


def test_stdio_mcp_passes_only_explicit_environment(tmp_path: Path):
    path = tmp_path / "harness.toml"
    path.write_text(
        """
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"
[mcp_servers.ida]
transport = "stdio"
command = ["ida-mcp"]
pass_env_names = ["IDA_TOKEN"]
allowed_tools = ["decompile"]
""",
        encoding="utf-8",
    )
    calls = []

    def runner(argv, **kwargs):
        message = json.loads(kwargs["input"].decode("utf-8"))
        calls.append((argv, kwargs, message))
        wire = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}).encode("utf-8") + b"\n"
        return SimpleNamespace(returncode=0, stdout=wire, stderr=b"")

    cfg = load_configuration(path)
    registry = build_mcp_registry(
        cfg,
        environ={"PATH": "/bin", "LANG": "C", "IDA_TOKEN": "ida-secret", "UNRELATED_SECRET": "nope"},
        stdio_runner=runner,
    )
    result = registry.call_tool("ida", "decompile", {"address": "0x401000"})
    assert result["result"] == {"ok": True}
    child_env = calls[0][1]["env"]
    assert child_env["IDA_TOKEN"] == "ida-secret"
    assert "UNRELATED_SECRET" not in child_env
    assert calls[0][1]["shell"] is False


def test_registry_exposes_only_two_harness_owned_mcp_tools(tmp_path: Path):
    cfg = load_configuration(_http_config(tmp_path / "harness.toml"))
    registry = build_mcp_registry(cfg, environ={"MCP_TOKEN": "x"}, http_opener=_MCPOpener())
    specs = registry.tool_specs()
    assert [spec.name for spec in specs] == ["mcp_list", "mcp_call"]
