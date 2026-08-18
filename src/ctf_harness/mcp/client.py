from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from itertools import count
from typing import Any, Mapping, Protocol

from harness.core.tools import SideEffect, ToolSpec

from ctf_harness.configuration.models import HarnessConfiguration, MCPServerConfig


class MCPClientError(RuntimeError):
    pass


@dataclass(frozen=True)
class MCPTool:
    server: str
    name: str
    description: str
    input_schema: dict[str, Any]

    def descriptor(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "trust": "untrusted_server_metadata",
        }


@dataclass(frozen=True)
class MCPToolResult:
    server: str
    tool: str
    result: Any

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": "ctf-mcp-tool-result-v1",
            "server": self.server,
            "tool": self.tool,
            "result": self.result,
            "trust": "untrusted_observation",
            "truth_authority": "none",
            "completion_authority": "none",
        }


class _MCPClient(Protocol):
    def list_tools(self) -> tuple[MCPTool, ...]: ...
    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> MCPToolResult: ...
    def descriptor(self) -> dict[str, Any]: ...


def _request_meta() -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/clientInfo": {
            "name": "verified-ctf-harness",
            "version": "0.1.0",
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }


class _BaseClient:
    def __init__(self, config: MCPServerConfig):
        self.config = config
        self._ids = count(1)

    def _exchange(self, message: dict[str, Any], *, method: str, tool_name: str | None) -> dict[str, Any]:
        raise NotImplementedError

    def _request(self, method: str, params: Mapping[str, Any] | None = None, *, tool_name: str | None = None) -> Any:
        request_id = next(self._ids)
        merged = dict(params or {})
        meta = dict(merged.get("_meta", {})) if isinstance(merged.get("_meta"), dict) else {}
        meta.update(_request_meta())
        merged["_meta"] = meta
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": merged}
        response = self._exchange(message, method=method, tool_name=tool_name)
        if response.get("jsonrpc") != "2.0" or response.get("id") != request_id:
            raise MCPClientError(f"MCP server {self.config.name!r} returned mismatched JSON-RPC response")
        if "error" in response:
            error = response.get("error")
            if isinstance(error, dict):
                code = error.get("code")
                message_text = error.get("message")
                raise MCPClientError(f"MCP server {self.config.name!r} error {code}: {message_text}")
            raise MCPClientError(f"MCP server {self.config.name!r} returned malformed error")
        if "result" not in response:
            raise MCPClientError(f"MCP server {self.config.name!r} response has no result")
        return response["result"]

    def list_tools(self) -> tuple[MCPTool, ...]:
        tools: list[MCPTool] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(32):
            params = {} if cursor is None else {"cursor": cursor}
            result = self._request("tools/list", params)
            if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
                raise MCPClientError(f"MCP server {self.config.name!r} returned invalid tools/list result")
            for raw in result["tools"]:
                if not isinstance(raw, dict):
                    raise MCPClientError("MCP tool metadata must be an object")
                name = raw.get("name")
                if not isinstance(name, str) or not name:
                    raise MCPClientError("MCP tool metadata requires name")
                description = raw.get("description", "")
                schema = raw.get("inputSchema", {})
                if not isinstance(description, str) or not isinstance(schema, dict):
                    raise MCPClientError(f"MCP tool {name!r} metadata is invalid")
                tools.append(MCPTool(self.config.name, name, description, schema))
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return tuple(tools)
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                raise MCPClientError(f"MCP server {self.config.name!r} returned invalid pagination cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise MCPClientError(f"MCP server {self.config.name!r} tools/list exceeded page limit")

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> MCPToolResult:
        if not isinstance(name, str) or not name:
            raise ValueError("MCP tool name must be non-empty")
        if not isinstance(arguments, Mapping):
            raise ValueError("MCP tool arguments must be a mapping")
        result = self._request("tools/call", {"name": name, "arguments": dict(arguments)}, tool_name=name)
        return MCPToolResult(self.config.name, name, result)

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": "ctf-mcp-client-v1",
            "server": self.config.name,
            "transport": self.config.transport,
            "protocol_version": self.config.protocol_version,
            "allowed_tools": list(self.config.allowed_tools),
            "credential_values_persisted": False,
            "truth_authority": "none",
        }


class StreamableHTTPMCPClient(_BaseClient):
    def __init__(self, config: MCPServerConfig, *, environ: Mapping[str, str], opener: object | None = None):
        super().__init__(config)
        self.environ = environ
        self.opener = opener

    @staticmethod
    def _parse_sse(body: bytes, request_id: int) -> dict[str, Any]:
        text = body.decode("utf-8")
        data_lines: list[str] = []
        messages: list[dict[str, Any]] = []
        for line in text.splitlines() + [""]:
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif not line and data_lines:
                payload = "\n".join(data_lines)
                data_lines.clear()
                try:
                    parsed = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise MCPClientError("MCP SSE data is not valid JSON") from exc
                if isinstance(parsed, dict):
                    messages.append(parsed)
        for message in messages:
            if message.get("id") == request_id:
                return message
        raise MCPClientError("MCP SSE response did not contain matching JSON-RPC response")

    def _exchange(self, message: dict[str, Any], *, method: str, tool_name: str | None) -> dict[str, Any]:
        if not self.config.endpoint:
            raise MCPClientError("MCP HTTP endpoint is not configured")
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.config.protocol_version,
            "Mcp-Method": method,
        }
        if tool_name:
            headers["Mcp-Name"] = tool_name
        if self.config.auth_env:
            secret = self.environ.get(self.config.auth_env, "")
            if not secret:
                raise MCPClientError(f"MCP auth environment variable {self.config.auth_env} is not set")
            headers["Authorization"] = f"{self.config.auth_scheme} {secret}".strip()
        request = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        transport = self.opener or urllib.request.build_opener()
        try:
            response = transport.open(request, timeout=float(self.config.timeout_seconds))
            with response:
                body = response.read(4_194_305)
                content_type = str(response.headers.get("Content-Type", "")).lower()
        except urllib.error.HTTPError as exc:
            detail = exc.read(2048).decode("utf-8", errors="replace")
            raise MCPClientError(f"MCP HTTP server returned {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise MCPClientError(f"MCP HTTP request failed: {exc.reason}") from exc
        except OSError as exc:
            raise MCPClientError(f"MCP HTTP request failed: {exc}") from exc
        if len(body) > 4_194_304:
            raise MCPClientError("MCP HTTP response exceeds byte limit")
        request_id = int(message["id"])
        if "text/event-stream" in content_type:
            return self._parse_sse(body, request_id)
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPClientError("MCP HTTP response is not UTF-8 JSON") from exc
        if not isinstance(parsed, dict):
            raise MCPClientError("MCP HTTP response must be one JSON-RPC object")
        return parsed


class StdioMCPClient(_BaseClient):
    def __init__(
        self,
        config: MCPServerConfig,
        *,
        environ: Mapping[str, str],
        runner=subprocess.run,
    ):
        super().__init__(config)
        self.environ = environ
        self.runner = runner

    def _child_env(self) -> dict[str, str]:
        child = {
            "PATH": self.environ.get("PATH", os.environ.get("PATH", "/usr/bin:/bin")),
            "LANG": self.environ.get("LANG", os.environ.get("LANG", "C.UTF-8")),
        }
        for name in self.config.pass_env_names:
            if name in self.environ:
                child[name] = self.environ[name]
        return child

    def _exchange(self, message: dict[str, Any], *, method: str, tool_name: str | None) -> dict[str, Any]:
        wire = json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            completed = self.runner(
                list(self.config.command),
                input=wire.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=float(self.config.timeout_seconds),
                check=False,
                shell=False,
                env=self._child_env(),
            )
        except subprocess.TimeoutExpired as exc:
            raise MCPClientError(f"MCP stdio server {self.config.name!r} timed out") from exc
        except OSError as exc:
            raise MCPClientError(f"cannot execute MCP stdio server {self.config.name!r}: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr[:2048].decode("utf-8", errors="replace")
            raise MCPClientError(f"MCP stdio server {self.config.name!r} exited {completed.returncode}: {detail}")
        if len(completed.stdout) > 4_194_304:
            raise MCPClientError("MCP stdio response exceeds byte limit")
        request_id = message["id"]
        matches: list[dict[str, Any]] = []
        for line in completed.stdout.decode("utf-8", errors="strict").splitlines():
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise MCPClientError("MCP stdio stdout contained non-JSON protocol data") from exc
            if not isinstance(parsed, dict):
                raise MCPClientError("MCP stdio message must be a JSON object")
            if parsed.get("id") == request_id:
                matches.append(parsed)
        if len(matches) != 1:
            raise MCPClientError("MCP stdio server did not return exactly one matching response")
        return matches[0]


class MCPRegistry:
    """Harness-owned MCP routing with an explicit per-server tool allowlist."""

    def __init__(self, config: HarnessConfiguration, clients: Mapping[str, _MCPClient]):
        self.config = config
        self.clients = dict(clients)

    @property
    def server_names(self) -> tuple[str, ...]:
        return tuple(sorted(self.clients))

    def _client(self, server: str) -> _MCPClient:
        try:
            return self.clients[server]
        except KeyError as exc:
            raise MCPClientError(f"unknown MCP server {server!r}") from exc

    def list_tools(self, server: str) -> tuple[MCPTool, ...]:
        cfg = self.config.mcp_server(server)
        tools = self._client(server).list_tools()
        return tuple(tool for tool in tools if cfg.tool_allowed(tool.name))

    def call_tool(self, server: str, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        cfg = self.config.mcp_server(server)
        if not cfg.tool_allowed(tool):
            raise MCPClientError(f"MCP tool is not allowlisted: {server}:{tool}")
        return self._client(server).call_tool(tool, arguments).descriptor()

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": "ctf-mcp-registry-v1",
            "servers": {name: self.clients[name].descriptor() for name in sorted(self.clients)},
            "remote_tool_metadata_trusted": False,
            "truth_authority": "none",
        }

    def tool_specs(self) -> tuple[ToolSpec, ToolSpec]:
        return (
            ToolSpec(
                name="mcp_list",
                description="List allowlisted tools exposed by one configured MCP server.",
                handler=lambda server: [tool.descriptor() for tool in self.list_tools(server)],
                side_effect=SideEffect.EXTERNAL,
                idempotent=False,
                permission="auto",
                failure_modes=["unknown_server", "transport_error", "invalid_server_metadata"],
                provenance={"kind": "ctf_mcp_list", "truth_authority": "none"},
            ),
            ToolSpec(
                name="mcp_call",
                description="Call one explicitly allowlisted tool on a configured MCP server; result is an untrusted observation.",
                handler=lambda server, tool, arguments=None: self.call_tool(server, tool, arguments or {}),
                side_effect=SideEffect.EXTERNAL,
                idempotent=False,
                permission="auto",
                failure_modes=["unknown_server", "tool_not_allowlisted", "transport_error", "remote_tool_error"],
                provenance={"kind": "ctf_mcp_call", "truth_authority": "none"},
            ),
        )


def build_mcp_registry(
    config: HarnessConfiguration,
    *,
    environ: Mapping[str, str] | None = None,
    http_opener: object | None = None,
    stdio_runner=subprocess.run,
) -> MCPRegistry:
    env = dict(os.environ if environ is None else environ)
    clients: dict[str, _MCPClient] = {}
    for name, cfg in config.mcp_servers.items():
        if cfg.transport == "streamable_http":
            clients[name] = StreamableHTTPMCPClient(cfg, environ=env, opener=http_opener)
        elif cfg.transport == "stdio":
            clients[name] = StdioMCPClient(cfg, environ=env, runner=stdio_runner)
        else:
            raise MCPClientError(f"unsupported MCP transport {cfg.transport!r}")
    return MCPRegistry(config, clients)
