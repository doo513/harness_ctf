from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

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
    title: str | None = None

    def descriptor(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "name": self.name,
            "title": self.title,
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
            "schema_version": "ctf-mcp-tool-result-v2",
            "server": self.server,
            "tool": self.tool,
            "result": self.result,
            "trust": "untrusted_observation",
            "truth_authority": "none",
            "completion_authority": "none",
        }


class MCPClientBackend(Protocol):
    def list_tools(self) -> tuple[MCPTool, ...]: ...
    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> MCPToolResult: ...
    def descriptor(self) -> dict[str, Any]: ...


ClientFactory = Callable[[MCPServerConfig, Mapping[str, str]], MCPClientBackend]


def _run_async(factory: Callable[[], Any]) -> Any:
    """Run an SDK operation from the Harness' synchronous ToolSpec boundary."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(factory())
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="ctf-mcp") as pool:
        return pool.submit(lambda: asyncio.run(factory())).result()


def _dump_model(value: Any) -> Any:
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return dump(mode="json", by_alias=True, exclude_none=True)
    return value


def _redacted_error(exc: BaseException, secrets: tuple[str, ...]) -> str:
    text = str(exc)
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text[:4096]


class SDKMCPClient:
    """Thin adapter over the official MCP Python SDK v2.

    The SDK owns wire protocol negotiation/validation and transport semantics.
    The Harness owns configuration, secret scoping, allowlisting, approval, and
    trust classification.
    """

    def __init__(self, config: MCPServerConfig, *, environ: Mapping[str, str]):
        self.config = config
        self.environ = dict(environ)

    def _mode(self) -> str:
        return self.config.protocol_version or "auto"

    def _stdio_transport(self):
        child_env = {
            name: self.environ[name]
            for name in self.config.pass_env_names
            if name in self.environ
        }
        params = StdioServerParameters(
            command=self.config.command[0],
            args=list(self.config.command[1:]),
            env=child_env,
        )
        return stdio_client(params)

    def _auth_header(self) -> tuple[dict[str, str], tuple[str, ...]]:
        if not self.config.auth_env:
            return {}, ()
        secret = self.environ.get(self.config.auth_env, "")
        if not secret:
            raise MCPClientError(f"MCP auth environment variable {self.config.auth_env} is not set")
        return {"Authorization": f"{self.config.auth_scheme} {secret}".strip()}, (secret,)

    async def _with_client(self, operation: Callable[[Client], Any]) -> Any:
        mode = self._mode()
        try:
            if self.config.transport == "stdio":
                async with Client(
                    self._stdio_transport(),
                    mode=mode,
                    read_timeout_seconds=float(self.config.timeout_seconds),
                ) as client:
                    return await operation(client)

            if self.config.transport == "streamable_http":
                if not self.config.endpoint:
                    raise MCPClientError("MCP HTTP endpoint is not configured")
                headers, _ = self._auth_header()
                async with httpx2.AsyncClient(
                    headers=headers,
                    timeout=float(self.config.timeout_seconds),
                    follow_redirects=False,
                ) as http_client:
                    transport = streamable_http_client(
                        self.config.endpoint,
                        http_client=http_client,
                        terminate_on_close=False,
                    )
                    async with Client(
                        transport,
                        mode=mode,
                        read_timeout_seconds=float(self.config.timeout_seconds),
                    ) as client:
                        return await operation(client)

            raise MCPClientError(f"unsupported MCP transport {self.config.transport!r}")
        except MCPClientError:
            raise
        except Exception as exc:
            secrets: tuple[str, ...] = ()
            if self.config.auth_env:
                value = self.environ.get(self.config.auth_env, "")
                secrets = (value,) if value else ()
            raise MCPClientError(
                f"MCP server {self.config.name!r} operation failed: {_redacted_error(exc, secrets)}"
            ) from exc

    @staticmethod
    async def _list_all(client: Client, *, server: str) -> tuple[MCPTool, ...]:
        tools: list[MCPTool] = []
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(32):
            result = await client.list_tools(cursor=cursor)
            for tool in result.tools:
                schema = tool.input_schema
                if not isinstance(schema, dict):
                    raise MCPClientError(f"MCP tool {tool.name!r} input schema is not an object")
                tools.append(
                    MCPTool(
                        server=server,
                        name=tool.name,
                        title=tool.title,
                        description=tool.description or "",
                        input_schema=dict(schema),
                    )
                )
            next_cursor = result.next_cursor
            if next_cursor is None:
                return tuple(tools)
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen:
                raise MCPClientError(f"MCP server {server!r} returned an invalid pagination cursor")
            seen.add(next_cursor)
            cursor = next_cursor
        raise MCPClientError(f"MCP server {server!r} tools/list exceeded page limit")

    def list_tools(self) -> tuple[MCPTool, ...]:
        async def run():
            return await self._with_client(lambda client: self._list_all(client, server=self.config.name))

        return _run_async(run)

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> MCPToolResult:
        if not isinstance(name, str) or not name:
            raise ValueError("MCP tool name must be non-empty")
        if not isinstance(arguments, Mapping):
            raise ValueError("MCP tool arguments must be a mapping")

        async def operation(client: Client):
            tools = await self._list_all(client, server=self.config.name)
            if name not in {tool.name for tool in tools}:
                raise MCPClientError(f"MCP server {self.config.name!r} did not advertise tool {name!r}")
            result = await client.call_tool(
                name,
                dict(arguments),
                read_timeout_seconds=float(self.config.timeout_seconds),
            )
            return MCPToolResult(self.config.name, name, _dump_model(result))

        async def run():
            return await self._with_client(operation)

        return _run_async(run)

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": "ctf-mcp-sdk-client-v2",
            "server": self.config.name,
            "transport": self.config.transport,
            "protocol_mode": self._mode(),
            "allowed_tools": list(self.config.allowed_tools),
            "sdk": "mcp-python-v2",
            "credential_values_persisted": False,
            "truth_authority": "none",
        }


class MCPRegistry:
    """Harness-owned MCP routing with an explicit per-server tool allowlist."""

    def __init__(self, config: HarnessConfiguration, clients: Mapping[str, MCPClientBackend]):
        self.config = config
        self.clients = dict(clients)

    @property
    def server_names(self) -> tuple[str, ...]:
        return tuple(sorted(self.clients))

    def _client(self, server: str) -> MCPClientBackend:
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
            "schema_version": "ctf-mcp-registry-v2",
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
                description="Call one explicitly allowlisted MCP tool; result is an untrusted observation.",
                handler=lambda server, tool, arguments=None: self.call_tool(server, tool, arguments or {}),
                side_effect=SideEffect.EXTERNAL,
                idempotent=False,
                permission="confirm",
                failure_modes=["unknown_server", "tool_not_allowlisted", "transport_error", "remote_tool_error"],
                provenance={
                    "kind": "ctf_mcp_call",
                    "truth_authority": "none",
                    "approval_policy": "operator_confirm_required",
                },
            ),
        )


def build_sdk_clients(
    config: HarnessConfiguration,
    *,
    environ: Mapping[str, str] | None = None,
    client_factory: ClientFactory | None = None,
) -> dict[str, MCPClientBackend]:
    env = dict(os.environ if environ is None else environ)
    factory = client_factory or (lambda cfg, values: SDKMCPClient(cfg, environ=values))
    return {name: factory(cfg, env) for name, cfg in config.mcp_servers.items()}
