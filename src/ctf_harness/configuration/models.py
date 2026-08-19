from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    pass


_FORBIDDEN_SECRET_KEYS = {"api_key", "token", "secret", "password", "credential"}
_ALLOWED_MODEL_KEYS = {
    "provider",
    "model",
    "api_key_env",
    "base_url",
    "timeout_seconds",
    "max_output_bytes",
    "max_tokens",
    "command",
    "revision",
    "pass_env_names",
}
_ALLOWED_SITE_KEYS = {
    "provider",
    "base_url",
    "credential_kind",
    "credential_locator",
    "auth_mode",
    "cookie_name",
    "allow_submit",
}
_ALLOWED_MCP_KEYS = {
    "transport",
    "command",
    "endpoint",
    "protocol_version",
    "pass_env_names",
    "auth_env",
    "auth_scheme",
    "allowed_tools",
    "timeout_seconds",
}


def _require_non_empty(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{field_name} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True)
class ModelProviderConfig:
    name: str
    provider: str
    model: str | None = None
    api_key_env: str | None = None
    base_url: str | None = None
    timeout_seconds: float = 120.0
    max_output_bytes: int = 1_048_576
    max_tokens: int | None = None
    command: tuple[str, ...] = ()
    revision: str | None = None
    pass_env_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_non_empty(self.name, field_name="model profile name")
        _require_non_empty(self.provider, field_name=f"models.{self.name}.provider")
        if self.model is not None:
            _require_non_empty(self.model, field_name=f"models.{self.name}.model")
        if self.api_key_env is not None:
            _require_non_empty(self.api_key_env, field_name=f"models.{self.name}.api_key_env")
        if self.base_url is not None:
            _require_non_empty(self.base_url, field_name=f"models.{self.name}.base_url")
        if self.timeout_seconds <= 0:
            raise ConfigurationError(f"model profile {self.name!r} timeout_seconds must be positive")
        if isinstance(self.max_output_bytes, bool) or self.max_output_bytes <= 0:
            raise ConfigurationError(f"model profile {self.name!r} max_output_bytes must be positive")
        if self.max_tokens is not None and (isinstance(self.max_tokens, bool) or self.max_tokens <= 0):
            raise ConfigurationError(f"model profile {self.name!r} max_tokens must be positive")
        if any(not isinstance(item, str) or not item or "\x00" in item for item in self.command):
            raise ConfigurationError(f"model profile {self.name!r} command contains an invalid argv item")
        if any(not isinstance(item, str) or not item for item in self.pass_env_names):
            raise ConfigurationError(f"model profile {self.name!r} pass_env_names must be non-empty strings")

    def descriptor(self) -> dict:
        return {
            "name": self.name,
            "provider": self.provider,
            "model": self.model,
            "api_key_env": self.api_key_env,
            "base_url": self.base_url,
            "timeout_seconds": float(self.timeout_seconds),
            "max_output_bytes": self.max_output_bytes,
            "max_tokens": self.max_tokens,
            "command_argv0": self.command[0] if self.command else None,
            "revision": self.revision,
            "pass_env_names": list(self.pass_env_names),
            "credential_values_persisted": False,
        }


@dataclass(frozen=True)
class SiteProfileConfig:
    name: str
    provider: str
    base_url: str
    credential_kind: str = "env"
    credential_locator: str | None = None
    auth_mode: str = "token"
    cookie_name: str = "session"
    allow_submit: bool = False

    def __post_init__(self) -> None:
        _require_non_empty(self.name, field_name="site profile name")
        _require_non_empty(self.provider, field_name=f"sites.{self.name}.provider")
        _require_non_empty(self.base_url, field_name=f"sites.{self.name}.base_url")
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError(f"site profile {self.name!r} base_url must be an absolute http(s) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ConfigurationError(f"site profile {self.name!r} base_url must not contain credentials")
        if self.credential_kind not in {"env", "keyring", "session"}:
            raise ConfigurationError(f"site profile {self.name!r} credential_kind is unsupported")
        if self.credential_locator is not None:
            _require_non_empty(self.credential_locator, field_name=f"sites.{self.name}.credential_locator")
        if not isinstance(self.allow_submit, bool):
            raise ConfigurationError(f"site profile {self.name!r} allow_submit must be boolean")
        _require_non_empty(self.auth_mode, field_name=f"sites.{self.name}.auth_mode")
        _require_non_empty(self.cookie_name, field_name=f"sites.{self.name}.cookie_name")

    def descriptor(self) -> dict:
        return {
            "name": self.name,
            "provider": self.provider,
            "base_url": self.base_url,
            "credential_kind": self.credential_kind,
            "credential_locator": self.credential_locator,
            "auth_mode": self.auth_mode,
            "cookie_name": self.cookie_name,
            "allow_submit": self.allow_submit,
            "credential_values_persisted": False,
        }


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    transport: str
    command: tuple[str, ...] = ()
    endpoint: str | None = None
    protocol_version: str = "2026-07-28"
    pass_env_names: tuple[str, ...] = ()
    auth_env: str | None = None
    auth_scheme: str = "Bearer"
    allowed_tools: tuple[str, ...] = ()
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        _require_non_empty(self.name, field_name="MCP server name")
        _require_non_empty(self.transport, field_name=f"mcp_servers.{self.name}.transport")
        _require_non_empty(self.protocol_version, field_name=f"mcp_servers.{self.name}.protocol_version")
        if self.transport not in {"stdio", "streamable_http"}:
            raise ConfigurationError(f"MCP server {self.name!r} transport is unsupported")
        if self.timeout_seconds <= 0:
            raise ConfigurationError(f"MCP server {self.name!r} timeout_seconds must be positive")
        if any(not isinstance(item, str) or not item or "\x00" in item for item in self.command):
            raise ConfigurationError(f"MCP server {self.name!r} command contains an invalid argv item")
        if any(not isinstance(item, str) or not item for item in self.pass_env_names):
            raise ConfigurationError(f"MCP server {self.name!r} pass_env_names must be non-empty strings")
        if any(not isinstance(item, str) or not item for item in self.allowed_tools):
            raise ConfigurationError(f"MCP server {self.name!r} allowed_tools must be non-empty strings")
        if len(set(self.allowed_tools)) != len(self.allowed_tools):
            raise ConfigurationError(f"MCP server {self.name!r} allowed_tools must be unique")
        if self.transport == "stdio":
            if not self.command:
                raise ConfigurationError(f"MCP stdio server {self.name!r} requires command")
            if self.endpoint is not None:
                raise ConfigurationError(f"MCP stdio server {self.name!r} must not configure endpoint")
        else:
            if self.command:
                raise ConfigurationError(f"MCP HTTP server {self.name!r} must not configure command")
            if not self.endpoint:
                raise ConfigurationError(f"MCP HTTP server {self.name!r} requires endpoint")
            parsed = urlsplit(self.endpoint)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ConfigurationError(f"MCP HTTP server {self.name!r} endpoint must be absolute http(s)")
            if parsed.username is not None or parsed.password is not None:
                raise ConfigurationError(f"MCP HTTP server {self.name!r} endpoint must not contain credentials")
        if self.auth_env is not None:
            _require_non_empty(self.auth_env, field_name=f"mcp_servers.{self.name}.auth_env")
        _require_non_empty(self.auth_scheme, field_name=f"mcp_servers.{self.name}.auth_scheme")

    def tool_allowed(self, tool_name: str) -> bool:
        return "*" in self.allowed_tools or tool_name in self.allowed_tools

    def descriptor(self) -> dict:
        return {
            "name": self.name,
            "transport": self.transport,
            "command_argv0": self.command[0] if self.command else None,
            "endpoint": self.endpoint,
            "protocol_version": self.protocol_version,
            "pass_env_names": list(self.pass_env_names),
            "auth_env": self.auth_env,
            "auth_scheme": self.auth_scheme,
            "allowed_tools": list(self.allowed_tools),
            "timeout_seconds": float(self.timeout_seconds),
            "credential_values_persisted": False,
        }


@dataclass(frozen=True)
class HarnessConfiguration:
    active_model: str
    models: Mapping[str, ModelProviderConfig]
    active_site: str | None = None
    sites: Mapping[str, SiteProfileConfig] = field(default_factory=lambda: MappingProxyType({}))
    mcp_servers: Mapping[str, MCPServerConfig] = field(default_factory=lambda: MappingProxyType({}))
    source_path: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "models", MappingProxyType(dict(self.models)))
        object.__setattr__(self, "sites", MappingProxyType(dict(self.sites)))
        object.__setattr__(self, "mcp_servers", MappingProxyType(dict(self.mcp_servers)))
        if not self.active_model.strip():
            raise ConfigurationError("model.active must be non-empty")
        if self.active_model not in self.models:
            raise ConfigurationError(f"active model profile {self.active_model!r} is not configured")
        if self.active_site is not None and self.active_site not in self.sites:
            raise ConfigurationError(f"active site profile {self.active_site!r} is not configured")

    def model(self, name: str | None = None) -> ModelProviderConfig:
        selected = name or self.active_model
        try:
            return self.models[selected]
        except KeyError as exc:
            raise ConfigurationError(f"unknown model profile {selected!r}") from exc

    def site(self, name: str | None = None) -> SiteProfileConfig:
        selected = name or self.active_site
        if not selected:
            raise ConfigurationError("no active site profile is configured")
        try:
            return self.sites[selected]
        except KeyError as exc:
            raise ConfigurationError(f"unknown site profile {selected!r}") from exc

    def mcp_server(self, name: str) -> MCPServerConfig:
        try:
            return self.mcp_servers[name]
        except KeyError as exc:
            raise ConfigurationError(f"unknown MCP server {name!r}") from exc

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-harness-configuration-v3",
            "active_model": self.active_model,
            "models": {name: cfg.descriptor() for name, cfg in sorted(self.models.items())},
            "active_site": self.active_site,
            "sites": {name: cfg.descriptor() for name, cfg in sorted(self.sites.items())},
            "mcp_servers": {name: cfg.descriptor() for name, cfg in sorted(self.mcp_servers.items())},
            "source_path": self.source_path,
            "credential_values_persisted": False,
        }


def _expect_table(raw: object, *, field: str) -> dict:
    if not isinstance(raw, dict):
        raise ConfigurationError(f"{field} must be a TOML table")
    return raw


def _as_string(value: object, *, field: str, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ConfigurationError(f"{field} is required")
        return None
    return _require_non_empty(value, field_name=field)


def _as_string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ConfigurationError(f"{field} must be an array of non-empty strings")
    return tuple(value)


def _numeric(value: object, *, field: str, default: float) -> float:
    candidate = default if value is None else value
    if not isinstance(candidate, (int, float)) or isinstance(candidate, bool) or candidate <= 0:
        raise ConfigurationError(f"{field} must be a positive number")
    return float(candidate)


def _parse_model(name: str, raw: object) -> ModelProviderConfig:
    table = _expect_table(raw, field=f"models.{name}")
    forbidden = sorted(_FORBIDDEN_SECRET_KEYS.intersection(table))
    if forbidden:
        raise ConfigurationError(
            f"models.{name} contains inline secret field(s) {forbidden}; use api_key_env/pass_env_names instead"
        )
    unknown = sorted(set(table) - _ALLOWED_MODEL_KEYS)
    if unknown:
        raise ConfigurationError(f"models.{name} contains unknown field(s): {unknown}")
    max_output = table.get("max_output_bytes", 1_048_576)
    if not isinstance(max_output, int) or isinstance(max_output, bool):
        raise ConfigurationError(f"models.{name}.max_output_bytes must be an integer")
    max_tokens = table.get("max_tokens")
    if max_tokens is not None and (not isinstance(max_tokens, int) or isinstance(max_tokens, bool)):
        raise ConfigurationError(f"models.{name}.max_tokens must be an integer")
    return ModelProviderConfig(
        name=name,
        provider=_as_string(table.get("provider"), field=f"models.{name}.provider", required=True) or "",
        model=_as_string(table.get("model"), field=f"models.{name}.model"),
        api_key_env=_as_string(table.get("api_key_env"), field=f"models.{name}.api_key_env"),
        base_url=_as_string(table.get("base_url"), field=f"models.{name}.base_url"),
        timeout_seconds=_numeric(table.get("timeout_seconds"), field=f"models.{name}.timeout_seconds", default=120.0),
        max_output_bytes=max_output,
        max_tokens=max_tokens,
        command=_as_string_tuple(table.get("command"), field=f"models.{name}.command"),
        revision=_as_string(table.get("revision"), field=f"models.{name}.revision"),
        pass_env_names=_as_string_tuple(table.get("pass_env_names"), field=f"models.{name}.pass_env_names"),
    )


def _parse_site(name: str, raw: object) -> SiteProfileConfig:
    table = _expect_table(raw, field=f"sites.{name}")
    forbidden = sorted(_FORBIDDEN_SECRET_KEYS.intersection(table))
    if forbidden:
        raise ConfigurationError(
            f"sites.{name} contains inline secret field(s) {forbidden}; use credential_kind/credential_locator instead"
        )
    unknown = sorted(set(table) - _ALLOWED_SITE_KEYS)
    if unknown:
        raise ConfigurationError(f"sites.{name} contains unknown field(s): {unknown}")
    allow_submit = table.get("allow_submit", False)
    if not isinstance(allow_submit, bool):
        raise ConfigurationError(f"sites.{name}.allow_submit must be boolean")
    return SiteProfileConfig(
        name=name,
        provider=_as_string(table.get("provider"), field=f"sites.{name}.provider", required=True) or "",
        base_url=_as_string(table.get("base_url"), field=f"sites.{name}.base_url", required=True) or "",
        credential_kind=_as_string(table.get("credential_kind", "env"), field=f"sites.{name}.credential_kind", required=True) or "env",
        credential_locator=_as_string(table.get("credential_locator"), field=f"sites.{name}.credential_locator"),
        auth_mode=_as_string(table.get("auth_mode", "token"), field=f"sites.{name}.auth_mode", required=True) or "token",
        cookie_name=_as_string(table.get("cookie_name", "session"), field=f"sites.{name}.cookie_name", required=True) or "session",
        allow_submit=allow_submit,
    )


def _parse_mcp(name: str, raw: object) -> MCPServerConfig:
    table = _expect_table(raw, field=f"mcp_servers.{name}")
    forbidden = sorted(_FORBIDDEN_SECRET_KEYS.intersection(table))
    if forbidden:
        raise ConfigurationError(
            f"mcp_servers.{name} contains inline secret field(s) {forbidden}; use auth_env/pass_env_names instead"
        )
    unknown = sorted(set(table) - _ALLOWED_MCP_KEYS)
    if unknown:
        raise ConfigurationError(f"mcp_servers.{name} contains unknown field(s): {unknown}")
    return MCPServerConfig(
        name=name,
        transport=_as_string(table.get("transport"), field=f"mcp_servers.{name}.transport", required=True) or "",
        command=_as_string_tuple(table.get("command"), field=f"mcp_servers.{name}.command"),
        endpoint=_as_string(table.get("endpoint"), field=f"mcp_servers.{name}.endpoint"),
        protocol_version=_as_string(table.get("protocol_version", "2026-07-28"), field=f"mcp_servers.{name}.protocol_version", required=True) or "2026-07-28",
        pass_env_names=_as_string_tuple(table.get("pass_env_names"), field=f"mcp_servers.{name}.pass_env_names"),
        auth_env=_as_string(table.get("auth_env"), field=f"mcp_servers.{name}.auth_env"),
        auth_scheme=_as_string(table.get("auth_scheme", "Bearer"), field=f"mcp_servers.{name}.auth_scheme", required=True) or "Bearer",
        allowed_tools=_as_string_tuple(table.get("allowed_tools"), field=f"mcp_servers.{name}.allowed_tools"),
        timeout_seconds=_numeric(table.get("timeout_seconds"), field=f"mcp_servers.{name}.timeout_seconds", default=30.0),
    )


def load_configuration(
    path: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> HarnessConfiguration:
    """Load strict non-secret Harness configuration from TOML."""
    source = Path(path).expanduser()
    try:
        payload = source.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"cannot read configuration {source}: {exc}") from exc
    try:
        raw = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"invalid TOML configuration {source}: {exc}") from exc

    unknown_root = sorted(set(raw) - {"model", "models", "site", "sites", "mcp_servers"})
    if unknown_root:
        raise ConfigurationError(f"configuration contains unknown root section(s): {unknown_root}")
    model_table = _expect_table(raw.get("model", {}), field="model")
    unknown_model = sorted(set(model_table) - {"active"})
    if unknown_model:
        raise ConfigurationError(f"model contains unknown field(s): {unknown_model}")
    models_table = _expect_table(raw.get("models", {}), field="models")
    if not models_table:
        raise ConfigurationError("at least one [models.<name>] profile is required")
    site_table = _expect_table(raw.get("site", {}), field="site")
    unknown_site = sorted(set(site_table) - {"active"})
    if unknown_site:
        raise ConfigurationError(f"site contains unknown field(s): {unknown_site}")
    sites_table = _expect_table(raw.get("sites", {}), field="sites")
    mcp_table = _expect_table(raw.get("mcp_servers", {}), field="mcp_servers")

    models = {name: _parse_model(name, value) for name, value in models_table.items()}
    sites = {name: _parse_site(name, value) for name, value in sites_table.items()}
    mcp_servers = {name: _parse_mcp(name, value) for name, value in mcp_table.items()}
    active_model = _as_string(model_table.get("active"), field="model.active", required=True) or ""
    active_site = _as_string(site_table.get("active"), field="site.active")
    env = os.environ if environ is None else environ
    model_override = env.get("CTF_HARNESS_MODEL", "").strip()
    site_override = env.get("CTF_HARNESS_SITE", "").strip()
    if model_override:
        active_model = model_override
    if site_override:
        active_site = site_override
    return HarnessConfiguration(
        active_model=active_model,
        models=models,
        active_site=active_site,
        sites=sites,
        mcp_servers=mcp_servers,
        source_path=str(source),
    )
