from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
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
        if not self.name.strip():
            raise ConfigurationError("model profile name must be non-empty")
        if not self.provider.strip():
            raise ConfigurationError(f"model profile {self.name!r} requires provider")
        if self.model is not None and not self.model.strip():
            raise ConfigurationError(f"model profile {self.name!r} model must be non-empty")
        if self.api_key_env is not None and not self.api_key_env.strip():
            raise ConfigurationError(f"model profile {self.name!r} api_key_env must be non-empty")
        if self.base_url is not None and not self.base_url.strip():
            raise ConfigurationError(f"model profile {self.name!r} base_url must be non-empty")
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
        for value, field in ((self.name, "name"), (self.provider, "provider"), (self.base_url, "base_url")):
            if not isinstance(value, str) or not value.strip():
                raise ConfigurationError(f"site profile {field} must be non-empty")
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError(f"site profile {self.name!r} base_url must be an absolute http(s) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ConfigurationError(f"site profile {self.name!r} base_url must not contain credentials")
        if self.credential_kind not in {"env", "keyring", "session"}:
            raise ConfigurationError(f"site profile {self.name!r} credential_kind is unsupported")
        if self.credential_locator is not None and not self.credential_locator.strip():
            raise ConfigurationError(f"site profile {self.name!r} credential_locator must be non-empty")
        if not isinstance(self.allow_submit, bool):
            raise ConfigurationError(f"site profile {self.name!r} allow_submit must be boolean")
        if not self.auth_mode.strip() or not self.cookie_name.strip():
            raise ConfigurationError(f"site profile {self.name!r} auth_mode/cookie_name must be non-empty")

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
class HarnessConfiguration:
    active_model: str
    models: Mapping[str, ModelProviderConfig]
    active_site: str | None = None
    sites: Mapping[str, SiteProfileConfig] = MappingProxyType({})
    source_path: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "models", MappingProxyType(dict(self.models)))
        object.__setattr__(self, "sites", MappingProxyType(dict(self.sites)))
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

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-harness-configuration-v2",
            "active_model": self.active_model,
            "models": {name: cfg.descriptor() for name, cfg in sorted(self.models.items())},
            "active_site": self.active_site,
            "sites": {name: cfg.descriptor() for name, cfg in sorted(self.sites.items())},
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
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{field} must be a non-empty string")
    return value.strip()


def _as_string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ConfigurationError(f"{field} must be an array of non-empty strings")
    return tuple(value)


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
    timeout = table.get("timeout_seconds", 120.0)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise ConfigurationError(f"models.{name}.timeout_seconds must be numeric")
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
        timeout_seconds=float(timeout),
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

    unknown_root = sorted(set(raw) - {"model", "models", "site", "sites"})
    if unknown_root:
        raise ConfigurationError(f"configuration contains unknown root section(s): {unknown_root}")
    model_table = _expect_table(raw.get("model", {}), field="model")
    if sorted(set(model_table) - {"active"}):
        raise ConfigurationError("model contains unknown field(s)")
    models_table = _expect_table(raw.get("models", {}), field="models")
    if not models_table:
        raise ConfigurationError("at least one [models.<name>] profile is required")
    site_table = _expect_table(raw.get("site", {}), field="site")
    if sorted(set(site_table) - {"active"}):
        raise ConfigurationError("site contains unknown field(s)")
    sites_table = _expect_table(raw.get("sites", {}), field="sites")

    models = {name: _parse_model(name, value) for name, value in models_table.items()}
    sites = {name: _parse_site(name, value) for name, value in sites_table.items()}
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
        source_path=str(source),
    )
