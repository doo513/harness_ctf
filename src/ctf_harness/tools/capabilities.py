from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence

from harness.core.tools import SideEffect, ToolSpec


@dataclass(frozen=True)
class CapabilityResult:
    capability: str
    provider_id: str
    provider_revision: str
    payload: dict[str, Any]
    trust: str = "untrusted_observation"

    def __post_init__(self) -> None:
        for field in ("capability", "provider_id", "provider_revision", "trust"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must be non-empty")
        if not isinstance(self.payload, dict):
            raise ValueError("capability payload must be a dict")

    def descriptor(self) -> dict[str, Any]:
        return {
            "schema_version": "ctf-capability-result-v1",
            "capability": self.capability,
            "provider_id": self.provider_id,
            "provider_revision": self.provider_revision,
            "payload": self.payload,
            "trust": self.trust,
            "truth_authority": "none",
        }


class CapabilityProvider(Protocol):
    provider_id: str
    revision: str
    capabilities: tuple[str, ...]
    priority: int

    def available(self) -> bool: ...
    def invoke(self, capability: str, args: dict[str, Any]) -> CapabilityResult: ...
    def descriptor(self) -> dict[str, Any]: ...


class CapabilityCatalog:
    """Provider fallback behind one Harness-registered executable tool.

    This catalog is not an alternative to Base ActionRuntime. It becomes
    executable only when `make_tool()` is registered in the profile's normal
    tool inventory. Provider fallback therefore cannot invent a model-visible
    executable capability outside Harness-owned dispatch.
    """

    def __init__(self, providers: Sequence[CapabilityProvider] = ()):
        self._providers: dict[str, CapabilityProvider] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: CapabilityProvider) -> None:
        provider_id = getattr(provider, "provider_id", None)
        revision = getattr(provider, "revision", None)
        capabilities = getattr(provider, "capabilities", None)
        priority = getattr(provider, "priority", None)
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise ValueError("capability provider_id must be non-empty")
        if not isinstance(revision, str) or not revision.strip():
            raise ValueError("capability provider revision must be non-empty")
        if not isinstance(capabilities, tuple) or not capabilities or any(
            not isinstance(item, str) or not item.strip() for item in capabilities
        ):
            raise ValueError("capability provider must expose a non-empty immutable capability tuple")
        if len(set(capabilities)) != len(capabilities):
            raise ValueError("provider capabilities must be unique")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise ValueError("capability provider priority must be integer")
        if provider_id in self._providers:
            raise ValueError(f"duplicate capability provider: {provider_id}")
        if not callable(getattr(provider, "available", None)) or not callable(getattr(provider, "invoke", None)):
            raise ValueError("capability provider must expose available()/invoke()")
        self._providers[provider_id] = provider

    @property
    def provider_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))

    def providers_for(self, capability: str, *, include_unavailable: bool = False) -> tuple[CapabilityProvider, ...]:
        if not isinstance(capability, str) or not capability.strip():
            raise ValueError("capability must be non-empty")
        matching = [
            provider
            for provider in self._providers.values()
            if capability in provider.capabilities and (include_unavailable or provider.available())
        ]
        return tuple(sorted(matching, key=lambda provider: (-provider.priority, provider.provider_id)))

    def execute(self, capability: str, args: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(args, dict):
            raise ValueError("capability args must be an object")
        providers = self.providers_for(capability)
        if not providers:
            raise RuntimeError(f"capability unavailable: {capability}")
        failures: list[dict[str, str]] = []
        for provider in providers:
            try:
                result = provider.invoke(capability, dict(args))
            except (OSError, RuntimeError, ValueError) as exc:
                failures.append({"provider_id": provider.provider_id, "error_class": type(exc).__name__})
                continue
            if not isinstance(result, CapabilityResult):
                raise RuntimeError("capability provider returned an invalid result type")
            if result.capability != capability or result.provider_id != provider.provider_id:
                raise RuntimeError("capability provider result identity mismatch")
            rendered = result.descriptor()
            rendered["fallback_failures"] = failures
            return rendered
        raise RuntimeError(
            "all capability providers failed: "
            + ", ".join(item["provider_id"] + ":" + item["error_class"] for item in failures)
        )

    def descriptor(self) -> dict[str, Any]:
        capabilities = sorted({capability for provider in self._providers.values() for capability in provider.capabilities})
        providers = []
        for provider in sorted(self._providers.values(), key=lambda item: item.provider_id):
            desc = provider.descriptor()
            desc["available"] = bool(provider.available())
            providers.append(desc)
        return {
            "schema_version": "ctf-capability-catalog-v1",
            "capabilities": capabilities,
            "providers": providers,
            "execution_authority": "base_action_runtime_only_when_tool_registered",
            "truth_authority": "none",
        }

    def make_tool(self) -> ToolSpec:
        return ToolSpec(
            name="host_capability",
            description=(
                "Invoke one Harness-registered analysis capability provider by semantic capability name. "
                "Provider selection/fallback is Harness-owned and results are observations, never facts."
            ),
            handler=lambda capability, args=None: self.execute(capability, args or {}),
            side_effect=SideEffect.READ,
            idempotent=False,
            permission="auto",
            failure_modes=["capability_unavailable", "provider_failed", "invalid_provider_result"],
            provenance={
                "kind": "ctf_capability_dispatch",
                "schema": "ctf-capability-catalog-v1",
                "provider_fallback": True,
                "truth_authority": "none",
            },
        )
