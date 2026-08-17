from __future__ import annotations

from typing import Protocol, Sequence

from .base import DomainPlaybook


class DomainModule(Protocol):
    """One domain's cohesive contract without moving authority out of Harness Core."""

    domain: str
    revision: str
    playbook: DomainPlaybook

    def claim_specs(self) -> Sequence[object]: ...
    def build_verifiers(self) -> Sequence[object]: ...
    def progress_snapshot(self, verified_keys, *, completed: bool = False) -> dict: ...
    def descriptor(self) -> dict: ...


class DomainModuleRegistry:
    def __init__(self, modules: Sequence[DomainModule] = ()):
        self._modules: dict[str, DomainModule] = {}
        for module in modules:
            self.register(module)

    def register(self, module: DomainModule) -> None:
        domain = getattr(module, "domain", None)
        revision = getattr(module, "revision", None)
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain module must expose a non-empty domain")
        if not isinstance(revision, str) or not revision.strip():
            raise ValueError("domain module must expose a non-empty revision")
        if domain in self._modules:
            raise ValueError(f"duplicate domain module: {domain}")
        for method in ("claim_specs", "build_verifiers", "progress_snapshot", "descriptor"):
            if not callable(getattr(module, method, None)):
                raise ValueError(f"domain module must expose {method}()")
        self._modules[domain] = module

    def require(self, domain: str) -> DomainModule:
        try:
            return self._modules[domain]
        except KeyError as exc:
            raise ValueError(f"unregistered CTF domain module: {domain}") from exc

    @property
    def domains(self) -> tuple[str, ...]:
        return tuple(sorted(self._modules))

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-domain-module-registry-v1",
            "domains": [self._modules[name].descriptor() for name in self.domains],
            "truth_authority": "none",
            "execution_authority": "none",
        }
