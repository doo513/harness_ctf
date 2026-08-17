from __future__ import annotations

from typing import Iterable, Sequence

from .base import DomainPlaybook


class DomainRegistry:
    """Registry of advisory domain playbooks; never an executable tool registry."""

    def __init__(self, playbooks: Iterable[DomainPlaybook] = ()):
        self._playbooks: dict[str, DomainPlaybook] = {}
        for playbook in playbooks:
            self.register(playbook)

    def register(self, playbook: DomainPlaybook) -> None:
        domain = getattr(playbook, "domain", None)
        revision = getattr(playbook, "revision", None)
        snapshot = getattr(playbook, "snapshot", None)
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain playbook must expose a non-empty domain")
        if not isinstance(revision, str) or not revision.strip():
            raise ValueError("domain playbook must expose a non-empty revision")
        if not callable(snapshot):
            raise ValueError("domain playbook must expose snapshot(...)")
        if domain in self._playbooks:
            raise ValueError(f"duplicate domain playbook: {domain}")
        self._playbooks[domain] = playbook

    @property
    def domains(self) -> tuple[str, ...]:
        return tuple(sorted(self._playbooks))

    def require(self, domain: str) -> DomainPlaybook:
        if domain not in self._playbooks:
            raise ValueError(f"unregistered CTF domain: {domain}")
        return self._playbooks[domain]

    def project(
        self,
        *,
        active_domains: Sequence[str],
        verified_fact_keys: Sequence[str],
        hypothesis_statuses: Sequence[str],
        available_tools: Sequence[str],
        completed: bool,
    ) -> dict:
        if not isinstance(active_domains, (tuple, list)) or not active_domains:
            raise ValueError("at least one active domain is required")
        if len(set(active_domains)) != len(active_domains):
            raise ValueError("active domains must be unique")
        snapshots = []
        for domain in active_domains:
            snapshots.append(
                self.require(domain).snapshot(
                    verified_fact_keys=verified_fact_keys,
                    hypothesis_statuses=hypothesis_statuses,
                    available_tools=available_tools,
                    completed=completed,
                )
            )
        return {
            "schema_version": "ctf-domain-registry-v1",
            "active_domains": list(active_domains),
            "registered_domains": list(self.domains),
            "playbooks": snapshots,
            "behavior": "advisory_not_mandatory",
            "execution_authority": "none",
            "truth_authority": "none",
            "completion_authority": "none",
        }
