from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from ctf_harness.competition.base import CompetitionAdapter
from ctf_harness.competition.credentials import CredentialResolver
from ctf_harness.competition.ctfd import CTFdAdapter, CTFdAuthMode, HttpTransport
from ctf_harness.configuration.models import HarnessConfiguration, SiteProfileConfig
from ctf_harness.operational.models import CredentialKind, CredentialRef


class SiteAccessError(RuntimeError):
    pass


SiteFactory = Callable[[SiteProfileConfig], CompetitionAdapter]


@dataclass(frozen=True)
class SiteSession:
    """Configured platform session with explicit submission policy.

    This wrapper owns no solve/truth/completion authority. Submission is disabled
    unless the operator explicitly enables it in configuration.
    """

    profile_name: str
    adapter: CompetitionAdapter
    allow_submit: bool = False

    def validate_session(self) -> bool:
        return bool(self.adapter.validate_session())

    def list_challenges(self):
        return self.adapter.list_challenges()

    def get_challenge(self, challenge_id: str):
        return self.adapter.get_challenge(challenge_id)

    def download(self, file_url: str):
        return self.adapter.download(file_url)

    def submit_flag(self, challenge_id: str, candidate: str) -> bool:
        if not self.allow_submit:
            raise SiteAccessError("flag submission is disabled for this site profile")
        return bool(self.adapter.submit_flag(challenge_id, candidate))

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-site-session-v1",
            "profile_name": self.profile_name,
            "allow_submit": self.allow_submit,
            "truth_authority": "none",
            "completion_authority": "external_oracle_only",
        }


class SiteAccessGateway:
    """Resolve competition-site adapters from non-secret configuration."""

    def __init__(self, config: HarnessConfiguration):
        self.config = config
        self._factories: dict[str, SiteFactory] = {}

    def register(self, provider: str, factory: SiteFactory) -> None:
        normalized = provider.strip().lower()
        if not normalized:
            raise ValueError("site provider name must be non-empty")
        if normalized in self._factories:
            raise ValueError(f"site provider {normalized!r} is already registered")
        self._factories[normalized] = factory

    def build(self, name: str | None = None) -> SiteSession:
        cfg = self.config.site(name)
        provider = cfg.provider.strip().lower()
        try:
            factory = self._factories[provider]
        except KeyError as exc:
            raise SiteAccessError(f"unsupported site provider {cfg.provider!r}") from exc
        return SiteSession(profile_name=cfg.name, adapter=factory(cfg), allow_submit=cfg.allow_submit)

    def descriptor(self) -> dict:
        return {
            "schema_version": "ctf-site-access-gateway-v1",
            "active_site": self.config.active_site,
            "registered_providers": sorted(self._factories),
            "credential_values_persisted": False,
        }


def build_default_site_gateway(
    config: HarnessConfiguration,
    *,
    environ: Mapping[str, str] | None = None,
    keyring_getter=None,
    session_getter=None,
    ctfd_transport: HttpTransport | None = None,
) -> SiteAccessGateway:
    resolver = CredentialResolver(
        environ=environ,
        keyring_getter=keyring_getter,
        session_getter=session_getter,
    )
    gateway = SiteAccessGateway(config)

    def ctfd_factory(cfg: SiteProfileConfig) -> CompetitionAdapter:
        if not cfg.credential_locator:
            raise SiteAccessError(f"CTFd site profile {cfg.name!r} requires credential_locator")
        try:
            kind = CredentialKind(cfg.credential_kind)
        except ValueError as exc:
            raise SiteAccessError(f"unsupported credential kind {cfg.credential_kind!r}") from exc
        try:
            auth_mode = CTFdAuthMode(cfg.auth_mode)
        except ValueError as exc:
            raise SiteAccessError(f"unsupported CTFd auth mode {cfg.auth_mode!r}") from exc
        return CTFdAdapter(
            cfg.base_url,
            credential_ref=CredentialRef(kind=kind, locator=cfg.credential_locator),
            credential_resolver=resolver,
            auth_mode=auth_mode,
            cookie_name=cfg.cookie_name,
            transport=ctfd_transport,
        )

    gateway.register("ctfd", ctfd_factory)
    return gateway
