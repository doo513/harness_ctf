from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from typing import Any, Mapping
from urllib.parse import urlsplit

from harness.core.storage import canonical_hash

from ctf_harness.manifest.fingerprint import manifest_fingerprint
from ctf_harness.manifest.models import ChallengeManifest


def _require_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _require_sha256(value: object, *, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise ValueError(f"{field_name} must be lowercase SHA-256 hex")
    return value


def _artifact_bindings(artifact_hashes: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(artifact_hashes, Mapping):
        raise ValueError("artifact_hashes must be a mapping")
    pairs: list[tuple[str, str]] = []
    for ref, digest in artifact_hashes.items():
        pairs.append(
            (
                _require_text(ref, field_name="artifact reference"),
                _require_sha256(digest, field_name=f"artifact hash for {ref!r}"),
            )
        )
    if len({ref for ref, _ in pairs}) != len(pairs):
        raise ValueError("artifact references must be unique")
    return tuple(sorted(pairs))


def _reject_endpoint_userinfo(endpoint: str, *, field_name: str) -> str:
    normalized = _require_text(endpoint, field_name=field_name)
    if normalized != endpoint:
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    parsed = urlsplit(normalized)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field_name} must not contain embedded credentials")
    return normalized


def _validate_tcp_endpoint(endpoint: str) -> str:
    normalized = _reject_endpoint_userinfo(endpoint, field_name="endpoint")
    parsed = urlsplit(normalized)
    if parsed.scheme != "tcp":
        raise ValueError("TCP target endpoint must use tcp:// scheme")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("TCP target endpoint must not contain path/query/fragment")
    if not parsed.hostname:
        raise ValueError("TCP target endpoint host is missing")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("TCP target endpoint port is invalid") from exc
    if port is None or not (1 <= port <= 65535):
        raise ValueError("TCP target endpoint port must be in 1..65535")
    return normalized


@dataclass(frozen=True, init=False)
class OperationalChallengeRef:
    """Immutable operational snapshot derived only from ChallengeManifest."""

    challenge_id: str
    challenge_revision: str
    manifest_fingerprint: str
    artifact_hashes: tuple[tuple[str, str], ...]
    remote_endpoints: tuple[str, ...]
    allowed_network: bool
    oracle_type: str
    benchmark_policy: str

    def __post_init__(self) -> None:
        _require_text(self.challenge_id, field_name="challenge_id")
        _require_text(self.challenge_revision, field_name="challenge_revision")
        _require_sha256(self.manifest_fingerprint, field_name="manifest_fingerprint")
        if not isinstance(self.artifact_hashes, tuple):
            raise ValueError("artifact_hashes must be an immutable tuple")
        if any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
            for item in self.artifact_hashes
        ):
            raise ValueError("artifact_hashes must contain (ref, sha256) tuples")
        normalized = _artifact_bindings(dict(self.artifact_hashes))
        if normalized != self.artifact_hashes:
            raise ValueError("artifact_hashes must be unique and canonically sorted")
        if not isinstance(self.remote_endpoints, tuple):
            raise ValueError("remote_endpoints must be an immutable tuple")
        for endpoint in self.remote_endpoints:
            _reject_endpoint_userinfo(endpoint, field_name="remote endpoint")
        if len(set(self.remote_endpoints)) != len(self.remote_endpoints):
            raise ValueError("remote_endpoints must be unique")
        if not isinstance(self.allowed_network, bool):
            raise ValueError("allowed_network must be boolean")
        _require_text(self.oracle_type, field_name="oracle_type")
        _require_text(self.benchmark_policy, field_name="benchmark_policy")

    @classmethod
    def _from_bound_fields(
        cls,
        *,
        challenge_id: str,
        challenge_revision: str,
        manifest_fingerprint_value: str,
        artifact_hashes: tuple[tuple[str, str], ...],
        remote_endpoints: tuple[str, ...],
        allowed_network: bool,
        oracle_type: str,
        benchmark_policy: str,
    ) -> "OperationalChallengeRef":
        instance = object.__new__(cls)
        object.__setattr__(instance, "challenge_id", challenge_id)
        object.__setattr__(instance, "challenge_revision", challenge_revision)
        object.__setattr__(instance, "manifest_fingerprint", manifest_fingerprint_value)
        object.__setattr__(instance, "artifact_hashes", artifact_hashes)
        object.__setattr__(instance, "remote_endpoints", remote_endpoints)
        object.__setattr__(instance, "allowed_network", allowed_network)
        object.__setattr__(instance, "oracle_type", oracle_type)
        object.__setattr__(instance, "benchmark_policy", benchmark_policy)
        instance.__post_init__()
        return instance

    @classmethod
    def from_manifest(
        cls,
        manifest: ChallengeManifest,
        artifact_hashes: Mapping[str, str],
    ) -> "OperationalChallengeRef":
        if not isinstance(manifest, ChallengeManifest):
            raise ValueError("manifest must be ChallengeManifest")
        bindings = _artifact_bindings(artifact_hashes)
        fingerprint = manifest_fingerprint(manifest, dict(bindings))
        return cls._from_bound_fields(
            challenge_id=manifest.challenge_id,
            challenge_revision=manifest.challenge_revision,
            manifest_fingerprint_value=fingerprint,
            artifact_hashes=bindings,
            remote_endpoints=tuple(manifest.remote_endpoints),
            allowed_network=manifest.allowed_network,
            oracle_type=manifest.oracle_type,
            benchmark_policy=manifest.benchmark_policy,
        )

    def artifact_sha256(self, ref: str) -> str:
        key = _require_text(ref, field_name="artifact_ref")
        matches = [digest for artifact_ref, digest in self.artifact_hashes if artifact_ref == key]
        if len(matches) != 1:
            raise ValueError(f"artifact is not admitted by challenge manifest: {key!r}")
        return matches[0]

    def descriptor(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "challenge_revision": self.challenge_revision,
            "manifest_fingerprint": self.manifest_fingerprint,
            "artifact_hashes": [list(item) for item in self.artifact_hashes],
            "remote_endpoints": list(self.remote_endpoints),
            "allowed_network": self.allowed_network,
            "oracle_type": self.oracle_type,
            "benchmark_policy": self.benchmark_policy,
        }


class CredentialKind(str, Enum):
    ENV = "env"
    KEYRING = "keyring"
    SESSION = "session"


@dataclass(frozen=True)
class CredentialRef:
    kind: CredentialKind
    locator: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CredentialKind):
            raise ValueError("credential kind must be CredentialKind")
        _require_text(self.locator, field_name="credential locator")

    def descriptor(self) -> dict[str, str]:
        return {"kind": self.kind.value, "locator": self.locator}


class RuntimeKind(str, Enum):
    NATIVE = "native"
    CUSTOM_ARGV = "custom_argv"
    QEMU_USER = "qemu_user"


@dataclass(frozen=True)
class LocalTargetSpec:
    artifact_ref: str
    target_sha256: str
    architecture: str
    runtime_kind: RuntimeKind
    runtime_profile_id: str

    def __post_init__(self) -> None:
        _require_text(self.artifact_ref, field_name="artifact_ref")
        _require_sha256(self.target_sha256, field_name="target_sha256")
        _require_text(self.architecture, field_name="architecture")
        if not isinstance(self.runtime_kind, RuntimeKind):
            raise ValueError("runtime_kind must be RuntimeKind")
        _require_text(self.runtime_profile_id, field_name="runtime_profile_id")

    def descriptor(self) -> dict[str, Any]:
        return {
            "kind": "local",
            "artifact_ref": self.artifact_ref,
            "target_sha256": self.target_sha256,
            "architecture": self.architecture,
            "runtime_kind": self.runtime_kind.value,
            "runtime_profile_id": self.runtime_profile_id,
        }


class RemoteTransport(str, Enum):
    TCP = "tcp"


@dataclass(frozen=True)
class RemoteTargetSpec:
    endpoint: str
    transport: RemoteTransport
    credential_ref: CredentialRef | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.transport, RemoteTransport):
            raise ValueError("transport must be RemoteTransport")
        if self.transport is RemoteTransport.TCP:
            _validate_tcp_endpoint(self.endpoint)
        else:
            _reject_endpoint_userinfo(self.endpoint, field_name="endpoint")
        if self.credential_ref is not None and not isinstance(self.credential_ref, CredentialRef):
            raise ValueError("credential_ref must be CredentialRef when provided")

    def descriptor(self) -> dict[str, Any]:
        return {
            "kind": "remote",
            "endpoint": self.endpoint,
            "transport": self.transport.value,
            "credential_ref": None if self.credential_ref is None else self.credential_ref.descriptor(),
        }


TargetSpec = LocalTargetSpec | RemoteTargetSpec


@dataclass(frozen=True)
class AgentSpec:
    provider: str
    model_id: str
    model_revision: str
    controller_revision: str

    def __post_init__(self) -> None:
        for field_name in ("provider", "model_id", "model_revision", "controller_revision"):
            _require_text(getattr(self, field_name), field_name=field_name)

    def descriptor(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "model_revision": self.model_revision,
            "controller_revision": self.controller_revision,
        }


@dataclass(frozen=True)
class SolveBudget:
    max_steps: int
    max_wall_seconds: float
    max_tokens: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.max_steps, int) or isinstance(self.max_steps, bool) or self.max_steps <= 0:
            raise ValueError("max_steps must be a positive integer")
        if (
            not isinstance(self.max_wall_seconds, (int, float))
            or isinstance(self.max_wall_seconds, bool)
            or not math.isfinite(float(self.max_wall_seconds))
            or self.max_wall_seconds <= 0
        ):
            raise ValueError("max_wall_seconds must be finite and positive")
        if self.max_tokens is not None and (
            not isinstance(self.max_tokens, int)
            or isinstance(self.max_tokens, bool)
            or self.max_tokens <= 0
        ):
            raise ValueError("max_tokens must be a positive integer when provided")

    def descriptor(self) -> dict[str, Any]:
        return {
            "max_steps": self.max_steps,
            "max_wall_seconds": float(self.max_wall_seconds),
            "max_tokens": self.max_tokens,
        }


@dataclass(frozen=True)
class NetworkPolicy:
    challenge_transport: bool
    general_internet: bool
    external_retrieval: bool

    def __post_init__(self) -> None:
        for field_name in ("challenge_transport", "general_internet", "external_retrieval"):
            if not isinstance(getattr(self, field_name), bool):
                raise ValueError(f"{field_name} must be boolean")

    def descriptor(self) -> dict[str, bool]:
        return {
            "challenge_transport": self.challenge_transport,
            "general_internet": self.general_internet,
            "external_retrieval": self.external_retrieval,
        }


@dataclass(frozen=True)
class OraclePolicy:
    policy_id: str
    oracle_type: str = "external"

    def __post_init__(self) -> None:
        _require_text(self.policy_id, field_name="oracle policy_id")
        if self.oracle_type != "external":
            raise ValueError("initial operational CTF profile requires external oracle authority")

    def descriptor(self) -> dict[str, str]:
        return {"policy_id": self.policy_id, "oracle_type": self.oracle_type}


@dataclass(frozen=True)
class OutputPolicy:
    preserve_artifacts: bool = True
    generate_writeup: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.preserve_artifacts, bool) or not isinstance(self.generate_writeup, bool):
            raise ValueError("output policy fields must be boolean")

    def descriptor(self) -> dict[str, bool]:
        return {
            "preserve_artifacts": self.preserve_artifacts,
            "generate_writeup": self.generate_writeup,
        }


class RunIntent(str, Enum):
    SOLVE = "solve"
    SMOKE = "smoke"
    COMPETITION = "competition"


class ActorCompleteBehavior(str, Enum):
    CHECK_EXTERNAL_ORACLE = "check_external_oracle"
    HALT_INCOMPLETE = "halt_incomplete"


class UnsupportedCapabilityBehavior(str, Enum):
    RECOVER = "recover"
    HALT_INCOMPLETE = "halt_incomplete"


@dataclass(frozen=True)
class TerminationPolicy:
    """Control-only stop policy; never a completion authority."""

    actor_complete: ActorCompleteBehavior
    unsupported_capability: UnsupportedCapabilityBehavior

    def __post_init__(self) -> None:
        if not isinstance(self.actor_complete, ActorCompleteBehavior):
            raise ValueError("actor_complete must be ActorCompleteBehavior")
        if not isinstance(self.unsupported_capability, UnsupportedCapabilityBehavior):
            raise ValueError("unsupported_capability must be UnsupportedCapabilityBehavior")

    @classmethod
    def for_intent(cls, intent: RunIntent) -> "TerminationPolicy":
        if not isinstance(intent, RunIntent):
            raise ValueError("intent must be RunIntent")
        if intent is RunIntent.SMOKE:
            return cls(
                ActorCompleteBehavior.HALT_INCOMPLETE,
                UnsupportedCapabilityBehavior.HALT_INCOMPLETE,
            )
        return cls(
            ActorCompleteBehavior.CHECK_EXTERNAL_ORACLE,
            UnsupportedCapabilityBehavior.RECOVER,
        )

    def validate_for_intent(self, intent: RunIntent) -> None:
        if not isinstance(intent, RunIntent):
            raise ValueError("run_intent must be RunIntent")
        required_complete = (
            ActorCompleteBehavior.HALT_INCOMPLETE
            if intent is RunIntent.SMOKE
            else ActorCompleteBehavior.CHECK_EXTERNAL_ORACLE
        )
        if self.actor_complete is not required_complete:
            raise ValueError(
                f"{intent.value} run requires actor_complete={required_complete.value}; "
                "run policy cannot weaken or redefine completion authority"
            )

    def descriptor(self) -> dict[str, str]:
        return {
            "actor_complete": self.actor_complete.value,
            "unsupported_capability": self.unsupported_capability.value,
            "completion_authority": "external_oracle_only",
        }


@dataclass(frozen=True)
class SolveSpec:
    challenge: OperationalChallengeRef
    target: TargetSpec
    agent: AgentSpec
    budget: SolveBudget
    network_policy: NetworkPolicy
    oracle_policy: OraclePolicy
    output_policy: OutputPolicy = OutputPolicy()
    run_intent: RunIntent = RunIntent.SOLVE
    termination_policy: TerminationPolicy | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.challenge, OperationalChallengeRef):
            raise ValueError("challenge must be OperationalChallengeRef")
        if not isinstance(self.target, (LocalTargetSpec, RemoteTargetSpec)):
            raise ValueError("target must be LocalTargetSpec or RemoteTargetSpec")
        if not isinstance(self.agent, AgentSpec):
            raise ValueError("agent must be AgentSpec")
        if not isinstance(self.budget, SolveBudget):
            raise ValueError("budget must be SolveBudget")
        if not isinstance(self.network_policy, NetworkPolicy):
            raise ValueError("network_policy must be NetworkPolicy")
        if not isinstance(self.oracle_policy, OraclePolicy):
            raise ValueError("oracle_policy must be OraclePolicy")
        if not isinstance(self.output_policy, OutputPolicy):
            raise ValueError("output_policy must be OutputPolicy")
        if not isinstance(self.run_intent, RunIntent):
            raise ValueError("run_intent must be RunIntent")
        policy = self.termination_policy
        if policy is None:
            policy = TerminationPolicy.for_intent(self.run_intent)
            object.__setattr__(self, "termination_policy", policy)
        if not isinstance(policy, TerminationPolicy):
            raise ValueError("termination_policy must be TerminationPolicy")
        policy.validate_for_intent(self.run_intent)
        if self.oracle_policy.oracle_type != self.challenge.oracle_type:
            raise ValueError("solve oracle authority differs from admitted challenge manifest")

        if isinstance(self.target, LocalTargetSpec):
            admitted_sha = self.challenge.artifact_sha256(self.target.artifact_ref)
            if self.target.target_sha256 != admitted_sha:
                raise ValueError("local target SHA-256 differs from admitted artifact hash")
        else:
            if self.target.endpoint not in self.challenge.remote_endpoints:
                raise ValueError("remote endpoint is not admitted by challenge manifest")
            if not self.challenge.allowed_network:
                raise ValueError("challenge manifest does not allow network target access")
            if not self.network_policy.challenge_transport:
                raise ValueError("solve network policy blocks challenge transport")

    def descriptor(self) -> dict[str, Any]:
        assert self.termination_policy is not None
        return {
            "challenge": self.challenge.descriptor(),
            "target": self.target.descriptor(),
            "agent": self.agent.descriptor(),
            "budget": self.budget.descriptor(),
            "network_policy": self.network_policy.descriptor(),
            "oracle_policy": self.oracle_policy.descriptor(),
            "output_policy": self.output_policy.descriptor(),
            "run_intent": self.run_intent.value,
            "termination_policy": self.termination_policy.descriptor(),
        }

    def fingerprint(self) -> str:
        return canonical_hash(self.descriptor())
