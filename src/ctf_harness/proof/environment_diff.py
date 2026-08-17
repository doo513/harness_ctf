from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence

from harness.core.storage import ArtifactStore, canonical_hash

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

BASELINE_PWN_COMPATIBILITY_FIELDS = (
    "architecture",
    "bits",
    "endianness",
    "pie",
    "nx",
    "protocol",
    "target_revision",
)

TRUSTED_ENVIRONMENT_SOURCES = {
    "local_probe",
    "remote_probe",
    "operator_manifest",
}


def _optional_digest(value: str | None, *, field: str) -> None:
    if value is not None and (not isinstance(value, str) or not _HEX64.fullmatch(value)):
        raise ValueError(f"{field} must be 64 lowercase hex characters when present")


@dataclass(frozen=True)
class TargetEnvironmentFingerprint:
    architecture: str
    bits: int
    endianness: str
    pie: bool | None
    nx: bool | None
    protocol: str | None
    target_revision: str
    libc_sha256: str | None = None
    loader_sha256: str | None = None
    canary: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.architecture, str) or not self.architecture.strip():
            raise ValueError("architecture must be non-empty")
        if not isinstance(self.bits, int) or isinstance(self.bits, bool) or self.bits not in {32, 64}:
            raise ValueError("bits must be 32 or 64")
        if self.endianness not in {"little", "big"}:
            raise ValueError("endianness must be little or big")
        if self.pie is not None and not isinstance(self.pie, bool):
            raise ValueError("pie must be bool or None")
        if self.nx is not None and not isinstance(self.nx, bool):
            raise ValueError("nx must be bool or None")
        if self.canary is not None and not isinstance(self.canary, bool):
            raise ValueError("canary must be bool or None")
        if self.protocol is not None and (not isinstance(self.protocol, str) or not self.protocol.strip()):
            raise ValueError("protocol must be non-empty when present")
        if not isinstance(self.target_revision, str) or not self.target_revision.strip():
            raise ValueError("target_revision must be non-empty")
        _optional_digest(self.libc_sha256, field="libc_sha256")
        _optional_digest(self.loader_sha256, field="loader_sha256")

    def dump(self) -> dict:
        return asdict(self)

    def digest(self) -> str:
        return canonical_hash(self.dump())


@dataclass(frozen=True)
class EnvironmentDiff:
    differences: tuple[tuple[str, object, object], ...]
    missing_local: tuple[str, ...] = ()
    missing_remote: tuple[str, ...] = ()
    compared_fields: tuple[str, ...] = ()

    @property
    def adaptation_required(self) -> bool:
        return bool(self.differences)

    @property
    def conclusive(self) -> bool:
        return not self.missing_local and not self.missing_remote

    @property
    def compatible(self) -> bool:
        return self.conclusive and not self.differences


@dataclass(frozen=True)
class EnvironmentCompatibilityReceipt:
    schema_version: int
    kind: str
    proof_level: str
    local_fingerprint: str
    remote_fingerprint: str
    contract_fields: tuple[str, ...]
    differences: tuple[tuple[str, object, object], ...]
    missing_local: tuple[str, ...]
    missing_remote: tuple[str, ...]
    local_source: str
    remote_source: str
    compatible: bool

    def dump(self) -> dict:
        data = asdict(self)
        data["contract_fields"] = list(self.contract_fields)
        data["differences"] = [list(item) for item in self.differences]
        data["missing_local"] = list(self.missing_local)
        data["missing_remote"] = list(self.missing_remote)
        return data


def compare_environments(local: Mapping, remote: Mapping) -> EnvironmentDiff:
    """Backward-compatible generic diff helper; not itself semantic authority."""
    keys = tuple(sorted(set(local) | set(remote)))
    differences = tuple((key, local.get(key), remote.get(key)) for key in keys if local.get(key) != remote.get(key))
    return EnvironmentDiff(differences=differences, compared_fields=keys)


def _normalized_contract_fields(required_fields: Sequence[str]) -> tuple[str, ...]:
    fields = tuple(dict.fromkeys(str(item) for item in required_fields))
    if not fields or any(not field for field in fields):
        raise ValueError("environment compatibility contract must name non-empty fields")
    missing_baseline = set(BASELINE_PWN_COMPATIBILITY_FIELDS) - set(fields)
    if missing_baseline:
        raise ValueError(
            "Pwn environment contract cannot omit baseline fields: "
            + ", ".join(sorted(missing_baseline))
        )
    return fields


def compare_target_environments(
    local: Mapping,
    remote: Mapping,
    *,
    required_fields: Sequence[str] = BASELINE_PWN_COMPATIBILITY_FIELDS,
) -> EnvironmentDiff:
    fields = _normalized_contract_fields(required_fields)
    unknown = [field for field in fields if field not in local and field not in remote]
    if unknown:
        # Unknown contract field is a schema/configuration error, not a runtime
        # mismatch. It must not quietly become a compatible receipt.
        raise ValueError("environment contract contains unknown fields: " + ", ".join(unknown))
    missing_local = tuple(field for field in fields if field not in local or local.get(field) is None)
    missing_remote = tuple(field for field in fields if field not in remote or remote.get(field) is None)
    differences = tuple(
        (field, local.get(field), remote.get(field))
        for field in fields
        if field not in missing_local
        and field not in missing_remote
        and local.get(field) != remote.get(field)
    )
    return EnvironmentDiff(
        differences=differences,
        missing_local=missing_local,
        missing_remote=missing_remote,
        compared_fields=fields,
    )


def build_environment_compatibility_receipt(
    local: TargetEnvironmentFingerprint,
    remote: TargetEnvironmentFingerprint,
    *,
    local_source: str,
    remote_source: str,
    required_fields: Sequence[str] = BASELINE_PWN_COMPATIBILITY_FIELDS,
) -> EnvironmentCompatibilityReceipt:
    if local_source not in TRUSTED_ENVIRONMENT_SOURCES or remote_source not in TRUSTED_ENVIRONMENT_SOURCES:
        raise ValueError("environment source is not trusted for compatibility authority")
    diff = compare_target_environments(local.dump(), remote.dump(), required_fields=required_fields)
    return EnvironmentCompatibilityReceipt(
        schema_version=1,
        kind="pwn_environment_compatibility_receipt",
        proof_level="P4_ENVIRONMENT",
        local_fingerprint=local.digest(),
        remote_fingerprint=remote.digest(),
        contract_fields=diff.compared_fields,
        differences=diff.differences,
        missing_local=diff.missing_local,
        missing_remote=diff.missing_remote,
        local_source=local_source,
        remote_source=remote_source,
        compatible=diff.compatible,
    )


def persist_environment_compatibility_receipt(
    store: ArtifactStore,
    receipt: EnvironmentCompatibilityReceipt,
    *,
    name: str = "pwn-environment-compatibility.json",
) -> str:
    return store.put_json(name, {"ok": True, "output": receipt.dump(), "error": None})
