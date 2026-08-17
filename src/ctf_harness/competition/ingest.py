from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit

from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import RemoteTargetSpec, RemoteTransport

from .models import CompetitionChallengeSnapshot, DownloadedArtifact


@dataclass(frozen=True)
class CompetitionManifestInput:
    manifest: ChallengeManifest
    artifact_hashes: tuple[tuple[str, str], ...]

    def hash_mapping(self) -> dict[str, str]:
        return dict(self.artifact_hashes)


def normalize_connection_endpoint(connection_info: str | None) -> str | None:
    if connection_info is None or not connection_info.strip():
        return None
    text = connection_info.strip()
    parsed = urlsplit(text)
    if parsed.scheme in {"http", "https"}:
        RemoteTargetSpec(endpoint=text, transport=RemoteTransport.HTTP)
        return text
    if text.startswith("tcp://"):
        endpoint = text
    else:
        try:
            parts = shlex.split(text)
        except ValueError as exc:
            raise ValueError("malformed challenge connection_info") from exc
        if len(parts) != 3 or parts[0] not in {"nc", "ncat", "netcat"}:
            return None
        host = parts[1]
        try:
            port = int(parts[2])
        except ValueError as exc:
            raise ValueError("challenge connection_info has invalid TCP port") from exc
        if not 1 <= port <= 65535:
            raise ValueError("challenge connection_info port is outside 1..65535")
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        endpoint = f"tcp://{host}:{port}"
    RemoteTargetSpec(endpoint=endpoint, transport=RemoteTransport.TCP)
    return endpoint


def build_manifest_input(
    snapshot: CompetitionChallengeSnapshot,
    artifacts: Iterable[DownloadedArtifact],
    *,
    event: str,
    runner_image_digest: str,
    challenge_revision: str,
    flag_format: str | None = None,
    benchmark_policy: str = "competition",
    allowed_tools: tuple[str, ...] = (),
) -> CompetitionManifestInput:
    if not isinstance(snapshot, CompetitionChallengeSnapshot):
        raise ValueError("snapshot must be CompetitionChallengeSnapshot")
    downloaded = tuple(artifacts)
    refs = tuple(item.ref for item in downloaded)
    if len(set(refs)) != len(refs):
        raise ValueError("downloaded artifact refs must be unique")
    endpoint = normalize_connection_endpoint(snapshot.connection_info)
    manifest = ChallengeManifest(
        challenge_id=snapshot.challenge_id,
        event=event,
        description=snapshot.description,
        artifact_refs=refs,
        remote_endpoints=(() if endpoint is None else (endpoint,)),
        category_hint=snapshot.category,
        flag_format=flag_format,
        allowed_network=endpoint is not None,
        allowed_tools=allowed_tools,
        runner_image_digest=runner_image_digest,
        challenge_revision=challenge_revision,
        oracle_type="external",
        benchmark_policy=benchmark_policy,
    )
    hashes = tuple(sorted((item.ref, item.sha256) for item in downloaded))
    return CompetitionManifestInput(manifest, hashes)
