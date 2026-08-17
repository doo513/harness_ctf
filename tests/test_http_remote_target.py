from __future__ import annotations

import pytest

from ctf_harness.competition.ingest import normalize_connection_endpoint
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    AgentSpec,
    NetworkPolicy,
    OperationalChallengeRef,
    OraclePolicy,
    RemoteTargetSpec,
    RemoteTransport,
    SolveBudget,
    SolveSpec,
)


def _challenge(endpoint: str) -> OperationalChallengeRef:
    manifest = ChallengeManifest(
        challenge_id="http-target-fixture",
        event="controlled",
        description="HTTP target fixture",
        artifact_refs=(),
        remote_endpoints=(endpoint,),
        category_hint="web",
        flag_format="flag{...}",
        allowed_network=True,
        allowed_tools=("scoped_http",),
        runner_image_digest="sha256:" + "6" * 64,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )
    return OperationalChallengeRef.from_manifest(manifest, {})


def _agent() -> AgentSpec:
    return AgentSpec("controlled", "fixture", "r1", "ctf-llm-controller-v2")


def test_http_remote_target_accepts_http_https_and_competition_ingest() -> None:
    http = "http://example.test:8080/challenge?mode=1"
    https = "https://example.test/challenge"
    assert RemoteTargetSpec(http, RemoteTransport.HTTP).endpoint == http
    assert RemoteTargetSpec(https, RemoteTransport.HTTP).endpoint == https
    assert normalize_connection_endpoint(http) == http
    assert normalize_connection_endpoint(https) == https


def test_http_remote_target_rejects_credentials_fragment_and_wrong_scheme() -> None:
    with pytest.raises(ValueError, match="credentials"):
        RemoteTargetSpec("https://user:pass@example.test/challenge", RemoteTransport.HTTP)
    with pytest.raises(ValueError, match="fragment"):
        RemoteTargetSpec("https://example.test/challenge#secret", RemoteTransport.HTTP)
    with pytest.raises(ValueError, match="http:// or https://"):
        RemoteTargetSpec("tcp://example.test:80", RemoteTransport.HTTP)


def test_http_remote_solve_requires_manifest_admission_and_challenge_transport() -> None:
    endpoint = "https://example.test/challenge"
    challenge = _challenge(endpoint)
    target = RemoteTargetSpec(endpoint, RemoteTransport.HTTP)
    spec = SolveSpec(
        challenge=challenge,
        target=target,
        agent=_agent(),
        budget=SolveBudget(4, 10.0),
        network_policy=NetworkPolicy(True, False, False),
        oracle_policy=OraclePolicy("fixture-oracle"),
    )
    assert spec.target.transport is RemoteTransport.HTTP

    with pytest.raises(ValueError, match="not admitted"):
        SolveSpec(
            challenge=challenge,
            target=RemoteTargetSpec("https://other.test/challenge", RemoteTransport.HTTP),
            agent=_agent(),
            budget=SolveBudget(4, 10.0),
            network_policy=NetworkPolicy(True, False, False),
            oracle_policy=OraclePolicy("fixture-oracle"),
        )

    with pytest.raises(ValueError, match="blocks challenge transport"):
        SolveSpec(
            challenge=challenge,
            target=target,
            agent=_agent(),
            budget=SolveBudget(4, 10.0),
            network_policy=NetworkPolicy(False, False, False),
            oracle_policy=OraclePolicy("fixture-oracle"),
        )
