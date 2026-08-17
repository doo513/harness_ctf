from __future__ import annotations

from dataclasses import replace

import pytest

from ctf_harness.manifest.fingerprint import manifest_fingerprint
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.operational.models import (
    AgentSpec,
    CredentialKind,
    CredentialRef,
    LocalTargetSpec,
    NetworkPolicy,
    OperationalChallengeRef,
    OraclePolicy,
    OutputPolicy,
    RemoteTargetSpec,
    RemoteTransport,
    RuntimeKind,
    SolveBudget,
    SolveSpec,
)


RUNNER = "sha256:" + "f" * 64
CHAL_SHA = "a" * 64
LIBC_SHA = "b" * 64
HASHES = {"chal": CHAL_SHA, "libc.so.6": LIBC_SHA}
ENDPOINT = "tcp://challenge.example:31337"


def _manifest(*, allowed_network: bool = True) -> ChallengeManifest:
    return ChallengeManifest(
        challenge_id="operational-pwn-1",
        event="controlled",
        description="WP10 operational contract fixture",
        artifact_refs=("chal", "libc.so.6"),
        remote_endpoints=(ENDPOINT,),
        category_hint="pwn",
        flag_format="flag{...}",
        allowed_network=allowed_network,
        allowed_tools=("pwn_crash_probe",),
        runner_image_digest=RUNNER,
        challenge_revision="r1",
        oracle_type="external",
        benchmark_policy="research",
    )


def _challenge(*, allowed_network: bool = True) -> OperationalChallengeRef:
    return OperationalChallengeRef.from_manifest(_manifest(allowed_network=allowed_network), HASHES)


def _agent() -> AgentSpec:
    return AgentSpec(
        provider="fixture-provider",
        model_id="fixture-model",
        model_revision="model-r1",
        controller_revision="controller-r1",
    )


def _budget() -> SolveBudget:
    return SolveBudget(max_steps=80, max_wall_seconds=300.0, max_tokens=50_000)


def _network(*, challenge_transport: bool = False) -> NetworkPolicy:
    return NetworkPolicy(
        challenge_transport=challenge_transport,
        general_internet=False,
        external_retrieval=False,
    )


def _local_target(*, target_sha256: str = CHAL_SHA, runtime_profile_id: str = "native-default") -> LocalTargetSpec:
    return LocalTargetSpec(
        artifact_ref="chal",
        target_sha256=target_sha256,
        architecture="x86_64",
        runtime_kind=RuntimeKind.NATIVE,
        runtime_profile_id=runtime_profile_id,
    )


def _local_solve(**kwargs) -> SolveSpec:
    values = {
        "challenge": _challenge(),
        "target": _local_target(),
        "agent": _agent(),
        "budget": _budget(),
        "network_policy": _network(),
        "oracle_policy": OraclePolicy("external-flag-v1"),
        "output_policy": OutputPolicy(),
    }
    values.update(kwargs)
    return SolveSpec(**values)


def test_operational_challenge_ref_is_derived_from_manifest_identity() -> None:
    manifest = _manifest()
    challenge = OperationalChallengeRef.from_manifest(
        manifest,
        {"libc.so.6": LIBC_SHA, "chal": CHAL_SHA},
    )

    assert challenge.challenge_id == manifest.challenge_id
    assert challenge.challenge_revision == manifest.challenge_revision
    assert challenge.manifest_fingerprint == manifest_fingerprint(manifest, HASHES)
    assert challenge.artifact_hashes == (("chal", CHAL_SHA), ("libc.so.6", LIBC_SHA))
    assert challenge.artifact_sha256("chal") == CHAL_SHA


def test_operational_challenge_ref_rejects_non_manifest_artifact_set() -> None:
    with pytest.raises(ValueError, match="artifact hash set does not match manifest"):
        OperationalChallengeRef.from_manifest(_manifest(), {"chal": CHAL_SHA})


def test_credential_ref_carries_locator_not_secret_value() -> None:
    credential = CredentialRef(CredentialKind.ENV, "CTF_TOKEN")

    assert credential.descriptor() == {"kind": "env", "locator": "CTF_TOKEN"}
    assert "value" not in credential.descriptor()
    with pytest.raises(TypeError):
        CredentialRef(CredentialKind.ENV, "CTF_TOKEN", **{"value": "secret"})


def test_credential_ref_rejects_untyped_kind() -> None:
    with pytest.raises(ValueError, match="CredentialKind"):
        CredentialRef("env", "CTF_TOKEN")


def test_remote_target_rejects_credentials_or_tokens_embedded_in_endpoint() -> None:
    with pytest.raises(ValueError, match="embedded credentials"):
        RemoteTargetSpec("tcp://user:secret@challenge.example:31337", RemoteTransport.TCP)
    with pytest.raises(ValueError, match="path/query/fragment"):
        RemoteTargetSpec("tcp://challenge.example:31337/?token=secret", RemoteTransport.TCP)


def test_local_solve_binds_target_to_admitted_artifact() -> None:
    spec = _local_solve()

    assert spec.target.target_sha256 == CHAL_SHA
    assert spec.descriptor()["challenge"]["manifest_fingerprint"] == spec.challenge.manifest_fingerprint
    assert len(spec.fingerprint()) == 64


def test_local_target_hash_must_match_admitted_manifest_artifact() -> None:
    with pytest.raises(ValueError, match="differs from admitted artifact hash"):
        _local_solve(target=_local_target(target_sha256="c" * 64))


def test_local_target_artifact_must_exist_in_admitted_manifest() -> None:
    target = LocalTargetSpec(
        artifact_ref="missing",
        target_sha256="c" * 64,
        architecture="x86_64",
        runtime_kind=RuntimeKind.NATIVE,
        runtime_profile_id="native-default",
    )
    with pytest.raises(ValueError, match="artifact is not admitted"):
        _local_solve(target=target)


def test_remote_target_requires_admitted_endpoint_and_network_authority() -> None:
    remote = RemoteTargetSpec(ENDPOINT, RemoteTransport.TCP)
    spec = SolveSpec(
        challenge=_challenge(),
        target=remote,
        agent=_agent(),
        budget=_budget(),
        network_policy=_network(challenge_transport=True),
        oracle_policy=OraclePolicy("external-flag-v1"),
    )

    assert spec.target.endpoint == ENDPOINT
    assert spec.network_policy.challenge_transport

    with pytest.raises(ValueError, match="not admitted"):
        SolveSpec(
            challenge=_challenge(),
            target=RemoteTargetSpec("tcp://other.example:31337", RemoteTransport.TCP),
            agent=_agent(),
            budget=_budget(),
            network_policy=_network(challenge_transport=True),
            oracle_policy=OraclePolicy("external-flag-v1"),
        )

    with pytest.raises(ValueError, match="does not allow network"):
        SolveSpec(
            challenge=_challenge(allowed_network=False),
            target=remote,
            agent=_agent(),
            budget=_budget(),
            network_policy=_network(challenge_transport=True),
            oracle_policy=OraclePolicy("external-flag-v1"),
        )

    with pytest.raises(ValueError, match="blocks challenge transport"):
        SolveSpec(
            challenge=_challenge(),
            target=remote,
            agent=_agent(),
            budget=_budget(),
            network_policy=_network(challenge_transport=False),
            oracle_policy=OraclePolicy("external-flag-v1"),
        )


def test_remote_target_credential_is_reference_only() -> None:
    credential = CredentialRef(CredentialKind.SESSION, "dreamhack-session")
    target = RemoteTargetSpec(ENDPOINT, RemoteTransport.TCP, credential)

    assert target.descriptor()["credential_ref"] == {
        "kind": "session",
        "locator": "dreamhack-session",
    }


def test_initial_oracle_authority_cannot_be_weakened() -> None:
    with pytest.raises(ValueError, match="requires external oracle"):
        OraclePolicy("manual-only", oracle_type="manual")

    bad_challenge = replace(_challenge(), oracle_type="other")
    with pytest.raises(ValueError, match="oracle authority differs"):
        _local_solve(challenge=bad_challenge)


def test_solve_budget_is_strict_and_finite() -> None:
    with pytest.raises(ValueError, match="max_steps"):
        SolveBudget(max_steps=0, max_wall_seconds=1.0)
    with pytest.raises(ValueError, match="finite and positive"):
        SolveBudget(max_steps=1, max_wall_seconds=float("inf"))
    with pytest.raises(ValueError, match="max_tokens"):
        SolveBudget(max_steps=1, max_wall_seconds=1.0, max_tokens=0)


def test_runtime_and_transport_variants_fail_closed() -> None:
    with pytest.raises(ValueError, match="RuntimeKind"):
        LocalTargetSpec("chal", CHAL_SHA, "x86_64", "native", "native-default")
    with pytest.raises(ValueError, match="RemoteTransport"):
        RemoteTargetSpec(ENDPOINT, "tcp")


def test_solve_fingerprint_is_deterministic_and_sensitive_to_contract_changes() -> None:
    first = _local_solve()
    second = _local_solve()
    changed_runtime = _local_solve(target=_local_target(runtime_profile_id="native-r2"))
    changed_network = _local_solve(
        network_policy=NetworkPolicy(False, True, False),
    )

    assert first.fingerprint() == second.fingerprint()
    assert first.fingerprint() != changed_runtime.fingerprint()
    assert first.fingerprint() != changed_network.fingerprint()
