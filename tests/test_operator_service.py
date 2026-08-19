from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_harness.agent_controller import CTFLLMController
from ctf_harness.competition.models import CompetitionChallengeSnapshot, DownloadedArtifact
from ctf_harness.configuration import HarnessConfiguration, ModelProviderConfig
from ctf_harness.doctor import DoctorReport
from ctf_harness.operator import OperatorError, OperatorService


class _Model:
    def complete(self, *, system: str, user: str) -> str:
        return '{"kind":"STOP","payload":{}}'


class _ModelGateway:
    def __init__(self):
        self.model = _Model()
        self.built = []

    def build(self, name=None):
        self.built.append(name)
        return self.model

    def descriptor(self):
        return {"schema_version": "fake-model-gateway", "credential_values_persisted": False}


class _Session:
    def __init__(self, *, allow_submit: bool = False, unsafe_name: bool = False):
        self.allow_submit = allow_submit
        self.unsafe_name = unsafe_name
        self.snapshot = CompetitionChallengeSnapshot(
            platform="ctfd",
            challenge_id="7",
            name="fixture",
            description="fixture",
            category="pwn",
            file_urls=("/files/chal",),
            connection_info="nc ctf.example 31337",
        )

    def list_challenges(self):
        return (self.snapshot,)

    def get_challenge(self, challenge_id: str):
        assert challenge_id == "7"
        return self.snapshot

    def download(self, file_url: str):
        ref = "../escape" if self.unsafe_name else "chal"
        return DownloadedArtifact(ref=ref, content=b"fixture", source_url="https://ctf.example/files/chal")

    def submit_flag(self, challenge_id: str, candidate: str):
        if not self.allow_submit:
            raise RuntimeError("submission disabled")
        return candidate == "flag{ok}"


class _SiteGateway:
    def __init__(self, session):
        self.session = session

    def build(self):
        return self.session

    def descriptor(self):
        return {"schema_version": "fake-site-gateway", "credential_values_persisted": False}


class _MCPRegistry:
    def descriptor(self):
        return {"schema_version": "fake-mcp", "truth_authority": "none"}

    def list_tools(self, server: str):
        return ()

    def call_tool(self, server: str, tool: str, arguments):
        return {"server": server, "tool": tool, "result": dict(arguments), "truth_authority": "none"}


class _Doctor:
    def run(self):
        return DoctorReport(())


def _service(session=None):
    config = HarnessConfiguration(
        active_model="primary",
        models={"primary": ModelProviderConfig(name="primary", provider="openai", model="gpt-test", api_key_env="OPENAI_API_KEY")},
    )
    model_gateway = _ModelGateway()
    return OperatorService(
        config,
        environ={"OPENAI_API_KEY": "secret"},
        model_gateway=model_gateway,
        site_gateway=_SiteGateway(session or _Session()),
        mcp_registry=_MCPRegistry(),
        doctor=_Doctor(),
    ), model_gateway


def test_operator_status_is_secret_free_and_has_no_truth_authority():
    service, _ = _service()
    status = service.status()
    assert status["truth_authority"] == "none"
    assert status["completion_authority"] == "none"
    assert "secret" not in json.dumps(status)
    assert status["doctor"]["ready"] is True


def test_operator_controller_binds_gateway_model_to_existing_ctf_controller():
    service, gateway = _service()
    controller = service.controller()
    assert isinstance(controller, CTFLLMController)
    assert gateway.built == [None]


def test_operator_lists_and_reads_site_challenges():
    service, _ = _service()
    assert service.challenges()[0]["challenge_id"] == "7"
    assert service.challenge("7")["authority"] == "platform_snapshot_only"


def test_operator_download_prepares_workspace_without_artifact_admission(tmp_path: Path):
    service, _ = _service()
    result = service.download_challenge("7", tmp_path / "run")
    assert result["artifact_admission_performed"] is False
    assert (tmp_path / "run" / "input" / "chal").read_bytes() == b"fixture"
    assert result["artifacts"][0]["path"] == "input/chal"
    with pytest.raises(OperatorError, match="overwrite"):
        service.download_challenge("7", tmp_path / "run")


def test_operator_download_rejects_unsafe_provider_filename(tmp_path: Path):
    service, _ = _service(_Session(unsafe_name=True))
    with pytest.raises(OperatorError, match="simple filename"):
        service.download_challenge("7", tmp_path / "run")


def test_operator_mcp_call_remains_observation_only():
    service, _ = _service()
    result = service.mcp_call("analysis", "search", {"q": "x"})
    assert result["truth_authority"] == "none"


def test_operator_submit_is_explicit_and_delegated():
    service, _ = _service(_Session(allow_submit=True))
    assert service.submit_flag("7", "flag{ok}") is True
