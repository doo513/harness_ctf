from __future__ import annotations

from pathlib import Path

from ctf_harness.configuration import load_configuration
from ctf_harness.doctor import Doctor, DoctorStatus, ToolRequirement


def _config(path: Path) -> Path:
    path.write_text(
        """
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"

[site]
active = "competition"
[sites.competition]
provider = "ctfd"
base_url = "https://ctf.example"
credential_kind = "env"
credential_locator = "CTFD_TOKEN"
""",
        encoding="utf-8",
    )
    return path


def test_doctor_is_read_only_and_reports_missing_credentials(tmp_path: Path):
    cfg = load_configuration(_config(tmp_path / "harness.toml"))
    report = Doctor(cfg, environ={}, tool_requirements=()).run()
    assert report.ready is False
    rendered = report.descriptor()
    assert rendered["mutations_performed"] is False
    failures = {check["name"] for check in rendered["checks"] if check["status"] == "fail"}
    assert failures == {"model.credential", "site.credential"}


def test_doctor_accepts_injected_environment_and_tool_discovery(tmp_path: Path):
    cfg = load_configuration(_config(tmp_path / "harness.toml"))
    found = {"required-tool": "/usr/bin/required-tool", "optional-tool": None}
    report = Doctor(
        cfg,
        environ={"OPENAI_API_KEY": "model-secret", "CTFD_TOKEN": "site-secret"},
        tool_requirements=(
            ToolRequirement("required-tool", required=True, purpose="required"),
            ToolRequirement("optional-tool", required=False, purpose="optional"),
        ),
        which=lambda command: found.get(command),
    ).run()
    assert report.ready is True
    checks = {check.name: check for check in report.checks}
    assert checks["model.credential"].status is DoctorStatus.PASS
    assert checks["site.credential"].status is DoctorStatus.PASS
    assert checks["tool.required-tool"].status is DoctorStatus.PASS
    assert checks["tool.optional-tool"].status is DoctorStatus.WARN
    assert "model-secret" not in str(report.descriptor())
    assert "site-secret" not in str(report.descriptor())


def test_doctor_fails_external_process_profile_when_command_missing(tmp_path: Path):
    path = tmp_path / "harness.toml"
    path.write_text(
        """
[model]
active = "local"
[models.local]
provider = "external_process"
command = ["missing-adapter"]
revision = "v1"
""",
        encoding="utf-8",
    )
    cfg = load_configuration(path)
    report = Doctor(cfg, environ={}, tool_requirements=(), which=lambda _: None).run()
    assert report.ready is False
    checks = {check.name: check for check in report.checks}
    assert checks["model.command"].status is DoctorStatus.FAIL
