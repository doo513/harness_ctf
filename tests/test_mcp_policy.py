from __future__ import annotations

from pathlib import Path

from ctf_harness.configuration import load_configuration
from ctf_harness.mcp import build_mcp_registry


def test_public_mcp_tool_specs_require_confirmation_for_remote_calls(tmp_path: Path):
    path = tmp_path / "harness.toml"
    path.write_text(
        """
[model]
active = "primary"
[models.primary]
provider = "openai"
model = "gpt-test"
api_key_env = "OPENAI_API_KEY"

[mcp_servers.analysis]
transport = "streamable_http"
endpoint = "https://mcp.example/mcp"
allowed_tools = ["search"]
""",
        encoding="utf-8",
    )
    registry = build_mcp_registry(load_configuration(path), environ={})
    specs = {spec.name: spec for spec in registry.tool_specs()}
    assert specs["mcp_list"].permission == "auto"
    assert specs["mcp_call"].permission == "confirm"
    assert specs["mcp_call"].provenance["approval_policy"] == "operator_confirm_required"
