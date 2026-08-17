from __future__ import annotations

from pathlib import Path

from ctf_harness.domains.registry import DomainRegistry
from ctf_harness.domains.standard import CryptoPlaybook, ForensicsPlaybook, MiscPlaybook, ReversePlaybook, WebPlaybook
from ctf_harness.tools.domain_recon import make_domain_recon_handler


def test_cross_domain_recon_is_bounded_observation_not_fact(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "from flask import Flask\napp=Flask(__name__)\n@app.route('/login')\ndef login():\n    return 'flag{example}'\n",
        encoding="utf-8",
    )
    digest = make_domain_recon_handler(tmp_path)("app.py")
    assert digest["schema_version"] == "ctf-recon-digest-v1"
    assert digest["kind"] == "source"
    assert digest["python_syntax"] == "valid"
    assert "web_route" in digest["indicators"]
    assert "flag_shape" in digest["indicators"]
    assert digest["truth_authority"] == "observation_only"
    assert digest["raw_artifact_preserved"] is True


def test_standard_playbooks_are_advisory_and_capability_driven() -> None:
    registry = DomainRegistry((ReversePlaybook(), CryptoPlaybook(), WebPlaybook(), ForensicsPlaybook(), MiscPlaybook()))
    for domain in registry.domains:
        projected = registry.project(
            active_domains=(domain,),
            verified_fact_keys=(),
            hypothesis_statuses=("open",),
            available_tools=("domain_recon", "analysis_exec"),
            completed=False,
        )
        playbook = projected["playbooks"][0]
        assert playbook["domain"] == domain
        assert playbook["hard_sequence"] is False
        assert playbook["truth_authority"] == "none"
        assert playbook["current"]["questions"]
