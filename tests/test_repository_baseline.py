from __future__ import annotations

import json
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def _base_lock() -> dict[str, object]:
    return json.loads((ROOT / "base_harness.lock.json").read_text(encoding="utf-8"))


def test_base_optional_dependency_matches_lock() -> None:
    lock = _base_lock()
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["optional-dependencies"]["base"]

    assert dependencies == [
        f'{lock["package"]} @ git+https://github.com/{lock["repository"]}.git@{lock["commit"]}'
    ]


def test_verify_workflow_checks_out_locked_base_revision() -> None:
    lock = _base_lock()
    workflow = (ROOT / ".github" / "workflows" / "verify.yml").read_text(encoding="utf-8")

    assert f'repository: {lock["repository"]}' in workflow
    assert f'ref: {lock["commit"]}' in workflow


def test_permanent_verify_workflow_has_no_dreamhack_live_endpoint() -> None:
    workflow = (ROOT / ".github" / "workflows" / "verify.yml").read_text(encoding="utf-8").lower()

    assert "dreamhack.games" not in workflow
    assert "host3.dreamhack.games" not in workflow


def test_temporary_dreamhack_push_workflow_is_removed() -> None:
    assert not (ROOT / ".github" / "workflows" / "dh103-leak-temp.yml").exists()
