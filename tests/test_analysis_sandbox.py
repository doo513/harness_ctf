from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from harness.core.sandbox import RecordingIsolatedTestBackend

from ctf_harness.sandbox import AnalysisSandbox, AnalysisSandboxLayout


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_analysis_layout_copies_admitted_inputs_and_separates_rw_work(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"immutable-original")
    layout = AnalysisSandboxLayout.prepare(
        tmp_path / "analysis",
        admitted_inputs={"chal": source},
        expected_sha256={"chal": _sha(source)},
    )
    assert (layout.input_dir / "chal").read_bytes() == b"immutable-original"
    assert (layout.work_dir / "input").is_symlink()
    assert layout.generated_dir.is_dir()
    assert layout.artifacts_dir.is_dir()
    desc = layout.descriptor()
    assert desc["input_mode"] == "read_only"
    assert desc["work_mode"] == "read_write"
    assert desc["truth_authority"] == "none"


def test_analysis_layout_rejects_traversal_and_hash_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    with pytest.raises(ValueError, match="normalized relative"):
        AnalysisSandboxLayout.prepare(tmp_path / "bad1", admitted_inputs={"../chal": source})
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        AnalysisSandboxLayout.prepare(
            tmp_path / "bad2",
            admitted_inputs={"chal": source},
            expected_sha256={"chal": "0" * 64},
        )


def test_analysis_exec_is_distinct_from_target_execution_authority(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    layout = AnalysisSandboxLayout.prepare(tmp_path / "analysis", admitted_inputs={"chal": source})
    sandbox = AnalysisSandbox(layout, backend=RecordingIsolatedTestBackend())
    tool = sandbox.tool(timeout_seconds=7)
    assert tool.name == "analysis_exec"
    assert tool.execution_workspace == layout.work_dir.resolve()
    assert tool.provenance["network_mode"] == "deny"
    assert tool.provenance["target_execution_authority"] == "none"
    assert "input/" in tool.description
