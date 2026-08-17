from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from ctf_harness.sandbox import AnalysisSandbox, AnalysisSandboxLayout


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ctf-analysis-sandbox-") as td:
        root = Path(td)
        source = root / "admitted.bin"
        source.write_bytes(b"ADMITTED_ORIGINAL_513\n")
        source_hash = sha(source)
        layout = AnalysisSandboxLayout.prepare(
            root / "layout",
            admitted_inputs={"chal": source},
            expected_sha256={"chal": source_hash},
        )
        sandbox = AnalysisSandbox(layout)
        att = sandbox.backend.isolation_attestation(workspace=layout.work_dir)
        if att.source != "runtime_probe" or not att.strong_filesystem_boundary or not att.network_isolated:
            raise RuntimeError(f"analysis sandbox lacks live strong isolation: {att}")

        mutate = sandbox.backend.run_argv(
            workspace=layout.work_dir,
            argv=["/bin/sh", "-c", "printf MUTATED > input/chal"],
            timeout_seconds=5.0,
            env=None,
        )
        if mutate.returncode == 0:
            raise AssertionError("read-only admitted input was writable")
        if sha(layout.input_dir / "chal") != source_hash or sha(source) != source_hash:
            raise AssertionError("admitted input identity changed")

        generated = sandbox.backend.run_argv(
            workspace=layout.work_dir,
            argv=["/bin/sh", "-c", "printf 'print(513)\\n' > generated/solver.py && test -s generated/solver.py"],
            timeout_seconds=5.0,
            env=None,
        )
        if generated.returncode != 0 or not (layout.generated_dir / "solver.py").is_file():
            raise AssertionError(f"RW generated area failed: {generated}")

        network = sandbox.backend.run_argv(
            workspace=layout.work_dir,
            argv=[
                "/usr/bin/python3",
                "-c",
                "import socket,sys; s=socket.socket(); s.settimeout(.3); "
                "\ntry: s.connect(('1.1.1.1',80))\nexcept OSError: sys.exit(0)\nsys.exit(9)",
            ],
            timeout_seconds=5.0,
            env=None,
        )
        if network.returncode != 0:
            raise AssertionError("analysis sandbox unexpectedly reached unauthorized network")

        print(json.dumps({
            "probe": "analysis-sandbox-live-v1",
            "all_passed": True,
            "input_write_blocked": True,
            "generated_write_allowed": True,
            "network_denied": True,
            "input_sha256": source_hash,
            "attestation_source": att.source,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
