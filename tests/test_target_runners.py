from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ctf_harness.operational.models import RuntimeKind
from ctf_harness.target.runners import NativeRunner, QemuUserRunner, fingerprint_workspace_tree


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "chal"
    target.write_bytes(b"target-v1")
    target.chmod(0o755)
    return workspace, target


def test_native_runner_binds_target_but_keeps_runtime_identity_separate(tmp_path: Path) -> None:
    workspace, target = _workspace(tmp_path)
    runner = NativeRunner("native-test")

    launch = runner.build_launch(
        workspace=workspace,
        target_relpath="chal",
        expected_target_sha256=_sha(target),
    )

    assert launch.runtime_kind is RuntimeKind.NATIVE
    assert launch.argv == ("./chal",)
    assert launch.target_sha256 == _sha(target)
    assert launch.runtime_descriptor() == {
        "profile_id": "native-test",
        "runtime_kind": "native",
        "runtime_artifacts": [],
        "runtime_args": [],
    }
    assert launch.target_sha256 not in repr(launch.runtime_descriptor())
    assert len(launch.runtime_fingerprint()) == 64
    assert len(launch.launch_fingerprint()) == 64


def test_native_runner_rejects_target_hash_mismatch_and_escape(tmp_path: Path) -> None:
    workspace, _ = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")

    with pytest.raises(ValueError, match="target SHA-256 differs"):
        NativeRunner().build_launch(
            workspace=workspace,
            target_relpath="chal",
            expected_target_sha256="0" * 64,
        )
    with pytest.raises(ValueError, match="escapes workspace"):
        NativeRunner().build_launch(workspace=workspace, target_relpath="../outside")


def test_qemu_runner_binds_qemu_loader_and_sysroot_without_replacing_target_identity(tmp_path: Path) -> None:
    workspace, target = _workspace(tmp_path)
    qemu = tmp_path / "qemu-aarch64-static"
    qemu.write_bytes(b"qemu-runtime-v1")
    qemu.chmod(0o755)

    sysroot = workspace / "rootfs"
    (sysroot / "lib").mkdir(parents=True)
    loader = sysroot / "lib" / "ld-musl-aarch64.so.1"
    loader.write_bytes(b"loader-v1")
    (sysroot / "lib" / "libc.so").write_bytes(b"libc-v1")
    sysroot_fp = fingerprint_workspace_tree(sysroot)

    runner = QemuUserRunner(
        profile_id="dh103-aarch64",
        qemu_path=str(qemu.resolve()),
        qemu_sha256=_sha(qemu),
        qemu_args=("-strace",),
        sysroot_relpath="rootfs",
        sysroot_fingerprint=sysroot_fp,
        loader_relpath="rootfs/lib/ld-musl-aarch64.so.1",
        loader_sha256=_sha(loader),
        loader_args=("--library-path", "./rootfs/lib"),
    )
    launch = runner.build_launch(
        workspace=workspace,
        target_relpath="chal",
        expected_target_sha256=_sha(target),
    )

    assert launch.runtime_kind is RuntimeKind.QEMU_USER
    assert launch.target_sha256 == _sha(target)
    assert launch.argv == (
        str(qemu.resolve()),
        "-L",
        "./rootfs",
        "-strace",
        "./rootfs/lib/ld-musl-aarch64.so.1",
        "--library-path",
        "./rootfs/lib",
        "./chal",
    )
    identities = {item.role: item for item in launch.runtime_artifacts}
    assert identities["qemu"].sha256 == _sha(qemu)
    assert identities["loader"].sha256 == _sha(loader)
    assert identities["sysroot"].sha256 == sysroot_fp
    assert launch.target_sha256 not in repr(launch.runtime_descriptor())


def test_qemu_runner_fails_closed_when_runtime_artifact_changes(tmp_path: Path) -> None:
    workspace, target = _workspace(tmp_path)
    qemu = tmp_path / "qemu-aarch64-static"
    qemu.write_bytes(b"qemu-v1")
    qemu_sha = _sha(qemu)
    sysroot = workspace / "rootfs"
    sysroot.mkdir()
    (sysroot / "libc.so").write_bytes(b"libc-v1")
    sysroot_fp = fingerprint_workspace_tree(sysroot)

    runner = QemuUserRunner(
        profile_id="qemu-test",
        qemu_path=str(qemu.resolve()),
        qemu_sha256=qemu_sha,
        sysroot_relpath="rootfs",
        sysroot_fingerprint=sysroot_fp,
    )

    qemu.write_bytes(b"qemu-v2")
    with pytest.raises(ValueError, match="QEMU executable SHA-256 differs"):
        runner.build_launch(
            workspace=workspace,
            target_relpath="chal",
            expected_target_sha256=_sha(target),
        )

    qemu.write_bytes(b"qemu-v1")
    (sysroot / "libc.so").write_bytes(b"libc-v2")
    with pytest.raises(ValueError, match="sysroot tree fingerprint differs"):
        runner.build_launch(
            workspace=workspace,
            target_relpath="chal",
            expected_target_sha256=_sha(target),
        )


def test_runtime_tree_rejects_symlink_identity_escape(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    link = tree / "link"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink unavailable")

    with pytest.raises(ValueError, match="symbolic link"):
        fingerprint_workspace_tree(tree)
