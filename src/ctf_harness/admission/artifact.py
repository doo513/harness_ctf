from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class AdmittedArtifact:
    path: str
    sha256: str
    size: int


def _read_regular_file_once(path: str | Path) -> tuple[Path, bytes, int]:
    original = Path(path)
    info = original.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise ValueError("artifact admission rejects symbolic links")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("artifact path must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(original, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("opened artifact is not a regular file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk: break
            chunks.append(chunk)
        data = b"".join(chunks)
        if len(data) != opened.st_size:
            raise ValueError("artifact changed while being admitted")
        return original.resolve(strict=True), data, opened.st_size
    finally:
        os.close(fd)


def admit_artifact(path: str | Path, expected_sha256: str | None = None) -> AdmittedArtifact:
    resolved, data, size = _read_regular_file_once(path)
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
            raise ValueError("expected SHA-256 must be a 64-character hex digest")
        if digest != expected_sha256:
            raise ValueError("artifact SHA-256 mismatch")
    return AdmittedArtifact(str(resolved), digest, size)
