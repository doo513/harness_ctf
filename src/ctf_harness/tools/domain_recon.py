from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path

from ctf_harness.tools.recon import _resolve_workspace_file


_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _kind(sample: bytes, path: Path) -> str:
    if sample.startswith(b"\x7fELF"):
        return "elf"
    if sample.startswith(b"MZ"):
        return "pe"
    if sample.startswith(b"PK\x03\x04"):
        return "zip"
    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if sample.startswith(b"%PDF-"):
        return "pdf"
    suffix = path.suffix.lower()
    if suffix in {".py", ".js", ".ts", ".html", ".htm", ".php", ".java", ".c", ".cpp", ".rs", ".go"}:
        return "source"
    nul_ratio = sample.count(b"\x00") / max(1, len(sample))
    return "binary" if nul_ratio > 0.02 else "text"


def _indicators(text: str, kind: str, path: Path) -> list[str]:
    lowered = text.lower()
    found: set[str] = set()
    patterns = {
        "web_route": ("@app.route", "router.", "app.get(", "app.post(", "urlpatterns"),
        "auth": ("authorization", "session", "jwt", "csrf", "password"),
        "sql": ("select ", "insert ", "update ", "delete from", "execute("),
        "crypto_rsa": ("rsa", "modulus", "public_exponent", "private_exponent"),
        "crypto_symmetric": ("aes", "nonce", "iv", "ciphertext", "cbc", "gcm"),
        "flag_shape": ("flag{", "ctf{"),
        "network": ("http://", "https://", "socket", "connect("),
    }
    for label, needles in patterns.items():
        if any(needle in lowered for needle in needles):
            found.add(label)
    if kind in {"elf", "pe"}:
        found.add("native_executable")
    if path.suffix.lower() == ".py":
        found.add("python_source")
    return sorted(found)


def make_domain_recon_handler(workspace: str | Path, *, sample_limit: int = 2 * 1024 * 1024):
    root = Path(workspace).resolve()
    if not isinstance(sample_limit, int) or isinstance(sample_limit, bool) or sample_limit <= 0:
        raise ValueError("sample_limit must be a positive integer")

    def domain_recon(relative_path: str):
        target = _resolve_workspace_file(root, relative_path)
        size = target.stat().st_size
        with target.open("rb") as handle:
            sample = handle.read(sample_limit)
        kind = _kind(sample, target)
        strings = [match.decode("utf-8", errors="replace") for match in _PRINTABLE_RE.findall(sample)[:128]]
        text = sample.decode("utf-8", errors="replace") if kind in {"text", "source"} else "\n".join(strings)
        python_syntax = None
        if target.suffix.lower() == ".py":
            try:
                ast.parse(sample.decode("utf-8"))
                python_syntax = "valid"
            except (SyntaxError, UnicodeDecodeError):
                python_syntax = "invalid"
        return {
            "schema_version": "ctf-recon-digest-v1",
            "artifact": target.relative_to(root).as_posix(),
            "sha256": _sha256(target),
            "bytes": size,
            "kind": kind,
            "sample_bytes": len(sample),
            "sample_truncated": size > len(sample),
            "interesting_strings": strings[:64],
            "indicators": _indicators(text, kind, target),
            "python_syntax": python_syntax,
            "raw_artifact_preserved": True,
            "truth_authority": "observation_only",
        }

    return domain_recon
