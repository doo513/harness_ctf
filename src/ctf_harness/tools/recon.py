from __future__ import annotations
from pathlib import Path
from ctf_harness.recon.pwn import inspect_elf

def _resolve_workspace_file(workspace: str | Path, relative_path: str) -> Path:
    if not isinstance(relative_path, str) or not relative_path.strip(): raise ValueError("relative_path must be a non-empty string")
    raw = Path(relative_path)
    if raw.is_absolute(): raise ValueError("artifact path must be workspace-relative")
    root = Path(workspace).resolve(); unresolved = (root / raw).resolve(strict=False)
    try: unresolved.relative_to(root)
    except ValueError as exc: raise ValueError("artifact path escapes workspace") from exc
    candidate = (root / raw).resolve(strict=True)
    try: candidate.relative_to(root)
    except ValueError as exc: raise ValueError("artifact path escapes workspace") from exc
    if not candidate.is_file(): raise ValueError("artifact path must resolve to a regular file")
    return candidate

def make_pwn_recon_handler(workspace: str | Path):
    root = Path(workspace).resolve()
    def pwn_recon(relative_path: str):
        target = _resolve_workspace_file(root, relative_path); value = inspect_elf(target).dump(); value["workspace_relative_path"] = str(target.relative_to(root)); return value
    return pwn_recon
