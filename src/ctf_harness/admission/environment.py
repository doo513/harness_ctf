from __future__ import annotations

import hashlib
import json
import platform
import re
from dataclasses import asdict, dataclass

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

@dataclass(frozen=True)
class EnvironmentFingerprint:
    runner_image_digest: str
    machine: str
    system: str
    python: str
    network_allowed: bool
    tool_inventory: tuple[str, ...]

    def digest(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()


def capture_environment(*, runner_image_digest: str, network_allowed: bool, tool_inventory=()) -> EnvironmentFingerprint:
    if not isinstance(runner_image_digest, str) or not _DIGEST_RE.fullmatch(runner_image_digest):
        raise ValueError("runner_image_digest must be sha256:<64 lowercase hex>")
    inventory = tuple(sorted(set(str(item) for item in tool_inventory)))
    return EnvironmentFingerprint(runner_image_digest, platform.machine(), platform.system(), platform.python_version(), bool(network_allowed), inventory)
