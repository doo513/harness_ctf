from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

EXPECTED_BASE_COMMIT = "75834ac1ecb6c022771c2efee1f19495f356ee76"
EXPECTED_BASE_PACKAGE = "verified-state-harness"
EXPECTED_BASE_VERSION = "0.9.1"

@dataclass(frozen=True)
class BaseLock:
    repository: str
    branch: str
    commit: str
    package: str
    version: str

    @classmethod
    def load(cls, path: str | Path) -> "BaseLock":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**data)

    def validate(self) -> None:
        if self.commit != EXPECTED_BASE_COMMIT:
            raise ValueError("base_harness commit does not match the reviewed evidence baseline")
        if self.package != EXPECTED_BASE_PACKAGE or self.version != EXPECTED_BASE_VERSION:
            raise ValueError("base_harness package identity does not match the reviewed baseline")
