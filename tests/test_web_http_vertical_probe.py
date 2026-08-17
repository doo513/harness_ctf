from __future__ import annotations

import importlib.util
from pathlib import Path


def test_controlled_web_http_vertical_probe() -> None:
    path = Path(__file__).resolve().parents[1] / "scripts" / "web_http_vertical_probe.py"
    spec = importlib.util.spec_from_file_location("web_http_vertical_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main() == 0
