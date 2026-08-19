from __future__ import annotations

import argparse
import json

from ctf_harness.configuration import ConfigurationError, load_configuration
from ctf_harness.doctor import Doctor


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only verified CTF harness readiness diagnostics")
    parser.add_argument("--config", default="harness.toml", help="path to harness TOML configuration")
    args = parser.parse_args()
    try:
        config = load_configuration(args.config)
        report = Doctor(config).run()
    except ConfigurationError as exc:
        print(json.dumps({"schema_version": "ctf-doctor-report-v2", "ready": False, "configuration_error": str(exc)}))
        return 2
    print(json.dumps(report.descriptor(), ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report.ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
