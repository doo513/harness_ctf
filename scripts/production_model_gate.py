from __future__ import annotations

import json
import os
import sys

from ctf_harness.agent_adapters import ExternalProcessModelAdapter, ModelProcessError
from ctf_harness.agent_controller import CTFLLMController


def main() -> int:
    try:
        adapter = ExternalProcessModelAdapter.from_environment(
            pass_env_names=tuple(
                name for name in os.environ.get("CTF_MODEL_ADAPTER_PASS_ENV", "").split(",") if name
            )
        )
    except ModelProcessError as exc:
        print(json.dumps({
            "gate": "A0-production-model",
            "status": "OPEN",
            "actual_production_llm_executed": False,
            "reason": str(exc),
        }, sort_keys=True))
        return 2

    controller = CTFLLMController(adapter, require_hypothesis_for_tools=False)
    decision = controller.decide(
        "Return a complete decision only for this transport-attestation probe.",
        object(),
        {
            "ctf": {
                "run": {"intent": "smoke", "completion_authority": "external_oracle_only"},
                "capabilities": {"available_tools": []},
                "playbook": {"behavior": "advisory_not_mandatory"},
                "hypotheses": [],
            }
        },
    )
    print(json.dumps({
        "gate": "A0-production-model",
        "status": "EXECUTED",
        "actual_production_llm_executed": True,
        "adapter": adapter.descriptor(),
        "decision_kind": decision.kind,
        "decision_payload_keys": sorted(decision.payload),
        "truth_authority": "none",
        "completion_authority": "external_oracle_only",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
