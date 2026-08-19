# 05 — Operator Interface Evidence

Status: **PASS**

## Scope

Provide a stable operator application boundary that can serve CLI, interactive terminal, future TUI, or other front ends without duplicating provider/platform/MCP integration logic.

## Implemented artifacts

- `src/ctf_harness/operator/service.py`
- operator JSON CLI / interactive shell modules and package entry points
- `tests/test_operator_service.py`

## Available operations

- status / Doctor report;
- construct the existing `CTFLLMController` from the configured Model Gateway;
- list/read competition challenges;
- download challenge artifacts into the standard run-workspace projection;
- list MCP servers/tools and make explicit human MCP calls;
- explicitly submit a flag through the site submission policy gate.

## Structural / safety evidence

- UI-facing code depends on `OperatorService` rather than provider-specific adapters.
- `controller()` binds the Model Gateway adapter to the existing `CTFLLMController`; it does not create a parallel solve loop.
- Operator status has no truth/completion authority and excludes secret values.
- Challenge downloads allow only one simple filename, reject traversal/absolute paths, reject duplicates and overwrite, and use exclusive creation.
- Multi-file persistence is transactional for newly created artifacts: a later write failure rolls back prior writes from that operation.
- Downloading does not itself perform verified artifact admission.
- Explicit human MCP invocation still returns authority-free observation data.
- Flag submission remains delegated to the configured site policy gate.

## Direct test evidence

`tests/test_operator_service.py` verifies:

1. secret-free, authority-free status output;
2. reuse of existing `CTFLLMController`;
3. challenge list/read behavior;
4. workspace preparation without artifact admission;
5. overwrite refusal;
6. unsafe filename rejection;
7. MCP results remain authority-free;
8. explicit submission delegation.

## Final regression evidence

GitHub Actions run `32202024136` passed the complete Base and CTF suites plus all operational/proof/evaluation probes after the operator layer was added. No separate UI-owned truth, verification, solve, or completion path was introduced.

## Non-claims

The current presentation is a dependency-light CLI/interactive shell over `OperatorService`. A full-screen TUI is intentionally presentation-only future work and can reuse this service without changing integration authority.
