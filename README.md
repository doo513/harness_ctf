# verified-ctf-harness

CTF-specific semantic, execution, and proof layer for `doo513/base_harness`.

This repository intentionally does **not** reimplement the Verified-State kernel. The Base runtime remains the authority for execution, verification, recovery, and completion; CTF-specific integrations stay behind replaceable adapters and application-service boundaries.

## Operational readiness layer

The `implementation/operational-readiness` work adds the operator-facing stack around the existing SolveEngine in dependency order:

1. **Configuration & Model Gateway** — strict TOML configuration, non-secret credential references, OpenAI/Anthropic/Gemini HTTP adapters, and the existing external-process adapter.
2. **Site Access** — configured CTFd access using the existing CompetitionAdapter boundary; flag submission is disabled unless explicitly enabled.
3. **Doctor** — read-only checks for model/site credentials, local analysis tools, and MCP configuration.
4. **MCP** — Harness policy over the official MCP Python SDK v2. The SDK owns stdio/Streamable HTTP and protocol negotiation; the Harness owns configured servers, secret scoping, tool allowlists, operator approval, and trust classification.
5. **Operator Interface** — reusable `OperatorService`, JSON CLI commands, and an interactive terminal shell. Front ends do not receive truth or completion authority.

Copy `harness.example.toml` to a local `harness.toml`, configure profile names and URLs, and provide secret values through the referenced environment variables.

```bash
export OPENAI_API_KEY='...'
export CTFD_TOKEN='...'
python scripts/harness_doctor.py --config harness.toml
python scripts/harness_operator.py --config harness.toml status
python scripts/harness_operator.py --config harness.toml shell
```

Useful operator commands include `doctor`, `challenges`, `challenge`, `download`, `mcp`, `mcp-tools`, `mcp-call`, and `submit`. `download` prepares the standard run workspace input directory but deliberately does not admit downloaded data as verified truth.

## Authority boundary

The operational layer may select adapters, access configured sites, download artifacts, display status, and request external tools. It does **not** replace `CTFLLMController`, `SolveEngine`, verifiers, proof levels, or the external flag oracle. A model response, platform snapshot, downloaded artifact, or MCP result remains non-authoritative until it passes the existing Harness verification path.

## Compatibility boundary

Provider- and protocol-specific behavior is kept behind adapters. Model profiles can be added without changing the verifier/runtime core. MCP protocol evolution is delegated to the official SDK rather than reimplemented in this repository. The operator layer depends on `OperatorService`, so a later full-screen TUI or GUI can replace the presentation layer without rewriting model, site, MCP, or verification logic.

Implementation work is developed on evidence-gated branches and completed work packages include verification material under `docs/verification/`.
