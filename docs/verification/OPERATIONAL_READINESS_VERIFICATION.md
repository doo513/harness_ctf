# Operational Readiness Layer — Implementation Verification

## Scope

This change implements the operator-facing stack in dependency order without changing the Verified-State authority model:

1. Configuration & Model Gateway
2. Site Access Logic
3. Doctor
4. MCP Logic
5. Operator Interface

The existing `SolveEngine`, `AgentCTFRuntime`, verifier path, proof model, and external completion oracle remain authoritative and are not replaced.

## 1. Configuration & Model Gateway

Implemented strict TOML profiles for models, sites, and MCP servers. Raw secret fields are rejected; profiles reference environment/keyring/session locations instead.

Model providers:
- OpenAI Responses API transport
- Anthropic Messages API transport
- Gemini generateContent transport
- Existing external-process ModelAdapter

The gateway only builds ModelAdapters. Provider output must decode to the existing Decision `kind/payload` envelope. Provider usage metadata is retained as non-authoritative telemetry where available.

Verification coverage:
- inline-secret rejection
- active profile override
- missing credential fail-closed
- provider response normalization
- secret exclusion from descriptors
- explicit unsupported-provider rejection

## 2. Site Access Logic

Implemented a configuration-driven `SiteAccessGateway` over the existing `CompetitionAdapter` boundary. The default provider is CTFd and reuses the existing same-origin URL checks and transient credential resolver.

Flag submission is disabled unless `allow_submit=true` is explicitly configured. Site/platform data remains snapshot/observation data and does not become Harness truth.

Verification coverage:
- inline site-secret rejection
- transient environment credential resolution
- CTFd adapter reuse
- submission disabled by default
- explicit submission enablement

## 3. Doctor

Implemented a read-only readiness checker and CLI probe.

Checks include:
- active model profile and required credential/command
- active site profile and credential reference
- common local analysis commands
- MCP protocol, transport, auth environment, and tool allowlist

Doctor performs no installation, configuration mutation, paid model call, flag submission, MCP tool call, or truth-state write.

## 4. MCP Logic

Implemented MCP stdio and stateless HTTP client routing behind a Harness-owned registry.

Policy:
- built-in public registry fails closed unless protocol version is `2026-07-28`
- remote tool metadata is untrusted
- per-server `allowed_tools` filters visible/callable tools
- agent-visible surface is only `mcp_list` and `mcp_call`
- `mcp_call` requires Base Harness operator confirmation
- stdio subprocesses run with `shell=False` and only explicit environment forwarding
- MCP results are `untrusted_observation` with no truth/completion authority

Verification coverage:
- protocol-version fail-closed
- inline-secret rejection
- allowlist filtering
- denied non-allowlisted call
- HTTP protocol/auth headers
- stdio environment isolation
- confirmation policy for remote tool calls

## 5. Operator Interface

Implemented `OperatorService` as the application boundary for future TUI/GUI work plus a JSON CLI and interactive shell.

Available operations:
- status / doctor
- list/read competition challenges
- download challenge artifacts into the standard workspace projection
- list MCP servers/tools and explicit human MCP calls
- explicit flag submission through the site policy gate
- construct the existing `CTFLLMController` from the configured Model Gateway

Challenge downloads validate all artifact names before persistence, reject overwrite/duplicates, and roll back newly-created files on write failure. Downloading does not perform verified artifact admission.

## Structural review findings fixed during implementation

1. Replaced a dataclass `mappingproxy` default with `default_factory` for Python 3.11-safe construction.
2. Added an explicit public MCP protocol-version gate instead of silently claiming compatibility with other protocol versions.
3. Changed agent-driven MCP remote calls from automatic permission to operator confirmation because remote MCP side effects are not intrinsically known by the Harness.
4. Made operator challenge downloads transactional rather than leaving partially-written challenge workspaces after a later failure.
5. Kept Model Gateway, Site Access, MCP, Doctor, and Operator layers outside verifier/truth/completion authority.

## Deliberate non-claims / remaining external validation

- No real paid model credential is committed or exercised by deterministic tests.
- Real provider/API behavior still requires live credentialed smoke tests.
- `SolveBudget.max_tokens` remains unsupported by `SolveEngine` as a whole-run enforced budget; provider `max_tokens` is only a per-request output cap.
- The current operator interface is a dependency-free CLI/interactive shell over `OperatorService`, not a graphical/full-screen TUI. A later TUI should reuse `OperatorService` rather than reimplement integrations.
- Dynamic competition instance plugins remain separate `InstanceProvider` extensions.
- Domain-specific solve effectiveness is not claimed by this operational-readiness work.

## Regression gate

The repository CI remains the release gate: Base Harness regression/invariant probes, CTF pytest regression, controlled SolveEngine, sandbox, competition, Pwn semantic/proof/recovery, cross-domain, QEMU, and evaluation probes must continue to pass.
