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

Hardening added during review:
- custom model base URLs must be absolute HTTP(S), contain no userinfo/query/fragment, and non-loopback plaintext HTTP is rejected
- redirect following is disabled for credentialed provider requests
- provider-specific configuration confusion fails closed
- provider error text is redacted before surfacing
- OpenAI Responses explicitly requests `store=false`
- `max_tokens` is documented as a per-request output cap only

Verification coverage written:
- inline-secret rejection
- active profile override
- missing credential fail-closed
- provider response normalization
- secret exclusion from descriptors
- explicit unsupported-provider rejection
- custom base URL and provider-shape policy

## 2. Site Access Logic

Implemented a configuration-driven `SiteAccessGateway` over the existing `CompetitionAdapter` boundary. The default provider is CTFd and reuses the existing same-origin URL checks and transient credential resolver.

Flag submission is disabled unless `allow_submit=true` is explicitly configured. Site/platform data remains snapshot/observation data and does not become Harness truth.

Verification coverage written:
- inline site-secret rejection
- transient environment credential resolution
- CTFd adapter reuse
- submission disabled by default
- explicit submission enablement

## 3. Doctor

Implemented a read-only readiness checker and CLI probe.

Checks include:
- active model provider/profile and required credential/command
- active site provider/profile and credential reference
- common local analysis commands
- MCP mode, transport, auth environment, and tool allowlist

Doctor performs no installation, configuration mutation, paid model call, flag submission, MCP tool call, or truth-state write.

## 4. MCP Logic

### Final design

The first implementation attempted to own MCP JSON-RPC/stdio/HTTP behavior directly. Structural review rejected that direction because it would make the Harness responsible for tracking protocol-version details that belong to the MCP implementation layer.

The custom wire implementation was replaced by a thin adapter over the official MCP Python SDK v2.

Responsibility split:

**Official MCP SDK owns**
- protocol negotiation / explicit protocol mode
- stdio process transport
- Streamable HTTP transport
- pagination/result parsing and protocol validation
- modern/legacy request semantics
- multi-round input-required tool interactions

**Harness owns**
- configured server registry
- non-secret configuration and explicit secret forwarding
- per-server `allowed_tools`
- rejection of non-allowlisted calls
- operator approval for agent-driven `mcp_call`
- classification of remote metadata/results as untrusted observations

Policy:
- remote tool metadata is untrusted
- per-server `allowed_tools` filters visible/callable tools
- agent-visible surface is only `mcp_list` and `mcp_call`
- `mcp_call` requires Base Harness operator confirmation
- stdio only forwards explicitly configured extra variables; SDK safe-default environment behavior remains underneath
- HTTP auth is supplied through a dedicated SDK/httpx2 client with redirects disabled
- MCP results are `untrusted_observation` with no truth/completion authority
- protocol mode may be `auto`, `legacy`, or an SDK-supported explicit modern version; the Harness no longer pretends to implement protocol compatibility itself

Verification coverage written:
- inline-secret rejection
- allowlist filtering
- denied non-allowlisted call
- SDK client descriptors exclude secret values
- protocol-mode policy is delegated to the SDK
- agent-visible remote tool calls require confirmation

## 5. Operator Interface

Implemented `OperatorService` as the application boundary for terminal/TUI/GUI work plus a JSON CLI and interactive shell.

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
2. Removed the Harness-owned MCP wire implementation and moved protocol/transport responsibility to the official SDK.
3. Changed agent-driven MCP remote calls from automatic permission to operator confirmation because remote MCP side effects are not intrinsically known by the Harness.
4. Made operator challenge downloads transactional rather than leaving partially-written challenge workspaces after a later failure.
5. Hardened model custom endpoints, redirect handling, error redaction, and provider-specific configuration validation.
6. Kept Model Gateway, Site Access, MCP, Doctor, and Operator layers outside verifier/truth/completion authority.

## Deliberate non-claims / remaining external validation

- No real paid model credential is committed or exercised by deterministic tests.
- Real provider/API behavior still requires live credentialed smoke tests.
- Real MCP servers still require live transport/interoperability smoke tests.
- `SolveBudget.max_tokens` remains unsupported by `SolveEngine` as a whole-run enforced budget; provider `max_tokens` is only a per-request output cap.
- MCP connections are currently opened per SDK operation. Persistent connection lifecycle/session reuse is intentionally deferred until a real stateful/latency-sensitive MCP use case demonstrates the need.
- The current presentation layer is a dependency-free CLI/interactive shell over `OperatorService`; a richer full-screen TUI can reuse the same service without reimplementing integrations.
- Dynamic competition instance plugins remain separate `InstanceProvider` extensions.
- Domain-specific solve effectiveness is not claimed by this operational-readiness work.

## Regression gate

The repository CI remains the release gate: Base Harness regression/invariant probes, CTF pytest regression, controlled SolveEngine, sandbox, competition, Pwn semantic/proof/recovery, cross-domain, QEMU, and evaluation probes must continue to pass.

At the time this document was updated, deterministic test cases had been added but a successful full repository CI run had not yet been observed for this branch. This document therefore records implementation/review status, not a release-ready PASS claim.
