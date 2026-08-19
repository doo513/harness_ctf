# 04 — MCP Logic Evidence

Status: **PASS**

## Scope

Add MCP integration without making the Harness responsible for implementing the MCP wire protocol and without allowing remote MCP metadata/results to become trusted state.

## Implemented artifacts

- `src/ctf_harness/mcp/gateway.py`
- `src/ctf_harness/mcp/client.py`
- `tests/test_mcp_registry.py`
- `tests/test_mcp_policy.py`
- dependency pinned to `mcp==2.0.0`

## Structural review result

The first draft attempted to own MCP JSON-RPC/transport details inside the Harness. That design was rejected during stage review. The final implementation is a policy adapter over the official MCP Python SDK v2.

Responsibility split:

**MCP SDK**
- protocol negotiation/validation;
- stdio transport;
- Streamable HTTP transport;
- result parsing and pagination;
- client/tool-call protocol behavior.

**Harness**
- configured server registry;
- explicit secret forwarding;
- per-server tool allowlist;
- operator approval policy;
- trust/authority classification.

## Security / authority evidence

- MCP metadata is tagged `untrusted_server_metadata`.
- MCP call results are tagged `untrusted_observation`.
- Neither metadata nor results have truth/completion authority.
- Non-allowlisted calls fail before backend invocation.
- Agent-visible `mcp_list` is automatic read/discovery; `mcp_call` requires `permission="confirm"`.
- HTTP auth comes from an environment reference; redirects are disabled; surfaced errors redact credential values.
- Tool-list pagination is bounded and cursor validity is checked.

## Direct test evidence

`tests/test_mcp_registry.py` and `tests/test_mcp_policy.py` verify:

1. inline MCP credentials are rejected;
2. remote tool metadata is filtered by allowlist;
3. results remain untrusted and authority-free;
4. denied tools are not invoked;
5. SDK descriptors contain no auth value;
6. protocol mode is delegated to the SDK rather than falsely hard-coded by the Harness;
7. the public surface exposes only Harness-owned `mcp_list`/`mcp_call` tool specs;
8. remote MCP calls require operator confirmation.

## Final regression evidence

GitHub Actions run `32202024136` installed the pinned MCP SDK dependency, passed `pip check`, compile, Base/CTF pytest, and the complete runtime/proof/evaluation probe suite.

## Non-claims

Deterministic CI does not connect to a real third-party MCP server. Live server interoperability and latency are external smoke-test concerns. Connections currently use an operation-scoped lifecycle rather than claiming persistent MCP session reuse.
