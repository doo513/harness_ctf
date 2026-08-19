# 06 — Integration Review & Regression Evidence

Status: **PASS**

Verification code commit: `e1a64902c39a05d6f954c74981467f63b4f80d85`

GitHub Actions verification: run `32202024136`, job `95917655734`.

## Review method

After each operational-readiness stage, the implementation was reviewed for:

- authority-boundary regressions;
- provider/platform coupling;
- secret persistence;
- unsafe default side effects;
- fail-open behavior;
- stateful tool continuity;
- compatibility with the existing SolveEngine/Verified-State runtime;
- Base Harness and CTF regression impact.

## Findings fixed during review

### 1. Python dataclass default safety

A mapping default that could violate Python 3.11 dataclass mutable-default rules was replaced with `default_factory` construction.

### 2. MCP ownership boundary

A Harness-owned MCP wire implementation was removed. Protocol and transport behavior moved to the official SDK; the Harness retains policy only.

### 3. Remote MCP side effects

Because arbitrary remote MCP tools may have unknown side effects, agent-driven `mcp_call` was changed to operator-confirmed execution. Discovery remains separately exposed.

### 4. Challenge download transactionality

Operator downloads were changed to reject unsafe names/overwrite and to roll back already-created artifacts if a later persistence step fails.

### 5. Model-provider hardening

Custom endpoint validation, redirect denial, provider-shape validation, output bounds, and error redaction were added.

### 6. Stateful Remote TCP continuation-handle loss

The repository regression probe exposed a structural issue: a remote TCP `session_id` could be present only inside a structured observation whose Context Governor preview is intentionally bounded/truncated. A stateful continuation capability must not depend on lossy semantic evidence projection.

Fix:

- `RemoteTcpToolRuntime.control_projection()` now exposes only live Harness-generated session handles;
- handles are classified `kernel_control`, `instruction_authority=none`, `truth_authority=none`, `ephemeral=true`;
- `AgentCTFRuntime` projects this under `ctf.operational_control` outside the lossy observation preview path;
- the profile supplies the projection without giving it Fact/proof/completion authority;
- active Remote TCP sessions are bounded (`max_sessions`, default 8), closed sessions are pruned, and session-ID collisions are guarded;
- the controlled competition probe fails if a session ID is available only via lossy observation preview, preventing regression to the previous behavior.

The final controlled remote competition run completed with `model_calls=5`, `tool_calls=4`, exact admitted endpoint binding, `general_internet=false`, and external-oracle-only completion.

## Final CI evidence

From GitHub Actions run `32202024136`:

- dependency installation / `pip check`: PASS;
- compile: PASS;
- Base Harness pytest: **220 passed, 7 skipped**;
- Base invariant probes: PASS;
- CTF Harness pytest: **235 passed**;
- Agent foundation: PASS;
- minimal SolveEngine vertical: PASS;
- production model Gate A0 fail-closed behavior: PASS;
- AnalysisSandbox isolation: PASS;
- Pwn operational vertical: PASS;
- competition remote TCP SolveEngine: PASS;
- Crypto/Reverse controlled vertical: PASS;
- Pwn crash semantic: PASS;
- QEMU AArch64 runner: PASS;
- operational remote TCP runner: PASS;
- x86_64 control-flow semantic: PASS;
- local proof semantic: PASS;
- environment compatibility: PASS;
- remote behavior: PASS;
- external flag completion: PASS;
- hypothesis dedupe: PASS;
- recovery/progress: PASS;
- benchmark arm/integrity/corpus/executor/runtime probes: PASS.

## Preserved authority model

The final operational stack remains outside:

- verified Fact commit authority;
- semantic verification authority;
- proof-level promotion authority;
- final completion authority.

The existing Base/CTF runtime, Verifier/Proof path, and external oracle remain authoritative.

## Evidence-bounded conclusion

**Operational readiness: PASS.**

The implementation is integrated and regression-gated. This result does **not** establish real-model solve-rate improvement: CI intentionally reports no production LLM execution/private corpus effectiveness measurement in the evaluation probes. Those remain empirical evaluation work rather than a blocker for this operational-readiness implementation.
