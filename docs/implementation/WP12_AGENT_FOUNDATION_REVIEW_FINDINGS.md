# WP12 — Agent Foundation Meta-Review Findings

## Review basis

This review re-checks the entire Agent Foundation stage after implementation rather than treating passing tests as sufficient evidence.

Reviewed code head:

```text
4b17413b761268e4dcfb0ae5b3d87c5f62b493c0
```

Final executable gate:

```text
GitHub Actions run: 32056829487
job: 95468815926
conclusion: success
Base regression: 220 passed, 7 skipped
CTF regression: 154 passed in 7.29s
ctf-pytest-log artifact: 9296690377
artifact SHA-256: 708f6509c6068a34cb7f8ff7f8ead4ade27decfe03cc5a16d3058ebaf51720f0
```

The same gate passed the mandatory controlled Agent foundation probe and all existing P1–P6, WP06–WP08 probes.

---

# 1. Pre-implementation correction — do not duplicate Base Agent/context infrastructure

## Finding

The initial revised roadmap called for a new CTF `ContextAssembler`, typed model decision layer, and Harness-owned AgentController.

Review of the pinned Base showed those core responsibilities already exist:

```text
Base ContextProjector
Base trust-labelled context projection
Base Decision
Base ModelAdapter protocol
Base LLMController
Base HarnessRuntime controller -> decision -> governed dispatch
```

Creating a parallel CTF controller/context engine would have produced two governance paths and a future split-brain problem.

## Remediation

WP12 was narrowed to adapters only:

```text
Base ContextProjector
        +
CTF context extension

Base LLMController
        +
CTF prompt / hypothesis syntax adapter

Base Decision
        +
existing VerifiedCTFRuntime CTF hypothesis contract
```

Status: **CLOSED**.

---

# 2. RunIntent must control stopping, never completion

## Finding

The Dreamhack smoke exercise showed a concrete operational failure mode: a harness-evaluation run can drift into an unrestricted solve unless its purpose and stopping semantics are bound into the run contract.

A naïve `mode=smoke` boolean would be dangerous if it could directly mark a run successful.

## Remediation

Added fingerprint-bound:

```text
RunIntent
  SOLVE
  SMOKE
  COMPETITION

TerminationPolicy
  actor_complete
  unsupported_capability
```

Hard invariant:

```text
completion_authority = external_oracle_only
```

For `SOLVE` and `COMPETITION`, actor `complete` must invoke the existing external completion path.

For `SMOKE`, actor `complete` is an **incomplete policy stop**:

```text
halted = true
completed = false
completion_requested = false
oracle_checks = 0
```

Status: **CLOSED for the current operational intent set**.

---

# 3. Durable incomplete stop semantics

## Finding

An in-memory smoke halt is insufficient. A resumed run could otherwise forget that the operator intentionally stopped at a coverage boundary and begin calling the model/oracle again.

## Remediation

`AgentCTFRuntime` records a hash-chained `ctf.run.stop` event. Resume verifies the Base event chain, restores the stop, and stays halted.

Negative control proves after resume:

```text
model calls = 0
oracle checks = 0
completed = false
completion_requested = false
```

Status: **CLOSED**.

---

# 4. Missing capability is control/recovery state, not semantic failure truth

## Finding

A model can request a tool not present in the actual Base `ActionRuntime` inventory. Treating a guessed tool name as a tool execution or semantic fact would violate the Harness boundary.

## Remediation

Capability availability is projected directly from the existing Base tool runtime.

```text
SMOKE + missing capability
-> HALT_INCOMPLETE before tool execution

SOLVE + missing capability
-> CTFFailureKind.TOOL_MISSING
-> existing Base FailureRouter / Recovery
```

No new recovery controller was introduced.

Status: **CLOSED for exact Harness-owned tool availability**.

---

# 5. Capability catalog must not become a second tool authority

## Finding

The roadmap originally proposed an early `CapabilityRegistry`. A separate mutable registry could disagree with `ActionRuntime.tools` and allow the model to see a capability that cannot actually be executed.

## Remediation

WP12 uses a minimal **projection**, not a registry:

```text
available_tools = sorted(Base ActionRuntime tools)
```

Rich existing Base tool metadata remains available through the normal trusted context `tools` section.

Provider fallback / capability abstractions remain later work and must derive from registered executable providers, not replace them.

Status: **CLOSED for WP12**.

---

# 6. CTF hypotheses remain speculation

## Finding

Agent integration increases the risk that model text is accidentally promoted into trusted facts.

## Remediation

The CTF context projection explicitly labels CTF hypotheses:

```text
trust = untrusted_speculation
instruction_authority = none
truth_authority = none
```

A controlled model proposing:

```text
ctf.actor.self_claim = "SOLVED"
```

creates only a Base hypothesis. It never becomes `HarnessState.facts` without the existing verifier path and never completes a SMOKE run.

The existing `VerifiedCTFRuntime` remains responsible for evidence refs, semantic hypothesis identity, durable ledger anchoring, and dedupe.

Status: **CLOSED**.

---

# 7. CTF hypothesis syntax adapter must not replace runtime integrity checks

## Finding

`CTFLLMController` validates model output before dispatch. It would be incorrect for this adapter to resolve or trust evidence references itself, because the model-facing layer does not own artifact integrity.

## Remediation

Controller validation is deliberately limited to bounded syntax:

```text
required semantic fields
allowed field set
bounded field lengths
bounded evidence-ref count / ref length
bounded tool name
```

Registered evidence resolution and novelty identity remain `VerifiedCTFRuntime` responsibilities.

Status: **CLOSED**.

---

# 8. Untrusted durable event text required a second review fix

## Finding

The first `ctf.run.stop` implementation persisted the complete actor-provided stop reason and requested missing tool name in the Base hash-chained event log.

This was not a truth-authority violation, but it allowed unbounded untrusted model text into durable control logs.

## Remediation

Durable stop events now store:

```text
bounded preview
+ SHA-256(full untrusted text)
```

Limits:

```text
reason preview: 512 chars
subject preview: 128 chars
```

A negative control provides >5000 characters and proves the full string is absent while its digest is preserved.

Status: **CLOSED**.

---

# 9. Model-supplied CTF metadata needed explicit bounds

## Finding

Base JSON/Decision validation checks shape but does not impose CTF-specific size limits on hypothesis fields. An Agent could generate extremely large claim/evidence metadata before the CTF runtime sees it.

## Remediation

`CTFLLMController` bounds:

```text
tool name                  128 chars
hypothesis id              128
category                    64
target                     256
vulnerability_class        128
primitive                  128
claim                     1024
evidence refs               32 items
each evidence ref          256 chars
```

Oversized controls fail before runtime dispatch.

Status: **CLOSED**.

---

# 10. Current authority graph

After WP12:

```text
ModelAdapter
    ↓
Base LLMController + thin CTF syntax adapter
    ↓
Base Decision
    ↓
AgentCTFRuntime (control-only run policy)
    ↓
VerifiedCTFRuntime
    ↓
Base HarnessRuntime
    ├─ ActionRuntime
    ├─ Evidence
    ├─ Verification
    ├─ FailureRouter / Recovery
    └─ External completion oracle
```

Authority review:

```text
AgentController truth authority        NONE
AgentCTFRuntime truth authority        NONE
RunIntent completion authority         NONE
CTF hypothesis truth authority         NONE
Capability projection execution auth   NONE
HarnessState.facts                     SOLE semantic truth
External Oracle                        SOLE completion authority
```

Status: **PASS**.

---

# 11. What WP12 does NOT prove

The mandatory Agent probe uses a deterministic `ControlledModel` implementing the Base `ModelAdapter` shape.

Therefore:

```text
actual production LLM executed                 NO
production provider credentials integrated     NO
actual CTF independently solved                NO
Agent effectiveness measured                   NO
Minimal-vs-Verified model effectiveness         NO
```

The probe proves the **controller/runtime authority boundary**, not LLM intelligence.

Status: **OPEN empirical/provider gate**.

---

# 12. Next-stage configuration drift risk

## Finding

`SolveSpec` now owns operational `run_intent` and `termination_policy`, while `AgentCTFRuntime` can still be constructed directly with those same values.

That is acceptable for WP12 tests, but production orchestration could accidentally construct a runtime whose policy differs from the admitted `SolveSpec`.

## Required WP13 rule

The production `SolveEngine` must be the binding boundary:

```text
SolveSpec.run_intent
SolveSpec.termination_policy
SolveSpec.budget
SolveSpec target/agent identity
        ↓ exact mapping
AgentCTFRuntime / Base Budget / prepared profile/controller
```

The engine must reject any binding whose model/controller/target/runtime identity disagrees with the SolveSpec.

Status: **OPEN — explicit WP13 requirement**.

---

# 13. Tactical SUPPORTED/PROVED semantics remain later work

The existing hypothesis model already has:

```text
OPEN
SUPPORTED
REFUTED
PROVED
```

WP12 does not add another tactical state database and does not attempt to complete SUPPORTED/PROVED transition semantics.

That work belongs with the Pwn operational/playbook stage, where observation-driven tactical progress can be evaluated without changing fact authority.

Status: **OPEN BY DESIGN**.

---

# 14. Logical dependency review

Current dependency chain is acyclic:

```text
WP11 execution boundary
    ↓
WP12 Base-backed Agent foundation
    ↓
WP13 SolveSpec -> runtime binding / SolveEngine
    ↓
minimal end-to-end solve
```

WP12 does not depend on SolveEngine, CompetitionAdapter, DomainPlaybook, AnalysisSandbox, QEMU-system/VM support, or multi-agent infrastructure.

Status: **PASS**.

---

# 15. Exit decision

```text
Base context/controller reuse                       PASS
RunIntent fingerprint binding                      PASS
SMOKE incomplete halt                              PASS
SMOKE durable resume                               PASS
SOLVE external-oracle-only completion              PASS
missing capability governance                      PASS
CTF speculation trust labels                       PASS
actor self-claim cannot become fact                PASS
untrusted durable text bounded                     PASS
model CTF metadata bounded                         PASS
existing Base / P1-P6 / WP06-WP08 regression       PASS
production LLM execution                           OPEN
actual end-to-end CTF solve                        OPEN
```

**Decision:** `WP12 AGENT FOUNDATION PASS — CONTROLLED AUTHORITY/ORCHESTRATION BOUNDARY / PRODUCTION MODEL + E2E OPEN`.

The correct next engineering stage is WP13 SolveSpec-to-runtime binding and minimal SolveEngine infrastructure. A production-model empirical gate remains separately open and must not be falsely inferred from the controlled ModelAdapter fixture.