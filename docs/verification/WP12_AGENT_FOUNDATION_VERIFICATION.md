# WP12 — Agent Foundation Verification

**Status:** `PASS — CONTROLLED AGENT AUTHORITY/ORCHESTRATION BOUNDARY / PRODUCTION MODEL + E2E OPEN`

## 1. Goal

Add the minimum CTF-specific operational layer required for a model-driven run **without duplicating or weakening** the pinned Base controller/context/runtime authority.

WP12 must establish:

```text
RunIntent / TerminationPolicy
Base ContextProjector reuse
Base LLMController / Decision reuse
CTF-specific bounded hypothesis syntax
CTF run/capability/hypothesis context extension
incomplete SMOKE stop semantics
missing-capability governance
```

It must not claim model intelligence or end-to-end solving.

---

## 2. Pre-implementation architecture correction

Review of the pinned Base showed that the initially planned new `ContextAssembler`, typed decision core, and independent AgentController would duplicate existing infrastructure:

```text
ContextProjector
Decision
ModelAdapter
LLMController
HarnessRuntime controller/dispatch path
```

WP12 therefore implements adapters rather than replacements.

Current path:

```text
ModelAdapter
  ↓
Base LLMController + CTF syntax/prompt adapter
  ↓
Base Decision
  ↓
AgentCTFRuntime (control-only)
  ↓
VerifiedCTFRuntime
  ↓
Base HarnessRuntime
```

---

## 3. Run contract

Added to operational `SolveSpec`:

```text
RunIntent
  SOLVE
  SMOKE
  COMPETITION

TerminationPolicy
  actor_complete
  unsupported_capability
```

Invariant:

```text
completion_authority = external_oracle_only
```

Semantics:

```text
SOLVE / COMPETITION + actor complete
-> existing external completion oracle path

SMOKE + actor complete
-> halted = true
-> completed = false
-> completion_requested = false
-> oracle not called
```

Run intent and policy are part of the SolveSpec fingerprint.

---

## 4. CTF model decision boundary

`CTFLLMController` subclasses Base `LLMController` only to add CTF prompt/schema constraints.

It does not resolve evidence or promote truth.

Tool decisions carry bounded `ctf_hypothesis` metadata:

```text
id
category
target
vulnerability_class
primitive
claim
evidence_refs
```

Controller bounds model-supplied metadata before runtime dispatch. Registered evidence validation and hypothesis identity remain `VerifiedCTFRuntime` responsibilities.

---

## 5. CTF context extension

`AgentCTFRuntime` starts from the Base governed context and adds one `ctf` namespace.

```text
ctf.run
  -> kernel-control run intent/policy

ctf.capabilities
  -> exact available tool names derived from Base ActionRuntime

ctf.hypotheses
  -> bounded projection of CTF speculative ledger
```

Hypothesis entries are explicitly labelled:

```text
trust = untrusted_speculation
instruction_authority = none
truth_authority = none
```

A separate mutable capability registry was not created; the Base executable tool inventory remains the source.

---

## 6. Incomplete stop durability

SMOKE stop writes a Base hash-chained control event:

```text
ctf.run.stop
```

Resume verifies the existing Base event chain and restores the halted incomplete state.

The durable event contains bounded untrusted previews plus hashes rather than unlimited actor text:

```text
reason_preview <= 512 chars
reason_sha256 = SHA-256(full reason)
subject_preview <= 128 chars
subject_sha256 = SHA-256(full subject)
```

The stop path verifies facts are unchanged and refuses to coexist with `state.completed=True`.

---

## 7. Missing capability semantics

Capability availability is checked against Base `ActionRuntime.tools`.

```text
SMOKE + missing tool
-> incomplete stop before execution

SOLVE + missing tool
-> CTFFailureKind.TOOL_MISSING
-> Base FailureRouter / Recovery
```

No second recovery controller was added.

---

## 8. Controlled executable evidence

Final reviewed code head:

```text
4b17413b761268e4dcfb0ae5b3d87c5f62b493c0
```

Full GitHub Actions gate:

```text
run: 32056829487
job: 95468815926
conclusion: success
```

Regression:

```text
Base: 220 passed, 7 skipped
CTF: 154 passed in 7.29s
```

Preserved CTF pytest artifact:

```text
artifact: ctf-pytest-log
artifact id: 9296690377
SHA-256: 708f6509c6068a34cb7f8ff7f8ead4ade27decfe03cc5a16d3058ebaf51720f0
```

The same workflow passed:

- Controlled Agent foundation probe;
- native runtime-bound P1;
- controlled QEMU-user AArch64 P1;
- bounded/delimiter remote TCP probe;
- native x86_64 P2;
- sealed P3;
- P4 / P5 / P6;
- WP06 hypothesis/dedupe;
- WP07 recovery/progress;
- all existing WP08 evaluation probes.

---

## 9. Controlled Agent foundation probe

The mandatory probe uses a deterministic `ControlledModel` satisfying the Base `ModelAdapter` protocol.

It proves:

```text
Base LLMController reused                         YES
Base ContextProjector reused                      YES
Base Decision contract reused                     YES
SMOKE actor complete -> incomplete halt           YES
SMOKE external oracle checks                      0
missing capability stops before tool in SMOKE     YES
SOLVE complete requires external oracle           YES
CTF hypothesis truth authority                    NONE
```

It explicitly reports:

```text
actual_production_llm_executed = false
```

Therefore this is controller/runtime boundary evidence only.

---

## 10. Negative controls

WP12 tests require:

```text
SOLVE actor-complete policy weakened to halt       REJECT
SMOKE actor-complete policy changed to oracle      REJECT
actor self-claim "SOLVED" -> verified fact        REJECT / remains hypothesis
SMOKE actor complete -> oracle call                ABSENT
SMOKE stop resume -> model call                    ABSENT
SMOKE stop resume -> oracle call                   ABSENT
missing tool SMOKE -> backend execution            ABSENT
oversized tool name                                REJECT
oversized hypothesis claim                         REJECT
too many evidence refs                             REJECT
oversized evidence ref                             REJECT
>5000-char stop reason persisted raw              ABSENT
```

---

## 11. Meta-review findings

Full meta-review: `../implementation/WP12_AGENT_FOUNDATION_REVIEW_FINDINGS.md`.

Key conclusions:

```text
second context/controller authority introduced      NO
second fact/proof/completion authority introduced    NO
RunIntent changes success semantics                  NO
SMOKE stop is success                                NO
capability projection replaces ActionRuntime         NO
CTF hypothesis becomes Fact                          NO
unbounded actor text durable                         FIXED
unbounded CTF decision metadata                      FIXED
```

---

## 12. Explicitly open

WP12 does **not** establish:

```text
production LLM provider integration
production credentials
actual model call in CI/operational run
independent CTF solve
SolveSpec -> exact runtime binding
minimal end-to-end flag solve
Agent effectiveness
Minimal-vs-Verified effectiveness
SUPPORTED/PROVED tactical transition semantics
```

---

## 13. Next dependency-safe engineering stage

The next code stage is WP13 SolveSpec-to-runtime binding / minimal SolveEngine.

Required invariant:

```text
SolveSpec
  run_intent
  termination_policy
  budget
  challenge/target identity
  agent identity
        ↓ exact binding / reject mismatch
AgentCTFRuntime + Base Budget + prepared profile/controller
```

SolveEngine must remain orchestration only and cannot write facts/proof/completion.

A real production-model call remains a separate empirical Gate A0 and must stay marked OPEN until an actual provider/credential is supplied and attested.

---

## 14. Exit decision

```text
RunIntent / TerminationPolicy                     PASS
Base context reuse                                PASS
Base LLMController / Decision reuse               PASS
CTF decision bounds                               PASS
CTF hypothesis trust isolation                    PASS
SMOKE incomplete halt                             PASS
SMOKE durable resume                              PASS
missing capability governance                     PASS
untrusted durable log bounds                      PASS
Base + existing CTF regression                    PASS
production model execution                        OPEN
actual solve                                      OPEN
```

**Decision:** `WP12 AGENT FOUNDATION PASS — CONTROLLED BOUNDARY ONLY`.