# WP06 — Hypothesis / Dedupe Verification

**Status:** `PASS — ENGINEERING / CONTROLLED GATE`

## 1. Purpose

WP06 exists to prevent repeated CTF exploration from being treated as useful work when the semantic hypothesis, concrete action, and evidence state have not changed. It is planning/control state only. It must not become a second fact store, completion authority, or verifier authority.

The runtime path is:

```text
Actor tool proposal
→ parse stable CTF hypothesis identity
→ derive evidence-state identity from Core-registered durable evidence
→ hypothesis guard
→ begin durable attempt
→ Base HarnessRuntime tool dispatch / receipt authority
→ Base failure + recovery
→ durable attempt outcome
```

## 2. Implemented logic

### 2.1 Stable hypothesis identity

`HypothesisPool.fingerprint()` hashes only:

- category
- target
- vulnerability class
- primitive
- claim

Evidence is deliberately **excluded** from the semantic fingerprint. This keeps one hypothesis identity stable while its evidence state evolves.

### 2.2 Evidence-state identity

Evidence state is derived through Base `_evidence_novelty_identity()` for every supplied evidence ref. Therefore evidence must already be registered in the Core artifact/evidence state and pass ArtifactStore integrity verification.

The identity binds content digest to stable provenance. A new artifact filename/ref containing the same bytes from the same source does not manufacture novelty.

### 2.3 Runtime guard

`VerifiedCTFRuntime` enforces the guard before Base tool dispatch.

It blocks:

- a REFUTED hypothesis;
- the same hypothesis + action + evidence state after a non-retry-safe FAILED attempt;
- the same tuple after an AMBIGUOUS attempt.

A changed evidence state may reopen the CTF guard. It does **not** bypass Base non-idempotent receipt/idempotency semantics.

### 2.4 Durable attempt ledger

`ctf_hypotheses.json` stores hypotheses and attempts with states including `INFLIGHT`, `FAILED`, `SUCCEEDED`, and `AMBIGUOUS`.

A crash-left `INFLIGHT` attempt becomes `AMBIGUOUS` on load so the same hypothesis/action/evidence tuple cannot be silently replayed.

### 2.5 Rollback-resistant anchoring

A self-hashed sidecar alone is insufficient because an older valid envelope could otherwise be restored to erase failure history.

Every durable ledger save is therefore anchored into the Base hash-chained event log as `ctf.hypothesis.ledger_anchor` with the current ledger body hash. Resume requires the loaded sidecar hash to equal the latest Base event-log anchor before any normalization is persisted.

Consequently:

- direct content tamper is rejected by the sidecar hash;
- rollback to an older but valid sidecar is rejected by the Base event-log anchor;
- an unanchored newer sidecar is also rejected.

### 2.6 Explicit CTF refutation

A CTF-specific `refute` path requires:

- an already known semantic hypothesis;
- `refute.key == ctf_hypothesis.id`;
- non-empty contradiction evidence;
- contradiction evidence that passes the same Core durable evidence identity checks.

The sidecar branch becomes `REFUTED`, but this operation has `truth_authority = none`: it closes a speculative strategy branch and does not create a verified fact.

## 3. Failed iterations and corrections

### F-WP06-01 — new evidence expected to re-execute identical action in the same Base step

The first integration test expected changed evidence to force backend execution of identical `tool + args` in the same Base step. It failed because Base non-idempotent receipt replay correctly remained authoritative.

**Correction:** evidence novelty can reopen only the CTF hypothesis guard. It cannot bypass Core receipt replay.

### F-WP06-02 — adapted action expected to execute as a second non-idempotent action in the same Base step

A second test changed argv but still called `_dispatch_decision()` repeatedly without normal Base step/recovery transitions. Base `ReceiptStore.prepare()` correctly rejected a second different non-idempotent action at the same step.

**Correction:** integration tests and probes now exercise the real `run()/step_once()` path. Pending recovery is applied before the next Actor decision, and normal step advancement owns non-idempotent receipt identity.

### F-WP06-03 — valid-envelope rollback risk discovered during structural review

The original durable ledger envelope detected direct tamper but could not distinguish the newest valid state from an older valid state.

**Correction:** latest sidecar body hash is anchored in the Base hash-chained event log and checked on resume.

## 4. Execution evidence

Final controlled/full gate: GitHub Actions run `32024430497`, job `95370724209`, commit `7736d6581e851fd51692fe8655a630a97f5ee680`.

### E-WP06-01 — Base/Core regression preserved

- Base regression: `220 passed, 7 skipped`.
- Core freeze audit: PASS; `new_stage_created=false`.
- Stage02 backend/session probes: PASS.
- Stage04 semantic probe: 8/8 cases, zero false positives and zero false negatives.
- Stage05 recovery A/B/C/D controls: PASS with zero false success in negative controls.
- Stage06 task-progress authority probe: PASS with implicit task authority 0.
- Stage07 context and Stage08 retrieval probes: PASS.

### E-WP06-02 — CTF regression preserved

CTF test suite: `33 passed in 2.29s`.

This includes runtime integration, ledger integrity, rollback rejection, explicit evidence-backed refutation, and Core receipt-boundary tests.

### E-WP06-03 — actual Base run-loop controlled probe

`pwn-hypothesis-runtime-dedupe-controlled-v2` reported:

- `all_passed=true`
- `base_run_loop_exercised=true`
- backend execution calls: 6
- durable hypothesis attempts: 6
- guard blocks: 3
- explicit refutations: 1
- Base recovery transitions observed: 8
- same failure + same evidence blocked: true
- novel evidence + adapted action executed: true
- duplicate ref with same content/provenance blocked: true
- refuted hypothesis blocked before backend: true
- stable hypothesis count: 1
- `truth_authority=none`

Observed backend actions were exactly:

```text
probe same-action
probe evidence-action
probe adapted-action
probe evidence-action
probe evidence-new
probe adapted-action
```

The post-refutation action was not executed.

### E-WP06-04 — P1–P6 authority chain unchanged

The same final CI run re-executed and passed P1 crash, P2 control flow, P3 local proof, P4 environment compatibility, P5 remote behavior, and P6 Core-integrated external flag completion. WP06 therefore did not replace or bypass semantic/proof/completion authorities.

## 5. Appropriateness evaluation

The current split is appropriate:

- Base `HarnessState.facts` remains the only verified fact authority.
- Base tool receipts remain the non-idempotent execution authority.
- Base recovery remains the failure-transition authority.
- CTF HypothesisPool is a durable speculative control sidecar only.
- evidence novelty uses existing Core artifact/provenance semantics rather than a weaker CTF-local rule.

The Base event-log anchor is necessary because failure-history rollback would otherwise defeat dedupe across resume.

## 6. Structural logic / truth review

- **Truth authority:** no sidecar path can write VERIFIED facts or completion.
- **Execution authority:** CTF guard can deny dispatch but cannot force a Core receipt bypass.
- **Evidence authority:** arbitrary ref strings are insufficient; registered integrity-verified evidence is required.
- **Refutation authority:** branch closure requires contradiction evidence but remains speculative-state control, not semantic truth promotion.
- **Resume integrity:** direct tamper, old-valid rollback, and crash-left ambiguous execution are fail-closed.
- **Recovery ordering:** integration probe uses Base pending-recovery application before the next Actor decision.

No new Core stage was created and no Core state/verifier implementation was cloned into the CTF repository.

## 7. Truthfulness statement

**Proven by this WP:** deterministic hypothesis identity/evidence-state semantics, pre-dispatch repeat blocking, durable attempt persistence, rollback-resistant resume anchoring, explicit evidence-backed branch refutation, and integration through the real Base run/recovery loop under controlled tests.

**Not proven by this WP:** that these controls improve solve rate, token cost, wall time, or repeated-failure rate on a fresh/private or live CTF corpus. That requires the later benchmark WP and must not be inferred from this controlled gate.

## 8. Exit gate

- [x] stable semantic fingerprint independent of evidence state
- [x] same hypothesis/action/failure/evidence repeat blocked
- [x] registered genuinely new evidence can reopen the CTF guard
- [x] same content/provenance under a new ref is not novel
- [x] real `run()/step_once()` runtime integration
- [x] Base non-idempotent receipt authority is not bypassed
- [x] durable attempt ledger
- [x] crash-left INFLIGHT becomes fail-closed AMBIGUOUS
- [x] direct tamper rejected
- [x] older-valid ledger rollback rejected through Base event-log anchor
- [x] explicit registered-evidence refutation closes the branch
- [x] no fact/completion authority added
- [ ] actual CTF-corpus repeated-failure / solve-rate benefit measured — deferred to benchmark WP

**Decision:** `PASS — ENGINEERING / CONTROLLED GATE`. Empirical effectiveness remains intentionally open for benchmark evaluation.
