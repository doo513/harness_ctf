# WP07 — CTF Recovery / Progress Verification

**Status:** `PASS — ENGINEERING / CONTROLLED GATE`

## 1. Purpose

WP07 connects CTF-domain failure descriptions to the existing Base failure/recovery kernel without creating a second recovery authority. CTF progress remains a read-only projection over Core verified facts and completion state.

The intended boundary is:

```text
CTF domain failure classification
→ CTF mapping adapter
→ Core Failure
→ Base FailureRouter
→ Base pending RecoveryTransition
→ Base RuntimeRecovery applies transition
```

The CTF layer may classify and attach a recovery target, but it does not choose or apply the final recovery action independently.

## 2. Implemented logic

### 2.1 Typed CTF failure taxonomy

`CTFFailureKind` covers:

- RECON_INCOMPLETE
- CATEGORY_MISCLASSIFIED
- TOOL_MISSING
- TOOL_FAILURE
- INTERACTIVE_STALL
- HYPOTHESIS_REFUTED
- PRIMITIVE_NOT_REPRODUCIBLE
- LOCAL_PROOF_FAILED
- ENVIRONMENT_MISMATCH
- REMOTE_PROOF_FAILED
- FLAG_REJECTED
- NO_INFORMATION_GAIN
- BUDGET_EXHAUSTED

Unknown kinds fail closed.

`RecoveryMapping` contains an actual Core `FailureKind`, a CTF recovery target, and a retry-safe default. No new Core `FailureKind` was added.

### 2.2 Runtime integration

`VerifiedCTFRuntime.report_ctf_failure()`:

1. validates CTF failure kind/message/subject;
2. validates optional evidence through the existing Core registered/integrity-verified evidence identity path;
3. creates a Core `Failure` with a stable CTF signature;
4. calls the existing Base `fail()` path;
5. receives the real Base pending `RecoveryTransition`;
6. records a hash-chained `ctf.failure.mapped` audit event;
7. verifies that the adapter did not mutate verified facts.

This API is a trusted runtime/domain adapter API, not a new Actor decision kind.

### 2.3 Retry safety is explicit

`retry_safe` defaults conservatively to false. If supplied, it must be an actual boolean. Values such as the string `"false"` are rejected rather than being coerced by Python truthiness.

Consequently an `ENV_ERROR` does not become retryable merely because the domain adapter classified it as environmental.

### 2.4 Structural correction: do not misuse Core logical rollback

An earlier mapping design used Core `HYPOTHESIS_REFUTED` for CTF `CATEGORY_MISCLASSIFIED` and CTF sidecar `HYPOTHESIS_REFUTED`.

That mapping is structurally incorrect in the current Base architecture: Core `HYPOTHESIS_REFUTED → ROLLBACK` interprets `Failure.action` as an actual Core logical-hypothesis key and removes that untrusted Core hypothesis. CTF labels such as `category_switch` and `close_branch` are not Core hypothesis keys.

The final mapping therefore uses:

- CTF `CATEGORY_MISCLASSIFIED` → Core `NO_PROGRESS` → Base `REPLAN`, target `category_switch`;
- CTF sidecar `HYPOTHESIS_REFUTED` → Core `NO_PROGRESS` → Base `REPLAN`, target `close_branch`.

Actual Core logical-hypothesis rollback remains reserved for Core state that has the matching semantic key.

### 2.5 Key recovery mappings

Representative final mappings:

- RECON_INCOMPLETE → MISSING_INFO / `targeted_recon`
- TOOL_FAILURE → TOOL_ERROR / `repair_or_substitute`
- ENVIRONMENT_MISMATCH → ENV_ERROR / `environment_adaptation`
- LOCAL_PROOF_FAILED → VERIFICATION_FAILED / `proof_strategy_switch`
- REMOTE_PROOF_FAILED → VERIFICATION_FAILED / `inspect_environment_diff`
- FLAG_REJECTED → VERIFICATION_FAILED / `return_to_proof`
- NO_INFORMATION_GAIN → NO_PROGRESS / `strategy_switch`
- BUDGET_EXHAUSTED → BUDGET_EXCEEDED / `checkpoint_stop`

The mapping target is advisory/control context. The recovery action remains Base-owned.

### 2.6 Progress remains a verified-state projection

`VerifiedCTFProfile.task_progress_snapshot()` derives Pwn task progress from Core `state.facts` and `state.completed`.

A later verified milestone does not manufacture missing intermediate milestones. Example: `ctf.pwn.arch + ctf.pwn.remote_behavior` produces only `artifact_profiled + remote_behavior_verified`.

Final completion remains the external Core completion oracle path.

## 3. Execution evidence

Final full gate: GitHub Actions run `32025233219`, job `95373152096`, commit `0a13144ac1f11c51a9f2c137a2a8374f51a8eeef`.

### E-WP07-01 — Base/Core regression preserved

- Base pytest: `220 passed, 7 skipped`.
- Core freeze audit: PASS, `new_stage_created=false`.
- Stage02 backend binding / persistent-session live namespace probes: PASS.
- Stage04 semantic matrix: 8/8, false positives 0, false negatives 0.
- Stage05 A/B/C/D recovery benchmark and negative controls: PASS within its existing controlled scope.
- Stage06 task/world progress authority probe: PASS; implicit task authority 0, regression credit 0, snapshot mutations 0.
- Stage07 context and Stage08 retrieval probes: PASS.

### E-WP07-02 — CTF regression preserved

CTF pytest on the final HEAD: `44 passed in 3.86s`.

This includes:

- typed taxonomy coverage;
- unknown-kind fail-closed behavior;
- forged/unregistered evidence rejection;
- exact-boolean retry-safety contract;
- CTF sidecar branch change not misusing Core rollback;
- Base recovery transition integration;
- repeat-threshold/strategy-generation behavior;
- terminal budget handling;
- hash-chained mapping audit events;
- no verified-fact mutation.

### E-WP07-03 — controlled CTF recovery/progress integration probe

`pwn-ctf-recovery-progress-controlled-v1` reported `all_passed=true`.

Observed routes:

```text
RECON_INCOMPLETE
  → Core missing_info
  → Base observe
  → target targeted_recon

ENVIRONMENT_MISMATCH (retry_safe=false)
  → Core env_error
  → Base observe
  → target environment_adaptation

FLAG_REJECTED
  → Core verification_failed
  → Base replan
  → target return_to_proof
```

Repeated `NO_INFORMATION_GAIN` with the same stable signature produced:

```text
replan → replan → switch_strategy
strategy_generation: 0 → 0 → 1
```

`BUDGET_EXHAUSTED` produced Base `checkpoint_stop` and halted the controlled runtime.

The probe also reported:

- `facts_mutated=false`
- `routing_authority=base_failure_router`
- `recovery_authority=base_runtime_recovery`
- `truth_authority=none`
- `solve_rate_measured=false`

### E-WP07-04 — progress does not infer an unverified chain

The same probe supplied only:

```text
ctf.pwn.arch
ctf.pwn.remote_behavior
```

and obtained exactly:

```json
{
  "milestones": ["artifact_profiled", "remote_behavior_verified"],
  "score": 2.0
}
```

No crash/control/local/environment milestone was invented.

### E-WP07-05 — P1–P6 and WP06 remain green

The final run re-executed and passed:

- P1 crash semantic probe;
- P2 control-flow semantic probe;
- P3 local-proof semantic probe;
- P4 target-environment compatibility probe;
- P5 remote-behavior probe;
- P6 Core-integrated external flag completion probe;
- WP06 runtime hypothesis/dedupe probe.

WP07 therefore did not replace semantic, proof, execution, hypothesis, or completion authorities.

## 4. Appropriateness evaluation

The current boundary is appropriate because it reuses the existing recovery invariants instead of duplicating them:

- CTF layer: domain classification and target context;
- Base `FailureRouter`: recovery-action selection;
- Base `RuntimeRecovery`: transition application, repeat counting, strategy generation, and terminal halt;
- Core verified state: truth authority;
- Domain profile: deterministic task-progress projection.

The explicit correction away from Core `HYPOTHESIS_REFUTED` for CTF sidecar/category labels prevents a superficially convenient mapping from acquiring the wrong rollback semantics.

## 5. Structural logic / truth review

- **No new Core enum:** CTF taxonomy is translated into existing `FailureKind` values.
- **No second recovery kernel:** CTF code does not implement separate repeat thresholds, strategy generations, or terminalization.
- **Retry safety:** environmental classification alone is insufficient to authorize RETRY.
- **Evidence integrity:** supplied failure evidence must already be durable Core evidence.
- **No truth promotion:** reporting/mapping a failure cannot create a VERIFIED fact or completion.
- **No false milestone chain:** progress is derived from present verified keys only.
- **No rollback semantic collision:** CTF sidecar/category labels do not enter the Core logical-hypothesis rollback path.

No new stage was created.

## 6. Truthfulness statement

**Proven by this WP:** deterministic CTF→Core failure mapping, fail-closed contracts, real Base FailureRouter/RuntimeRecovery integration, conservative retry behavior, repeat-threshold strategy switching, budget terminalization, non-mutating progress projection, and preservation of existing P1–P6/WP06 authority boundaries under controlled CI.

**Not proven by this WP:** that CTF-specific typed recovery improves actual solve rate, token use, wall-clock time, or cost on fresh/private/live CTF problems.

The existing Base Stage05 A/B/C/D benchmark also must not be overstated: generic replan and typed-targeted both completed all three recoverable constructed scenarios; typed routing showed only one-step and one-tool-call joint-success savings, and the retry-only arm observed no actual retry-safe failures.

## 7. Exit gate

- [x] typed CTF failure taxonomy
- [x] CTF→existing Core FailureKind mapping
- [x] unknown kinds fail closed
- [x] optional evidence must be Core-registered and integrity verified
- [x] retry safety is conservative and exact-boolean only
- [x] ENVIRONMENT_MISMATCH cannot silently authorize unsafe retry
- [x] explicit retry-safe environmental route uses existing Base RETRY
- [x] repeated failure uses Base repeat threshold / strategy generation
- [x] budget exhaustion uses Base terminal checkpoint-stop
- [x] CTF sidecar/category changes do not misuse Core hypothesis rollback
- [x] runtime no-repeat enforcement remains integrated through WP06
- [x] verified facts are not mutated by failure mapping/recovery
- [x] progress derives only from verified Core state/completion
- [x] P1–P6 and WP06 remain green
- [ ] actual CTF-corpus recovery effectiveness measured — deferred to WP08 benchmark evaluation

**Decision:** `PASS — ENGINEERING / CONTROLLED GATE`. Empirical recovery effectiveness remains intentionally open for WP08.
