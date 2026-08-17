# WP05 — Proof Pipeline Verification

**Status:** `PASS` for the controlled P0→P6 proof pipeline. Fresh/private and live challenge evaluation remain separate work.

## 1. Implemented structure

- CTF `ProofLevel` remains separate from Core `VerificationLevel`.
- P0–P5 are a contiguous proof prefix.
- P6 is final external task acceptance and does not manufacture missing P0–P5 facts.
- P3, P4 and P5 use durable domain-specific receipts.
- P6 uses a hashed external submission receipt through the existing Core completion-oracle path.
- `HarnessState.facts` remains the semantic fact store and `state.completed` remains final completion truth.

## 2. Important structural corrections

### Contiguous proof prefix

An earlier implementation allowed an isolated remote-behavior fact to display P5. This was corrected so the proof ladder stops at the first missing gate. An old regression test exposed the semantic change in run `32014880957`; the stale contract was corrected and the full gate rerun.

### P6 authority

P6 was not implemented as a new `ctf.flag_valid` fact. `FlagReceiptCompletionOracle` is returned by `VerifiedCTFProfile.completion_oracle()` and Base `HarnessRuntime` performs the final completion transition.

The external receipt is bound to challenge ID, challenge revision and target, while completion also requires exact `GoalContract.task_id`. Accepted receipts require a hashed external response reference. Candidate and platform-response plaintext are not persisted by this receipt path.

## 3. Latest integrated evidence

Final stability run `32017690564`, pinned Base SHA `75834ac1ecb6c022771c2efee1f19495f356ee76`:

- Base pytest: **220 passed / 7 skipped**.
- Core freeze + Stage02/04/05/06/07/08 probes: PASS.
- CTF regression: **24 passed**.
- P1 crash: PASS.
- P2 x86_64 control: PASS.
- P3 local proof: PASS.
- P4 environment compatibility: PASS.
- P5 remote behavior: PASS.
- P6 Core-integrated external completion: PASS.

P6 evidence records one completion request and one oracle check. The accepted receipt sets `runtime_completed=true` and projects `P6_ACCEPTED`. Negative controls reject a rejected receipt, wrong revision, wrong target, wrong task ID and missing revision. The completion artifact contains hashes, not the submitted candidate or external response-reference plaintext.

## 4. Runtime-stability evidence

During P6 integration, run `32016757858` exposed a persistent-session read race in Base. Positive `wait_seconds` previously returned after the first readable startup output. Upstream remediation changed it to a bounded observation window and added deterministic unit + privileged namespace regression coverage.

Upstream run `32017301630` on SHA `75834ac1...` passed **220 tests / 7 skipped** plus all Core invariant probes. `harness_ctf` was then re-pinned to that exact SHA.

An intermediate downstream re-pin failed because lock/workflow/reviewed-SHA constants were temporarily inconsistent. After synchronizing all three, run `32017690564` passed the full P0→P6 chain. These failures remain part of the evidence history rather than being omitted.

## 5. Appropriateness evaluation

The proof model is consistent with Verified-State semantics:

- claim-verification strength stays in Core verification contracts;
- task progression stays in CTF proof levels;
- P0–P5 cannot imply skipped dependencies;
- P6 is task-native external truth rather than another intermediate claim;
- external acceptance does not backfill unobserved intermediate facts.

This separation avoids conflating “a strong claim was verified” with “the challenge is solved.”

## 6. Structural / truthfulness review

### Confirmed

- no second truth store;
- no new Core stage;
- no local→remote automatic promotion;
- no remote→completion automatic promotion;
- P6 challenge/revision/target/task binding;
- fail-closed negative controls for rejected or mismatched completion receipts;
- full controlled P0→P6 rerun on the remediated exact Base SHA.

### Remaining work

1. Hypothesis dedupe is not yet connected to actual tool execution.
2. CTF-specific recovery mapping is not yet connected to the Core runtime failure path.
3. P5 currently models a bounded single TCP exchange, not every stateful protocol.
4. The final benchmark runner image/tool inventory is not yet frozen.
5. No fresh/private Pwn A/B benchmark has yet measured success, false facts, repeated failures, tool calls, tokens, time or cost.
6. No live CTF evidence has yet been collected for this harness.

## 7. Truthfulness statement

**Supported:** the controlled P0→P6 authority chain, its negative controls, and the real Core completion transition operate correctly on the pinned tested CI environment.

**Not supported:** autonomous solving of fresh challenges, live-event effectiveness, arbitrary protocol coverage, or improvement over a baseline harness.

## 8. Exit gate

- [x] P0–P5 contiguous projection
- [x] external P6 without intermediate fact fabrication
- [x] durable P3/P4/P5 receipts
- [x] P6 bound to Core completion
- [x] revision/target/task negative controls
- [x] final full-chain rerun on remediated Base SHA
- [ ] fresh/private benchmark — separate evaluation WP

**Decision:** controlled P0→P6 proof-pipeline gate `PASS`.
