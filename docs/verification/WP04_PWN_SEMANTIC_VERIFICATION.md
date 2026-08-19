# WP04 — Pwn Semantic Verification

**Status:** `PASS` for the controlled Pwn semantic vertical slice; broad/live benchmark validation remains separate

## 1. Implemented semantic authority

The registered claim vocabulary is intentionally small and fail-closed:

- `ctf.pwn.arch` — LOGICAL
- `ctf.pwn.bits` — LOGICAL
- `ctf.pwn.endianness` — LOGICAL
- `ctf.pwn.nx` — LOGICAL when recon is conclusive
- `ctf.pwn.pie` — LOGICAL when recon is conclusive
- `ctf.pwn.crash_reproducible` — EXECUTION
- `ctf.pwn.control_flow` — EXECUTION, x86_64 RIP-only
- `ctf.pwn.local_exploit` — EXECUTION, control-plane local-proof receipt only
- `ctf.environment.compatible` — LOGICAL, explicit target-runtime compatibility contract
- `ctf.pwn.remote_behavior` — EXECUTION, endpoint-bound control-plane remote receipt only

P6 final success is **not** an ordinary semantic fact. It uses Core completion authority directly.

## 2. Semantic evidence chain

### Static / P0

Core artifact/evidence registration, `pwn_recon` provenance, integrity-verified `ArtifactStore` reads, schema/kind checks, one artifact identity and exact candidate binding are required. Unsupported semantic keys fail closed.

### P1 — reproducible crash

Requires at least two matching executions for exact target/input/signal. One crash or a timeout does not authorize the claim.

### P2 — x86_64 control

A fixed GDB probe must repeatedly observe RIP derived from exact little-endian input bytes at an exact offset. The earlier GDB absence and non-canonical-marker failures were diagnosed rather than bypassed; the verifier remained strict.

### P3 — local proof

`ExecutableDigestLocalProofOracle` is outside Actor authority, uses an operator-fixed output digest, executes the exact exploit/target through the isolated backend, and emits a receipt binding target/exploit/environment/oracle identities. Actor-source lookalikes and rejected receipts fail.

### P4 — environment compatibility

Runner identity and target-runtime identity are separate types. Baseline Pwn compatibility requires architecture, bits, endian, PIE, NX, protocol and target revision; challenge-specific dependencies such as libc/loader may be added. Missing values, mismatch, untrusted source or baseline omission fail closed.

### P5 — remote behavior

`TCPRemoteBehaviorOracle` is control-plane-only, configured from operator/admission data. It pins numeric endpoint addresses and binds endpoint ID, exact payload digest, observed response digest, remote-environment fingerprint and oracle ID. Plaintext payload/response are not required in durable proof state.

### P6 — final external truth boundary

`FlagReceiptCompletionOracle` is connected through `VerifiedCTFProfile.completion_oracle()` to the existing Base `HarnessRuntime` completion path. Final success therefore becomes `state.completed=True` only after an externally accepted receipt matches exact challenge ID, challenge revision, target and `GoalContract.task_id`.

No `ctf.flag_valid` fact or second completion truth store was introduced.

## 3. Latest integrated execution evidence

Final stability run: `32017690564` on CTF branch `implementation/evidence-roadmap`, pinned Base SHA `75834ac1ecb6c022771c2efee1f19495f356ee76`.

- Base pytest: **220 passed / 7 skipped**.
- Core freeze + Stage02/04/05/06/07/08 probes: PASS.
- `new_stage_created=false`.
- CTF regression: **24 passed**.
- P1 crash semantic probe: PASS, repeated signal 11.
- P2 x86_64 control probe: PASS, repeated `RIP=0x414141414141`, input offset 0.
- P3 local proof: PASS with runtime namespace/filesystem isolation and negative controls.
- P4 environment compatibility: PASS with mismatch/missing/provenance/contract negative controls.
- P5 endpoint-bound remote behavior: PASS with wrong-payload/Actor-source/candidate-mismatch negative controls and plaintext traffic non-persistence.
- P6 Core completion: PASS; accepted external receipt completes, rejected/mismatched receipts do not.

P6 controlled evidence includes:

- candidate hash `f7576f494844b167aad57a75fb7029603feb3526483c21925f52357435ee82ea`;
- response-reference hash `efce7e56668f0815d88e165d6a4863ea93073fd0ff7a3c7a0799c448273ef3a0`;
- challenge `synthetic-pwn-final`;
- revision `rev-2026-08-17`;
- target `tcp://challenge.invalid:31337`;
- independence level `external_task_oracle_receipt`;
- `runtime_completed=true` only for the accepted receipt;
- wrong revision, wrong target, wrong task ID and missing revision rejected;
- plaintext candidate and response reference not persisted.

## 4. Failure evidence retained

The vertical slice was not declared complete after individual happy-path passes. Recorded failures include:

- argv compatibility regression during upstream structured-runtime work;
- strict-isolation message compatibility regression;
- GDB missing from engineering runner;
- P2 non-canonical synthetic RIP marker;
- stale regression expecting non-contiguous P5;
- persistent-session first-readable-byte race exposed by run `32016757858`;
- initial CTF re-pin config mismatch where lock and workflow/freeze constant temporarily referenced different Base SHAs.

Each was isolated and re-run under the full gate. The final run uses the remediated Base read-window semantics.

## 5. Appropriateness evaluation

The proof strength increases monotonically in meaning without confusing claim-verification strength with task progression:

- P1 proves failure reproducibility;
- P2 proves a narrow control primitive;
- P3 proves one exact local exploit effect;
- P4 proves declared local/remote assumptions are compatible;
- P5 proves one exact remote behavior;
- P6 proves task-native external acceptance.

This layering is appropriate for the Verified-State architecture because Actor, Skill and Retrieval remain proposal/information sources while deterministic verifiers, control-plane proof oracles and the final external oracle retain truth authority.

## 6. Structural logic / truth review

### Confirmed

- `HarnessState.facts` remains the sole semantic fact store.
- `state.completed` remains the final Core completion state.
- P0–P6 were not added to Core `VerificationLevel`.
- no Stage09/new Core stage exists.
- every registered Pwn semantic rule maps to a real verifier.
- local proof never auto-promotes remote proof.
- remote proof never auto-promotes final completion.
- P6 does not manufacture missing P0–P5 facts.
- P5 and P6 proof authority remain separate from Actor unrestricted networking/submission claims.

### Remaining limitations outside this scoped gate

1. P2 currently authorizes x86_64 RIP control only.
2. P3 digest oracle is not a universal vocabulary for every Pwn effect.
3. P4 verification does not itself discover arbitrary remote environment facts.
4. P5 is currently a bounded single TCP exchange model; stateful/multistep remote proof needs additional adapters.
5. P5/P6 evidence is controlled/synthetic, not a public/live CTF solve.
6. runner image/tool inventory is not yet frozen as the final benchmark runner; engineering CI still installs GDB dynamically.
7. hypothesis dedupe/recovery are not yet fully wired into runtime execution.
8. fresh/private Pwn A/B benchmark has not yet run.

## 7. Truthfulness statement

**Supported by current evidence:** the implemented Pwn semantic contracts and the complete controlled P0→P6 authority chain behave according to their stated positive and negative contracts on the tested Ubuntu 24.04 CI environment.

**Not supported:** arbitrary Pwn challenge solving, live-event success rate, arbitrary protocol/architecture coverage, or superiority over another harness. Those require the later fresh/private benchmark and live evaluation tracks.

## 8. Exit gate

- [x] fail-closed semantic claim registry
- [x] Core-bound static verifiers
- [x] P1 reproducible crash
- [x] P2 x86_64 input-derived RIP control
- [x] P3 control-plane local proof
- [x] P4 explicit target-environment compatibility
- [x] P5 endpoint-bound remote behavior
- [x] P6 external receipt wired to Core completion
- [x] exact remediated Base SHA + full regression gate
- [ ] fresh/private Pwn benchmark — separate evaluation WP

**Decision:** controlled Pwn semantic vertical slice `PASS`. This is an engineering/semantic gate, not a real-world benchmark result.
