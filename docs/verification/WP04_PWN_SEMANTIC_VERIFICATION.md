# WP04 — Pwn Semantic Verification

**Status:** `PARTIAL` — static semantics + P1 crash + P2 x86_64 control + P3 local proof PASS; P4/P5 OPEN; P6 completion OPEN

## 1. Implemented semantic authority

Current registered claim contracts are intentionally small and claim-specific:

- `ctf.pwn.arch` — LOGICAL
- `ctf.pwn.bits` — LOGICAL
- `ctf.pwn.endianness` — LOGICAL
- `ctf.pwn.nx` — LOGICAL when recon is conclusive
- `ctf.pwn.pie` — LOGICAL when recon is conclusive
- `ctf.pwn.crash_reproducible` — EXECUTION
- `ctf.pwn.control_flow` — EXECUTION, x86_64 RIP-only scope
- `ctf.pwn.local_exploit` — EXECUTION, control-plane local-oracle receipt only

No semantic authority is registered yet for `ctf.environment.compatible`, `ctf.pwn.remote_behavior`, or `ctf.flag_valid`.

## 2. Evidence-validation logic

### Static claims

Static verifiers require registered Core artifact/evidence refs, successful `pwn_recon` provenance, integrity-checked Core `ArtifactStore` reads, expected schema/kind, one artifact identity, and exact candidate binding. Wrong values, missing observation provenance, mixed identities, tamper, and unsupported claim names are rejected.

### P1 — reproducible crash

`pwn_crash_probe` executes a fixed probe through the attested namespace backend. `CrashReproducibleVerifier` requires at least two evidence artifacts with the same target hash, input hash, and terminating signal. Timeout, one-shot evidence, or candidate mismatch is rejected.

### P2 — x86_64 control

`pwn_control_probe` runs a fixed GDB probe through the same namespace boundary. `ControlFlowVerifier` requires repeated observations of the same target/input and binds observed `RIP` to an exact little-endian byte sequence and offset in the supplied input. A crash alone is insufficient.

P2 failure/fix history is intentionally preserved:

1. Initial live probe failed because hosted runner did not contain GDB.
2. GDB was explicitly installed and version recorded; probe still failed.
3. Diagnostics showed RIP remained `0x401016`, the synthetic target's `ret` instruction. Root cause: the original marker `0x4141414141414141` is non-canonical on x86_64, so `ret` faults before RIP can become that value.
4. The verifier was **not weakened**. Only the synthetic test vector was changed to canonical unmapped `0x0000414141414141`.
5. CI run `32014073885` then observed the same RIP value twice at input offset 0 and passed.

### P3 — local proof

P3 does not accept Actor prose, a `shell` string, or exit-code-only evidence. `ExecutableDigestLocalProofOracle` is a control-plane oracle with an operator-fixed expected stdout digest. It executes `[./exploit, ./target]` only through the supplied attested backend and requires a live strong filesystem boundary.

The durable `LocalProofReceipt` binds:

- target SHA-256,
- exploit SHA-256,
- target-environment fingerprint,
- stable oracle ID,
- oracle evidence hash,
- oracle independence level,
- accepted/rejected decision.

`LocalExploitVerifier` additionally requires Core observation source `pwn_local_proof_oracle` and exact target/exploit/environment/oracle identity. Actor-like receipt provenance is rejected.

## 3. Execution evidence

**E-WP04-01 — P1:** run `32015174592`, `pwn-crash-semantic-live`: `all_passed=true`, `attestation_source=runtime_probe`, evidence count 2, signal 11.

**E-WP04-02 — P2:** same run, GDB `15.1-1ubuntu1~24.04.1`; repeated control records both observed `RIP=0x414141414141`, input offset 0, identical target/input hashes; `all_passed=true`.

**E-WP04-03 — P3:** same run, `pwn-local-proof-live`: `accepted=true`, `attestation_source=runtime_probe`, `filesystem_isolated=true`, exact target/exploit/environment hashes recorded, stable oracle ID `pwn_local_executable_digest:b0f20fb6fe00fbc7`.

**E-WP04-04 — P3 negative controls:** `actor_source_rejected=true`, `rejected_oracle_rejected=true`, and a mismatched exploit hash is rejected by the verifier.

**E-WP04-05 — Core regression:** same run: base `219 passed / 7 skipped`; Core freeze and Stage02/04/05/06/07/08 probes pass; core freeze reports `new_stage_created=false`.

**E-WP04-06 — CTF regression:** same run: `15 passed`.

**E-WP04-07 — failed-gate evidence:** P3 implementation commit `8154e778...` produced failed run `32014880957`: base/Core probes passed but an existing regression test still encoded the old non-contiguous P5 ladder rule. The implementation was not declared complete. Test contract was corrected in commit `d531dcb8...`, then the full gate passed.

## 4. Appropriateness evaluation

The current P1–P3 design is appropriate for a verified-state harness because each stronger semantic claim requires correspondingly stronger evidence:

- P1 proves reproducible failure, not exploitability.
- P2 proves input-derived instruction-pointer control in the currently supported x86_64 scope, not a working exploit.
- P3 proves one exact exploit artifact satisfied an operator-fixed local oracle against one exact target/environment. It does not infer remote success.

The P3 oracle is intentionally outside the Actor tool authority. This avoids turning self-authored exploit output into self-verification.

## 5. Structural logic evaluation

### Positive

- Core `HarnessState.facts` remains the sole authoritative fact store.
- P0–P6 remain CTF proof projections, not new Core verification levels or stages.
- Every registered CTF semantic rule maps to a real verifier.
- Evidence is content-integrity checked and provenance constrained.
- P2 failure investigation changed the faulty test vector rather than weakening semantic checks.
- P3 separates exploit generation from proof authority.

### Remaining structural problems

1. **P2 architecture scope:** only x86_64 RIP control is currently semantically authorized. Other architectures must fail closed.
2. **P3 oracle generality:** the implemented digest oracle is a deterministic local-proof mechanism, not yet a universal proof model for shell, file-read, protocol, or stateful exploit effects.
3. **P4 absent:** local and remote target-runtime compatibility is not yet a verified fact.
4. **P5 absent:** no remote behavior receipt/verifier exists yet.
5. **P6 absent:** accepted flag receipt is not yet wired as the Core completion oracle.
6. **Runner reproducibility:** engineering CI installs GDB dynamically; a frozen benchmark runner image/tool inventory remains an open WP00 item.

## 6. Truthfulness evaluation

**Supported by current evidence:** the implemented static claims, reproducible crash contract, x86_64 input-derived RIP control contract, and one control-plane local-proof contract execute successfully under the tested CI namespace boundary and fail the implemented negative controls.

**Not supported:** arbitrary Pwn exploitability, arbitrary local-shell success, remote exploitation, broad architecture coverage, live CTF success, or benchmark superiority. The P1–P3 probes are controlled engineering tests, not a real-world CTF benchmark.

## 7. Exit gate

- [x] explicit fail-closed claim registry
- [x] Core-bound static verifiers
- [x] artifact/provenance integrity checks
- [x] P1 reproducible crash verifier
- [x] P2 x86_64 control verifier
- [x] P3 control-plane local exploit verifier
- [ ] P4 target-environment compatibility verifier
- [ ] P5 remote behavior verifier
- [ ] P6 external submission integrated with Core completion

**Decision:** `PARTIAL`. Proceed to P4 only; do not claim a complete Pwn proof slice yet.
