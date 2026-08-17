# WP04 — Pwn Semantic Verification

**Status:** `PARTIAL` — static semantics + P1 crash + P2 x86_64 control + P3 local proof + P4 environment compatibility PASS; P5/P6 OPEN

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
- `ctf.environment.compatible` — LOGICAL, explicit target-runtime compatibility contract

No semantic authority is registered yet for `ctf.pwn.remote_behavior` or final flag validity/completion.

## 2. Evidence-validation logic

### Static claims

Static verifiers require registered Core artifact/evidence refs, successful `pwn_recon` provenance, integrity-checked Core `ArtifactStore` reads, expected schema/kind, one artifact identity, and exact candidate binding. Wrong values, missing observation provenance, mixed identities, tamper, and unsupported claim names are rejected.

### P1 — reproducible crash

`pwn_crash_probe` executes a fixed probe through the attested namespace backend. `CrashReproducibleVerifier` requires at least two evidence artifacts with the same target hash, input hash, and terminating signal. Timeout, one-shot evidence, or candidate mismatch is rejected.

### P2 — x86_64 control

`pwn_control_probe` runs a fixed GDB probe through the same namespace boundary. `ControlFlowVerifier` requires repeated observations of the same target/input and binds observed `RIP` to an exact little-endian byte sequence and offset in the supplied input. A crash alone is insufficient.

P2 failure/fix history is preserved: GDB absence was detected; after installation, the original non-canonical marker `0x4141414141414141` caused a #GP at `ret`, leaving RIP at `0x401016`. The verifier was not weakened; only the synthetic vector was changed to canonical unmapped `0x0000414141414141`. Run `32014073885` then observed the intended RIP twice at offset 0.

### P3 — local proof

P3 does not accept Actor prose, a `shell` string, or exit-code-only evidence. `ExecutableDigestLocalProofOracle` is a control-plane oracle with an operator-fixed expected stdout digest. It executes `[./exploit, ./target]` through the attested backend and requires a live strong filesystem boundary.

`LocalProofReceipt` binds target SHA-256, exploit SHA-256, target-environment fingerprint, stable oracle ID, oracle evidence hash, independence level and decision. `LocalExploitVerifier` requires Core observation source `pwn_local_proof_oracle` and exact identity binding.

### P4 — target-environment compatibility

P4 deliberately does **not** reuse `admission.EnvironmentFingerprint`. Admission fingerprint describes the harness runner; P4 must describe the challenge target/runtime. `TargetEnvironmentFingerprint` therefore has separate semantics.

Baseline Pwn compatibility fields are mandatory:

- architecture
- bits
- endianness
- PIE
- NX
- protocol
- target revision

Challenge-specific dependencies may be added explicitly; the controlled P4 contract additionally included `libc_sha256` and `loader_sha256`. A contract may not omit baseline fields. Missing/unknown values make compatibility inconclusive rather than silently equal.

Trusted environment sources are restricted to `local_probe`, `remote_probe`, and `operator_manifest`. `EnvironmentCompatibilityVerifier` requires a registered Core observation source `pwn_environment_compare`, a compatible receipt, no differences/missing fields, all baseline fields, and exact local/remote fingerprint + contract binding.

## 3. Execution / controlled evidence

**E-WP04-01 — latest full gate:** CI run `32015639019` SUCCESS. Base `219 passed / 7 skipped`; Core freeze and Stage02/04/05/06/07/08 probes PASS; `new_stage_created=false`; CTF regression `18 passed`.

**E-WP04-02 — P1/P2/P3 regression:** same run re-executed all prior live probes successfully. P2 again observed `RIP=0x414141414141`, offset 0 twice; P3 again reported `accepted=true`, `runtime_probe`, filesystem isolation, Actor-source rejection and rejected-oracle rejection.

**E-WP04-03 — P4 positive contract:** `pwn-environment-compatibility-controlled` reported `all_passed=true`, `compatible=true`. Local and remote target fingerprints were both `3f90aea773eba2fdc4b10a5270224f59188ca6e2d758f4b52d5cfa3bee3149fe` under the declared baseline + libc/loader contract.

**E-WP04-04 — P4 negative controls:** same probe reports `mismatch_rejected=true`, `missing_field_rejected=true`, `actor_source_rejected=true`, `untrusted_source_rejected=true`, `baseline_omission_rejected=true`.

**E-WP04-05 — prior failed gate retained:** P3 feature run `32014880957` failed because an old regression encoded non-contiguous P5 semantics. Base/Core remained green; the stale test contract was corrected and the next full run passed.

## 4. Appropriateness evaluation

The semantic strength increases with the proof level:

- P1: reproducible failure only.
- P2: input-derived x86_64 RIP control only.
- P3: exact local exploit/target/environment satisfies an operator-fixed local oracle.
- P4: an explicit set of required target-runtime properties is known and equal under trusted sources.

P4 is appropriately LOGICAL rather than EXECUTION because the claim is an equality/compatibility theorem over trusted environment observations/manifests; it does not itself execute the remote exploit. Dynamic remote behavior remains P5.

Separating runner identity from target-runtime identity fixes a truth-model ambiguity that could otherwise declare two targets compatible merely because the harness ran in the same container.

## 5. Structural logic / truth review

### Positive

- Core `HarnessState.facts` remains the only authoritative fact store.
- No Core stage or `VerificationLevel` was added.
- Every registered semantic rule names a real verifier.
- P0–P4 proof semantics are separated from Actor narrative and retrieval content.
- P4 contract cannot be weakened below the mandatory baseline fields.
- Additional runtime dependencies such as libc/loader are explicit contract inputs, not hidden assumptions.

### Remaining structural problems

1. P2 semantic authority is x86_64 RIP-only.
2. P3 digest oracle is not yet a universal local proof vocabulary.
3. P4 does not discover a real remote environment by itself; it verifies equality of supplied trusted target-environment evidence.
4. `operator_manifest` is only truthful if admission/control-plane code supplies it; Actor-authored manifest data must never receive that provenance label.
5. P5 remote behavior receipt/verifier is absent.
6. P6 external flag acceptance is not wired to Core completion.
7. Benchmark runner image/tool inventory remains unfrozen; GDB is dynamically installed in engineering CI.

## 6. Truthfulness evaluation

**Supported:** static properties, controlled P1 crash, controlled P2 x86_64 RIP control, controlled P3 local oracle proof, and P4 compatibility-contract semantics including negative controls.

**Not supported:** actual discovery of arbitrary remote libc/loader/protocol facts, arbitrary Pwn exploitability, live remote exploitation, live CTF success, or benchmark superiority. P4 is a controlled semantic-contract test, not real-world remote-environment proof.

## 7. Exit gate

- [x] explicit fail-closed claim registry
- [x] Core-bound static verifiers
- [x] artifact/provenance integrity checks
- [x] P1 reproducible crash verifier
- [x] P2 x86_64 control verifier
- [x] P3 control-plane local exploit verifier
- [x] P4 target-environment compatibility verifier
- [ ] P5 remote behavior verifier
- [ ] P6 external submission integrated with Core completion

**Decision:** `PARTIAL`. P4 gate is complete; proceed to P5 only.
