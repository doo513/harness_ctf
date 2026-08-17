# WP05 — Proof Pipeline Verification

**Status:** `PARTIAL` — P0→P3 contiguous path executable; P4/P5/P6 still OPEN

## 1. Implemented logic

- CTF `ProofLevel` P0–P6 remains separate from Core `VerificationLevel`.
- P0–P5 now form a **contiguous proof path**; projection stops at the first missing proof gate.
- P6 remains special: external task-oracle acceptance is final truth and may project to P6 without fabricating intermediate facts.
- P3 introduces a durable `LocalProofReceipt` persisted through Core `ArtifactStore`.
- local proof identity binds target SHA-256, exploit SHA-256, environment fingerprint and oracle ID.
- local and remote claim namespaces remain distinct; no P3→P5 auto-promotion exists.
- flag submission receipt continues to hash the candidate instead of persisting plaintext.

## 2. Structural correction: non-contiguous P5

The previous implementation treated the proof ladder as a “highest independently evidenced level” display. Therefore `ctf.pwn.remote_behavior` alone projected to P5 even if P0–P4 were absent.

That representation was reassessed as structurally misleading because the type is explicitly named a **proof ladder** and downstream logic may interpret P5 as evidence that earlier proof gates were traversed. The implementation was changed so P0–P5 are contiguous.

The correction was tested rather than silently changed:

- implementation commit `8154e778...` changed the ladder and added P3;
- CI run `32014880957` failed because the old regression test still asserted remote-only → P5;
- base `219 passed / 7 skipped` and Core invariant probes passed in that failed run, isolating the failure to the stale CTF contract;
- commit `d531dcb8...` updated the regression to the new contiguous contract;
- run `32015174592` then passed the full gate.

This failure→fix sequence is retained as evidence that the new semantic contract is deliberate rather than an accidental test deletion.

## 3. P3 durable-proof evidence

Run `32015174592` produced `pwn-local-proof-live` with:

- `accepted=true`
- `attestation_source=runtime_probe`
- `filesystem_isolated=true`
- target SHA-256 `88f35d201071d0deedbb6fae08059d9bbda0d9995436eda9d4a7e8e6f3da4030`
- exploit SHA-256 `871b34c27fe3a9a7f5ce2c2686eacb08de066d2fc88be07ec56d48b56e06a36a`
- environment fingerprint `39be50fc5b675f6a2a6242ea67f9eea319b17577053bc96dd3e3463f454c264f`
- oracle ID `pwn_local_executable_digest:b0f20fb6fe00fbc7`
- `actor_source_rejected=true`
- `rejected_oracle_rejected=true`
- `noncontiguous_p5_blocked=true`

The same run reports CTF regression `15 passed`, base `219 passed / 7 skipped`, and all Core invariant probes PASS.

## 4. Appropriateness evaluation

### ProofLevel vs VerificationLevel

The separation remains appropriate:

- Core `VerificationLevel` expresses how one claim was verified.
- CTF `ProofLevel` expresses task-level progression across multiple verified claims and the final oracle.

No Core enum or stage was added.

### Contiguous P0–P5

For the selected Pwn proof model, contiguity is more appropriate than “highest isolated fact” because P3, P4 and P5 have explicit local→environment→remote dependency semantics. An isolated remote observation may still be a valid verified fact and may count as an independent task milestone, but it must not imply that the full proof path reached P5.

This distinction is important: **task progress and proof-path level are not identical concepts.** `pwn_progress_snapshot()` may report independently verified milestones; `proof_level_from_verified_keys()` now reports the strongest contiguous proof prefix.

### P6 exception

P6 is correctly exempt from contiguity. If the external CTF oracle accepts a flag/proof, final task success is true even if optional intermediate instrumentation was unavailable. The system must not manufacture P0–P5 facts in that case.

## 5. Logic / truthfulness evaluation

### Confirmed

- remote-only fact no longer masquerades as a completed P0–P5 path;
- P3 receipt is durable evidence, not just an in-memory DTO;
- Actor-authored lookalike receipt cannot pass the verifier without the trusted Core observation source;
- rejected local oracle evidence cannot become `ctf.pwn.local_exploit`;
- P6 is not inferred from flag-shaped data.

### Remaining problems

1. P4 target-environment compatibility has no registered semantic verifier yet.
2. P5 remote behavior has no control-plane receipt/verifier yet.
3. P6 flag submission is not yet the profile's Core completion oracle.
4. `ProofReceipt` generic DTO is not yet the universal automatic receipt format; P3 currently uses a stronger domain-specific `LocalProofReceipt`.
5. End-to-end controller flow that automatically performs P3→P4→P5→P6 is not implemented yet.

## 6. Truthfulness statement

**Proven in controlled engineering tests:** P0→P3 contiguous projection, durable P3 receipt integrity/provenance checks, and negative controls for Actor source / rejected oracle / non-contiguous P5.

**Not proven:** target-environment equivalence, actual remote exploitation, live CTF flag acceptance, or end-to-end solve performance.

## 7. Exit gate

- [x] separate proof-level type
- [x] P0–P5 contiguous projection
- [x] P6 external-acceptance exception without intermediate fabrication
- [x] no local→remote auto-promotion
- [x] durable P3 domain-specific proof receipt
- [x] executable P1–P3 semantic chain
- [ ] P4 target-environment compatibility
- [ ] P5 remote behavior proof
- [ ] P6 external flag oracle wired to Core completion
- [ ] end-to-end Pwn proof pipeline benchmark

**Decision:** `PARTIAL`. P3 gate is complete; proceed to P4.
