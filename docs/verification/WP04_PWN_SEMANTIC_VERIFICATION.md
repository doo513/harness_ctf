# WP04 — Pwn Semantic Verification

**Status:** `PARTIAL` — static semantics + P1 crash + P2 x86_64 control + P3 local proof + P4 environment compatibility + P5 remote behavior PASS; P6 OPEN

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
- `ctf.pwn.remote_behavior` — EXECUTION, endpoint-bound control-plane TCP oracle receipt only

Final flag validity/completion remains outside ordinary semantic claims and is still OPEN.

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

Baseline Pwn compatibility fields are mandatory: architecture, bits, endianness, PIE, NX, protocol and target revision. Challenge-specific dependencies may be added explicitly; the controlled P4 contract additionally included `libc_sha256` and `loader_sha256`. A contract may not omit baseline fields. Missing/unknown values make compatibility inconclusive rather than silently equal.

Trusted environment sources are restricted to `local_probe`, `remote_probe`, and `operator_manifest`. `EnvironmentCompatibilityVerifier` requires a registered Core observation source `pwn_environment_compare`, a compatible receipt, no differences/missing fields, all baseline fields, and exact local/remote fingerprint + contract binding.

### P5 — endpoint-bound remote behavior

P5 does not expose arbitrary Actor egress as proof authority. `TCPRemoteBehaviorOracle` is a control-plane component configured from `operator_manifest` or `challenge_admission` only.

The oracle resolves the configured hostname once, pins the numeric address set, and subsequently connects to those pinned addresses. The semantic contract also fixes the expected response SHA-256, payload/response size limits and endpoint identity. Acceptance requires a completed bounded response with exactly the operator-fixed response digest.

`RemoteBehaviorReceipt` persists hashes and endpoint identity instead of plaintext payload/response. It binds:

- endpoint ID,
- observed peer IP/port,
- exact payload SHA-256,
- observed response SHA-256 and byte count,
- response completeness,
- remote target-environment fingerprint,
- stable oracle ID,
- independence level and decision.

`RemoteBehaviorVerifier` requires Core source `pwn_remote_proof_oracle`, an accepted complete receipt, exact endpoint/payload/response/environment/oracle identity and valid peer metadata. An Actor-authored lookalike receipt or a different payload/endpoint cannot authorize the claim.

## 3. Execution / controlled evidence

**E-WP04-01 — latest full gate:** CI run `32016195605` SUCCESS. Base `219 passed / 7 skipped`; Core freeze and Stage02/04/05/06/07/08 probes PASS; `new_stage_created=false`; CTF regression `20 passed`.

**E-WP04-02 — P1–P4 regression:** same run re-executed all earlier P1–P4 gates successfully, including repeated RIP control, filesystem-isolated P3 proof and the P4 baseline+libc+loader comparison contract.

**E-WP04-03 — P5 positive controlled TCP exchange:** `pwn-remote-behavior-controlled` reports `all_passed=true`, `accepted=true`, peer `127.0.0.1`, pinned IP set `[127.0.0.1]`, endpoint ID `5afa5cedc1a1a52c46d5756a38116ed3b926f346fd7722526d4ca7cf59fd7769`, payload SHA-256 `faad3aa4dbdae3674703a7fbca3b68a23566fc43820a033de98af0ad64b45cb6`, response SHA-256 `4694c4df2c99cbedab25780b59e527484aaab1cac71572ecc711b898a9c15351`, remote-environment fingerprint `3f90aea773eba2fdc4b10a5270224f59188ca6e2d758f4b52d5cfa3bee3149fe`, oracle ID `pwn_remote_tcp_response_digest:5afa5cedc1a1a52c`.

The ephemeral peer port is run-specific and is evidence metadata, not a stable semantic identifier.

**E-WP04-04 — P5 negative controls:** same probe reports `wrong_payload_rejected=true`, `actor_source_rejected=true`, `actor_endpoint_source_rejected=true`, `candidate_mismatch_rejected=true`, `isolated_p5_blocked=true`, `plaintext_payload_persisted=false`, `plaintext_response_persisted=false`.

**E-WP04-05 — proof continuity:** full P0–P5 keys reach P5; an isolated `ctf.pwn.remote_behavior` fact does not.

**E-WP04-06 — prior failed-gate history retained:** P3 feature run `32014880957` failed because an old regression encoded non-contiguous P5 semantics. Base/Core remained green; the stale test contract was corrected and the next full run passed.

## 4. Appropriateness evaluation

The semantic strength now increases through P5:

- P1: reproducible failure only.
- P2: input-derived x86_64 RIP control only.
- P3: exact local exploit/target/environment satisfies an operator-fixed local oracle.
- P4: an explicit set of target-runtime assumptions is known and equal under trusted sources.
- P5: one exact payload against one operator-fixed endpoint produces one operator-fixed remote behavior under one bound remote-environment identity.

P5 is appropriately `EXECUTION`: unlike P4, its evidence is an actual network exchange. Keeping the endpoint oracle outside Actor tool authority also prevents “proof” from becoming equivalent to unrestricted Actor networking.

One-time resolution plus numeric-address pinning reduces target drift between configuration and evaluation and binds the proof to a concrete endpoint set. This is stronger than repeatedly resolving an Actor-supplied hostname during proof execution.

## 5. Structural logic / truth review

### Positive

- Core `HarnessState.facts` remains the only authoritative fact store.
- No Core stage or `VerificationLevel` was added.
- Every registered semantic rule names a real verifier.
- P0–P5 proof semantics remain distinct from Actor narrative and retrieval content.
- P5 endpoint configuration is operator/admission sourced, not Actor sourced.
- Payload and response plaintext are not persisted in the P5 receipt.
- Remote evidence is bound to the P4 remote-environment fingerprint instead of being treated as environment-free proof.

### Remaining structural problems

1. P2 semantic authority is x86_64 RIP-only.
2. P3 digest oracle is not yet a universal local proof vocabulary.
3. P4 does not independently discover arbitrary real remote environment facts.
4. P5 currently models a bounded single TCP request/response-to-EOF exchange. Stateful/multistep protocols and long-lived remote exploit sessions require a richer control-plane remote proof adapter.
5. P5 engineering evidence uses a loopback synthetic service, not a public/live CTF target.
6. Admission-to-P5 orchestration that automatically consumes a real challenge endpoint is not yet implemented.
7. Competition mode may eventually require tightly scoped Actor networking for exploration, but that must remain separate from proof authority and receive an explicit endpoint/egress policy.
8. P6 external flag acceptance is not wired to Core completion.
9. Benchmark runner image/tool inventory remains unfrozen; GDB is dynamically installed in engineering CI.

## 6. Truthfulness evaluation

**Supported:** static properties and controlled P1–P5 semantic contracts, including endpoint pinning, exact payload/response/environment identity, and the implemented negative controls.

**Not supported:** successful exploitation of an arbitrary internet service, live CTF remote proof, arbitrary protocol support, real-world solve rate, or benchmark superiority. The P5 result is a controlled synthetic remote-protocol proof, not a live CTF success claim.

## 7. Exit gate

- [x] explicit fail-closed claim registry
- [x] Core-bound static verifiers
- [x] artifact/provenance integrity checks
- [x] P1 reproducible crash verifier
- [x] P2 x86_64 control verifier
- [x] P3 control-plane local exploit verifier
- [x] P4 target-environment compatibility verifier
- [x] P5 endpoint-bound remote behavior verifier
- [ ] P6 external submission integrated with Core completion

**Decision:** `PARTIAL`. P5 gate is complete; proceed to P6 only.
