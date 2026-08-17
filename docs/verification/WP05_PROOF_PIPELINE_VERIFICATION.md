# WP05 — Proof Pipeline Verification

**Status:** `PARTIAL` — P0→P4 contiguous path executable; P5/P6 OPEN

## 1. Implemented logic

- CTF `ProofLevel` P0–P6 remains separate from Core `VerificationLevel`.
- P0–P5 form a contiguous proof path; projection stops at the first missing proof gate.
- P6 remains special: external task-oracle acceptance is final truth without fabricating P0–P5 facts.
- P3 has a durable domain-specific local proof receipt.
- P4 has a durable target-environment compatibility receipt with an explicit comparison contract.
- local and remote claim namespaces remain distinct; no P3/P4→P5 auto-promotion exists.
- flag submission receipts hash candidate values rather than persisting plaintext.

## 2. Previously corrected structural issue

The earlier “highest independently evidenced level” projection allowed `ctf.pwn.remote_behavior` alone to display P5. This was changed to a contiguous P0–P5 path because a proof ladder must not imply traversal of missing gates. The stale test failure in run `32014880957` and subsequent correction are retained as evidence.

Task progress remains different: independent verified milestones may still be reported by `pwn_progress_snapshot()`, while `proof_level_from_verified_keys()` reports the strongest contiguous proof prefix.

## 3. P3 durable proof evidence

Run `32015174592` proved the P3 control-plane local proof path with exact target/exploit/environment/oracle binding, Actor-source rejection, rejected-oracle rejection and non-contiguous P5 blocking. The full Base/Core regression also passed.

## 4. P4 proof evidence

Run `32015639019` SUCCESS:

- Base `219 passed / 7 skipped`.
- Core freeze + Stage02/04/05/06/07/08 probes PASS; `new_stage_created=false`.
- CTF regression `18 passed`.
- prior P1/P2/P3 probes all PASS.
- P4 controlled comparison reports `compatible=true` and `all_passed=true`.
- local/remote target fingerprint: `3f90aea773eba2fdc4b10a5270224f59188ca6e2d758f4b52d5cfa3bee3149fe`.
- contract fields: architecture, bits, endianness, PIE, NX, protocol, target revision, libc SHA-256, loader SHA-256.
- negative controls: mismatch, missing field, Actor provenance, untrusted source, baseline omission all rejected.

With verified keys P0–P4 present, the projection can reach `P4_ENVIRONMENT`. A P5 fact by itself still cannot produce P5.

## 5. Appropriateness evaluation

P4 belongs between local and remote proof because it makes local→remote assumptions explicit rather than implicit. A local exploit receipt alone cannot establish that the same exploit assumptions hold remotely.

The P4 contract is intentionally parameterized. Baseline machine/protocol properties cannot be omitted, while challenge-specific dependencies such as libc or loader may be added. This avoids claiming “environment compatible” from a shallow architecture-only equality check.

The verification level is LOGICAL because the semantic claim is deterministic equality/completeness over trusted environment evidence. Remote execution evidence belongs to P5.

## 6. Structural logic / truth review

### Confirmed

- runner environment and target runtime identity are distinct types.
- P4 cannot be created from Actor observation provenance.
- missing required values do not compare equal by omission.
- a mismatched libc/loader can force adaptation rather than silently reaching P4.
- proof projection is contiguous through P4.
- P6 remains an independent final external truth boundary.

### Remaining problems

1. P4 does not itself collect authoritative real-remote facts; collection adapters must preserve the declared source trust semantics.
2. P5 remote behavior is not implemented.
3. P6 completion wiring is not implemented.
4. No end-to-end controller/proof-flow orchestration yet creates P3→P4→P5→P6 automatically.
5. No fresh/private Pwn benchmark has yet measured whether the proof gates improve solve quality/cost.

## 7. Truthfulness statement

**Proven in controlled engineering tests:** contiguous P0→P4 projection and the P4 target-environment comparison contract, including mismatch/missing/provenance/contract negative controls.

**Not proven:** that the harness can independently infer all required remote environment fields on a real challenge, execute an arbitrary remote exploit, obtain a live flag, or outperform a baseline solver.

## 8. Exit gate

- [x] separate proof-level type
- [x] P0–P5 contiguous projection
- [x] P6 external-acceptance exception
- [x] durable P3 local proof receipt
- [x] durable P4 environment compatibility receipt
- [x] executable P1–P4 semantic chain in controlled gates
- [ ] P5 remote behavior proof
- [ ] P6 external flag oracle wired to Core completion
- [ ] end-to-end Pwn proof pipeline benchmark

**Decision:** `PARTIAL`. P4 gate is complete; proceed to P5.
