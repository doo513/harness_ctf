# WP04 — Pwn Semantic Verification

**Status:** `PARTIAL` — static semantics + reproducible-crash P1 gate PASS; P2–P5 semantics OPEN

## 1. Implemented semantic authority

Current registered claim contracts are intentionally small:

- `ctf.pwn.arch` — LOGICAL
- `ctf.pwn.bits` — LOGICAL
- `ctf.pwn.endianness` — LOGICAL
- `ctf.pwn.nx` — LOGICAL when recon is conclusive
- `ctf.pwn.pie` — LOGICAL when recon is conclusive
- `ctf.pwn.crash_reproducible` — EXECUTION

No verifier authority is registered yet for offset, control-flow, local exploit, environment compatibility, remote behavior or flag validity.

## 2. Static verifier evidence

Static Core-bound verifiers require:

1. claim evidence refs registered in Core `artifacts` and `evidence_refs`;
2. a matching successful Core observation source `pwn_recon`;
3. integrity-checked read through Core `ArtifactStore`;
4. expected schema/kind;
5. a single artifact SHA identity across evidence;
6. exact candidate/value match.

Tests reject wrong candidates, missing observation provenance, mixed artifact identity, tampered content and unsupported claim names.

## 3. Reproducible crash execution evidence

`pwn_crash_probe` is a semantic adapter around the attested backend. Actor input is limited to `[workspace-relative-target, base64-input]`; the adapter executes a fixed trusted Python probe through the namespace backend.

`CrashReproducibleVerifier` requires at least two independent registered evidence artifacts with identical target hash, input hash and positive terminating signal. Timeout, one-shot evidence or candidate mismatch is rejected.

**E-WP04-01:** CI run `32012528321` live privileged crash probe: `all_passed=true`, `attestation_source=runtime_probe`, evidence count 2, signal 11.  
**E-WP04-02:** wrong signal candidate is rejected.  
**E-WP04-03:** one-evidence reproduction claim is rejected.  
**E-WP04-04:** Core Stage04 regression in the same run reports 8/8 matrix cases pass, false positives 0, false negatives 0, level inflation blocked, semantic masquerade blocked, artifact tamper blocked.

## 4. Appropriateness evaluation

The implementation is appropriate because semantic authority is only granted where a deterministic claim-specific checker exists. The initial bug where registry names had no corresponding Core verifier was found during structural review and corrected; unsupported domains remain fail-closed rather than falling back to the base CTF structural catch-all.

## 5. Structural logic / truth review

- **Verifier existence:** every currently registered CTF rule names a real verifier.
- **Evidence provenance:** static and crash verifiers require registered Core observations, not Actor-authored lookalikes.
- **Weak evidence:** canary string hint has no truth authority.
- **Execution evidence:** crash proof is target/input/signal-bound, but crash alone does not imply exploitability/control.
- **Major open gap:** `ctf.pwn.control_flow`, `ctf.pwn.local_exploit`, `ctf.environment.compatible`, `ctf.pwn.remote_behavior` have no semantic verifier. Thus a complete Pwn proof ladder cannot yet execute.

## 6. Truthfulness statement

Proven: the listed static properties and reproducible-crash contract can reach Core verification under the implemented evidence rules; negative controls tested so far fail closed.  
Not proven: exploitability, control, local solve, remote solve, or final CTF success.

## 7. Exit gate

- [x] explicit fail-closed claim registry
- [x] Core-bound static verifiers
- [x] artifact/provenance integrity checks
- [x] live P1 reproducible crash verifier
- [ ] P2 control verifier
- [ ] P3 local exploit verifier
- [ ] P4 environment compatibility verifier
- [ ] P5 remote behavior verifier
- [ ] P6 external submission integrated with Core completion

**Decision:** `PARTIAL`. Do not start cross-domain expansion or benchmark claims yet.
