# WP03 — Deterministic Pwn Recon / Classification Verification

**Status:** `PASS` for initial ELF recon scope

## 1. Implemented logic

`PwnReconSnapshot` deterministically records ELF identity/properties including architecture, bits, endian, ELF type, entry point, interpreter, explicit NX/PIE evidence and `canary_symbol_hint`.

Conservative semantics:

- no `PT_GNU_STACK` => NX is `None`, not guessed.
- ET_DYN without sufficient PIE flag evidence => PIE is `None`.
- `__stack_chk_fail` byte occurrence => only `canary_symbol_hint=True`; no canary semantic claim authority exists.
- recon path must be workspace-relative and symlink-resolved path must remain inside workspace.
- classification returns `CategoryAssessment(authoritative=False)`.

## 2. Evidence verification

**E-WP03-01:** CTF CI `32012528321` reports CTF regression `13 passed`.  
**E-WP03-02:** synthetic ELF tests confirm x86_64 parsing and conservative `None` for unproven NX/PIE states.  
**E-WP03-03:** raw canary symbol occurrence is surfaced only as a hint.  
**E-WP03-04:** workspace symlink escape is rejected.  
**E-WP03-05:** category assessment is explicitly non-authoritative.

## 3. Appropriateness evaluation

This matches the roadmap’s information-gain objective while avoiding false certainty. Recon supplies structured evidence for later claim-specific verifiers rather than directly asserting arbitrary CTF facts.

## 4. Structural logic / truth review

- **Semantic overclaim:** the earlier `canary_present` naming/claim idea was removed because a byte string is insufficient proof of active protection. Current name encodes hint status.
- **Classification authority:** no truth/progress authority.
- **Parser scope:** currently ELF-focused and deliberately small; section/import/symbol richness is incomplete.
- **Artifact binding:** snapshot carries artifact SHA-256 so semantic verifiers can reject mixed identities.

## 5. Truthfulness statement

Proven: the implemented ELF fields follow tested deterministic parsing rules and unknown/insufficient evidence remains unknown.  
Not proven: this is a complete `checksec` replacement or full Pwn reconnaissance implementation.

## 6. Exit gate

- [x] deterministic structured snapshot
- [x] artifact hash binding
- [x] workspace confinement
- [x] classification non-authoritative
- [x] weak canary evidence downgraded to hint

**Decision:** initial WP03 scope `PASS`; richer recon can be added only when demanded by the Pwn corpus.
