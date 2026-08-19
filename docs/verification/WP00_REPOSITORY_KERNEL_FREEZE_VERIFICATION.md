# WP00 — Repository / Kernel Freeze Verification

**Status:** `PARTIAL` — Core boundary PASS, runner-image freeze OPEN  
**Implementation baseline:** `c8f87c62c2fb58fd48438e3b8621e0c5cdb58200`  
**Pinned Core:** `20079ffd90cc063958f084da8286e05f38ccdef0`

## 1. Implemented logic

- `base_harness.lock.json` fixes repository, branch, package version and exact commit.
- `locking.py` rejects a different reviewed Core revision.
- CI independently checks checked-out Core HEAD against the lock.
- CTF repository contains no `src/harness` Core fork.
- `facts.py` exposes only frozen `CTFFactView` projections over `state.facts`; it has no commit/update authority.

## 2. Evidence verification

**E-WP00-01:** CI run `32012528321` checked out Core `20079ffd...` and exact-SHA gate passed.  
**E-WP00-02:** same run executed the complete pinned Core test suite: `219 passed, 7 skipped`. The skipped tests are environment-conditional; the security-critical namespace session is separately required below.  
**E-WP00-03:** Core freeze probe reported `all_passed=true`, `new_stage_created=false`.  
**E-WP00-04:** CTF regression reported `13 passed`. `test_fact_projection.py` verifies CTF projection exposes only `ctf.*` facts and no `commit`/`update` method.

## 3. Appropriateness evaluation

The dependency boundary is appropriate: CTF specialization consumes Core truth/verification/runtime contracts instead of copying them. This directly preserves one truth authority and makes Core regression detectable.

## 4. Structural logic / truth review

- **Authority duplication:** none found in the current CTF code. `CTFFactView` is read-only.
- **Stage proliferation:** none; Core freeze probe explicitly reports no new Stage.
- **Truth risk:** lock validation fixes a reviewed source revision, but does not itself prove binary/package supply-chain identity outside the checked-out Git commit.
- **Open structural item:** roadmap also requires a frozen CTF runner image digest. No runner image is yet built/published/pinned, so WP00 cannot be called fully complete.

## 5. Truthfulness statement

Proven: CTF repo is bound to the reviewed Core SHA in CI and does not currently implement a competing fact commit path.  
Not proven: reproducible runner-image identity or whole-system CTF performance.

## 6. Exit gate

- [x] exact Core SHA pinned
- [x] Core regression passes
- [x] no CTF-side Core fork
- [x] no second fact commit API
- [ ] CTF runner image digest frozen

**Decision:** keep WP00 `PARTIAL`; runner image freeze is required before benchmark-grade environment claims.
