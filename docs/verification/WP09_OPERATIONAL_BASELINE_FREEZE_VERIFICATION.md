# WP09 — Operational Baseline Freeze Verification

**Status:** `PASS — OPERATIONAL BASELINE FROZEN`

## 1. Goal

Freeze a reproducible repository baseline before operational solve contracts and target execution abstractions are added.

The WP09 gate is intentionally narrow. It does not claim autonomous solving effectiveness. It establishes that the Base revision, package dependency, CI checkout, and permanent verification workflow are consistent and that temporary evidence-acquisition workflows are not left attached to ordinary branch pushes.

---

## 2. Previous Gap

Pre-WP09 reviewed HEAD:

```text
db83730d06c907e59f53b2f10b3def248ee9e03b
```

At that HEAD:

```text
base_harness.lock.json commit
= 75834ac1ecb6c022771c2efee1f19495f356ee76

.github/workflows/verify.yml Base checkout
= 75834ac1ecb6c022771c2efee1f19495f356ee76

pyproject.toml optional Base dependency
= 20079ffd90cc063958f084da8286e05f38ccdef0
```

Therefore the Base revision exercised by CI could differ from the revision installed by a user through the package optional dependency.

The branch also contained temporary push-triggered acquisition/probe workflows used during WP08 investigation:

```text
.github/workflows/dh103-leak-temp.yml
.github/workflows/qemu-system-export-temp.yml
```

The first contacted an ephemeral Dreamhack endpoint. The second installed/bundled QEMU on every branch push for one-off artifact acquisition. Both were useful historical investigation mechanisms, but neither belongs on the permanent operational branch path.

The QEMU export workflow was found during a second WP09 review after the first gate. It was removed rather than silently leaving the earlier report overstated.

---

## 3. Contract

WP09 establishes the repository-level invariant:

```text
Base lock revision
= Base package dependency revision
= Base CI checkout revision
```

and the CI responsibility split:

```text
permanent verify workflow
-> deterministic controlled evidence only

one-off dependency/evidence acquisition
-> explicit temporary/operator action, then removed

real challenge smoke
-> explicit/operator-triggered execution outside the required CI gate
```

No Base runtime contract or CTF truth authority was changed.

---

## 4. Implementation

### 4.1 Base dependency alignment

`pyproject.toml` now points the optional `base` dependency at:

```text
doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76
```

matching `base_harness.lock.json` and the permanent verification workflow checkout.

### 4.2 Temporary workflow removal

Deleted:

```text
.github/workflows/dh103-leak-temp.yml
.github/workflows/qemu-system-export-temp.yml
```

Historical Dreamhack/QEMU acquisition evidence remains in WP08 reports and historical Actions runs where relevant. The temporary workflows are not production dependencies.

### 4.3 Repository baseline regression tests

Added and then strengthened:

```text
tests/test_repository_baseline.py
```

The tests assert:

1. package Base dependency equals lock package/repository/commit;
2. `verify.yml` checks out the locked Base repository/revision;
3. permanent `verify.yml` contains no known Dreamhack live endpoint;
4. no workflow whose filename is marked `temp`/`temporary` remains in `.github/workflows/`.

The fourth condition replaces the initial one-file Dreamhack-only assertion so another temporary acquisition workflow cannot remain unnoticed under a different name.

---

## 5. Positive Evidence

Initial WP09 implementation gate:

```text
commit: f9c9f33c4522754a4adc7b7a41db22c4826ef764
GitHub Actions run: 32043326712
conclusion: success
CTF pytest: 96 passed in 4.99s
```

Second-review remediation gate, after removal of the remaining temporary QEMU export workflow and generic temporary-workflow negative control:

```text
commit: f0e37ad752f4c049f157c11541119a00b39d1075
GitHub Actions run: 32043831571
conclusion: success
```

The remediation gate ran on top of the already-passed WP10 contract implementation and therefore is not used to redefine WP10's evidence identity; it demonstrates that the strengthened WP09 repository invariant remains compatible with the full existing branch gate.

Both relevant gates preserved:

- pinned Base revision check;
- install / `pip check`;
- compile;
- Base regression;
- Base invariant probes;
- CTF regression;
- P1 crash semantic probe;
- P2 x86_64 control-flow semantic probe;
- P3 local-proof semantic probe;
- P4 target-environment compatibility probe;
- P5 remote-behavior probe;
- P6 external flag completion probe;
- WP06 hypothesis/dedupe probe;
- WP07 recovery/progress probe;
- WP08 arm runtime, benchmark integrity, corpus ingestion, executor boundary, and runtime-backed executor probes.

---

## 6. Negative Control

The repository baseline tests are fail-closed policy assertions.

The gate fails if a future change introduces any of the following:

```text
pyproject Base commit != lock commit
verify checkout repo/ref != lock repo/commit
known Dreamhack live endpoint in permanent verify.yml
workflow filename marked temp/temporary left on the branch
```

These assertions do not prove arbitrary future workflow safety. They specifically prevent recurrence of the defects that required WP09 and its second-review remediation.

---

## 7. Regression

**Result: PASS.**

The WP09 code gate and remediation gate preserved all existing Base regression/invariant stages and all existing CTF P1–P6/WP06/WP07/WP08 controlled probes.

WP09 did not modify:

- Base source code;
- CTF semantic verifier truth criteria;
- proof authority;
- recovery/progress authority;
- evaluation success authority.

---

## 8. Real-world Evidence

No new real challenge execution is required for WP09.

The existing Dreamhack 103 smoke evidence remains historical input to the operational roadmap, but live challenge availability and one-off QEMU export jobs are deliberately not required CI conditions.

---

## 9. Unsupported / Open

WP09 itself does not provide:

- operational target execution;
- QEMU-backed registered P1 evidence;
- real model controller;
- end-to-end autonomous solve loop.

Operational contracts are now covered by WP10; execution remains WP11 work.

---

## 10. Exit Decision

```text
Base package/lock/CI pin consistency      PASS
Base regression                           PASS
CTF regression                            PASS
temporary push workflows                  NONE
permanent Dreamhack endpoint dependency   NONE
existing controlled P1-P6 probes          PASS
WP06/WP07/WP08 probes                      PASS
```

**Decision:** `PASS — OPERATIONAL BASELINE FROZEN`.

The current implementation gate after WP10 is WP11 target execution. WP08 effectiveness remains open; WP09 does not convert controlled infrastructure evidence into a solve-rate claim.
