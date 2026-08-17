# WP09 — Operational Baseline Freeze Verification

**Status:** `PASS — OPERATIONAL BASELINE FROZEN`

## 1. Goal

Freeze a reproducible repository baseline before operational solve contracts and target execution abstractions are added.

The WP09 gate is intentionally narrow. It does not claim autonomous solving effectiveness. It establishes that the Base revision, package dependency, CI checkout, and permanent verification workflow are consistent and do not depend on an ephemeral live Dreamhack endpoint.

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

The same branch also contained:

```text
.github/workflows/dh103-leak-temp.yml
```

which contacted an ephemeral Dreamhack endpoint on branch push. This was useful for WP08 smoke evidence but was not an acceptable permanent deterministic CI dependency.

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

### 4.2 Temporary live workflow removal

Deleted:

```text
.github/workflows/dh103-leak-temp.yml
```

Historical Dreamhack smoke evidence remains in the WP08 reports and historical Actions runs. It is not converted into a permanent CI dependency.

### 4.3 Repository baseline regression tests

Added:

```text
tests/test_repository_baseline.py
```

The tests assert:

1. package Base dependency equals lock package/repository/commit;
2. `verify.yml` checks out the locked Base repository/revision;
3. permanent `verify.yml` contains no known Dreamhack live endpoint;
4. the temporary Dreamhack push workflow is absent.

---

## 5. Positive Evidence

WP09 implementation code gate:

```text
commit: f9c9f33c4522754a4adc7b7a41db22c4826ef764
GitHub Actions run: 32043326712
conclusion: success
```

The run completed successfully for:

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

The preserved CTF pytest artifact reports:

```text
96 passed in 4.99s
```

The increase from the previous 92-test baseline is the four WP09 repository invariant tests.

---

## 6. Negative Control

The repository baseline tests are fail-closed policy assertions.

The gate fails if a future change introduces any of the following:

```text
pyproject Base commit != lock commit
verify checkout repo/ref != lock repo/commit
known Dreamhack live endpoint in permanent verify.yml
temporary Dreamhack push workflow restored
```

These assertions do not prove arbitrary future workflow safety. They specifically prevent recurrence of the defects that required WP09.

---

## 7. Regression

**Result: PASS.**

The WP09 code gate preserved all existing Base regression/invariant stages and all existing CTF P1–P6/WP06/WP07/WP08 controlled probes in the same successful Actions job.

WP09 did not modify:

- Base source code;
- CTF semantic verifiers;
- proof authority;
- recovery/progress authority;
- evaluation success authority.

---

## 8. Real-world Evidence

No new real challenge execution is required for WP09.

The existing Dreamhack 103 smoke evidence remains historical input to the operational roadmap, but live challenge availability is deliberately no longer a required CI condition.

---

## 9. Unsupported / Open

WP09 does not provide:

- operational `SolveSpec` / `TargetSpec` contracts;
- target runtime abstraction;
- QEMU-backed registered P1 evidence;
- real model controller;
- end-to-end autonomous solve loop.

Those remain WP10+ work.

---

## 10. Exit Decision

```text
Base package/lock/CI pin consistency      PASS
Base regression                           PASS
CTF regression                            PASS — 96 passed
existing controlled P1-P6 probes          PASS
WP06/WP07/WP08 probes                      PASS
permanent live endpoint dependency         NONE
```

**Decision:** `PASS — OPERATIONAL BASELINE FROZEN`.

The next implementation gate is WP10 operational solve contracts, followed by WP11 target execution. WP08 effectiveness remains open; WP09 does not convert controlled infrastructure evidence into a solve-rate claim.
