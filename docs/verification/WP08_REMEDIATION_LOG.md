# WP08 — Evaluation Remediation Log

**Track:** Evaluation / Benchmark Infrastructure  
**Policy:** feature freeze until regression is green  
**Current status:** `CLOSED — CODE + DOCUMENTATION GATES PASS`  

This document records failures discovered while strengthening WP08. A fix is not considered closed merely because code changed; executable full-gate evidence is required.

## 1. Triggering regression

### E-WP08-R00 — pre-remediation gate

- Run: `32030758336`
- Commit: `db8e8cd07a2ebf269e16c68fe0c7a4a56ff49831`
- Base: `220 passed, 7 skipped`
- Base/Core invariant probes: PASS
- CTF: `68 passed, 20 failed`
- Downstream probes: skipped because CTF regression was red.

Conclusion: Base/Core remained stable. Failures were localized to WP08 contract migration, stale fixtures, validation coverage, and the runtime-backed evaluation adapter.

## 2. Error → cause → fix ledger

| ID | Error / observation | Root cause | Type | Fix | Commit(s) | Status |
|---|---|---|---|---|---|---|
| R-01 | `IndependentAdjudication` missing `run_id` / `run_evidence_sha256` | Fixtures lagged behind strengthened adjudication contract | Migration / fixture | Bind adjudication to exact benchmark run and exact execution evidence | `feae8f9...`, `2fc32a8...` | CLOSED |
| R-02 | `ExecutorRunReceipt` missing `run_id` | Fake/controlled executors emitted legacy receipts | Migration / fixture | Bind receipt to `spec.run_id()`; add wrong-run/adjudication controls | `0dfb204...`, `05b78c6...` | CLOSED |
| R-03 | Ingestion tests stopped at `initial CTF profile requires external oracle authority` | Fixture used `oracle_type="external_flag"`; production contract accepts `external` | Fixture/schema | Change controlled fixture/probe only; preserve production fail-closed manifest | `46106a6...`, `b5248c8...` | CLOSED |
| R-04 | Rejected adjudication could report `P6_ACCEPTED` | Only `accepted => P6-or-None` was enforced, not `P6 => accepted` | **Production truth defect** | Add inverse fail-closed P6/oracle invariant | `cd18e73...` | CLOSED |
| R-05 | Minimal failure test expected plaintext signature suffix | Pinned Base intentionally stores deterministic hashed `Failure.signature` | Test expectation | Preserve Base behavior; assert kind/target/message plus deterministic hash | `c99725b...` | CLOSED |
| R-06 | Arm-runtime and runtime-executor probes existed but full CI omitted them | Validation coverage lag | **Verification-structure defect** | Make both probes mandatory workflow steps | `8f80283...` | CLOSED |
| R-07 | `Budget.__init__() got unexpected keyword argument 'max_steps'` | Evaluation budget vocabulary was passed directly to pinned Base Budget API | **Production adapter defect** | Translate to `hard_max_steps` / `hard_wall_seconds`; add regression | `61d564f...`, `85d4684...` | CLOSED |
| R-08 | Runtime outcome wall time differed from `metrics.json` | Adapter treated mutable `runtime.metrics` as wall-time authority although Base computes final wall time only in persisted metrics snapshot | **Production evidence-provenance defect** | Make durable `metrics.json` authority; validate run ID/schema/state consistency; add mismatch negative control | `13f1f49...`, `2353d0a...` | CLOSED |

## 3. Failure evidence preserved

### R-01 through R-05

Run `32030758336`:

```text
Base: 220 passed, 7 skipped
CTF:  68 passed, 20 failed
```

### R-07

Expanded gate run `32036712068` passed Base/Core, CTF, P1–P6, WP06/07, arm-runtime, integrity, ingestion, and executor-boundary checks, then failed only the runtime-backed executor because the adapter called pinned Base `Budget` with the wrong constructor fields.

### R-08

Run `32036990853`:

```text
Base: 220 passed, 7 skipped
CTF:  90 passed
```

All mandatory probes except the runtime-backed executor passed. The final failure was the mismatch between benchmark `outcome.wall_seconds` and durable `metrics.json["wall_seconds"]`.

Pinned Base inspection established the cause: `_save_metrics()` copies `self.metrics`, computes `wall_seconds` only in that persisted snapshot, writes `metrics.json`, and does not update mutable `runtime.metrics` with that value.

The fix therefore changed evidence authority rather than weakening the assertion.

## 4. Final code gate

### E-WP08-R04

- Run: `32037308514`
- Code commit: `2353d0a045acf5a5b47acd4691370e872e2bef0a`
- Pinned Base: `75834ac1ecb6c022771c2efee1f19495f356ee76`
- Base: `220 passed, 7 skipped`
- CTF: `92 passed in 5.06s`

Same-run PASS:

- Base Core freeze / Stage02 / Stage04–08 probes;
- P1–P6;
- WP06 hypothesis/dedupe;
- WP07 recovery/progress;
- canonical benchmark arm runtime;
- benchmark integrity;
- corpus ingestion;
- executor boundary;
- runtime-backed benchmark executor.

## 5. Documentation gate

### E-WP08-R05

After updating:

- `WP08_REMEDIATION_LOG.md`;
- `WP08_EVALUATION_VERIFICATION.md`;
- verification index;

commit `1d82198fee7b896567458fdbc4cad876402190a2` was re-run through the same full workflow.

- Documentation gate run: `32037625609`
- Result: `SUCCESS`
- Every mandatory step from Base regression through runtime-backed benchmark executor: PASS.

A final full workflow is also required for this status-closing documentation commit; the GitHub Actions state of current branch HEAD is the final repository gate.

## 6. Appropriateness evaluation

The fixes are appropriate because none weakens the asserted property merely to make tests pass:

- stronger run/evidence fields remained mandatory;
- stale fixtures were migrated to production contracts;
- the P6 truth condition was strengthened;
- Base hashed failure identity was preserved;
- missing probes became mandatory;
- API differences are translated at the CTF adapter boundary;
- durable Base metrics replaced a weaker mutable in-memory source.

No Base stage, Core truth store, or completion authority was duplicated.

## 7. Structural logic / truth evaluation

### Logic

```text
frozen benchmark input
→ canonical arm
→ validated executor/boundary
→ exact run receipt
→ durable execution evidence
→ exact independent adjudication
→ metrics/result bundle
```

The sequence is now internally consistent under the controlled gate.

### Truthfulness

Current evidence supports:

> the WP08 evaluation infrastructure behaves according to its controlled contracts.

Current evidence does **not** support:

> the Verified CTF Harness improves real CTF solve rate or efficiency.

Reason:

- real fresh/private Pwn corpus: **not supplied**;
- real fixed LLM A/B execution: **not completed**;
- empirical solve-rate improvement: **not established**;
- stochastic repeat/confidence evidence: **not available**.

## 8. Decision

**Remediation:** `CLOSED`  
**Controlled WP08 infrastructure:** `PASS`  
**Real Pwn A/B effectiveness:** `OPEN / NOT ESTABLISHED`
