# WP08 — Evaluation Remediation Log

**Track:** Evaluation / Benchmark Infrastructure  
**Policy:** feature freeze until regression is green  
**Current status:** `CLOSED — CODE GATE PASS; DOCUMENTATION GATE PENDING`  

This document records failures discovered while strengthening WP08. A remediation is closed only after the exact updated code branch passes the full GitHub Actions gate. Documentation-only commits are re-run through the same gate before the stage report is considered final.

## 1. Triggering regression

### E-WP08-R00 — pre-remediation full gate

- GitHub Actions run: `32030758336`
- Branch commit: `db8e8cd07a2ebf269e16c68fe0c7a4a56ff49831`
- Base regression: `220 passed, 7 skipped`
- Base/Core invariant probes: PASS
- CTF regression: `68 passed, 20 failed`
- Downstream P1–P6/WP06/WP07/WP08 probes: skipped because CTF regression was red.

Interpretation: the frozen Base/Core was not the source of this regression. The failures were localized to the evolving WP08 evaluation contract, stale fixtures, validation coverage, and the new runtime-backed evaluation adapter.

## 2. Failure groups and remediation

| ID | Observed failure | Root cause | Classification | Remediation | Fix commit(s) | Final code-gate result |
|---|---|---|---|---|---|---|
| R-01 | `IndependentAdjudication.__init__()` missing `run_id` / `run_evidence_sha256` | Evaluation contract was strengthened, but older fixtures still constructed unbound adjudications | Contract migration / fixture lag | Bind every adjudication to exact `BenchmarkRunSpec.run_id()` and exact execution-evidence SHA | `feae8f9eb2a9c1e054df5ae27aacdb71b9a1a8fd`, `2fc32a8912d33acbcaae83b5436f49cf93945495` | CLOSED — run `32037308514` |
| R-02 | `ExecutorRunReceipt.__init__()` missing `run_id` | Executor receipt contract was strengthened, but Fake/controlled executors still emitted legacy receipts | Contract migration / fixture lag | Bind every receipt to `spec.run_id()`; add wrong-run and wrong-adjudication negative controls | `0dfb204fe0524fc6d7c736afe9cf2e166de8ca15`, `05b78c64442137572eb73ea98fc21e21b8fc4982` | CLOSED — run `32037308514` |
| R-03 | Corpus-ingestion tests failed before tamper/path/policy assertions with `initial CTF profile requires external oracle authority` | Fixture used `oracle_type="external_flag"` while `ChallengeManifest` accepts only `external` | Fixture/schema mismatch | Change only controlled fixtures/probe to the production manifest contract; keep production fail-closed | `46106a694d35aa719548d8aee13225a4302bc33b`, `b5248c84d990fcec5c73e73e0ca2cd95565b5b72` | CLOSED — run `32037308514` |
| R-04 | Rejected adjudication could still declare `highest_proof_level=P6_ACCEPTED` | Model enforced `oracle_accepted => P6-or-None` but not inverse `P6 => oracle_accepted` | **Production truth invariant defect** | Add fail-closed inverse invariant: `P6_ACCEPTED` cannot exist without external oracle acceptance | `cd18e7331f4fa1efd7978ee0fd18c415ae0f5924` | CLOSED — run `32037308514` |
| R-05 | Minimal-arm failure-signature test expected a semantic plaintext suffix but Core stores a 16-hex digest | Test contradicted frozen Base `Failure.signature` policy | Test expectation defect | Preserve Base hashed signature; verify the same deterministic `Failure.signature` while separately asserting kind/target/message | `c99725b035f422360e0cf3181c2b0d161bfb36a5` | CLOSED — run `32037308514` |
| R-06 | Canonical arm-runtime and runtime-backed executor scripts existed but were not part of the full CI gate | Validation coverage lag | **Verification-structure defect** | Add both probes to the mandatory workflow so code cannot be considered green while these execution paths are untested | `8f802833bb732406fae9478c2aeb0b7dde30cd69` | CLOSED — both probes executed in run `32037308514` |
| R-07 | Runtime-backed executor failed with `Budget.__init__() got an unexpected keyword argument 'max_steps'` | Evaluation vocabulary (`max_steps`, `max_wall_seconds`) was passed directly into pinned Base `Budget`, whose contract is `hard_max_steps`, `hard_wall_seconds` | **Production adapter defect** | Translate evaluation budgets at the adapter boundary; do not change Base API. Add regression test against pinned Base Budget schema | `61d564fba6c9827275fa53f0896c32408e0f94d6`, `85d468444e7f7586e39678dfef388b155f05ef7a` | CLOSED — run `32037308514` |
| R-08 | Runtime-backed probe failed because `receipt.outcome.wall_seconds != metrics.json["wall_seconds"]` | Base computes wall time only in the persisted metrics snapshot; the adapter incorrectly treated mutable `runtime.metrics` as wall-time authority | **Production evidence-provenance defect** | Load `metrics.json` after `runtime.run()`, validate schema/run ID/state consistency, derive steps/tool calls/completed/wall time from that durable snapshot, and reject persisted/state disagreement | `13f1f4928578ea413268ebda112668637614cb5f`, `2353d0a045acf5a5b47acd4691370e872e2bef0a` | CLOSED — run `32037308514` |

## 3. Failed runs preserved as evidence

### E-WP08-R01 — original 20-failure regression

Run `32030758336`:

```text
Base: 220 passed, 7 skipped
CTF:  68 passed, 20 failed
```

This exposed R-01 through R-05.

### E-WP08-R02 — validation coverage expansion exposed runtime adapter defect

Run `32036712068`:

- Base/Core: PASS
- CTF regression: PASS
- P1–P6: PASS
- WP06/WP07: PASS
- canonical arm runtime: PASS
- WP08 integrity/ingestion/executor-boundary: PASS
- runtime-backed executor: FAIL

Failure: evaluation budget fields were incorrectly passed to pinned Base `Budget`.

### E-WP08-R03 — budget fix exposed wall-time provenance defect

Run `32036990853`:

```text
Base: 220 passed, 7 skipped
CTF:  90 passed
```

All mandatory probes passed except runtime-backed executor. The failing assertion was:

```text
receipt.outcome.wall_seconds == metrics["wall_seconds"]
```

Pinned Base inspection showed `_save_metrics()` creates a copy of `self.metrics`, computes `wall_seconds` into that copy, writes `metrics.json`, and does not write that value back to `runtime.metrics`. Therefore the adapter's in-memory wall-time source was semantically wrong.

## 4. Final code revalidation

### E-WP08-R04 — exact code HEAD full gate

- GitHub Actions run: `32037308514`
- Code commit: `2353d0a045acf5a5b47acd4691370e872e2bef0a`
- Pinned Base: `doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76`
- Base regression: `220 passed, 7 skipped`
- CTF regression artifact: `92 passed in 5.06s`
- P1 crash: PASS
- P2 x86_64 control-flow: PASS
- P3 local proof: PASS
- P4 environment compatibility: PASS
- P5 remote behavior: PASS
- P6 Core external completion: PASS
- WP06 hypothesis/dedupe: PASS
- WP07 CTF recovery/progress: PASS
- canonical Minimal/Verified arm-runtime probe: PASS
- benchmark integrity probe: PASS
- corpus-ingestion integrity probe: PASS
- executor-boundary probe: PASS
- runtime-backed benchmark executor probe: PASS

The final gate executes all listed probes in one workflow after the CTF regression gate. No downstream probe is counted if the CTF regression is red.

## 5. Appropriateness assessment

### 5.1 No weakening to make tests green

- R-01/R-02 preserve the stronger run/evidence binding instead of making new fields optional.
- R-03 changes only stale controlled fixtures and keeps `ChallengeManifest` authority fail-closed.
- R-04 strengthens production truth semantics.
- R-05 keeps the frozen Base failure-identity contract.
- R-06 increases required validation coverage.
- R-07 translates between two explicit APIs rather than changing Base to match the CTF adapter.
- R-08 moves metric authority from mutable process memory to the durable Base-produced evidence file and cross-checks it against returned state.

### 5.2 Authority boundaries preserved

The remediation gives no new truth/completion authority to:

- Actor;
- benchmark executor;
- retrieval;
- benchmark metadata;
- controlled fixture/probe output.

Independent adjudication remains bound to exact execution evidence, and P6 remains an external-oracle condition.

### 5.3 Base/Core remains frozen

No Stage09 or new numbered Base stage was introduced. The CTF evaluation layer consumes the pinned Base contract and adapts to it explicitly.

## 6. Structural / truth review

### Logic

- Exact run identity now flows through `BenchmarkRunSpec → ExecutorRunReceipt → IndependentAdjudication → BenchmarkRunRecord`.
- The canonical Minimal and Verified arms are both executable runtime paths, not metadata-only labels.
- Runtime outcome timing/counters are now taken from the durable Base metrics snapshot rather than a mismatched in-memory view.
- P6 is bidirectionally constrained with oracle acceptance.

### Truthfulness

- Controlled green probes establish infrastructure behavior only.
- `unpublished=True` does not independently prove freshness.
- No real LLM result is represented by the synthetic executor probes.
- No controlled fixture result is treated as evidence of solve-rate improvement.
- Stored hashes establish integrity/binding, not external truth by themselves.

### Remaining open risks

- Actual fresh/private Pwn corpus has not been supplied or independently reviewed.
- Production model identity/usage attestation has not yet been exercised with a real Actor.
- Research leakage blocking is tested as a boundary contract/controlled attestation path; no real model benchmark has yet demonstrated the full production boundary.
- Statistical uncertainty/repeats are not meaningful until real stochastic Actor runs exist.

## 7. Exit decision

**Code remediation decision:** `PASS` at commit `2353d0a045acf5a5b47acd4691370e872e2bef0a`, run `32037308514`.

**Documentation decision:** pending one final exact-HEAD CI after remediation/verification documents are updated.

**Effectiveness claim:** `NOT ESTABLISHED`.
