# WP08 — Evaluation Remediation Log

**Track:** Evaluation / Benchmark Infrastructure  
**Policy:** feature freeze until regression is green  
**Current status:** `IN PROGRESS — remediation gate`  

This document records failures discovered while strengthening WP08. A remediation is not marked closed merely because code was changed; it is closed only after the exact updated branch passes the full GitHub Actions gate.

## 1. Triggering regression

### E-WP08-R00 — latest pre-remediation full gate

- GitHub Actions run: `32030758336`
- Branch commit: `db8e8cd07a2ebf269e16c68fe0c7a4a56ff49831`
- Base regression: `220 passed, 7 skipped`
- Base/Core invariant probes: PASS
- CTF regression: `68 passed, 20 failed`
- Downstream P1–P6/WP06/WP07/WP08 probes: skipped because CTF regression was red.

Interpretation: the frozen Base/Core was not the source of this regression. Failures were localized to the evolving WP08 evaluation contract and its fixtures/tests.

## 2. Failure groups and remediation

| ID | Observed failure | Root cause | Classification | Remediation | Commit | Revalidation |
|---|---|---|---|---|---|---|
| R-01 | `IndependentAdjudication.__init__()` missing `run_id` / `run_evidence_sha256` | Evaluation contract was strengthened, but older test/probe fixtures still constructed unbound adjudications | Contract migration / fixture lag | Bind every fixture adjudication to exact `BenchmarkRunSpec.run_id()` and exact execution evidence SHA | `feae8f9eb2a9c1e054df5ae27aacdb71b9a1a8fd`, `2fc32a8912d33acbcaae83b5436f49cf93945495` | PENDING latest full gate |
| R-02 | `ExecutorRunReceipt.__init__()` missing `run_id` | Executor receipt contract was strengthened, but Fake/controlled executors still returned legacy receipts | Contract migration / fixture lag | Bind receipt to `spec.run_id()`; add wrong-run negative control | `0dfb204fe0524fc6d7c736afe9cf2e166de8ca15`, `05b78c64442137572eb73ea98fc21e21b8fc4982` | PENDING latest full gate |
| R-03 | Corpus-ingestion tests failed before tamper/path/policy assertions with `initial CTF profile requires external oracle authority` | Fixture used `oracle_type="external_flag"` while `ChallengeManifest` contract accepts only `external` | Fixture/schema mismatch | Change controlled ingestion fixture to the production manifest contract; do not relax manifest authority | `46106a694d35aa719548d8aee13225a4302bc33b` | PENDING latest full gate |
| R-04 | Rejected adjudication could still declare `highest_proof_level=P6_ACCEPTED` | Model enforced `oracle_accepted => P6-or-None` but not the inverse `P6 => oracle_accepted` | **Production truth invariant defect** | Add fail-closed inverse invariant: P6 cannot exist without external oracle acceptance | `cd18e7331f4fa1efd7978ee0fd18c415ae0f5924` | PENDING latest full gate |
| R-05 | Minimal-arm failure-signature test expected semantic plaintext suffix but Core stores a 16-hex digest | Test contradicted frozen Base `Failure.signature` policy (`kind + action + stable key/message -> SHA-256 prefix`) | Test expectation defect | Preserve Core hashed signature; construct the same `Failure` and compare the deterministic digest while separately asserting target/message | `c99725b035f422360e0cf3181c2b0d161bfb36a5` | PENDING latest full gate |

## 3. Why these fixes are appropriate

### 3.1 No weakening to make tests green

- R-01/R-02 preserve the stronger run/evidence binding rather than making the new fields optional.
- R-03 changes only the stale fixture and keeps the production manifest fail-closed.
- R-04 strengthens truth semantics in production code.
- R-05 keeps the frozen Base failure-identity design instead of changing Core to satisfy a CTF-side test.

### 3.2 Authority boundaries preserved

The remediation does not give new truth/completion authority to the Actor, executor, retrieval, or benchmark metadata. Independent adjudication remains bound to execution evidence, and P6 remains an external-oracle condition.

### 3.3 Base/Core remains frozen

No Stage09 or new numbered Base stage is introduced. These fixes remain inside the CTF evaluation track except for consuming the already-pinned Base behavior.

## 4. Revalidation gate

The remediation is complete only when one exact branch SHA passes all of:

1. pinned Base revision check;
2. Base full pytest;
3. Base Core invariant probes;
4. CTF full pytest;
5. P1–P6 semantic/proof probes;
6. WP06 hypothesis/dedupe probe;
7. WP07 recovery/progress probe;
8. WP08 evaluation integrity probe;
9. WP08 corpus ingestion probe;
10. WP08 executor-boundary probe;
11. runtime-backed benchmark executor probe once included in the workflow.

Current revalidation run at document creation: `32036473501` (`IN PROGRESS`).

## 5. Truthfulness status

- Real fresh/private Pwn corpus supplied: **NO**
- Real fixed LLM A/B execution completed: **NO**
- Solve-rate improvement established: **NO**
- Current work proves benchmark effectiveness: **NO**
- Current work is limited to evaluation-infrastructure correctness/remediation: **YES**
