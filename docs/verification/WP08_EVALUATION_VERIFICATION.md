# WP08 — Evaluation / Benchmark Infrastructure Verification

**Status:** `PASS — CONTROLLED INFRASTRUCTURE GATE / EFFECTIVENESS OPEN`

## 1. Purpose

WP08 builds and verifies the evaluation path required before making any claim that the Verified CTF Harness improves CTF performance.

The gate is deliberately stricter than “benchmark code exists”. It requires executable evidence that:

1. benchmark cases and experiments have frozen identities;
2. Minimal and Verified arms are actually different runtime paths rather than labels;
3. execution is bound to an exact planned run;
4. benchmark success is decided independently from the Actor/runtime claim;
5. stored metrics/results are traceable to durable execution evidence;
6. research/competition results cannot be silently mixed;
7. invalid/tampered benchmark inputs fail closed;
8. previous P1–P6, hypothesis, recovery, and progress authority boundaries remain intact.

This WP **does not** establish solve-rate, token, cost, or time improvement. No real fresh/private Pwn corpus and no fixed real LLM A/B execution have been completed.

---

## 2. Implemented evaluation flow

```text
ChallengeManifest + admitted artifact hashes
→ BenchmarkCase
→ CorpusLock
→ ExperimentContract
→ BenchmarkRunSpec
   ├─ comparison_key
   └─ exact run_id
→ BenchmarkPlan
→ canonical arm runtime
   ├─ MinimalCTFBenchmarkRuntime
   └─ VerifiedCTFBenchmarkRuntime
→ validated ExecutorDescriptor / BoundaryAttestation
→ RuntimeBenchmarkExecutor
→ Base/Verified CTF runtime execution
→ durable Base metrics.json + state/evidence hashes
→ ExecutorRunReceipt(exact run_id, run_evidence_sha256)
→ IndependentAdjudication(exact run_id, exact run_evidence_sha256)
→ BenchmarkRunRecord
→ paired metrics / exact-plan BenchmarkResultBundle
```

Authority rule:

```text
Actor/runtime completed_claimed != benchmark success
benchmark success = independently adjudicated oracle acceptance
```

P6 rule:

```text
P6_ACCEPTED => external oracle accepted
external oracle accepted => P6 or accepted-without-lower-level-overclaim
```

A rejected adjudication is not allowed to report `P6_ACCEPTED`.

---

## 3. Frozen benchmark identity

### 3.1 Challenge / corpus identity

`BenchmarkCase` binds:

- case ID;
- challenge ID;
- challenge revision;
- manifest fingerprint;
- evaluation mode;
- category;
- optional difficulty metadata.

`CorpusLock` requires immutable case tuples, unique case IDs/fingerprints, a single evaluation mode, and a deterministic fingerprint.

`validate_first_pwn_pilot()` requires the declared first pilot to be:

- research mode;
- unpublished/private declaration;
- Pwn-only;
- 10–15 cases.

This is a **shape/declaration gate only**. It does not prove that a problem has never appeared publicly or in model training data.

### 3.2 Corpus ingestion

`ingest_corpus_index()` verifies the actual corpus files before building the frozen case set.

Controlled checks cover:

- index integrity;
- manifest hashing;
- artifact expected SHA-256;
- artifact tamper rejection;
- normalized relative paths;
- path traversal rejection;
- symbolic-link rejection;
- exact manifest artifact-ref/hash-key agreement;
- unsupported-field rejection;
- strict boolean schema;
- benchmark-policy mode agreement;
- production `oracle_type="external"` contract.

No second challenge identity system is introduced; ingestion feeds the existing manifest/fingerprint path.

---

## 4. Canonical A/B arm runtime

The initial comparison permits exactly:

```text
A — Minimal CTF Loop
B — Verified CTF Harness
```

### Minimal arm

Uses the Base kernel/runtime path while disabling CTF-specific experimental features:

- semantic verified-fact promotion disabled;
- CTF hypothesis guard disabled;
- CTF typed recovery disabled;
- CTF task-progress authority disabled;
- proof projection disabled.

### Verified arm

Uses the existing `VerifiedCTFRuntime` with:

- semantic verification;
- CTF hypothesis/dedupe guard;
- typed CTF recovery mapping;
- CTF task progress;
- proof projection.

The controlled arm-runtime probe verifies that the two arms are executable paths with the intended feature separation. Partial ad-hoc arm configurations are not silently accepted as one of the canonical first A/B arms.

### Comparability contract

The comparison key binds the same:

- case/revision/fingerprint;
- model ID/revision;
- controller revision;
- tool inventory;
- sandbox ID;
- oracle policy;
- step/wall/token budgets;
- seed;
- repeat index.

Only the declared arm feature configuration may differ in the canonical pair.

---

## 5. Execution boundary and run attribution

### 5.1 Executor contract

Before execution, `execute_planned_run()` validates that the executor descriptor matches the frozen experiment for:

- model identity;
- model revision;
- controller revision;
- tools;
- sandbox;
- oracle policy.

Research-mode controlled boundary tests require declarations/attestation consistent with:

- web search blocked;
- external retrieval blocked;
- general Internet egress blocked;
- challenge transport separately scoped.

A mismatched research boundary is rejected before executor execution.

This proves the **boundary contract and controlled attestation path**, not yet a real-model production network-isolation benchmark.

### 5.2 Exact run binding

`ExecutorRunReceipt` must carry:

- executor identity;
- exact `BenchmarkRunSpec.run_id()`;
- durable run-evidence SHA-256;
- raw outcome.

A receipt from another planned run is rejected before adjudication.

`IndependentAdjudication` must then bind to:

- the same exact run ID;
- the same execution-evidence SHA-256;
- an adjudicator ID;
- adjudication evidence SHA-256.

This blocks accidental cross-run/cross-evidence result attribution.

---

## 6. Runtime-backed benchmark executor

`RuntimeBenchmarkExecutor` connects benchmark plans to the actual canonical Base/Verified CTF runtime builders.

### 6.1 Budget adapter

Evaluation terminology:

```text
max_steps
max_wall_seconds
```

is explicitly translated into pinned Base `Budget` fields:

```text
hard_max_steps
hard_wall_seconds
```

The Base API is not modified to satisfy the CTF layer.

### 6.2 Durable metric authority

A defect discovered during this WP showed that pinned Base computes `wall_seconds` only in the persisted metrics snapshot. Therefore benchmark outcome metrics now use:

```text
runtime.run()
→ Base metrics.json
→ schema/run-id validation
→ returned-state consistency checks
→ RawRunOutcome
```

`metrics.json` is required to provide valid:

- Base runtime run ID;
- steps;
- tool calls;
- completion boolean;
- finite non-negative wall time.

Persisted steps/completion must agree with the returned `HarnessState`; disagreement fails closed.

The controlled regression deliberately makes mutable in-memory metrics differ from `metrics.json` and verifies that the durable file remains the benchmark authority.

### 6.3 Execution evidence receipt

The executor creates `benchmark_execution_evidence.json` containing/binding:

- benchmark run ID;
- comparison key;
- manifest fingerprint;
- arm configuration;
- runtime class;
- executor fingerprint;
- returned state hash;
- `metrics.json` hash;
- event log hash when present;
- tool-call log hash when present;
- normalized benchmark outcome.

The canonical hash of this body becomes the `run_evidence_sha256` used by independent adjudication.

---

## 7. Independent truth and metrics

### 7.1 Success authority

`RawRunOutcome.completed_claimed` is informational only.

If a runtime claims completion but independent adjudication rejects it:

```text
success = false
false_completion = true
```

The controlled permanent-reject example produces:

```text
Minimal success  = 0.0
Verified success = 0.0
delta            = 0.0
```

so the infrastructure does not manufacture improvement from arm identity.

### 7.2 Metrics

Implemented benchmark metrics include:

- oracle success rate;
- highest proof level;
- false completion count;
- independently labelled false verified-fact count;
- repeated-failure count;
- tool calls;
- steps;
- wall time;
- optional input/output tokens;
- optional cost.

A/B results are paired by exact comparison key. Research and competition records cannot be aggregated or paired together.

### 7.3 Result bundle integrity

`BenchmarkResultBundle` requires the exact planned result set:

- no missing run;
- no extra run;
- no duplicate run ID;
- exact case/comparison/mode/arm/repeat identity.

The stored bundle is self-integrity wrapped and bound to the benchmark-plan fingerprint.

A self-hash proves stored-byte integrity, **not** freshness or external correctness by itself.

---

## 8. Remediation evidence

Detailed failure history is maintained in:

`docs/verification/WP08_REMEDIATION_LOG.md`

The remediation found eight material groups:

1. stale adjudication fixtures after exact run/evidence binding;
2. stale executor receipts after exact run binding;
3. corpus fixture `oracle_type` mismatch;
4. missing inverse P6/oracle invariant;
5. test expectation contradicting Base hashed failure signatures;
6. arm/runtime executor probes omitted from mandatory CI;
7. evaluation-to-Base Budget adapter mismatch;
8. in-memory vs durable wall-time evidence provenance mismatch.

The fixes were not implemented by relaxing verification. Production defects were strengthened, stale fixtures were migrated to current contracts, and Base behavior remained pinned.

---

## 9. Executable evidence

### E-WP08-01 — final code gate

GitHub Actions:

- run: `32037308514`
- code commit: `2353d0a045acf5a5b47acd4691370e872e2bef0a`
- pinned Base: `doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76`

Results:

```text
Base pytest: 220 passed, 7 skipped
CTF pytest:  92 passed in 5.06s
```

All mandatory workflow probes passed:

- Core freeze audit;
- Stage02 backend binding;
- Stage02 live namespace/persistent-session probe;
- Stage04 Base semantic matrix;
- Stage05 recovery benchmark/negative controls;
- Stage06 task progress;
- Stage07 context;
- Stage08 retrieval;
- P1 crash;
- P2 x86_64 control-flow;
- P3 local proof;
- P4 environment compatibility;
- P5 remote behavior;
- P6 external flag/Core completion;
- WP06 hypothesis/dedupe;
- WP07 CTF recovery/progress;
- canonical benchmark arm runtime;
- benchmark integrity;
- corpus ingestion integrity;
- benchmark executor boundary;
- runtime-backed benchmark executor.

### E-WP08-02 — benchmark integrity controlled probe

`ctf-evaluation-integrity-controlled-v4` asserts:

- controlled 10-case pilot shape;
- 20 canonical A/B specs;
- deterministic plan identity;
- research search switches disabled;
- exact run/adjudication evidence binding;
- false completion detection;
- invalid fact counting;
- repeated-failure counting;
- exact-plan result bundle;
- permanent-reject success delta remains zero;
- `effectiveness_measured=false`;
- `solve_rate_improvement_claimed=false`.

### E-WP08-03 — corpus ingestion controlled probe

`ctf-evaluation-corpus-ingestion-controlled-v2` asserts:

- index/manifest/artifact hash binding;
- artifact tamper rejection;
- path traversal rejection;
- stable ingestion fingerprint;
- external-oracle manifest contract preserved;
- `actual_private_corpus=false`;
- `freshness_independently_proven=false`.

### E-WP08-04 — executor boundary controlled probe

`ctf-evaluation-executor-boundary-controlled-v2` asserts:

- research web/retrieval/general Internet restrictions are required;
- misconfiguration is rejected before execution;
- challenge transport is distinct from general Internet;
- budget violations are rejected before adjudication;
- receipt run ID is bound;
- adjudication run/evidence is bound;
- executor self-completion is not success authority;
- `actual_llm_executed=false`;
- `effectiveness_measured=false`.

### E-WP08-05 — canonical arm/runtime evidence

`ctf-evaluation-canonical-arm-runtime-controlled-v1` asserts:

- Minimal uses the Base kernel path;
- Verified uses existing `VerifiedCTFRuntime`;
- Minimal CTF task-progress authority is disabled;
- Minimal semantic fact commit is blocked;
- Minimal can execute the ordinary tool path without the CTF hypothesis guard;
- the same unqualified action is blocked by the Verified CTF hypothesis guard;
- partial A/B configurations are not accepted as canonical arms;
- no real LLM/private corpus/effectiveness claim.

### E-WP08-06 — runtime-backed executor evidence

The final workflow executes `evaluation_runtime_executor_probe.py` successfully after the durable-metric fix. This exercises both canonical arms through `RuntimeBenchmarkExecutor` and verifies that the generated receipt/outcome is consistent with persisted runtime evidence.

---

## 10. Appropriateness assessment

### Appropriate

- Reuses Base truth/recovery/progress/runtime instead of building a benchmark-specific kernel.
- Treats benchmark execution as evidence production, not truth authority.
- Uses exact run/evidence attribution to reduce accidental cross-run contamination.
- Uses independent adjudication for success.
- Keeps Minimal/Verified difference explicit and executable.
- Fails closed on malformed/tampered corpus data.
- Uses durable Base-produced metrics rather than volatile process memory.
- Preserves negative controls and no-improvement controlled examples.

### Deliberately not implemented yet

- fake private corpus generation;
- fake LLM outcomes;
- automatic claim that `unpublished=True` proves freshness;
- performance conclusions from synthetic fixtures;
- multi-agent/skills expansion before Pwn A/B evidence.

---

## 11. Overall structural assessment

### 11.1 Logical consistency

**Assessment: PASS within the controlled infrastructure scope.**

The evaluation pipeline has a coherent order:

```text
frozen input
→ controlled arm selection
→ attested executor contract
→ exact execution receipt
→ durable evidence
→ independent adjudication
→ metrics/result bundle
```

No later layer is allowed to retroactively redefine an earlier identity.

### 11.2 Truthfulness

**Assessment: PASS within the controlled infrastructure scope.**

The repository explicitly distinguishes:

- code/tests;
- controlled synthetic evidence;
- future fresh/private benchmark evidence;
- future real competition evidence.

The current evidence supports “the evaluation infrastructure behaves as specified under controlled tests.” It does **not** support “the harness solves more CTFs.”

### 11.3 Remaining structural limitations

1. No independently reviewed fresh/private 10–15 challenge Pwn corpus.
2. No fixed real model/controller A/B execution.
3. No repeated stochastic runs/confidence intervals.
4. Real research runner network/leakage boundary has not been demonstrated with the actual model execution stack.
5. Real usage/token/cost evidence provider has not yet been exercised in the benchmark.
6. Cross-domain generalization remains untested.

These are benchmark-entry conditions, not reasons to weaken the current infrastructure gate.

---

## 12. Exit gate

- [x] frozen case/corpus identity
- [x] strict corpus ingestion
- [x] 10–15 first-Pwn-pilot shape gate
- [x] research/competition separation
- [x] canonical Minimal vs Verified executable arms
- [x] same model/controller/tools/sandbox/oracle/budget/seed comparison identity
- [x] exact executor receipt run binding
- [x] exact adjudication run/evidence binding
- [x] P6 cannot exist without oracle acceptance
- [x] independent success authority
- [x] false-completion / false-fact / repeated-failure metrics
- [x] exact-plan result bundle
- [x] controlled research boundary negative checks
- [x] runtime-backed benchmark executor
- [x] evaluation-to-Base Budget translation regression
- [x] durable Base metrics authority regression
- [x] P1–P6/WP06/WP07 remain green in the same full gate
- [x] remediation history recorded separately
- [ ] actual fresh/private Pwn corpus supplied and independently reviewed
- [ ] fixed real LLM/controller A/B execution
- [ ] real usage/token/cost evidence
- [ ] repeated runs / uncertainty analysis
- [ ] empirical solve-rate or efficiency improvement evidence

## Decision

**WP08 infrastructure decision:** `PASS — CONTROLLED INFRASTRUCTURE GATE`.

**Effectiveness decision:** `OPEN / NOT ESTABLISHED`.

The next substantive action is not another harness feature. It is to supply/freeze a real fresh/private Pwn pilot corpus and execute the canonical fixed A/B experiment. Until that evidence exists, no solve-rate improvement claim is permitted.
