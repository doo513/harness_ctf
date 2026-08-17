# WP08 — Evaluation / Benchmark Infrastructure Verification

**Status:** `PASS — BENCHMARK INFRASTRUCTURE / CONTROLLED GATE`

## 1. Purpose and scope

WP08 exists to make later Pwn A/B evaluation difficult to accidentally overstate or corrupt. This gate verifies benchmark identity, leakage-policy contracts, independent adjudication, metric calculation, and result-bundle integrity.

It does **not** claim that Verified CTF Harness improves solve rate, token cost, wall time, or any other real CTF outcome.

No actual fresh/private Pwn challenge corpus and no fixed real LLM Actor A/B execution were supplied for this gate.

## 2. Evaluation identity chain

The implemented identity chain is:

```text
ChallengeManifest + admitted artifact hashes
→ BenchmarkCase
→ CorpusLock
→ ExperimentContract
→ BenchmarkRunSpec comparison_key / run_id
→ BenchmarkPlan
→ RawRunOutcome
→ IndependentAdjudication + adjudicator evidence SHA
→ BenchmarkRunRecord
→ exact-plan BenchmarkResultBundle
```

### 2.1 Frozen challenge identity

`BenchmarkCase` contains:

- case ID;
- challenge ID;
- challenge revision;
- existing manifest fingerprint;
- evaluation mode;
- category/difficulty metadata.

`case_from_manifest()` derives the case from the existing ChallengeManifest and artifact-hash fingerprint path rather than introducing a second challenge identity mechanism.

`CorpusLock` requires immutable case tuples, unique case IDs and manifest fingerprints, one evaluation mode, and a canonical order-independent fingerprint.

### 2.2 First Pwn pilot shape gate

`validate_first_pwn_pilot()` requires:

- research mode;
- unpublished/private declaration;
- 10–15 frozen cases;
- Pwn-only category.

This is deliberately only a **shape/declaration gate**. It does not independently prove that a challenge has never been published, cannot exist in model training data, or is contamination-free.

### 2.3 Research / competition separation

Research leakage policy requires:

- web disabled;
- exact challenge-name search disabled;
- writeup search disabled;
- direct flag search disabled;
- provenance accounting required.

Competition mode is a separate policy and result mode. Aggregation/comparison rejects mixed research/competition records.

The policy in this WP is a benchmark contract. Physical enforcement by the actual benchmark executor is a separate boundary and is not claimed by this gate.

### 2.4 A/B comparability

The first benchmark plan supports exactly two canonical arms:

```text
A — Minimal CTF Loop
B — Verified CTF Harness
```

A comparison key binds the same:

- frozen challenge case/revision;
- model ID and revision;
- controller revision;
- tool inventory;
- sandbox ID;
- oracle policy ID;
- step/wall/token budgets;
- seed;
- repeat index.

Only the declared harness feature toggles differ between the canonical A/B arms.

A changed budget, challenge metadata, experiment contract, or repeat index produces a different comparison key and cannot be silently compared as the same pair.

Drop-one ablations are intentionally not mixed into this first two-arm plan contract.

## 3. Independent truth and metrics

### 3.1 Success authority

`RawRunOutcome.completed_claimed` is not success authority.

Final benchmark success is:

```text
IndependentAdjudication.oracle_accepted
```

A run may claim completion and still be recorded as failure if the independent adjudicator rejects it. This is counted as `false_completion`.

### 3.2 Adjudication evidence identity

Each independent adjudication must provide:

- non-empty `adjudicator_id`;
- lowercase SHA-256 `evidence_sha256`;
- oracle acceptance label;
- highest independently adjudicated proof level;
- optional independently invalid verified-fact keys.

The adjudicator ID/evidence hash are preserved in `BenchmarkRunRecord` and the result bundle.

The current data model does not itself inspect or authenticate the future adjudicator artifact. The real executor/adjudicator integration must produce that durable evidence and bind its hash.

### 3.3 Metrics

Implemented metrics include:

- oracle success rate;
- highest proof level;
- false completion count;
- independently labelled false fact count;
- repeated failure count;
- tool calls;
- steps;
- wall time;
- optional input/output tokens;
- optional cost.

`repeated_failure_count` counts occurrences beyond the first occurrence of the same stable failure signature.

Paired A/B comparison reports Verified-minus-Minimal deltas while requiring exact comparison-pair identity.

## 4. Result integrity

`BenchmarkResultBundle.finalize()` requires the result set to match the frozen plan exactly:

- no missing planned runs;
- no extra runs;
- no duplicate run IDs;
- exact case/comparison/mode/arm/repeat identity;
- valid adjudicator/evidence identity for every record.

The saved result bundle is integrity wrapped by `body_sha256` and bound to the benchmark-plan fingerprint.

This protects stored-result integrity. A self-hash is **not** independent proof that benchmark inputs are fresh or that an adjudicator is trustworthy.

## 5. Controlled negative checks

The controlled evaluation probe deliberately uses synthetic metadata fixtures and a permanent-reject adjudication example.

The Minimal fixture claims completion, but the independent adjudication rejects it. Therefore:

- Minimal success = 0;
- false completion = true;
- independently labelled invalid fact = 1;
- three occurrences of one failure signature produce repeated-failure count 2.

The Verified fixture is also independently rejected, so the controlled success-rate delta is 0. This demonstrates that the infrastructure does not manufacture an improvement from harness identity alone.

The probe explicitly declares:

- `fixture_only=true`;
- `actual_private_challenge_corpus_supplied=false`;
- `freshness_independently_proven=false`;
- `effectiveness_measured=false`;
- `solve_rate_improvement_claimed=false`.

## 6. Execution evidence

Full gate: GitHub Actions run `32026483587`, job `95376845196`, branch commit `d1a8dbbe1b2835f56f46c4fe1b84348fd8df2fed`.

### E-WP08-01 — Base/Core regression

- Base pytest: `220 passed, 7 skipped`.
- Core freeze audit: PASS, no new stage created.
- Stage02 backend/session probes: PASS.
- Stage04 semantic matrix: PASS.
- Stage05 recovery controls/negative controls: PASS within their existing controlled scope.
- Stage06 progress authority: PASS.
- Stage07 context: PASS.
- Stage08 retrieval: PASS.

### E-WP08-02 — CTF regression

The preserved CTF pytest artifact for the same full run reports:

```text
56 passed in 3.86s
```

### E-WP08-03 — prior CTF authority chain preserved

The same run passed:

- P1 crash semantic probe;
- P2 control-flow semantic probe;
- P3 local proof probe;
- P4 environment compatibility probe;
- P5 remote behavior probe;
- P6 Core external completion probe;
- WP06 hypothesis/dedupe probe;
- WP07 CTF recovery/progress probe.

### E-WP08-04 — benchmark integrity probe

`ctf-evaluation-integrity-controlled-v2` completed successfully after asserting:

- 10-case Pwn pilot **shape** gate;
- 20 canonical A/B run specifications;
- order-independent plan identity;
- research search switches disabled;
- permanent-reject success rates remain 0/0 with delta 0;
- false completion detection;
- independent invalid-fact counting;
- repeated-failure counting;
- adjudication evidence hash binding;
- exact-plan result-bundle binding;
- no effectiveness or solve-rate improvement claim.

## 7. Structural / truth review

- **No fabricated Actor:** no fake LLM execution result is presented as a benchmark.
- **No fabricated private corpus:** the 10 controlled cases are metadata fixtures only.
- **No self-declared success:** Actor completion does not override independent oracle adjudication.
- **No cross-mode contamination:** research and competition records cannot be aggregated or paired together.
- **No loose A/B pairing:** model/tools/sandbox/oracle/budget/seed/repeat identity is part of the comparison key.
- **No partial-result benchmark:** result bundles must contain the exact planned run set.
- **No freshness overclaim:** `unpublished=True` is a declaration, not independent evidence.
- **No leakage-enforcement overclaim:** LeakagePolicy is currently a contract, not yet the physical executor gate.
- **No result-authenticity overclaim:** result self-hash verifies stored bytes, not external truth by itself.
- **No new Base stage:** WP08 remains a CTF evaluation track built on the frozen Stage01–08 Core.

## 8. Exit gate

- [x] frozen challenge/corpus identity contract
- [x] 10–15 Pwn first-pilot shape validator
- [x] research/competition result separation
- [x] research leakage-policy contract
- [x] exact canonical Minimal vs Verified A/B plan
- [x] same model/controller/tools/sandbox/oracle/budget/seed pairing
- [x] independent oracle success authority
- [x] adjudicator ID and durable evidence SHA field
- [x] false completion metric
- [x] independently labelled false-fact metric
- [x] repeated-failure metric
- [x] exact-plan result completeness
- [x] integrity-wrapped result bundle
- [x] controlled negative truth checks
- [x] prior P1–P6/WP06/WP07 gates remain green
- [ ] physical research leakage enforcement in benchmark executor
- [ ] actual fresh/private 10–15 Pwn corpus supplied and independently reviewed
- [ ] fixed real model/controller A/B execution
- [ ] multiple repeats/seeds and uncertainty intervals where appropriate
- [ ] empirical solve-rate / efficiency evidence

**Decision:** `PASS — BENCHMARK INFRASTRUCTURE / CONTROLLED GATE`.

The next WP08 subtask is corpus ingestion and executor/adjudicator boundary enforcement. Actual benchmark effectiveness remains OPEN until a real fresh/private Pwn corpus and fixed Actor execution exist.
