# WP08 — Corpus Ingestion / Executor Boundary Verification

**Status:** `PASS — CONTROLLED INFRASTRUCTURE SUBGATE`

## 1. Purpose

This subgate closes two infrastructure gaps left after `WP08_EVALUATION_VERIFICATION.md`:

1. benchmark corpus identity previously began from already-constructed Python objects rather than hash-verified source files;
2. research leakage policy was a contract but was not coupled to an execution-boundary attestation before an executor could run.

This subgate verifies the fail-closed interfaces for those gaps. It does **not** claim that a real runner has physically demonstrated network isolation, that a real fresh/private corpus has been supplied, or that a real LLM A/B benchmark has run.

## 2. Corpus ingestion

Implemented in `src/ctf_harness/evaluation/ingest.py`.

The ingestion chain is now:

```text
corpus.json
→ strict index schema
→ challenge manifest JSON
→ strict manifest schema
→ exact expected artifact SHA-256 map
→ existing admit_artifact() byte verification
→ BenchmarkCase
→ CorpusLock
→ IngestedCorpus fingerprint
```

### 2.1 Source evidence preserved

`IngestedCorpus` preserves:

- corpus-index SHA-256;
- each admitted source-manifest SHA-256;
- each admitted challenge-artifact SHA-256;
- frozen `CorpusLock` fingerprint.

This prevents the evaluation plan from depending only on user-facing case labels while losing the source bytes that created the identity.

### 2.2 Path/schema fail-closed rules

Controlled tests verify rejection of:

- artifact SHA mismatch after tampering;
- manifest/corpus benchmark-mode mismatch;
- artifact-hash key set different from `artifact_refs`;
- `../` traversal / non-normalized relative paths;
- manifest symlink paths;
- artifact symlink paths;
- unknown corpus-index fields;
- unknown challenge-manifest fields;
- non-boolean `allowed_network` values;
- duplicate manifest-path reuse.

The controlled ingestion probe explicitly declares:

- `fixture_only=true`;
- `actual_private_corpus=false`;
- `freshness_independently_proven=false`;
- `effectiveness_measured=false`.

## 3. Execution authority separation

Implemented in `src/ctf_harness/evaluation/executor.py`.

The evaluation path is now separated into three authorities:

```text
BenchmarkRunExecutor
→ produces execution outcome + run receipt

ExecutionBoundaryAttestor
→ independently describes/attests the allowed execution boundary

IndependentAdjudicator
→ independently decides benchmark truth/success
```

The executor cannot self-authorize success, and an attestation whose issuer ID equals the executor ID is rejected.

The adjudicator ID must also differ from both the executor and boundary-attestor IDs.

These identity constraints establish structural authority separation; the controlled fake implementations are not evidence that the future production components are organizationally or cryptographically independent.

## 4. Exact run binding

The following identities are bound before a benchmark record can exist:

```text
BenchmarkPlan
→ exact BenchmarkRunSpec
→ run_id
→ challenge manifest fingerprint
→ executor descriptor fingerprint
→ boundary attestation
→ executor run receipt
→ run evidence SHA-256
→ independent adjudication
→ BenchmarkRunRecord
```

### 4.1 Boundary attestation

`ExecutionBoundaryAttestation` is bound to:

- attestor issuer ID;
- attestation evidence SHA-256;
- executor fingerprint;
- sandbox ID;
- exact benchmark `run_id`;
- exact challenge manifest fingerprint;
- web-search state;
- external-retrieval state;
- general-internet egress state;
- challenge-transport scope.

An otherwise valid attestation for another run or another challenge cannot be reused.

### 4.2 Executor receipt

`ExecutorRunReceipt` is bound to:

- executor ID;
- exact benchmark `run_id`;
- run-evidence SHA-256;
- `RawRunOutcome`.

A receipt for another run is rejected before independent adjudication.

### 4.3 Adjudication

`IndependentAdjudication` is bound to:

- adjudicator ID;
- adjudication evidence SHA-256;
- exact benchmark `run_id`;
- exact executor run-evidence SHA-256;
- oracle acceptance;
- independently adjudicated proof level;
- independently invalid verified-fact labels.

`build_run_record()` rejects adjudication for another run or another execution receipt.

P6 is now semantically equivalent to external oracle acceptance:

- accepted + non-P6 → reject;
- rejected + P6 → reject.

## 5. Research execution boundary

Before a research-mode executor is called, the descriptor + boundary attestation must establish:

- web search disabled / blocked;
- external retrieval disabled / blocked;
- general Internet egress disabled / blocked;
- any permitted network path scoped to challenge transport.

Challenge transport is intentionally distinct from unrestricted Internet access so TCP/HTTP challenge services remain representable without enabling arbitrary web/writeup search.

Competition mode remains a separate policy and may declare broader network access when its attestation matches.

### Important scope boundary

`ExecutionBoundaryAttestor` is currently an interface plus controlled fake attestor in tests/probes.

Therefore this subgate proves:

> the benchmark orchestrator refuses execution unless a matching boundary attestation exists.

It does **not** yet prove:

> a production runner physically enforces and independently measures those network restrictions.

That production attestor remains OPEN.

## 6. Frozen budget enforcement

An executor outcome is rejected before adjudication when it exceeds the frozen experiment contract:

- `steps > max_steps`;
- `wall_seconds > max_wall_seconds`;
- configured token budget but missing measured token counts;
- input + output tokens exceeding `max_tokens`.

This prevents one A/B arm from silently gaining a larger effective budget while retaining the same comparison label.

## 7. Result evidence chain

`BenchmarkRunRecord` / result-bundle schema v2 preserves:

- run and case identity;
- executor ID + descriptor fingerprint;
- boundary-attestor ID + evidence SHA;
- run-evidence SHA;
- independent adjudicator ID + evidence SHA;
- independent success/proof/fact labels;
- execution/resource metrics.

The bundle still requires the exact planned run set and remains integrity wrapped.

## 8. Controlled tests and probes

### CTF regression

Latest current-HEAD controlled regression after this subgate:

```text
87 passed
```

The same workflow continues to run the pinned Base regression and pre-existing P1–P6/WP06/WP07 probes before the WP08 probes.

### Corpus ingestion probe

`ctf-evaluation-corpus-ingestion-controlled-v1` verifies:

- stable ingestion fingerprint;
- index hash binding;
- manifest hash binding;
- exact artifact expected-hash enforcement;
- artifact tamper rejection;
- path traversal rejection;
- no private-corpus/freshness/effectiveness claim.

### Executor boundary probe

`ctf-evaluation-executor-boundary-controlled-v4` verifies:

- separate boundary-attestor authority;
- web-search misconfiguration rejected before executor call;
- general-Internet misconfiguration rejected before executor call;
- wrong-run boundary rejected before executor call;
- executor self-attestation identity rejected;
- token-budget violation rejected before adjudication;
- boundary bound to exact run + manifest;
- executor receipt bound to exact run;
- adjudication bound to the same run + run evidence;
- executor completion not used as success authority;
- no real LLM/private-corpus/effectiveness claim.

### Benchmark integrity probe

The existing controlled benchmark-integrity probe was updated to preserve:

- execution evidence;
- boundary-attestation evidence;
- exact run + manifest binding;
- independent adjudication evidence;
- exact-plan result-bundle binding.

Its permanent-reject controlled case continues to produce no fabricated success-rate improvement.

## 9. Structural / logical / truth review

- **Truth authority:** independent adjudicator remains final benchmark truth authority.
- **Execution authority:** executor cannot self-complete a benchmark record as success.
- **Boundary authority:** separate attestor is required before execution.
- **Cross-run replay:** boundary, execution receipt and adjudication are all run-bound.
- **Cross-challenge replay:** execution/boundary evidence is manifest-bound.
- **Budget fairness:** frozen budget is validated on returned outcome before adjudication.
- **Corpus identity:** source index/manifest/artifact bytes are hashed into the admission chain.
- **Path integrity:** traversal/symlink/schema drift negative controls are present.
- **P6 consistency:** P6 and independent oracle acceptance cannot contradict each other.
- **No Core duplication:** no new truth store, verification level or Base stage was introduced.
- **No benchmark overclaim:** controlled fake executors/attestors/adjudicators remain fixtures only.

## 10. Exit gate

- [x] hash-verified corpus index ingestion
- [x] source manifest hashes retained
- [x] exact artifact expected-hash enforcement
- [x] traversal/symlink/schema negative controls
- [x] separate executor / boundary-attestor / adjudicator interfaces
- [x] research boundary required before executor invocation
- [x] challenge transport separated from unrestricted Internet
- [x] boundary bound to exact executor/run/manifest
- [x] executor receipt bound to exact run
- [x] adjudication bound to exact run + run evidence
- [x] execution/adjudication evidence retained in result bundle
- [x] frozen step/wall/token budget enforcement
- [x] P6 ↔ independent oracle acceptance consistency
- [x] controlled CTF regression green
- [x] prior P1–P6/WP06/WP07 gates retained in workflow
- [ ] production boundary attestor backed by real runner/network evidence
- [ ] actual fresh/private 10–15 Pwn corpus supplied and independently reviewed
- [ ] real fixed-model/controller Minimal-vs-Verified executor adapter
- [ ] real A/B runs with multiple repeats/seeds
- [ ] empirical solve-rate / token / wall-time / cost evidence

**Decision:** `PASS — CONTROLLED INFRASTRUCTURE SUBGATE`.

The next engineering task is the real benchmark executor adapter that maps canonical `ArmConfig` values into actual runtime behavior. Until that exists and a fresh/private corpus is supplied, WP08 remains infrastructure-complete but empirically unproven.
