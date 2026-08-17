# WP13–WP19 Remaining Roadmap Verification

## Final decision

**Status:** `PASS — OPERATIONAL/INTEGRATION BOUNDARIES IMPLEMENTED AND REGRESSION-GATED / EMPIRICAL PROVIDER + REAL-CORPUS EFFECTIVENESS OPEN`

This verification closes the implementation work that can be established deterministically or with controlled live fixtures while preserving the existing Evidence/Verifier/External-Oracle authority model.

The latest push workflow on `implementation/remaining-roadmap-stage-work` completed successfully before this record was written. The same branch was also cross-checked locally for the new Pwn, Competition TCP, Web HTTP, Crypto, and Reverse vertical probes.

---

## 1. WP13 — DomainPlaybook / AnalysisSandbox

### Implemented

```text
DomainPlaybook
→ question / expected information / capability / pivot
→ advisory only

Hypothesis SUPPORTED
→ tactical use allowed
→ Fact promotion NOT allowed

AnalysisSandbox
→ admitted input hash-bound
→ input read-only
→ work/generated/artifacts writable
→ production network deny
→ separate from TargetRunner
```

### Verification

- hard-coded command-sequence semantics absent;
- playbook has no fact/execution/completion authority;
- supported hypothesis remains speculative sidecar state;
- live namespace probe blocks admitted-input mutation;
- live namespace probe permits generated work;
- live namespace probe denies arbitrary network egress;
- Base and existing CTF regressions remain green.

**Decision:** `PASS`.

---

## 2. Gate A0 — production Agent ↔ Harness boundary

### Implemented

`ExternalProcessModelAdapter` provides:

```text
Harness prompt/context
→ bounded JSON stdin
→ external provider process
→ one typed Decision JSON stdout
→ CTFLLMController
→ SolveEngine / AgentCTFRuntime
```

Security/operational properties:

- `shell=False`;
- timeout and output-size limits;
- parent environment not inherited by default;
- provider credential environment forwarding is explicit;
- descriptor persists environment names, never values;
- external process cannot create Fact/completion authority.

### Verification

CI deliberately runs Gate A0 without provider configuration and requires:

```text
status = OPEN
actual_production_llm_executed = false
```

This proves fail-closed configuration semantics.

**Decision:** `IMPLEMENTATION PASS / ACTUAL PRODUCTION PROVIDER EXECUTION OPEN`.

Reason for OPEN: repository/CI has no operator-supplied production LLM credential/provider process. A controlled fixture must not be relabelled as a real production model call.

---

## 3. WP14 — Pwn Operational Vertical Slice

Controlled live fixture:

```text
real x86_64 ELF
→ PwnPlaybook context
→ deterministic pwn_recon
→ AnalysisSandbox payload generation
→ TargetRunner execution
→ observed accepted behavior
→ external completion oracle
```

Checks:

- generated exploit payload is written in analysis work area;
- admitted target SHA-256 is unchanged after solve;
- completion is requested by Actor but established only by external oracle;
- previous P1–P6 semantic/proof/recovery probes remain green.

**Decision:** `PASS — CONTROLLED OPERATIONAL VERTICAL`.

This is wiring/authority evidence, not a claim that a production LLM autonomously solves unseen Pwn challenges.

---

## 4. WP15 — Competition Integration

### Platform layer

Implemented:

```text
CompetitionAdapter
├─ CTFd metadata/list/detail/download/submission
├─ CredentialResolver → transient SecretHandle
├─ SecretRedactor
├─ InstanceProvider
└─ SubmissionGuard
```

CTFd/platform snapshots remain non-authoritative until converted into the existing:

```text
ChallengeManifest
→ artifact hash/admission
→ OperationalChallengeRef
```

### TCP competition transport

Implemented:

```text
RemoteTargetSpec(TCP)
→ SolveEngine exact remote binding
→ RemoteTcpRunner
→ remote_tcp Harness tool
→ bounded persistent session
→ external oracle
```

Rules:

- exact admitted endpoint;
- DNS/IP pinning remains RemoteTcpRunner authority;
- `challenge_transport=true` required;
- `general_internet=false` required;
- `external_retrieval=false` required;
- Actor subprocess network remains denied;
- raw transport observation is not semantic proof.

A controlled competition TCP service is exercised end-to-end through SolveEngine.

### HTTP competition/Web transport

Implemented:

```text
RemoteTargetSpec(HTTP)
→ SolveEngine exact HTTP binding
→ ChallengeHttpClient
→ scoped_http Harness tool
→ admitted origin only
→ external oracle
```

Rules:

- only admitted HTTP/HTTPS origin;
- URL credentials rejected;
- `Authorization`, `Cookie`, `Proxy-Authorization` actor headers rejected;
- cross-origin redirect rejected;
- bounded response body;
- platform session/credential store is not shared with challenge HTTP tool.

**Decision:** `PASS — CONTROLLED COMPETITION/TRANSPORT BOUNDARIES`.

Actual vendor/plugin-specific dynamic instance APIs remain provider extensions; `InstanceProvider` is the stable interface and no false generic CTFd instance API is assumed.

---

## 5. WP16 — Need-Driven Runtime / Architecture Generalization

No speculative `QemuSystemRunner`, VirtualBox, VMware, or generic VM authority was added.

Existing provider boundary remains:

```text
TargetRunner
├─ NativeRunner
├─ CustomArgvRunner
└─ QemuUserRunner
```

Controlled QEMU AArch64 execution remains regression-gated. New full-system/VM/browser execution providers must be added only for a concrete challenge and must preserve equivalent target/runtime/launch identity and isolation contracts.

**Decision:** `PASS — GENERALIZATION BOUNDARY PRESERVED / NEW PROVIDERS NEED-DRIVEN`.

---

## 6. WP17 — Cross-Domain Expansion

### Common extension layer

Implemented:

- `DomainRegistry`;
- `DomainModuleRegistry`;
- Pwn semantic assets collected under `PwnDomainModule` without moving verifier authority;
- advisory playbooks for Pwn, Reverse, Crypto, Web, Forensics, Misc;
- bounded deterministic `ReconDigest`;
- low-confidence multi-domain classification evidence;
- `FlagCandidateExtractor` where candidate != accepted;
- `CapabilityCatalog` provider fallback behind normal Base ActionRuntime;
- scoped IDA capability provider with artifact SHA revalidation;
- scoped HTTP challenge tool.

### Controlled cross-domain execution

Crypto controlled vertical:

```text
DomainPlaybook
→ ReconDigest
→ AnalysisSandbox deterministic computation
→ Observation
→ external oracle
```

Reverse controlled vertical:

```text
DomainPlaybook
→ ReconDigest
→ AnalysisSandbox targeted strings extraction
→ Observation
→ external oracle
```

Web controlled vertical:

```text
Web Playbook context
→ RemoteTargetSpec(HTTP)
→ scoped_http
→ Observation
→ external oracle
```

Pwn progress is not projected into non-Pwn active-domain runs.

**Decision:** `PASS — COMMON CONTRACT + CONTROLLED PWN/CRYPTO/REVERSE/WEB VERTICALS`.

Open empirical/domain work:

- fresh real Web/Crypto/Reverse solve-rate evaluation;
- domain-specific semantic verifier suites equivalent in maturity to Pwn;
- Forensics/Misc real vertical fixtures when concrete challenge classes are selected.

---

## 7. Workspace / Resume projection

Implemented `RunWorkspaceProjection`:

```text
authoritative durable run
→ IDs / relative refs / hashes / selected metrics
→ human/agent workspace run.json
```

It does not copy raw Fact state, secrets, or create a second resume authority.

**Decision:** `PASS`.

---

## 8. WP18 — Real Evaluation / Ablation foundation

Existing WP08 benchmark infrastructure remains the execution/measurement authority.

Added deterministic single-factor ablation identity for:

- Playbook;
- AnalysisSandbox;
- semantic verification;
- hypothesis guard;
- typed recovery;
- task progress.

Invariant:

```text
one ablation arm
= baseline
- exactly one declared feature
```

Ablation descriptors explicitly state:

```text
effectiveness_claim = none_until_empirical_runs
```

**Decision:** `INFRASTRUCTURE PASS / REAL LLM + REAL CORPUS EFFECTIVENESS OPEN`.

A real ablation result cannot be manufactured without the same production model, frozen corpus, budgets, and independent adjudication across arms.

---

## 9. WP19 — Multi-Agent (optional)

Implemented dependency-safe optional foundation:

```text
EvidenceBus
├─ Verified channel
│  └─ publication allowed only for an already-existing Harness Fact
└─ Tentative channel
   └─ hypothesis/evidence provenance required

MultiAgentCoordinator
→ immutable shared snapshot
→ parallel worker findings
→ deterministic publication order
→ no mutable HarnessState access
```

Coordinator authority:

```text
Fact write        NONE
Tool execution    NONE
Completion        NONE
```

**Decision:** `OPTIONAL FOUNDATION PASS / MULTI-AGENT EFFECTIVENESS OPEN`.

---

## 10. Regression gate

Final stage-work verification requires the same workflow to pass:

1. pinned Base revision check;
2. Base pytest regression;
3. Base invariant probes;
4. full CTF pytest regression;
5. controlled Agent Foundation;
6. live minimal SolveEngine;
7. Gate A0 fail-closed control;
8. live AnalysisSandbox isolation;
9. live Pwn operational vertical;
10. controlled Competition TCP SolveEngine vertical;
11. controlled Web HTTP SolveEngine vertical (also executed in pytest regression);
12. controlled Crypto/Reverse SolveEngine vertical;
13. all previous Pwn P1–P6 semantic/proof/recovery probes;
14. all existing WP08 evaluation integrity/executor probes.

The latest push workflow on the stage-work branch completed successfully with these implementation layers present before this document was created. This documentation commit must itself pass the same regression gate before merge.

---

## 11. Final status matrix

| Stage | Engineering status | Empirical status |
|---|---|---|
| WP13 Playbook / AnalysisSandbox | **PASS** | controlled/live isolation verified |
| Gate A0 production adapter | **PASS** | **OPEN: real provider credential/call** |
| WP14 Pwn vertical | **PASS** | controlled E2E; fresh autonomous solve OPEN |
| WP15 Competition / TCP / HTTP | **PASS** | controlled platform/transport verticals |
| WP16 runtime generalization | **PASS** | new providers need-driven |
| WP17 cross-domain foundation | **PASS** | real fresh-domain effectiveness OPEN |
| WP18 ablation infrastructure | **PASS** | real provider/corpus experiment OPEN |
| WP19 optional multi-agent boundary | **PASS** | effectiveness OPEN |

## Final conclusion

The remaining roadmap has been implemented to the point that repository-controlled engineering boundaries can be honestly verified. What remains OPEN is not missing core wiring but empirical work that intrinsically requires external inputs: a production model/provider credential, fresh/private challenge corpora, vendor-specific dynamic-instance providers, and measured evidence that multi-agent or individual ablated features improve solve performance.