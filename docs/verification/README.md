# Evidence-Gated Verification Index

Latest implementation code gate:

- CTF code commit: `4b17413b761268e4dcfb0ae5b3d87c5f62b493c0`
- Pinned Base: `doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76`
- GitHub Actions run: `32056829487` — `success`
- Base regression: `220 passed, 7 skipped`
- CTF regression: `154 passed in 7.29s`
- preserved CTF pytest artifact: `9296690377`, SHA-256 `708f6509c6068a34cb7f8ff7f8ead4ade27decfe03cc5a16d3058ebaf51720f0`

The same full gate passed Base invariants, the controlled Agent foundation probe, runtime-bound native P1, controlled QEMU-user AArch64 P1, delayed/over-read operational TCP transport, runtime-bound native x86_64 P2, sealed runtime-bound P3, P4–P6, WP06/WP07, and all existing WP08 evaluation probes.

| Work package | Status | Report |
|---|---|---|
| WP00 Repository / Kernel Freeze | PARTIAL | `WP00_REPOSITORY_KERNEL_FREEZE_VERIFICATION.md` |
| WP01 Admission / Environment | PARTIAL | `WP01_ADMISSION_ENVIRONMENT_VERIFICATION.md` |
| WP02 Structured / Interactive Runtime | PASS | `WP02_STRUCTURED_INTERACTIVE_RUNTIME_VERIFICATION.md` |
| WP03 Pwn Recon / Classification | PASS | `WP03_PWN_RECON_CLASSIFICATION_VERIFICATION.md` |
| WP04 Pwn Semantic Verification | PARTIAL | `WP04_PWN_SEMANTIC_VERIFICATION.md` |
| WP05 Proof Pipeline | PARTIAL | `WP05_PROOF_PIPELINE_VERIFICATION.md` |
| WP06 Hypothesis / Dedupe | PARTIAL | `WP06_HYPOTHESIS_DEDUPE_VERIFICATION.md` |
| WP07 Recovery / Progress | PARTIAL | `WP07_RECOVERY_PROGRESS_VERIFICATION.md` |
| WP08 Evaluation / Benchmark Infrastructure | PASS — controlled infrastructure only | `WP08_EVALUATION_VERIFICATION.md` |
| WP08 Remediation History | CLOSED at code gate; documentation HEAD revalidated separately | `WP08_REMEDIATION_LOG.md` |
| WP09 Operational Baseline Freeze | PASS | `WP09_OPERATIONAL_BASELINE_FREEZE_VERIFICATION.md` |
| WP10 Operational Solve Contracts | PASS | `WP10_OPERATIONAL_SOLVE_CONTRACT_VERIFICATION.md` |
| WP11 Target Execution Layer | PASS — execution boundary stabilized | `WP11_TARGET_EXECUTION_VERIFICATION.md` |
| WP11 Stage 0 Review | PASS | `WP11_STAGE0_EXECUTION_BOUNDARY_VERIFICATION.md` |
| WP12 Agent Foundation | PASS — controlled authority/orchestration boundary | `WP12_AGENT_FOUNDATION_VERIFICATION.md` |

## Status semantics

`PASS` means the **named scope** is exercised by executable evidence. It does not imply broader real-world effectiveness.

`PARTIAL` means implemented logic exists and controlled evidence may pass, but at least one scoped exit condition remains open.

For WP08:

```text
controlled evaluation infrastructure = PASS
real fresh/private Pwn A/B effectiveness = NOT ESTABLISHED
```

For WP09:

```text
Base package/lock/CI provenance = consistent
temporary acquisition/probe workflows = removed
```

For WP10:

```text
ChallengeManifest identity authority = preserved
OperationalChallengeRef / SolveSpec identity = deterministic
credential-bearing TCP URI forms = rejected
```

For WP11:

```text
NativeRunner / CustomArgvRunner / QemuUserRunner = execution providers
P1/P2/P3 runtime + launch identity preservation = PASS
P2 non-native semantic inflation = blocked
P3 actor-controlled workspace TOCTOU = blocked by read-only accepted boundary
RemoteTcpSession delayed/delimiter/exact bounded reads = PASS
RemoteTcpRunner remains transport, not P5 authority
actual Dreamhack 103 replay = OPEN empirical follow-up
AArch64 P2 = UNSUPPORTED / later semantic work
full-system/VM provider = NOT IMPLEMENTED / add only when a real case requires it
```

For WP12:

```text
Base ContextProjector / Decision / LLMController reused = PASS
RunIntent / TerminationPolicy fingerprint-bound = PASS
SMOKE actor complete = durable incomplete stop, never success
SOLVE / COMPETITION actor complete = external oracle only
missing capability = incomplete stop or existing Base recovery
CTF hypotheses = untrusted speculation, never Fact authority
untrusted durable stop text = bounded preview + digest
model CTF metadata = bounded before runtime dispatch
production LLM executed = NO
actual end-to-end CTF solve = OPEN
```

No report uses code existence, synthetic fixtures, self-reported completion, or documentation text alone as proof of CTF effectiveness.

## Preserved failure history

WP11 Stage 0 red gate:

```text
run 32054672074
controlled QEMU P1 fixture omitted strengthened runtime/launch fact identity
actual QEMU execution and SIGSEGV observation succeeded
classification = fixture lag after production fact-contract strengthening
```

The failure and remediation remain recorded in `WP11_STAGE0_EXECUTION_BOUNDARY_VERIFICATION.md`.

## Agent Foundation meta-review

The WP12 implementation was re-reviewed after its first green gate. The review found and fixed two additional boundary issues before declaring the stage complete:

1. actor/model stop reason and missing-capability subject were initially stored as unbounded raw text in durable hash-chained control events;
2. CTF-specific model hypothesis metadata had shape validation but lacked explicit size bounds.

Final code gate `32056829487` includes both remediations. Full findings are recorded in `../implementation/WP12_AGENT_FOUNDATION_REVIEW_FINDINGS.md`.

## Current next evidence gate

The next dependency-safe engineering stage is **WP13 SolveSpec-to-runtime binding / minimal SolveEngine**.

Required invariants:

```text
SolveSpec identity
  run_intent
  termination_policy
  budget
  challenge/target identity
  agent identity
        ↓ exact binding / mismatch rejection
AgentCTFRuntime + Base Budget + prepared profile/controller
```

SolveEngine must remain orchestration only. It may not write verified facts, proof state, or completion.

A production-model empirical Gate A0 remains separately OPEN because the controlled WP12 probe uses a deterministic ModelAdapter fixture. No production provider/credential has been supplied or attested, so actual LLM execution and solve effectiveness must not be inferred from WP12.

After the minimal SolveEngine boundary is implemented and verified, the first controlled native x86_64 end-to-end vertical slice should be used to expose orchestration defects before DomainPlaybook, AnalysisSandbox, CompetitionAdapter, or additional runtime providers are added.