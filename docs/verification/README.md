# Evidence-Gated Verification Index

Latest implementation code gate:

- CTF code commit: `c9b6b34ec2499232cdcf9dfb38ad8379bd0aed75`
- Pinned Base: `doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76`
- GitHub Actions run: `32054864672` — `success`
- Base regression: `220 passed, 7 skipped`
- CTF regression: `135 passed in 5.59s`
- preserved CTF pytest artifact: `9296044612`, SHA-256 `d6453dd93b823f665f88b13dc5d5e65e7019da4276ab30db312b40d1ec93e2a2`

The same full gate passed Base invariants, runtime-bound native P1, controlled QEMU-user AArch64 P1, delayed/over-read operational TCP transport, runtime-bound native x86_64 P2, sealed runtime-bound P3, P4–P6, WP06/WP07, and all existing WP08 evaluation probes.

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
operational model-driven solver = NOT YET ESTABLISHED
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

No report uses code existence, synthetic fixtures, self-reported completion, or documentation text alone as proof of CTF effectiveness.

## Stage 0 failure history

The first strengthened WP11 gate, run `32054672074`, failed after Base and CTF regressions because the controlled QEMU P1 fixture still supplied the legacy fact candidate shape. Actual QEMU execution and SIGSEGV observation succeeded. The fixture was updated to bind the production schema v2 runtime/launch identity, and the full gate then passed at run `32054864672`.

The red gate remains recorded in `WP11_STAGE0_EXECUTION_BOUNDARY_VERIFICATION.md`.

## Current next evidence gate

Execution is now sufficiently stable to begin the **Agent Foundation** without making SolveEngine wiring a circular WP11 prerequisite.

Next dependency-driven sequence:

1. define `RunIntent` / `TerminationPolicy` without giving them completion authority;
2. build CTF model context as a projection over the existing Base context/state authority;
3. expose a minimal capability catalog describing only Harness-owned actions available to the model;
4. define typed model decisions and a Harness-owned AgentController boundary;
5. execute Gate A0 proving model/controller decisions cannot directly mutate facts, proof, or completion;
6. then build the minimal SolveEngine vertical slice;
7. only after a real model-driven solve loop exists, run fresh/private Minimal-vs-Verified effectiveness evaluation.

A smoke stop, budget stop, unsupported-capability stop, or controller self-report must never set `state.completed=True`. Final completion remains External Oracle authority.