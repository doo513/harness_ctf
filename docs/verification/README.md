# Evidence-Gated Verification Index

Latest implementation code gate:

- CTF code commit: `8ff8f535f31072b643cbeb4bed957b6a09e36f47`
- Pinned Base: `doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76`
- GitHub Actions run: `32045210634` — `success`
- Base regression: `PASS`
- CTF regression: `129 passed in 5.34s`

The same full gate passed the Base invariant probes, migrated native P1 crash probe, controlled QEMU AArch64 P1 runner probe, controlled operational remote TCP runner probe, existing P2–P6 proof/semantic probes, WP06 hypothesis/dedupe, WP07 recovery/progress, and the WP08 arm/integrity/ingestion/executor/runtime-backed evaluation probes.

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
| WP11 Target Execution Layer | PARTIAL — core execution gate passed | `WP11_TARGET_EXECUTION_VERIFICATION.md` |

## Status semantics

`PASS` means the scoped exit gate is exercised by executable evidence. It does not imply broader real-world effectiveness.

`PARTIAL` means implemented logic exists and controlled evidence may already pass, but at least one roadmap exit condition remains open.

For WP08 specifically:

```text
controlled evaluation infrastructure = PASS
real fresh/private Pwn A/B effectiveness = NOT ESTABLISHED
```

For WP09 specifically:

```text
Base package/lock/CI provenance = consistent
temporary push acquisition/probe workflows = removed
operational solver = NOT YET ESTABLISHED
```

For WP10 specifically:

```text
ChallengeManifest identity authority = preserved
operational SolveSpec/target/policy identity = deterministic
credential-bearing TCP URI forms = rejected
target execution = separate WP11 concern
```

For WP11 specifically:

```text
native/custom/QEMU runtime identity contracts = implemented
native crash path migration = PASS
controlled QEMU AArch64 P1 = PASS
operational admitted remote TCP transport = PASS
actual Dreamhack 103 handout replay = OPEN
control/local-proof full runner migration = OPEN
```

No report uses code existence, synthetic fixtures, self-reported completion, or documentation text alone as proof of CTF effectiveness.

## Current next evidence gate

The execution blocker identified by the Dreamhack smoke case is now partially removed: non-native AArch64 target execution can produce runtime-bound P1 evidence through the normal crash verifier under a controlled QEMU fixture, and operational remote TCP transport is admission/policy bound.

WP11 is intentionally not marked complete because the roadmap's real-world and migration exits are still open.

Next implementation sequence:

1. migrate the existing control/local-proof execution paths onto the target/runtime abstraction while preserving their current architecture-specific truth rules;
2. replay the exact Dreamhack 103 handout through `QemuUserRunner` when the artifact bytes/runtime inputs are available and register the reproduced SIGSEGV through the normal Harness evidence -> verifier -> fact path;
3. integrate the operational remote transport into the later SolveEngine-facing tool boundary;
4. only then proceed to the Harness-owned Agent Controller / SolveEngine vertical slice;
5. keep AArch64 P2 semantic generalization in its planned later evidence-generalization scope rather than hiding it behind a generic verifier;
6. after an operational solver exists, execute the already-built canonical Minimal vs Verified real A/B benchmark with fresh/private cases.

This changes implementation maturity, not the WP08 effectiveness standard. No solve-rate, token, cost, or time improvement claim is permitted until the real fixed A/B evidence exists.
