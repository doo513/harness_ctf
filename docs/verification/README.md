# Evidence-Gated Verification Index

Latest implementation code gate:

- CTF code commit: `f9c9f33c4522754a4adc7b7a41db22c4826ef764`
- Pinned Base: `doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76`
- GitHub Actions run: `32043326712` — `success`
- Base regression: `PASS`
- CTF regression: `96 passed in 4.99s`

The same full gate passed the Base invariant probes, P1–P6 proof/semantic probes, WP06 hypothesis/dedupe, WP07 recovery/progress, and the WP08 arm/integrity/ingestion/executor/runtime-backed evaluation probes.

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
permanent live Dreamhack CI dependency = removed
operational solver = NOT YET ESTABLISHED
```

No report uses code existence, synthetic fixtures, self-reported completion, or documentation text alone as proof of CTF effectiveness.

## Current next evidence gate

WP08 established that the evaluation machinery can measure a real experiment, but the Dreamhack 103 smoke case also exposed that the current Harness cannot yet register some non-native execution evidence through its normal target/tool path. Therefore benchmark infrastructure should not be expanded further before the operational execution path exists.

Next implementation sequence:

1. WP10 — define operational challenge/target/solve contracts while preserving `ChallengeManifest` as the challenge identity source of truth;
2. WP11 — introduce Base-backed target execution/runtime provenance for native and QEMU targets;
3. register the Dreamhack 103 reproducible SIGSEGV through the normal Harness evidence -> verifier -> fact path;
4. then add the Harness-owned model controller / solve loop and reach the first end-to-end Pwn vertical slice;
5. only after an operational solver exists, execute the already-built canonical Minimal vs Verified real A/B benchmark with fresh/private cases.

This changes implementation priority, not the WP08 effectiveness standard. No solve-rate, token, cost, or time improvement claim is permitted until the real fixed A/B evidence exists.
