# WP08 — Dreamhack Challenge 103 Real-World Smoke Benchmark

**Status:** `PARTIAL EXECUTION — ADMISSION/RECON PASS, SOLVE A/B NOT ESTABLISHED`

## 1. Purpose

Use Dreamhack Wargame challenge `103` as a real handout smoke case for the WP08 benchmark path.

This challenge is public. It is therefore **not** part of the planned fresh/private 10–15 case Pwn effectiveness corpus and no freshness/private-corpus claim is made.

No public writeup or externally searched challenge solution was used while inspecting the supplied handout.

An authenticated platform session had been supplied separately for an earlier acquisition attempt. That secret is **not persisted** in this repository, document, workflow, benchmark manifest, or artifact.

## 2. Supplied handout identity

Uploaded ZIP SHA-256:

```text
9702b626bc915d54e5c9843ed2f6e2a8e8c61807d0cf7d8ee362eeee1eabc247
```

Archive members:

| Artifact | Size | SHA-256 |
|---|---:|---|
| `run.sh` | 279 | `dc57f57c4b6da60e7816dd2ef109d436bf49f08dd9185a7e5794e248cab170f3` |
| `rootfs` | 4,251,833 | `c1caaf893103ac88120f0cc5d5763f73207c18d1d2887882af02ff7688f44b3b` |
| `kernel` | 9,637,896 | `c57eb423719833daa482ab8326332153cbef064cc72ee7ff92ef5f2eac10bf9e` |
| `chal` | 14,576 | `5ae9ddba6772b90059e24efdeb0c5ec7f70ce7c3cd3e3b919d17e86cd1304e22` |

Observed file types:

```text
chal   = ELF 64-bit LSB executable, ARM aarch64, dynamically linked, stripped
kernel = Linux kernel ARM64 Image
rootfs = gzip-compressed initramfs
run.sh = POSIX shell script
```

This resolves the earlier artifact-acquisition blocker.

## 3. Challenge environment evidence

The supplied `run.sh` launches:

```text
qemu-system-aarch64
-M virt
-cpu cortex-a57
-kernel kernel
-initrd rootfs
host TCP 8000 -> guest TCP 8000
```

The local handout uses a placeholder flag value for local testing. It is **not** treated as Dreamhack oracle success.

Rootfs evidence:

```text
/etc/inetd.conf : chal stream tcp nowait nobody /usr/bin/chal
/etc/services   : chal 8000/tcp
```

The rootfs boot script writes the kernel-command-line flag environment value into `/flag`.

`/usr/bin/chal` in the rootfs matches the supplied `chal` hash.

### Extraction limitation

Unpacking the initramfs in the benchmark worker produced a device-node error for `/dev/console` because the sandbox cannot create that device node. Regular files needed for static inspection were extracted successfully.

This is classified as an **execution-environment limitation**, not a challenge defect.

## 4. Exact WP03 recon result

The repository's current `ctf_harness.recon.pwn.inspect_elf_bytes()` logic was applied to the supplied `chal` bytes.

Result:

```json
{
  "schema_version": 1,
  "kind": "pwn_recon_snapshot",
  "artifact_sha256": "5ae9ddba6772b90059e24efdeb0c5ec7f70ce7c3cd3e3b919d17e86cd1304e22",
  "file_type": "ELF",
  "elf_type": "EXEC",
  "architecture": "aarch64",
  "bits": 64,
  "endianness": "little",
  "pie": false,
  "nx": true,
  "canary_symbol_hint": null,
  "interpreter": "/lib/ld-musl-aarch64.so.1",
  "entrypoint": 4198564
}
```

**Recon gate:** `PASS`.

The recon implementation already recognizes ELF machine 183 as `aarch64`; architecture identification is therefore not the current blocker.

## 5. Handout-only vulnerability hypothesis

Static AArch64 disassembly of the supplied binary identified a candidate unbounded stack write in the request handler.

Relevant control-flow facts:

```text
handler frame size     = 0x80
control code input     = [sp + 0x54]
argument count         = control_code >> 7
argument buffer base   = sp + 0x60
each argument write    = 8 bytes
```

The loop repeatedly reads `%lf` and stores each 64-bit representation at:

```text
buffer_base + index * 8
```

The caller's frame begins immediately after the handler's 0x80-byte frame. Therefore, relative to the caller stack pointer:

```text
arg[0] -> caller_sp - 0x20
arg[1] -> caller_sp - 0x18
arg[2] -> caller_sp - 0x10
arg[3] -> caller_sp - 0x08
arg[4] -> caller saved x29
arg[5] -> caller saved x30 / LR
```

A control code whose `control_code >> 7 >= 6` therefore provides a **static candidate** for overwriting the caller's saved link register.

This is deliberately recorded only as a hypothesis. The input path also normalizes NaN and very small absolute double values, so a useful controlled pointer value is not established by this static observation alone.

**Do not promote this observation to P1/P2/P3.**

## 6. Actual execution gate

The benchmark worker was checked for:

```text
qemu-system-aarch64
qemu-aarch64
qemu-aarch64-static
```

All were absent.

The package-manager path could not obtain package metadata because outbound package-network access timed out. A separate attempt to acquire an AArch64 emulator binary did not produce an executable in the worker.

Therefore the supplied `run.sh` could not be booted and `chal` could not be dynamically executed under AArch64 emulation in this run.

### Proof result

| Level | Result | Reason |
|---|---|---|
| P0 Surface | **PASS / observed** | handout admitted; AArch64/NX/non-PIE/static surface identified |
| P1 Primitive | **NOT VERIFIED** | no executable AArch64/QEMU backend; crash not reproduced |
| P2 Control | **UNSUPPORTED + NOT VERIFIED** | current claim registry maps `ctf.pwn.control_flow` to `pwn_control_flow_x86_64` |
| P3 Local | **NOT REACHED** | P1/P2 absent |
| P4 Environment | **NOT REACHED** | no executable target runtime |
| P5 Remote | **NOT REACHED** | no active challenge endpoint included in this handout run |
| P6 Accepted | **NOT REACHED** | no platform oracle submission/acceptance |

## 7. Harness coverage defect exposed by the smoke case

The current repository has an architecture-aware recon layer but an architecture-specific P2 semantic verifier boundary:

```text
ctf.pwn.control_flow
→ pwn_control_flow_x86_64
```

This is appropriate as a fail-closed current contract, but it means AArch64 Pwn challenges cannot complete the existing P0–P5 verified vertical slice.

This smoke case therefore exposes a concrete pre-corpus coverage gap:

> AArch64 recon is supported, but AArch64 control-flow semantic verification is not yet implemented.

No generic verifier fallback was introduced to make this challenge appear supported.

## 8. Minimal vs Verified A/B status

A valid first solve A/B requires the same frozen:

- challenge bytes;
- model and model revision;
- controller revision;
- tools;
- sandbox;
- oracle policy;
- budgets/seeds;

with two independent runtime executions:

```text
MinimalCTFBenchmarkRuntime
vs
VerifiedCTFBenchmarkRuntime
```

The current benchmark worker does not have a run-specific real LLM Agent Controller connected for two independent solves. Reusing the already-informed interactive analyst as both sequential arms would contaminate the second run and would not satisfy the current WP08 comparison contract.

Accordingly:

```text
minimal_solve_run = NOT EXECUTED
verified_solve_run = NOT EXECUTED
paired_success_delta = NOT MEASURED
paired_wall_time_delta = NOT MEASURED
paired_tool_call_delta = NOT MEASURED
```

Synthetic/no-op controller outputs are not substituted for a real solve benchmark.

## 9. Benchmark assessment

### What this case successfully tested

- real challenge artifact acquisition and hashing;
- real ARM64/rootfs challenge shape;
- current WP03 recon behavior on an AArch64 ELF;
- truthful proof-level stopping behavior;
- architecture support boundary discovery;
- benchmark discipline against counting a local dummy flag as external success;
- benchmark discipline against fabricating Minimal/Verified solve records.

### What it did not test

- reproducible AArch64 crash;
- AArch64 PC/LR control;
- local exploit;
- remote exploit;
- Dreamhack flag acceptance;
- real Agent Controller solve behavior;
- Minimal-vs-Verified effectiveness.

## 10. Required changes before this exact problem can become a full solve A/B case

1. provide an executable AArch64 target backend in the benchmark runner (`qemu-system-aarch64` or an explicitly supported equivalent);
2. add claim-specific AArch64 P2 control-flow verification rather than weakening the existing x86_64 verifier;
3. connect a real fixed-model Agent Controller to `RuntimeBenchmarkExecutor` for independent Minimal and Verified runs;
4. for P5/P6, supply/create the authorized remote endpoint and external platform oracle path without persisting credentials.

These are separate requirements. Adding only a UI/TUI would not resolve any of them.

## 11. Truthfulness decision

```text
artifact_admission                = PASS
static_recon                      = PASS
static_stack_overwrite_hypothesis = OBSERVED / UNVERIFIED
P1_crash                          = NOT VERIFIED
P2_control                        = UNSUPPORTED / NOT VERIFIED
P3_local                          = NOT REACHED
P4_environment                    = NOT REACHED
P5_remote                         = NOT REACHED
P6_accepted                       = NOT REACHED
minimal_verified_solve_AB         = NOT EXECUTED
solve_rate_improvement            = NOT ESTABLISHED
```

**Decision:** `PARTIAL REAL-WORLD SMOKE BENCHMARK — VALID COVERAGE FINDING, NO SOLVE/EFFECTIVENESS CLAIM`.
