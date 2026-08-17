# WP08 — Dreamhack Challenge 103 Real-World Smoke Benchmark

**Status:** `PARTIAL REAL-WORLD EXECUTION — LIVE PRIMITIVE OBSERVED / SOLVE A/B NOT ESTABLISHED`

## 1. Purpose and scope

Dreamhack Wargame challenge `103` was used as a real public handout smoke case for the WP08 evaluation path.

This is **not** the planned fresh/private 10–15 case Pwn effectiveness corpus. No freshness, contamination resistance, or solve-rate improvement claim is made.

No public writeup or externally searched challenge solution was used while inspecting or exercising the supplied handout.

An authenticated Dreamhack session had been supplied separately during an earlier acquisition attempt. That secret is intentionally **not persisted** in this repository, document, workflow, benchmark manifest, or artifact.

This benchmark distinguishes three different statements:

1. a primitive was externally observed;
2. the current harness can convert that evidence into a verified `HarnessState.facts` claim;
3. a complete Minimal-vs-Verified solve A/B was executed.

Those are not interchangeable.

---

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

Observed types:

```text
chal   = ELF 64-bit LSB executable, ARM aarch64, dynamically linked, stripped
kernel = Linux kernel ARM64 Image
rootfs = gzip-compressed initramfs
run.sh = POSIX shell script
```

The rootfs `/usr/bin/chal` SHA-256 is the same as the separately supplied `chal`.

---

## 3. Challenge environment evidence

The supplied launcher uses:

```text
qemu-system-aarch64
-M virt
-cpu cortex-a57
-kernel kernel
-initrd rootfs
host TCP 8000 -> guest TCP 8000
```

Rootfs configuration:

```text
/etc/inetd.conf : chal stream tcp nowait nobody /usr/bin/chal
/etc/services   : chal 8000/tcp
```

The boot script writes the kernel command-line `FLAG` environment value into `/flag`.

The local launcher contains a dummy/local flag. It is **not** treated as Dreamhack P6 evidence.

### Initramfs extraction note

The benchmark worker could not create `/dev/console` while unpacking the initramfs because device-node creation is prohibited by the sandbox. Regular files, dynamic libraries, init scripts, and the challenge binary required for analysis were extracted successfully.

This is an execution-environment limitation, not a challenge defect.

---

## 4. Exact current harness recon

The repository's current `ctf_harness.recon.pwn.inspect_elf_bytes()` logic was applied to the supplied `chal` bytes.

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

**Recon:** `PASS`.

The current recon implementation already maps ELF machine 183 to `aarch64`.

---

## 5. Static vulnerability analysis

Handout-only AArch64 disassembly identified the following request-handler layout:

```text
handler frame size     = 0x80
control code input     = [sp + 0x54]
argument count         = control_code >> 7
argument buffer base   = sp + 0x60
each argument write    = 8 bytes
```

The `%lf` input loop stores the parsed 64-bit representation at:

```text
buffer_base + index * 8
```

Relative to the caller stack pointer:

```text
arg[0] -> caller_sp - 0x20
arg[1] -> caller_sp - 0x18
arg[2] -> caller_sp - 0x10
arg[3] -> caller_sp - 0x08
arg[4] -> caller saved x29
arg[5] -> caller saved x30 / LR
```

Therefore a control code for six or more arguments can overwrite the caller's saved frame/link registers before invalid-function dispatch throws `bad_function_call`.

The input path normalizes NaN and values with absolute magnitude below approximately `1e-5` to zero. This initially appeared to prevent ordinary low userland pointers from being supplied as IEEE-754 doubles.

---

## 6. AArch64 execution backend acquired for the smoke run

The local worker did not initially contain QEMU and could not reach package repositories directly. A **temporary GitHub Actions export workflow** was therefore used only to obtain an Ubuntu runner's `qemu-aarch64-static`, after which the workflow was removed.

Temporary export run:

```text
GitHub Actions run = 32040272120
artifact id        = 9291817858
```

Acquired executable:

```text
qemu-aarch64-static version = 8.2.2 (Ubuntu/Debian package build)
SHA-256                      = e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e
```

The supplied musl loader was invoked explicitly with the extracted rootfs library directories. A normal execution then produced the same application behavior as the remote service:

```text
321
1
2

=> =3.000000
```

The temporary QEMU workflow and temporary live-endpoint CI step were removed after evidence collection; they are not permanent benchmark dependencies.

---

## 7. Reproducible crash evidence

### Baseline

Input:

```text
1
```

Input SHA-256:

```text
4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865
```

Result:

```text
return code = 0
output      = Exception: bad_function_call
```

### Overflow candidate

Input:

```text
768
0
0
0
0
0
0
```

Input SHA-256:

```text
3508c90d68e9b6b7a8ff53110f0d29827258ddd54d5864211f647a20ea49b167
```

Two independent executions against the same challenge binary/rootfs produced:

```text
run 1: target signal = SIGSEGV (11)
run 2: target signal = SIGSEGV (11)
```

QEMU reported:

```text
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
```

A second input using six `1.0` arguments also reproduced SIGSEGV twice.

### P1 interpretation

This evidence satisfies the **semantic content** of the existing P1 reproducibility rule:

```text
same target + same input + same terminating signal + independent executions
```

However, the production `CrashProbeBackend` currently directly executes `[exec_path]`. It has no target-runtime adapter field for `qemu-aarch64 + loader + target`. Therefore these real QEMU observations were **not fabricated into `pwn_crash_probe` artifacts** and were not inserted into `HarnessState.facts` as if the existing tool had produced them.

Result distinction:

```text
external P1 observation = PASS
current-harness registered P1 fact for this challenge = NOT PRODUCED
```

---

## 8. Live AArch64 LR/PC control observation

A temporary local GDB Remote Serial Protocol client was used against `qemu-aarch64-static -g` to read AArch64 core registers at the target SIGSEGV stop.

### Zero input

For six zero arguments, two runs produced:

```text
SIGSEGV
x29 = 0x0
x30 = 0x0
PC  = 0x0
```

### `1.0` input

Input SHA-256:

```text
05b0d58f3473627bb6d5188ed7574fb295b556a07ec4b4e69cb98663e5cc64e0
```

IEEE-754 representation of `1.0`:

```text
0x3ff0000000000000
```

Two independent runs produced:

```text
SIGSEGV
x29 = 0x3ff0000000000000
x30 = 0x3ff0000000000000
PC  = 0x3ff0000000000000
```

This demonstrates actual caller LR/PC control through the sixth double argument.

### P2 interpretation

This is strong **external AArch64 control-flow evidence**, but the current claim registry is explicitly:

```text
ctf.pwn.control_flow
→ pwn_control_flow_x86_64
```

The existing x86_64 verifier's input-to-register semantics also assume an exact byte-sequence relation suitable for its current probe, whereas this challenge transforms textual decimal input through `%lf` into IEEE-754 register-overwrite bytes.

Therefore no generic verifier fallback was added and no x86_64 evidence schema was relabelled as AArch64 evidence.

Result distinction:

```text
external AArch64 P2 observation = PASS
current-harness registered P2 fact = UNSUPPORTED / NOT PRODUCED
```

---

## 9. Top-Byte-Ignore exploitability finding

The small-double filter does not fully remove pointer control on AArch64.

Example bit pattern:

```text
0x3f00000000400ca8
```

interprets as a finite double of approximately:

```text
3.0517578153443665e-05
```

which is above the filter threshold.

The low address is the binary `_init` location (`0x400ca8`) with top byte `0x3f`. Under the tested AArch64 user-mode environment, using this value as the saved LR changed the normal SIGSEGV behavior into repeated execution/timeout, consistent with top-byte-ignore semantics resolving the tagged instruction address to the low code address.

This makes tagged-pointer ROP a plausible exploit path despite the double-value filter.

This finding is **not** equivalent to P3 local exploit proof. A completed flag-producing exploit was not established in this benchmark run.

---

## 10. Live remote-service smoke evidence

After the authorized challenge endpoint was supplied, a temporary GitHub Actions network probe was run because the local worker could not resolve the remote hostname.

Evidence run:

```text
GitHub Actions run = 32040086852
job                = 95417742165
```

The same workflow also preserved the normal project gates:

```text
Base regression = 220 passed, 7 skipped
CTF regression  = 92 passed
existing P1–P6/WP06/WP07/WP08 controlled probes = PASS
```

Observed remote behavior:

### Valid operation

```text
input:
321
1
2

output included:
=3.000000
Control code?
```

Thus the live endpoint's normal operation matches the supplied handout.

### Invalid baseline

```text
1
```

produced:

```text
Exception: bad_function_call
```

### Six-argument overflow candidate

```text
768
0
0
0
0
0
0
```

also visibly produced:

```text
Exception: bad_function_call
```

TCP transcript alone does not expose the target process's terminating signal, so this remote observation is **not** used to claim remote crash reproduction.

The live endpoint was removed from the permanent CI workflow immediately after this smoke evidence was captured so expiry does not create future CI failures.

---

## 11. Current proof-state assessment for this challenge

Two views must be kept separate.

### 11.1 What was physically observed

| Stage | External observation |
|---|---|
| P0 Surface | **PASS** — AArch64, 64-bit, little endian, NX, non-PIE |
| P1 Primitive | **PASS** — same target/input SIGSEGV 11 reproduced twice |
| P2 Control | **PASS as external observation** — x30 and PC changed to exact IEEE-754 argument bits twice |
| P3 Local | **NOT ESTABLISHED** — no local flag-producing exploit receipt |
| P4 Environment | **PARTIAL OBSERVATION** — rootfs/libs and remote protocol match; no formal compatibility receipt |
| P5 Remote | **RAW REMOTE BEHAVIOR OBSERVED** — valid operation matches; exploit not proven remotely |
| P6 Accepted | **NOT REACHED** — no platform flag acceptance |

### 11.2 What the current Verified CTF Harness can truthfully register

| Stage | Current harness result |
|---|---|
| P0 | **SUPPORTED** |
| P1 | **NOT REGISTERED FOR THIS RUN** — crash probe lacks AArch64 runtime adapter |
| P2 | **UNSUPPORTED** — verifier is x86_64-specific |
| P3 | **NOT REACHED** |
| P4 | **NOT REACHED in contiguous proof** |
| P5 | **NOT REACHED in contiguous proof** |
| P6 | **NOT REACHED** |

Therefore the Verified proof projection must **not** pretend that the manually observed P1/P2 evidence is already a current-harness fact.

---

## 12. Harness coverage gaps exposed

### G-103-01 — target-runtime execution adapter

Current `CrashProbeBackend` directly executes the target file. This works for host-native ELF cases but cannot represent:

```text
qemu-aarch64-static
→ challenge musl loader
→ AArch64 challenge ELF
```

without changing the target identity or fabricating receipt provenance.

Required direction: a fixed, attested target-runtime adapter whose receipt separately binds emulator/runtime identity and challenge target SHA.

### G-103-02 — claim-specific AArch64 P2 verifier

Recon is architecture-aware, but P2 is currently x86_64-specific.

Required direction: an AArch64 verifier that can bind:

```text
textual input
→ %lf parse / IEEE-754 bits
→ saved LR
→ observed PC
```

rather than reusing the x86_64 raw-byte contract.

### G-103-03 — real Agent Controller

WP08 has actual Minimal and Verified runtime classes, but this benchmark environment still does not have a real fixed-model Agent Controller wired for two independent solves.

Without it, the infrastructure can execute deterministic controlled probes but cannot produce a valid model solve-rate A/B.

### G-103-04 — external platform completion adapter

The live challenge endpoint alone is not the P6 oracle. Platform flag acceptance still requires a credential-safe external completion path.

---

## 13. Minimal vs Verified A/B status

A valid solve comparison requires the same frozen:

- challenge bytes;
- model/revision;
- controller revision;
- tool inventory;
- sandbox/runtime;
- oracle policy;
- budgets/seeds;

with two independent runs:

```text
MinimalCTFBenchmarkRuntime
vs
VerifiedCTFBenchmarkRuntime
```

This was **not** replaced with two sequential uses of the already-informed interactive analyst. Doing so would contaminate the second arm.

Accordingly:

```text
minimal_solve_run        = NOT EXECUTED
verified_solve_run       = NOT EXECUTED
paired_success_delta     = NOT MEASURED
paired_wall_time_delta   = NOT MEASURED
paired_tool_call_delta   = NOT MEASURED
solve_rate_improvement   = NOT ESTABLISHED
```

---

## 14. Benchmark value

This public challenge produced useful real-world evidence even without a complete A/B:

1. artifact acquisition and identity work on a nontrivial kernel/rootfs handout;
2. current recon correctly handles AArch64;
3. a real deterministic crash primitive exists;
4. actual AArch64 PC/LR control exists;
5. target-specific TBI behavior materially changes exploitation strategy;
6. the current harness correctly has no authority to call its x86_64 P2 verifier an AArch64 verifier;
7. direct-exec crash tooling is too host-native for this class of challenge;
8. a real model Agent Controller is still required before WP08 can measure Minimal-vs-Verified solve effectiveness;
9. the remote service behavior is consistent with the admitted handout;
10. no local dummy flag, manual observation, or raw network response was incorrectly promoted to P6.

---

## 15. Final truthfulness decision

```text
artifact_admission                       = PASS
static_recon                             = PASS
external_reproducible_crash              = PASS
external_AArch64_LR_PC_control           = PASS
current_harness_P1_fact_for_this_case    = NOT PRODUCED
current_harness_P2_fact_for_this_case    = UNSUPPORTED
TBI_tagged_pointer_path                  = OBSERVED LOCALLY / EXPLOIT HYPOTHESIS ADVANCED
local_flag_proof                         = NOT ESTABLISHED
remote_normal_behavior                   = OBSERVED
remote_exploit                           = NOT ESTABLISHED
platform_flag_acceptance                 = NOT REACHED
minimal_vs_verified_real_model_A_B       = NOT EXECUTED
solve_rate_improvement                   = NOT ESTABLISHED
```

**Decision:** `VALID REAL-WORLD SMOKE BENCHMARK — COVERAGE GAPS IDENTIFIED; NO FALSE SOLVE/EFFECTIVENESS CLAIM`.
