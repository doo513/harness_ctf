# WP11 — Target Execution Layer Verification

**Status:** `PASS — EXECUTION BOUNDARY STABILIZED / REAL-WORLD REPLAY REMAINS EMPIRICAL FOLLOW-UP`

## 1. Goal

Establish one evidence-bound execution boundary for Pwn target execution without making a particular emulator, container, or VM the architecture center.

```text
target identity  = challenge target bytes
runtime identity = registered execution environment
launch identity  = target + runtime + exact argv
```

`TargetRunner` owns process launch description; Base owns process isolation/execution; evidence + claim-specific verifiers own semantic promotion. Remote transport remains separate from P5 truth authority.

## 2. Current supported execution providers

```text
NativeRunner
CustomArgvRunner
QemuUserRunner
RemoteTcpRunner  # challenge transport, not local process runner / not P5 authority
```

QEMU user-mode is one provider. WP11 does not create a QEMU-system/VM architecture. Future container/emulator/VM support is added only when an admitted challenge demonstrates the need and the provider can preserve the same identity/integrity contract.

## 3. Stage 0 closure

The original WP11 partial gate left three practical gaps:

```text
pwn_control_probe  -> direct/architecture-specific execution
P3 local proof     -> separate direct target execution contract
Remote TCP read    -> single recv() semantics
```

Stage 0 closed those execution-boundary gaps.

### P1

Runtime-bound schema v2 verified facts now preserve:

```text
target_sha256
input_sha256
signal
runtime_fingerprint
launch_fingerprint
```

so execution conditions are not lost after verification.

### P2

The x86_64 RIP control probe now builds its launch through a registered `TargetRunner` and emits runtime/launch-bound evidence. The verifier remains intentionally native x86_64 only; non-native runtime profiles fail closed before execution.

### P3

The local proof oracle now uses an exact `RuntimeLaunch`, persists runtime/launch identity in its receipt/fact candidate, and requires a live strong Base filesystem boundary with `workspace_writable=False`.

The read-only requirement was added after review showed that Base workspaces are writable by default. Without the seal, an actor-controlled exploit could mutate the target/workspace runtime after identity validation. The live probe actively attempts target mutation and requires it to fail; a writable-workspace negative control is rejected.

### Remote TCP

`RemoteTcpSession` now supports bounded persistent protocol reads:

```text
read(wait_seconds, idle_grace_seconds)
read_until(delimiter, wait_seconds)
read_exact(byte_count, wait_seconds)
bounded_drain(wait_seconds)
```

A pending buffer preserves delimiter over-read while transcript hashes/counts record each network byte exactly once.

## 4. Evidence history

### Red gate

```text
run: 32054672074
result: failure
Base: 220 passed, 7 skipped
CTF: 135 passed
failure: controlled QEMU P1 fixture omitted newly-required runtime/launch fact identity
```

The QEMU execution and SIGSEGV observation succeeded. The failure was preserved and classified as fixture lag after strengthening the production schema v2 fact contract.

### Final code gate

```text
code HEAD: c9b6b34ec2499232cdcf9dfb38ad8379bd0aed75
run: 32054864672
job: 95462571212
conclusion: success
Base: 220 passed, 7 skipped
CTF: 135 passed in 5.59s
```

Preserved regression artifact:

```text
ctf-pytest-log
artifact id: 9296044612
sha256: d6453dd93b823f665f88b13dc5d5e65e7019da4276ab30db312b40d1ec93e2a2
```

The same workflow passed native P1, controlled QEMU-user AArch64 P1, delayed/over-read remote TCP, native x86_64 P2, sealed P3, P4, P5, P6, WP06, WP07, and all existing WP08 probes.

Full Stage 0 defect/remediation and logical review: `WP11_STAGE0_EXECUTION_BOUNDARY_VERIFICATION.md`.

## 5. Authority review

```text
TargetRunner                  = execution description, not truth
RemoteTcpRunner               = admitted transport, not P5 truth
runtime/launch fingerprints   = execution conditions in P1/P2/P3 facts
HarnessState.facts            = semantic truth authority
CTF proof projection          = projection only
External Oracle               = final completion authority
```

No second fact/proof/recovery/completion authority was added.

## 6. Explicitly unsupported / not claimed

```text
actual Dreamhack 103 handout replay         OPEN empirical follow-up
AArch64 LR/PC P2 semantic verifier          OPEN later architecture generalization
full-system/VM execution provider           NOT IMPLEMENTED; add only when needed
actual model-driven solve loop              OPEN next stages
Minimal-vs-Verified effectiveness           NOT MEASURED
```

A controlled QEMU-user P1 is not evidence of full-system environment equivalence.

## 7. Exit decision

```text
process execution abstraction            PASS
P1 execution identity preservation       PASS
P2 execution migration                   PASS
P3 execution migration + actor seal      PASS
remote persistent protocol semantics     PASS
semantic inflation blocked               PASS
existing regression gates                PASS
```

**Decision:** WP11 execution-boundary work required before Agent integration is complete. SolveEngine wiring is no longer treated as a WP11 prerequisite because that would create a dependency on a component implemented later. The next stage is Agent Foundation.