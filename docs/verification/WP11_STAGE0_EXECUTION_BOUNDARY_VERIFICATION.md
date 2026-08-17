# WP11 Stage 0 — Execution Boundary Stabilization Verification

**Status:** `PASS — EXECUTION BOUNDARY STABILIZED / EMPIRICAL DREAMHACK REPLAY OPEN`

## 1. Scope

This gate stabilizes the execution boundary required before adding a Harness-owned Agent Controller. It intentionally does **not** add a solver, a new completion authority, AArch64 P2 semantics, or a QEMU/VM-specific architecture.

Authority remains:

```text
ChallengeManifest / OperationalChallengeRef
-> TargetRunner / RemoteTcpRunner execution
-> Evidence
-> claim-specific Verifier
-> HarnessState.facts
-> CTF proof projection
-> External completion oracle
```

`TargetRunner` is the generic local execution abstraction. QEMU user-mode is one registered provider, not the architecture center.

## 2. Implemented changes

### 2.1 P1 runtime identity is authoritative

Runtime-bound crash schema v2 already carried `runtime_fingerprint` and `launch_fingerprint`, but the verified candidate previously omitted them. This could let downstream consumers see a crash fact without the execution conditions under which it was reproduced.

Remediation:

```text
ctf.pwn.crash_reproducible schema v2 fact
= target_sha256
+ input_sha256
+ signal
+ runtime_fingerprint
+ launch_fingerprint
```

Mixed legacy/runtime-bound evidence and runtime/launch mismatches fail closed.

### 2.2 P2 x86_64 control execution migrated to TargetRunner

The old control probe invoked the target directly under GDB. It now builds a `RuntimeLaunch` through a registered `TargetRunner`, binds target/runtime/launch identity, and records schema v2 evidence.

The semantic verifier remains deliberately narrow:

```text
architecture/semantic authority = x86_64 RIP
runtime support in this verifier = native only
```

A non-native runner is rejected before execution. TargetRunner support is not interpreted as AArch64/QEMU P2 support.

### 2.3 P3 local proof migrated and sealed against actor-controlled TOCTOU

The old local proof passed `./target` directly to the actor-controlled exploit. The migrated oracle builds the exact target `RuntimeLaunch` and passes its argv to the exploit.

During Stage 0 review a more serious issue was found: Base namespace workspaces are writable by default. An actor-controlled exploit could therefore mutate the target or workspace runtime after identity validation and before using the launch.

Remediation:

- accepted P3 requires Base live strong filesystem isolation;
- accepted P3 additionally requires `workspace_writable=False`;
- the receipt binds runtime and launch fingerprints;
- the live probe attempts to modify the target and must observe that the write is blocked;
- a writable-workspace control must be rejected before producing accepted P3 proof.

This keeps `environment_fingerprint`, target identity, and concrete execution identity from drifting apart through actor-controlled workspace mutation.

### 2.4 Remote persistent I/O made bounded and stateful

The previous operational TCP session used a single `recv()` per read. That is insufficient for delayed banners, fragmented prompts, and multi-stage exploit protocols.

Added:

```text
read(wait_seconds, idle_grace_seconds)
read_until(delimiter, wait_seconds)
read_exact(byte_count, wait_seconds)
bounded_drain(wait_seconds)
```

A pending buffer preserves delimiter over-read. Transcript accounting hashes/counts network bytes exactly once when received, so later logical reads of pending bytes do not duplicate provenance.

Remote transport remains transport only; it has no P5 or completion authority.

## 3. Red gate preserved

First full Stage 0 gate:

```text
GitHub Actions run: 32054672074
result: FAIL
Base: 220 passed, 7 skipped
CTF: 135 passed
native P1: PASS
controlled QEMU AArch64 P1: FAIL at verifier candidate binding
```

Exact failure class:

```text
candidate does not exactly bind the reproduced crash execution identity
```

The QEMU execution and SIGSEGV observation had succeeded. The controlled QEMU fixture still used the old P1 candidate shape and omitted runtime/launch fingerprints.

Classification: `fixture lag caused by strengthened production fact contract`, not a QEMU execution failure.

Remediation updated the controlled QEMU candidate to carry the same runtime/launch identity required by schema v2 production facts.

## 4. Final executable gate

Final Stage 0 code HEAD:

```text
c9b6b34ec2499232cdcf9dfb38ad8379bd0aed75
```

GitHub Actions:

```text
run: 32054864672
job: 95462571212
conclusion: success
```

Regression:

```text
Base: 220 passed, 7 skipped
CTF: 135 passed in 5.59s
```

Preserved CTF pytest artifact:

```text
artifact: ctf-pytest-log
artifact id: 9296044612
sha256: d6453dd93b823f665f88b13dc5d5e65e7019da4276ab30db312b40d1ec93e2a2
```

The same full workflow passed:

- Base pin and Base regression/invariant probes;
- native runtime-bound P1;
- controlled QEMU user-mode AArch64 P1 with runtime identity in fact candidate;
- admitted RemoteTcpRunner delayed-response + delimiter-overread probe;
- runtime-bound native x86_64 P2;
- runtime-bound sealed P3 local proof;
- P4 environment compatibility;
- P5 remote behavior;
- P6 external completion;
- WP06 hypothesis/dedupe;
- WP07 recovery/progress;
- all existing WP08 evaluation probes.

## 5. Negative controls proven

Stage 0 specifically requires and observed:

```text
P1 candidate runtime tamper                         REJECT
P1 mixed runtime/launch evidence                    REJECT
P2 non-native runtime profile                       REJECT BEFORE EXECUTION
P2 runtime candidate tamper                         REJECT
P3 actor target mutation                            BLOCKED
P3 writable workspace                               REJECT
P3 runtime candidate tamper                         REJECT
Remote unadmitted endpoint                          REJECT
Remote challenge-transport policy denial            REJECT
Remote delayed chunks                               ACCUMULATED WITH BOUNDS
Remote delimiter over-read                          PRESERVED
Remote transcript plaintext persistence             ABSENT
```

## 6. Architecture / logical review

### Authority duplication

**PASS.** No second fact, proof, recovery, or completion authority was introduced. TargetRunner and RemoteTcpRunner remain execution/transport components.

### Semantic inflation

**PASS.** Migrating P2 to TargetRunner did not generalize x86_64 RIP semantics to QEMU/AArch64. Unsupported runtime/semantic combinations fail closed.

### Execution identity loss

**FIXED.** Runtime/launch identities now survive in schema v2 P1/P2/P3 verified candidates rather than existing only in verifier diagnostic details.

### P3 integrity / TOCTOU

**FIXED for actor-controlled workspace mutation.** Accepted P3 requires a read-only workspace and the live negative control demonstrates blocked target mutation.

Operator-side or concurrently mutated external runtime artifacts remain part of the trusted operator/runtime boundary; a future provider that exposes mutable external artifacts must provide equivalent immutability/revalidation rather than weakening this gate.

### Remote delayed-response correctness

**FIXED.** The session now has bounded accumulation and over-read preservation. Pending bytes do not get double-counted in transcript hashes.

### QEMU/virtualization overfitting

**PASS.** No `QemuSystemRunner`, VirtualBox, VMware, or generic VM subsystem was added. New execution environments remain need-driven TargetRunner/provider extensions.

### SolveEngine circular dependency

**REMOVED FROM WP11 EXIT.** WP11 stabilizes the execution/transport contract. Actual SolveEngine wiring belongs to the later SolveEngine stage after Agent foundation exists.

## 7. Remaining empirical items

These are **not** Stage 0 blockers:

```text
actual Dreamhack 103 handout replay through the new execution path
AArch64 P2 semantic verifier
full-system / VM provider when a real case requires it
SolveEngine integration
actual model-driven solve loop
```

They must not be inferred from controlled fixtures.

## 8. Exit decision

```text
P1 runtime-bound fact semantics        PASS
P2 TargetRunner migration              PASS
P3 TargetRunner migration              PASS
P3 actor-controlled runtime sealing    PASS
Remote persistent protocol semantics   PASS
Base / P1-P6 / WP06-WP08 regression    PASS
new truth authority introduced         NO
semantic support overclaimed           NO
```

**Decision:** Stage 0 is complete. The next dependency-safe stage is Agent Foundation: RunIntent/TerminationPolicy, ContextAssembler built on Base context, a minimal capability catalog, typed model decisions, and a Harness-owned AgentController boundary.