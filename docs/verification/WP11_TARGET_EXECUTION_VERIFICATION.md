# WP11 — Target Execution Layer Verification

**Status:** `PARTIAL — TARGET EXECUTION CORE PASS / FULL MIGRATION + DREAMHACK 103 REPLAY OPEN`

## 1. Goal

Remove the host-native direct-execution assumption from the operational Pwn path and establish explicit, evidence-bound target/runtime execution for native, fixed-launcher, QEMU user-mode, and remote TCP targets.

WP11 must preserve two distinct identities:

```text
target identity  = challenge target bytes
runtime identity = executable/runtime environment used to run that target
```

It must also preserve the existing Base execution/isolation authority for process-backed probes rather than introducing an unrestricted subprocess path in the Harness process.

---

## 2. Previous Gap

Before WP11 the crash helper executed:

```python
subprocess.run([exec_path], ...)
```

inside its fixed helper.

That worked for a host-native ELF, but it could not truthfully represent:

```text
qemu-aarch64-static
-> optional sysroot / loader
-> challenge ELF
```

without either changing target identity to the emulator or bypassing the existing evidence path.

The Dreamhack 103 smoke case had already demonstrated the practical consequence: an AArch64 SIGSEGV and LR/PC control were physically observed externally, but the current Harness could not register that P1 execution through its normal crash tool path.

---

## 3. Contract

### 3.1 RuntimeLaunch

Added an immutable launch boundary that binds:

```text
profile_id
runtime_kind
exact argv
target_sha256
runtime artifacts
runtime args
```

with two hashes serving different purposes:

```text
runtime_fingerprint
= runtime profile/artifact identity only

launch_fingerprint
= target_sha256 + runtime_fingerprint + exact argv
```

The target SHA is deliberately excluded from the runtime descriptor so emulator/runtime identity cannot replace challenge identity.

### 3.2 Process-backed runner profiles

Implemented:

```text
NativeRunner
CustomArgvRunner
QemuUserRunner
```

`CustomArgvRunner` is not an arbitrary command runner. Its launcher executable SHA-256 and fixed argument tuple are configured in the registered profile; the Actor may not supply extra launcher arguments at execution time.

`QemuUserRunner` binds:

```text
QEMU executable SHA-256
optional sysroot tree fingerprint
optional loader SHA-256
fixed QEMU / loader args
target SHA-256 separately
```

The sysroot tree fingerprint covers regular-file content plus safe internal relative symlink identity. Absolute or tree-escaping symlinks fail closed because their referents would sit outside the tree fingerprint's authority.

### 3.3 Crash schema v2

The crash probe now accepts:

```text
[target, input_b64]
```

for backward-compatible default native execution, or:

```text
[target, input_b64, registered_runtime_profile_id]
```

for an explicitly registered runtime.

Schema v2 records/binds:

```text
target_sha256
input_sha256
runtime descriptor
runtime_fingerprint
launch argv
launch_fingerprint
return code
signal
timeout
stdout/stderr hashes
```

The helper re-validates the target and runtime artifacts immediately before `subprocess.run(..., shell=False)` inside the delegated Base sandbox execution path.

### 3.4 Crash verifier compatibility

`CrashReproducibleVerifier` accepts legacy schema v1 and runtime-bound schema v2 without weakening P1 semantics.

The P1 truth condition remains:

```text
same target
+ same input
+ same terminating signal
+ independent registered observations
```

For schema v2, reproduced observations must additionally have the same runtime and launch fingerprints. Mixing v1 and v2 observations fails closed.

### 3.5 RemoteTcpRunner

Added an operational TCP transport distinct from the existing P5 semantic oracle.

Construction requires:

```text
OperationalChallengeRef
+ admitted RemoteTargetSpec
+ NetworkPolicy(challenge_transport=True)
```

It therefore rejects an endpoint not present in the admitted manifest or a challenge whose manifest disallows network access.

The runner resolves the admitted hostname once, pins the numeric IPv4/IPv6 set, connects only to those addresses, bounds per-action send/read sizes, and emits transcript receipts containing hashes/counts rather than persisted plaintext request/response bodies.

This is challenge transport, not general Internet authority and not P5 success authority.

---

## 4. Implementation

Added/changed:

```text
src/ctf_harness/target/__init__.py
src/ctf_harness/target/models.py
src/ctf_harness/target/runners.py
src/ctf_harness/target/remote.py
src/ctf_harness/tools/crash.py
src/ctf_harness/verifiers/pwn/crash.py

tests/test_target_runners.py
tests/test_crash_target_runtime.py
tests/test_remote_target_runner.py

scripts/target_runner_qemu_probe.py
scripts/target_runner_remote_tcp_probe.py
.github/workflows/verify.yml
```

The verification workflow now installs `qemu-user-static` for the controlled AArch64 execution probe.

---

## 5. Review defects found and remediated during implementation

### R11-01 — QEMU executable alone was insufficient provenance

The first runner draft bound QEMU and loader but did not bind a sysroot tree. This could allow library content to change while the apparent runtime profile stayed stable.

Remediation:

```text
sysroot_relpath
+ sysroot_fingerprint
```

were added, with the fingerprint rechecked again inside the crash helper before target execution.

### R11-02 — rejecting every sysroot symlink was over-restrictive

The first tree fingerprint rejected all symlinks. That is unnecessarily incompatible with ordinary Linux runtime trees.

Remediation:

- internal relative symlink identity is hashed;
- absolute symlinks fail closed;
- relative symlinks escaping the runtime tree fail closed.

### R11-03 — remote target admission was initially too weak

The first `RemoteTcpRunner` accepted a `RemoteTargetSpec` plus policy, but that object alone did not prove that the endpoint came from the admitted challenge manifest.

Remediation:

`OperationalChallengeRef` is now mandatory, and the runner rechecks:

```text
endpoint in admitted remote_endpoints
allowed_network == true
challenge_transport == true
```

before DNS resolution/connection.

### R11-04 — CustomArgvRunner was missing from the roadmap implementation

The initial WP11 slice covered native/QEMU but omitted the planned fixed custom-launcher case.

Remediation:

`CustomArgvRunner` was added with a hash-bound launcher and immutable fixed args. It cannot accept dynamic Actor-supplied command arguments.

### R11-05 — WP10 secret boundary had an endpoint-string hole

During WP11 review, a `RemoteTargetSpec` could theoretically carry raw URI userinfo/query material such as credential-bearing endpoint strings even though `CredentialRef` had no raw value field.

This is a WP10 contract defect discovered during WP11 and was remediated in the operational models. TCP target endpoints now reject embedded username/password, path/query/fragment token material, missing hosts, invalid ports, and surrounding whitespace.

### R11-06 — OperationalChallengeRef could be manually constructed

The first WP10 dataclass exposed a normal constructor, which meant callers could create copied challenge identity fields without going through `ChallengeManifest`.

Remediation:

normal dataclass initialization was disabled. The supported public construction path is now `OperationalChallengeRef.from_manifest(...)`, preserving `ChallengeManifest + artifact hashes` as the operational challenge source of truth.

---

## 6. Positive Evidence

Final reviewed code gate:

```text
branch: implementation/evidence-roadmap
code HEAD: 8ff8f535f31072b643cbeb4bed957b6a09e36f47
GitHub Actions run: 32045210634
conclusion: success
CTF pytest: 129 passed in 5.34s
```

The exact same workflow passed:

- Base pinned revision check;
- compile/install/pip check;
- Base regression;
- Base invariant probes;
- CTF pytest regression;
- live native P1 crash semantic probe through the migrated crash path;
- controlled QEMU AArch64 crash runner probe;
- controlled operational remote TCP runner probe;
- existing x86_64 P2 control-flow probe;
- existing P3 local-proof probe;
- existing P4 environment compatibility probe;
- existing P5 remote-behavior probe;
- existing P6 external completion probe;
- WP06 hypothesis/dedupe;
- WP07 recovery/progress;
- all existing WP08 evaluation probes.

### Controlled QEMU AArch64 probe

The controlled QEMU probe builds a minimal AArch64 `ET_EXEC` fixture without a cross-compiler. The guest performs a deterministic NULL dereference.

The probe then executes the target twice through:

```text
QemuUserRunner
-> migrated pwn_crash_probe
-> Base LinuxNamespaceSandboxBackend
-> registered observations
-> CrashReproducibleVerifier
```

and requires both executions to expose guest `SIGSEGV` as signal 11 with the same runtime/launch identity.

This is executable evidence that the new path is not merely a data-model abstraction.

### Controlled remote TCP probe

The controlled remote probe verifies:

```text
admitted local TCP endpoint
-> DNS/IP pin
-> open
-> send
-> read
-> close
-> transcript receipt hashes
```

and separately confirms that blocked challenge transport and an unadmitted endpoint are rejected.

---

## 7. Negative Controls

Current WP10/WP11 tests and probes fail closed on, among other cases:

- target path escape;
- target SHA mismatch;
- mutated custom launcher;
- malformed/dynamic custom fixed args;
- QEMU SHA mismatch;
- sysroot tree mutation;
- unsupported/escaping sysroot symlink;
- loader SHA mismatch;
- unregistered runtime profile;
- crash runtime/launch fingerprint tampering;
- mixing crash evidence from different runtime identities;
- timeout presented as a reproduced crash;
- unadmitted remote endpoint;
- manifest network denial;
- solve challenge-transport denial;
- credential-bearing TCP endpoint URI;
- persisted transcript plaintext in the receipt contract;
- oversized remote send/read action;
- use of a closed remote session.

---

## 8. Regression

**Result: PASS for the current branch code gate.**

The WP11 code did not weaken existing P1 truth criteria and the same full workflow preserved the previous Base, P2–P6, WP06, WP07, and WP08 gates.

The current regression count is:

```text
129 passed in 5.34s
```

---

## 9. Real-world Evidence

The repository retains the prior Dreamhack 103 smoke report showing external AArch64 crash/control observations, but the actual handout bytes are not committed into this repository.

Therefore this WP11 implementation did **not** fabricate a real Dreamhack replay from documentation-only hashes/notes.

Current distinction:

```text
controlled QEMU AArch64 P1 through normal Harness path = PASS
actual Dreamhack 103 P1 replay through normal Harness path = OPEN
```

A real WP11 Dreamhack gate requires the exact handout artifacts/runtime inputs to be supplied to the target runner and two crash observations to be registered and verified through the production path.

---

## 10. Remaining WP11 scope

The following roadmap items remain open:

1. replay the actual Dreamhack 103 handout through `QemuUserRunner` and register P1 through normal Harness evidence/fact flow;
2. migrate the current x86_64 control probe onto the same target/runtime execution abstraction without pretending QEMU/AArch64 P2 is already supported;
3. migrate the current local-proof execution path onto the target/runtime abstraction;
4. integrate the new operational remote transport with the later solve/runtime tool boundary rather than leaving it as an independently callable transport class;
5. converge the process-launch and remote-session APIs into the final common TargetRunner/SolveEngine-facing facade if that remains useful after the controller contract is implemented.

AArch64 P2 semantic verification remains WP15 work and must not be folded into WP11 with a generic verifier fallback.

---

## 11. Exit Decision

### Process/transport core gate

```text
NativeRunner                                      PASS
CustomArgvRunner                                  PASS
QemuUserRunner                                    PASS
separate target/runtime identity                  PASS
runtime artifact revalidation                     PASS
native P1 migrated to runtime-bound schema        PASS
controlled QEMU AArch64 P1                        PASS
RemoteTcpRunner admitted transport                PASS
Base process-isolation authority preserved        PASS
existing regression/probes                        PASS
```

### Full roadmap WP11 gate

```text
actual Dreamhack 103 P1 registered                OPEN
pwn_control_probe runner migration                OPEN
local-proof runner migration                      OPEN
SolveEngine-facing transport integration          OPEN
```

**Decision:** `PARTIAL — TARGET EXECUTION CORE PASS / FULL WP11 EXIT GATE OPEN`.

The correct next action is to finish the remaining WP11 migration and replay the exact Dreamhack handout when those artifacts are available. WP12 Agent Controller should not be declared complete before that execution boundary is stable.
