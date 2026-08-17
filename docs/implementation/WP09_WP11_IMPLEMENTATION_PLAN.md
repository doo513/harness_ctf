# WP09–WP11 Operational Implementation Plan

## Scope

This plan converts the current verified research/runtime infrastructure into the first operational execution slice without weakening the existing Base/CTF verification gates.

Pre-WP09 review baseline:

- branch: `implementation/evidence-roadmap`
- reviewed HEAD: `db83730d06c907e59f53b2f10b3def248ee9e03b`
- pinned Base lock/CI revision: `75834ac1ecb6c022771c2efee1f19495f356ee76`
- latest reviewed full verify run: `32042968611` — success
- CTF regression artifact from that run: `92 passed in 4.97s`

The implementation order remains:

```text
WP09 Operational Baseline Freeze
  -> WP10 Operational Solve Contracts
  -> WP11 Target Execution Layer
  -> Dreamhack 103 P1 registered through normal Harness evidence/fact flow
```

No new numbered Base stage is introduced.

---

# Review corrections to the roadmap

## C1 — ChallengeManifest remains canonical

The operational layer must not create a second challenge identity system. Existing `ctf_harness.manifest.models.ChallengeManifest` remains the canonical challenge metadata/admission identity.

If an operational `ChallengeSpec` name is used, it must be a thin binding/reference to the admitted manifest and fingerprint, not a duplicate copy of challenge ID/revision/artifacts/endpoints/policy fields.

Recommended separation:

```text
ChallengeManifest          = admitted challenge identity / policy source of truth
OperationalChallengeRef    = manifest fingerprint + selected runtime bindings
TargetSpec                  = how a selected target is reached/executed
SolveSpec                   = challenge ref + target + agent/budget/network/oracle/output policy
CredentialRef              = secret locator only; never raw secret material
```

## C2 — TargetRunner must preserve Base execution authority

`CrashProbeBackend` currently delegates into the Base sandbox backend, but its helper then executes the target as `subprocess.run([exec_path], ...)`. That direct target argv is the concrete blocker for QEMU/loader execution.

WP11 must not fix this by introducing an unrestricted subprocess path in the Harness process. Target execution must remain behind the existing Base execution/isolation boundary and retain `IsolationAttestation`/tool receipt provenance.

The runner layer therefore composes an attested target argv/runtime description and executes it through the delegated Base backend.

## C3 — Target identity and runtime identity are separate

For a QEMU user-mode case:

```text
target identity  = challenge ELF SHA-256
runtime identity = QEMU SHA-256 + loader SHA-256 + sysroot fingerprint + argv/env descriptor
```

The verifier must continue to bind the actual challenge binary as the target. Emulator identity is execution provenance, not replacement target identity.

## C4 — WP11 is implemented in two slices without adding a new WP

First slice:

```text
NativeRunner
CustomArgvRunner
QemuUserRunner
ExecutionReceipt/runtime attestation
crash-probe migration
```

Second slice, still inside WP11:

```text
RemoteTcpRunner / session transport
```

This keeps the first exit gate focused on the already observed Dreamhack 103 blocker while preserving the roadmap requirement that remote transport exists before the later end-to-end milestone.

## C5 — Existing crash verifier semantics should remain narrow

`CrashReproducibleVerifier` currently proves:

```text
same target SHA
+ same input SHA
+ same terminating signal
+ independent registered observations
```

WP11 should extend the crash observation schema with runtime provenance in a backward-compatible/new-version manner, but it must not weaken this semantic condition or relabel external notes as Harness facts.

---

# WP09 — Operational Baseline Freeze

## Goal

Freeze a reproducible, non-live-dependent repository baseline before operational contracts are added.

## Confirmed gaps

### G09-01 — Base dependency mismatch

Before WP09:

```text
base_harness.lock.json / verify.yml
= 75834ac1ecb6c022771c2efee1f19495f356ee76

pyproject.toml optional `base`
= 20079ffd90cc063958f084da8286e05f38ccdef0
```

This permits a user installation to differ from the Base revision used by the evidence gate.

### G09-02 — live Dreamhack push workflow

A temporary `.github/workflows/dh103-leak-temp.yml` ran against an ephemeral Dreamhack endpoint on branch push. It is useful historical smoke evidence but is not suitable as a permanent CI dependency.

### G09-03 — repository policy was not self-enforcing

The CI checkout matched the lock, but there was no regression test binding the package optional dependency to the same lock revision.

## Implementation tasks

### T09-01 — Align package dependency

Files:

- `pyproject.toml`
- `base_harness.lock.json` (source of truth; no revision change required)

Requirement:

```text
optional dependency package/repository/commit == lock package/repository/commit
```

### T09-02 — Remove temporary live push dependency

Delete:

- `.github/workflows/dh103-leak-temp.yml`

Preserve historical evidence only in WP08 documentation/run records.

A future real challenge smoke runner must be explicit/operator-triggered and must not become a required deterministic CI gate.

### T09-03 — Add repository baseline invariant tests

Add tests that fail when:

1. optional Base dependency differs from the lock;
2. `verify.yml` checks out a Base repository/revision different from the lock;
3. permanent verify workflow contains the known Dreamhack live endpoint;
4. the temporary push workflow returns.

### T09-04 — Record pre/post baseline evidence

Record:

- pre-WP09 HEAD and successful verify run;
- WP09 code HEAD;
- Base regression gate result;
- CTF regression count/result;
- all existing P1–P6/WP06/WP07/WP08 probes;
- absence of required live endpoint execution.

## Negative controls

The baseline policy must fail closed if a fixture/change introduces:

- a different Base commit in `pyproject.toml`;
- a different Base checkout ref in `verify.yml`;
- the Dreamhack endpoint into the permanent verify workflow.

## Exit gate

```text
Base package/lock/CI pin consistency      PASS
Base regression                           PASS
CTF regression                            PASS
existing controlled P1-P6 probes          PASS
WP06/WP07/WP08 probes                      PASS
permanent live endpoint dependency         NONE
```

WP10 starts only after this gate is green.

---

# WP10 — Operational Solve Contracts

## Goal

Define stable operational contracts consumed later by CLI/API/benchmark/controller without duplicating existing manifest/admission authority.

## Design boundary

Do not modify Base kernel contracts for CTF convenience.

Do not move CLI concerns into these models.

## Proposed module layout

```text
src/ctf_harness/operational/
  __init__.py
  models.py
  fingerprint.py

 tests/
  test_operational_models.py
```

`operational` is preferred over `cli` or `solver` at this stage because the first deliverable is contract identity, not a controller implementation.

## Core models

### OperationalChallengeRef

Minimum fields:

```text
manifest_fingerprint
challenge_id
challenge_revision
```

Construction should require an already-valid `ChallengeManifest`; challenge ID/revision are copied only as consistency guards, not independent authority.

### CredentialRef

Allowed forms should initially be explicit and closed, for example:

```text
env:<NAME>
keyring:<service>/<name>   # only when a resolver exists
session:<key>              # only when a session store exists
```

WP10 should implement only reference validation/serialization. It must not resolve secrets inside model objects.

### LocalTargetSpec

Minimum fields:

```text
artifact_ref
target_sha256
runtime_kind
runtime_config
```

The target digest identifies challenge code/data. Runtime config must not overwrite target identity.

### RemoteTargetSpec

Minimum fields:

```text
endpoint
transport
credential_ref optional
```

No raw cookie/token/password field is allowed.

### TargetSpec

A tagged/closed union over supported target forms. Unknown target/runtime kinds fail closed.

### AgentSpec

Identity only at WP10:

```text
provider
model_id
model_revision
controller_revision
```

Do not add actual provider clients in WP10.

### SolveSpec

Binds:

```text
OperationalChallengeRef
TargetSpec
AgentSpec
budget policy
network policy
oracle policy
output policy
```

The object must have deterministic canonical serialization/fingerprint.

## Validation rules

At minimum:

1. empty IDs/revisions rejected;
2. malformed SHA-256 rejected;
3. raw credential-like fields are not accepted by schemas;
4. remote target is rejected when network policy forbids challenge transport;
5. target artifact reference must belong to the admitted manifest when built from that manifest;
6. duplicated challenge identity conflicting with the manifest is rejected;
7. unsupported target/runtime kind rejected;
8. non-deterministic mappings are canonicalized before fingerprinting.

## Tests

### Contract tests

- valid manifest -> `OperationalChallengeRef`;
- deterministic fingerprints;
- equivalent construction order -> same fingerprint;
- changed target/runtime/policy -> changed fingerprint;
- invalid digest -> reject;
- challenge ID/revision mismatch -> reject;
- raw credential value field -> impossible/not accepted;
- unsupported transport/runtime -> reject.

### Integration test

Build one SolveSpec from an existing admitted fixture and prove it can be consumed by a trivial no-execution adapter without changing the `ChallengeManifest` fingerprint.

## Exit gate

```text
existing ChallengeManifest authority preserved       PASS
operational contracts deterministic                  PASS
credential values absent from contracts              PASS
invalid/unsupported variants fail closed             PASS
existing WP00-WP09 regression                        PASS
```

No CLI and no real model call are part of WP10.

---

# WP11 — Target Execution Layer

## Goal

Make target execution/runtime provenance explicit so native and non-native targets can enter the same evidence path without bypassing Base sandbox authority.

## Confirmed blocker

Current crash helper executes:

```python
subprocess.run([exec_path], ...)
```

Therefore it cannot truthfully represent:

```text
qemu-aarch64-static
  -> musl loader
  -> challenge ELF
```

while preserving separate runtime and target identities.

## Proposed module layout

```text
src/ctf_harness/target/
  __init__.py
  models.py
  runners.py
  receipts.py

 tests/
  test_target_models.py
  test_target_runner_native.py
  test_target_runner_qemu.py
```

## Execution model

### TargetExecutionRequest

Minimum fields:

```text
target artifact/ref + target SHA-256
input bytes identity
runtime descriptor
argv descriptor
timeout
environment descriptor
```

### RuntimeDescriptor

Closed variants:

```text
native
custom_argv
qemu_user
remote_tcp   # second WP11 slice
```

### ExecutionReceipt

Minimum durable fields:

```text
schema_version
kind
target_sha256
runtime_fingerprint
input_sha256
argv_descriptor
isolation_attestation reference/fingerprint
returncode
signal
timed_out
stdout_sha256
stderr_sha256
```

Where appropriate, stdout/stderr bytes remain artifact-backed rather than embedded into trusted claims.

## Runner authority rule

A TargetRunner does not own arbitrary process execution.

Expected shape:

```text
TargetRunner
  -> validate TargetExecutionRequest
  -> construct fixed runtime argv
  -> delegated Base execution backend
  -> receive ExecutionResult + isolation provenance
  -> build canonical ExecutionReceipt
```

No `shell=True` and no unrestricted Agent-provided command string.

## Slice 1 — process-backed runners

### NativeRunner

Equivalent to the current direct target behavior but through the new request/receipt contract.

### CustomArgvRunner

Allows a fixed executable prefix/template only when all executable/runtime paths are admitted and hashed.

It is not an arbitrary shell escape hatch.

### QemuUserRunner

Binds at minimum:

```text
qemu executable SHA-256
loader SHA-256 when used
sysroot fingerprint
challenge target SHA-256
fixed argv construction
```

The target remains the challenge ELF.

## Crash probe migration

Replace the hard-coded direct `[exec_path]` execution assumption with a target-runtime request.

Compatibility strategy:

1. preserve existing native crash fixture behavior;
2. introduce a new observation schema version or explicitly backward-compatible runtime fields;
3. update parser/verifier only to validate new provenance, never to weaken reproducibility semantics;
4. keep `same target + same input + same signal + independent artifacts` as the P1 truth condition.

## Dreamhack 103 gate

The actual handout runtime path must be representable as:

```text
QemuUserRunner
+ supplied loader/sysroot
+ challenge ELF target identity
```

The same overflow input must produce two independently registered crash observations with the same terminating signal.

Required flow:

```text
TargetExecutionRequest
 -> Base-backed QemuUserRunner
 -> ExecutionReceipt / pwn_crash_probe observation
 -> registered evidence artifact
 -> CrashReproducibleVerifier
 -> HarnessState verified fact
```

External smoke notes alone do not satisfy this gate.

## Slice 2 — RemoteTcpRunner

Implement after native/QEMU migration is green.

Requirements:

- explicit endpoint from `RemoteTargetSpec`;
- network policy check before connection;
- challenge transport distinguished from general Internet access;
- persistent session lifecycle where needed;
- transcript/evidence hashes;
- no credentials exposed to the model or persisted in observation artifacts.

## Negative controls

Must reject or fail closed on:

1. target path escaping workspace;
2. target digest mismatch;
3. QEMU/runtime binary digest mismatch;
4. loader/sysroot mismatch;
5. unsupported architecture/runtime combination;
6. arbitrary shell metacharacter/string injection paths;
7. timeout presented as crash;
8. changed target/input/signal presented as reproducible P1;
9. un-attested execution presented as verified runtime evidence.

## Exit gate

First process slice:

```text
native x86_64 crash fixture through new runner        PASS
QEMU AArch64 crash fixture through new runner         PASS
existing native P1 semantics unchanged                PASS
runtime/target identity separately bound              PASS
Base isolation/execution authority preserved          PASS
```

WP11 final gate:

```text
Dreamhack 103 reproducible SIGSEGV registered as normal Harness evidence/fact   PASS
remote target transport contract operational                                  PASS
all previous regression/probes                                                 PASS
```

---

# Commit / evidence discipline

Each WP should use separate implementation and verification commits where practical.

For every WP report record:

1. Goal
2. Previous Gap
3. Contract
4. Implementation
5. Positive Evidence
6. Negative Control
7. Regression
8. Real-world Evidence, if any
9. Unsupported
10. Exit Decision (`PASS`, `PARTIAL`, `FAIL`)

A WP is not marked `PASS` from code review alone. The branch HEAD must have a successful full evidence gate corresponding to the implementation under review.
