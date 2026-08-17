# WP10 — Operational Solve Contract Verification

**Status:** `PASS — OPERATIONAL CONTRACT GATE`

## 1. Goal

Define deterministic operational solve contracts that can later be consumed by a TargetRunner, model controller, benchmark adapter, CLI, or competition adapter without creating a second challenge identity authority.

WP10 deliberately does **not** execute targets or call a real model.

---

## 2. Previous Gap

The repository already had a strong admitted challenge identity:

```text
ChallengeManifest
+ artifact hashes
-> manifest_fingerprint
```

and WP08 had experiment/run contracts for benchmark attribution.

What was missing was an operational contract binding:

```text
admitted challenge
+ selected local/remote target
+ model/controller identity
+ solve budget
+ network policy
+ oracle policy
+ output policy
```

for a future actual solve run.

Creating a new `ChallengeSpec` by copying the manifest fields would have introduced a second challenge identity system. WP10 therefore keeps `ChallengeManifest` as the source of truth and derives a thin immutable operational reference from it.

---

## 3. Contract

Added `ctf_harness.operational` with the following contracts.

### `OperationalChallengeRef`

Constructed from an already-valid `ChallengeManifest` plus the exact artifact hash set.

It binds:

- challenge ID;
- challenge revision;
- existing manifest fingerprint;
- canonical `(artifact_ref, sha256)` bindings;
- admitted remote endpoints;
- admitted network policy;
- admitted oracle type;
- benchmark policy.

It does not redefine description/category/tool policy or create a new fingerprint algorithm.

### `CredentialRef`

Carries only:

```text
kind
locator
```

with initial closed kinds:

```text
env
keyring
session
```

There is no raw credential value field in the contract.

### `LocalTargetSpec`

Binds:

```text
artifact_ref
target_sha256
architecture
runtime_kind
runtime_profile_id
```

Initial runtime kinds are closed to:

```text
native
custom_argv
qemu_user
```

The runtime profile identifies how the target will later be executed; it does not replace target identity.

### `RemoteTargetSpec`

Binds:

```text
endpoint
transport
optional CredentialRef
```

The initial transport is TCP.

### `AgentSpec`

Binds provider/model/model-revision/controller-revision identity only. No provider client is implemented in WP10.

### `SolveBudget`

Binds solve-level:

```text
max_steps
max_wall_seconds
optional max_tokens
```

This is intentionally separate from the pinned Base `Budget`. A later SolveEngine adapter must explicitly translate the operational step/wall contract into Base `hard_max_steps` / `hard_wall_seconds`; WP10 does not modify Base.

### `NetworkPolicy`

Separates:

```text
challenge_transport
general_internet
external_retrieval
```

so challenge connectivity is not automatically equivalent to unrestricted Internet access.

### `OraclePolicy`

The initial operational profile remains external-oracle-only and must agree with the admitted challenge manifest.

### `SolveSpec`

Canonical binding of challenge, target, agent, budget, network, oracle, and output policy. Its fingerprint is computed with the existing Base canonical hash function.

---

## 4. Implementation

Added:

```text
src/ctf_harness/operational/__init__.py
src/ctf_harness/operational/models.py
tests/test_operational_models.py
```

Important fail-closed invariants:

1. the artifact hash set used to create an operational challenge ref must exactly equal the manifest artifact set;
2. a local target artifact must be admitted by the challenge manifest;
3. local target SHA-256 must equal the admitted artifact hash;
4. a remote endpoint must appear in the manifest;
5. the manifest must allow network access before a remote target can be used;
6. the solve network policy must explicitly permit challenge transport;
7. solve oracle authority must match the manifest;
8. runtime/transport/credential kinds are typed closed variants rather than arbitrary strings;
9. malformed hashes and non-finite/non-positive budgets are rejected.

---

## 5. Positive Evidence

WP10 implementation code gate:

```text
commit: 702b75c0a6e6f7fca60f276b996026b7946468a9
GitHub Actions run: 32043650906
conclusion: success
```

Preserved CTF pytest artifact:

```text
109 passed in 4.98s
```

The same Actions run also completed successfully for:

- Base pinned revision check;
- Base regression;
- Base invariant probes;
- P1 crash semantic probe;
- P2 x86_64 control-flow probe;
- P3 local-proof probe;
- P4 environment compatibility probe;
- P5 remote behavior probe;
- P6 external flag completion probe;
- WP06 hypothesis/dedupe;
- WP07 recovery/progress;
- all existing WP08 evaluation probes.

---

## 6. Negative Controls

The new tests explicitly reject:

- incomplete artifact hash sets;
- credential construction with an untyped credential kind;
- extra raw credential `value` field construction;
- local target hash mismatch;
- local target referencing a non-admitted artifact;
- remote endpoint not present in the manifest;
- remote target when the manifest disallows network access;
- remote target when solve policy blocks challenge transport;
- non-external initial oracle authority;
- invalid/non-finite budgets;
- raw untyped runtime/transport variants.

They also verify that equivalent contract construction produces the same fingerprint and meaningful runtime/network changes produce different fingerprints.

---

## 7. Regression

**Result: PASS.**

The full gate passed on the exact WP10 code commit. Existing CTF proof/recovery/evaluation authority was not modified.

`ChallengeManifest` and `manifest_fingerprint()` remain the challenge identity source of truth.

---

## 8. Real-world Evidence

No new live target execution is claimed by WP10.

The Dreamhack 103 evidence remains the real-world reason WP11 is necessary, but WP10 only establishes the contract boundary required to represent such a target truthfully.

---

## 9. Unsupported / Open

WP10 does not yet provide:

- Native/QEMU target execution;
- runtime attestation/receipt;
- migrated crash probe;
- Dreamhack 103 registered P1 fact;
- persistent remote session execution;
- real model controller;
- end-to-end solve loop.

---

## 10. Exit Decision

```text
ChallengeManifest authority preserved              PASS
operational challenge identity deterministic       PASS
local target admitted-artifact binding             PASS
remote endpoint/network binding                    PASS
credential values absent from contract             PASS
invalid/unsupported variants fail closed           PASS
SolveSpec deterministic fingerprint                PASS
existing WP00-WP09 regression/probes               PASS
```

**Decision:** `PASS — OPERATIONAL CONTRACT GATE`.

The next code gate is WP11 Target Execution Layer. The first substantive WP11 objective is to move the existing native crash path behind an explicit target/runtime request and then represent the QEMU AArch64 execution path while keeping target identity and runtime identity separate.
