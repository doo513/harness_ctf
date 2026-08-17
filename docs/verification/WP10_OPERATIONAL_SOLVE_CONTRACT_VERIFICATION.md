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

Direct normal dataclass construction is disabled. The supported public construction path is:

```text
OperationalChallengeRef.from_manifest(...)
```

so copied identity fields cannot become a second normal challenge authority.

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

For TCP, the endpoint contract is canonicalized by validation rather than accepting arbitrary URI material. It requires `tcp://`, host, and port, and rejects embedded username/password, path/query/fragment data, invalid ports, or surrounding whitespace. Raw secrets therefore cannot be smuggled into the normal TCP target contract through URI userinfo/query fields.

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
2. normal public construction of `OperationalChallengeRef` is disabled;
3. a local target artifact must be admitted by the challenge manifest;
4. local target SHA-256 must equal the admitted artifact hash;
5. a remote endpoint must appear in the manifest;
6. the manifest must allow network access before a remote target can be used;
7. the solve network policy must explicitly permit challenge transport;
8. solve oracle authority must match the manifest;
9. runtime/transport/credential kinds are typed closed variants rather than arbitrary strings;
10. malformed hashes and non-finite/non-positive budgets are rejected;
11. credential-bearing/token-bearing TCP URI forms are rejected before they enter `SolveSpec`.

---

## 5. Positive Evidence

Initial WP10 implementation code gate:

```text
commit: 702b75c0a6e6f7fca60f276b996026b7946468a9
GitHub Actions run: 32043650906
conclusion: success
CTF pytest: 109 passed in 4.98s
```

WP11 review subsequently found two WP10 hardening issues and remediated them:

1. `RemoteTargetSpec.endpoint` could otherwise be used to carry URI userinfo/query secret material;
2. `OperationalChallengeRef` exposed a normal dataclass constructor even though `ChallengeManifest` was intended to remain the source of truth.

Those fixes were revalidated in the later full code gate:

```text
code HEAD: 8ff8f535f31072b643cbeb4bed957b6a09e36f47
GitHub Actions run: 32045210634
conclusion: success
CTF pytest: 129 passed in 5.34s
```

The same later workflow also preserved all existing Base/P1–P6/WP06–WP08 gates and the new WP11 controlled target-runner probes.

---

## 6. Negative Controls

The current tests explicitly reject:

- incomplete artifact hash sets;
- forged normal `OperationalChallengeRef(...)` construction;
- credential construction with an untyped credential kind;
- extra raw credential `value` field construction;
- credential-bearing TCP URI userinfo;
- TCP URI query/path/fragment token material;
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

The initial WP10 gate passed, and the later WP10-hardening/WP11 combined gate also passed. Existing CTF proof/recovery/evaluation authority was not weakened.

`ChallengeManifest` and `manifest_fingerprint()` remain the challenge identity source of truth.

---

## 8. Real-world Evidence

No live target execution is claimed by WP10 itself.

The Dreamhack 103 evidence remains the real-world reason WP11 is necessary, but WP10 only establishes the contract boundary required to represent such a target truthfully.

---

## 9. Unsupported / Open

WP10 does not itself provide execution. Native/QEMU/remote execution is WP11 scope, the real model controller is later scope, and the end-to-end solve loop is later scope.

`CredentialRef` is a reference contract only. WP10 does not claim that keyring/session resolvers already exist or that a credential reference has been successfully resolved.

---

## 10. Exit Decision

```text
ChallengeManifest authority preserved              PASS
normal forged challenge-ref construction blocked   PASS
operational challenge identity deterministic       PASS
local target admitted-artifact binding             PASS
remote endpoint/network binding                    PASS
credential-bearing TCP URI forms rejected          PASS
credential values absent from normal value field   PASS
invalid/unsupported variants fail closed           PASS
SolveSpec deterministic fingerprint                PASS
existing regression/probes                         PASS
```

**Decision:** `PASS — OPERATIONAL CONTRACT GATE`.

The next active roadmap item remains WP11 Target Execution Layer. The current WP11 status is intentionally tracked separately because its full exit gate requires more than the WP10 contract.
