# WP09–WP11 Implementation Review Findings

## Review basis

This document records corrections found by comparing the implementation plan against the actual `implementation/evidence-roadmap` branch, the pinned Base Harness revision, existing P1–P6/WP06–WP08 verification paths, and executable GitHub Actions evidence.

Latest reviewed implementation code gate:

```text
CTF code HEAD: 8ff8f535f31072b643cbeb4bed957b6a09e36f47
Base: doo513/base_harness@75834ac1ecb6c022771c2efee1f19495f356ee76
Actions run: 32045210634
CTF pytest: 129 passed in 5.34s
full verify conclusion: success
```

The roadmap direction remains valid, but several details required correction before implementation could be considered evidence-aligned.

---

# 1. WP09 findings

## F09-01 — Base pin mismatch was real

Confirmed before remediation:

```text
base_harness.lock.json / verify.yml
= 75834ac1ecb6c022771c2efee1f19495f356ee76

pyproject.toml optional base dependency
= 20079ffd90cc063958f084da8286e05f38ccdef0
```

Direction in the plan was correct.

Remediation status: **CLOSED**.

## F09-02 — removing only the Dreamhack workflow was insufficient

The first review focused on the live Dreamhack workflow, but a second temporary push workflow for QEMU acquisition also remained.

This showed that the original WP09 check was too filename-specific.

Remediation:

- removed both temporary push workflows;
- changed the baseline regression to reject workflows marked `temp`/`temporary` generically.

Status: **CLOSED**.

---

# 2. WP10 findings

## F10-01 — ChallengeSpec must not become a second challenge authority

The initial roadmap terminology could be misread as introducing a new full `ChallengeSpec` beside `ChallengeManifest`.

Actual repository evidence showed that `ChallengeManifest + artifact hashes -> manifest_fingerprint` already owns challenge identity.

Corrected contract:

```text
ChallengeManifest
-> OperationalChallengeRef
-> TargetSpec / SolveSpec
```

`OperationalChallengeRef` is a derived binding, not a replacement manifest.

Status: **CLOSED**.

## F10-02 — public construction could still forge the derived reference

The first WP10 implementation used a frozen dataclass but still exposed its normal constructor. That allowed callers to copy/forge challenge identity fields without going through `ChallengeManifest`.

Remediation:

- normal dataclass initialization disabled;
- supported construction path is `OperationalChallengeRef.from_manifest(...)`.

Status: **CLOSED**.

## F10-03 — CredentialRef alone did not close the secret boundary

The first contract had no raw credential value field, but a remote URI could still carry:

```text
tcp://user:secret@host:port
```

or query/path token material.

Remediation:

TCP target endpoints reject:

- URI userinfo;
- path/query/fragment;
- invalid/missing host or port;
- surrounding whitespace.

Status: **CLOSED** for the current TCP target contract.

## F10-04 — Credential resolvers do not exist yet

`CredentialRef` is only a reference model in WP10. The current repository does not yet prove keyring/session resolution.

Therefore documentation must not describe those variants as operational credential integrations.

Status: **OPEN BY DESIGN** until the later competition/credential integration scope.

---

# 3. WP11 findings

## F11-01 — direct target execution was the real blocker

Confirmed pre-WP11 crash behavior:

```text
subprocess.run([exec_path], ...)
```

This could not represent QEMU/loader execution while retaining the challenge ELF as the target identity.

The plan correctly prioritized TargetRunner before Agent Controller.

Status: **CLOSED for the migrated crash path**.

## F11-02 — target identity and runtime identity must remain separate

Implemented separation:

```text
target_sha256
!=
runtime_fingerprint
```

and a concrete launch binds both through `launch_fingerprint`.

Status: **CLOSED for current process-backed runner contracts**.

## F11-03 — QEMU + loader was still insufficient provenance

The first runner draft omitted sysroot tree identity. That would allow runtime libraries to change without changing the apparent runtime identity.

Remediation:

```text
QEMU SHA-256
+ loader SHA-256
+ sysroot tree fingerprint
```

with revalidation immediately before execution inside the Base sandbox helper.

Status: **CLOSED for the current QEMU user-mode profile**.

## F11-04 — rejecting all sysroot symlinks was over-restrictive

A Linux runtime tree can legitimately contain symlinks.

Remediation:

- internal relative symlinks are included in tree identity;
- absolute and tree-escaping symlinks fail closed.

Status: **CLOSED for the supported symlink model**.

## F11-05 — CustomArgvRunner was initially omitted

The roadmap explicitly included a custom argv runner, but the first implementation slice only had native/QEMU.

Remediation:

- added `CustomArgvRunner`;
- launcher executable is hash-bound;
- launcher arguments are immutable profile configuration;
- Actor cannot provide dynamic launcher argv.

Status: **CLOSED**.

## F11-06 — remote transport needed challenge admission, not only network policy

The first remote transport draft took a remote target and network policy but could not prove the endpoint belonged to the admitted challenge.

Remediation:

`RemoteTcpRunner` now requires:

```text
OperationalChallengeRef
+ RemoteTargetSpec
+ NetworkPolicy
```

and rejects unadmitted endpoints or manifest-level network denial.

Status: **CLOSED**.

## F11-07 — remote transport is not P5 truth authority

The operational TCP runner must not make semantic success claims from merely receiving bytes.

Current separation:

```text
RemoteTcpRunner
= challenge transport

existing P5 verifier/oracle
= semantic remote-proof authority
```

Status: **CORRECTLY SEPARATED**.

## F11-08 — controlled QEMU success is not Dreamhack 103 replay

The controlled AArch64 fixture now proves:

```text
QemuUserRunner
-> Base namespace execution
-> SIGSEGV observation
-> crash schema v2
-> P1 verifier
```

but it does not prove the real Dreamhack handout has been replayed through the new path.

The repository does not contain the actual handout bytes required for that replay.

Status: **CONTROLLED PATH PASS / REAL HANDOUT OPEN**.

## F11-09 — full tool migration remains incomplete

The roadmap called for target execution abstraction to be used by more than crash probing.

Current status:

```text
pwn_crash_probe        migrated
pwn_control_probe      existing probe still architecture/direct-execution specific
local proof            existing proof path still has its own execution contract
remote behavior        semantic oracle remains separate; new transport exists but is not SolveEngine-integrated
```

This is why WP11 must remain `PARTIAL`, despite the successful controlled target-execution gate.

Status: **OPEN**.

---

# 4. Current evidence-backed status

```text
WP09  PASS
WP10  PASS
WP11  PARTIAL
```

WP11 controlled capabilities currently demonstrated in one full gate:

```text
NativeRunner                       PASS
CustomArgvRunner                   PASS (contract/tests)
QemuUserRunner                     PASS
native P1 migrated                 PASS
controlled QEMU AArch64 P1         PASS
RemoteTcpRunner                    PASS
existing P2-P6 regressions         PASS
WP06-WP08 regressions              PASS
```

Still open:

```text
actual Dreamhack 103 replay
control-probe execution migration
local-proof execution migration
SolveEngine-facing remote transport integration
final common TargetRunner facade
```

---

# 5. Correct next implementation order

Do not start another benchmark feature and do not declare WP12 complete yet.

Continue inside existing WP11 scope:

```text
1. migrate x86_64 control execution onto target/runtime identity
2. migrate local-proof target execution
3. connect operational remote transport to the future solve-tool boundary
4. replay Dreamhack 103 exact handout when artifact bytes are available
5. close WP11 only after its evidence gate is satisfied
```

Then continue the existing roadmap:

```text
WP12 Harness-owned Agent Controller
-> WP13 SolveEngine
-> WP14 native x86_64 end-to-end vertical slice
```

AArch64 P2 semantic generalization remains later WP15 scope. It should not be pulled forward by weakening or relabelling the current x86_64 verifier.
