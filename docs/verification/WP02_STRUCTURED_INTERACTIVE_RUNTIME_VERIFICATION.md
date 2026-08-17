# WP02 — Structured / Interactive Runtime Verification

**Status:** `PASS` for the scoped runtime foundation

## 1. Implemented logic

Core upstream branch `ctf/structured-session-runtime` adds:

- `ExecutionBackend.run_argv()` and `SandboxedArgvToolSpec`.
- argv-preserving Linux namespace execution; legacy `run_shell()` remains compatibility-only.
- backend-owned persistent `ExecutionSession` and `SandboxedSessionToolSpec`.
- session operations: `create/send/read/interrupt/status/close`.
- session IDs bound to exact tool name + backend object.
- ephemeral resume policy: dead/unowned session IDs fail closed rather than being silently recreated.
- persistent namespace root lifetime tied to session lifecycle.

CTF `VerifiedCTFProfile` reuses these exact Core tools/backend objects.

## 2. Evidence verification

**E-WP02-01:** upstream initial CI `32009897033` failed after `_run_shell_unchecked` compatibility was removed. It was restored; this failure is retained as regression evidence.  
**E-WP02-02:** upstream run `32010024066` then passed full Core tests/probes for structured argv.  
**E-WP02-03:** integration run `32012528321`: Core `219 passed, 7 skipped`; Stage02 backend-binding probe `all_passed=true`, generic in-process WRITE/EXTERNAL path blocked.  
**E-WP02-04:** same run executes privileged `stage2_session_namespace_probe.py`; result: `runtime_probe`, interactive I/O true, outside-workspace read blocked, network policy deny, all passed.  
**E-WP02-05:** CTF regression confirms `argv` and `session` specs are the upstream types and are bound to the supplied backend object.

## 3. Appropriateness evaluation

This resolves the roadmap gap without weakening strict isolation. Structured argv removes Actor-controlled shell interpolation from the new path. Long-lived interaction remains owned by the same attested backend rather than a CTF-side in-process session manager.

## 4. Structural logic / truth review

- **Attestation/execution mismatch:** tested and blocked.
- **Filesystem escape:** privileged live probe blocks outside-workspace read.
- **Network denial:** live attestation records DENY boundary.
- **Observation vs truth:** runtime outputs are still observations; no session operation commits facts.
- **Known limitation:** session handles are intentionally ephemeral across process restart. Durable transcript/artifact persistence is separate from live process persistence.

## 5. Truthfulness statement

Proven on Ubuntu 24.04 hosted runner with privileged namespace probe: structured persistent process interaction operates through the attested namespace backend and tested escape paths are blocked.  
Not proven: every kernel/container platform behaves identically, or that GDB/TCP-specific higher-level adapters are already complete.

## 6. Exit gate

- [x] structured argv
- [x] backend-owned persistent sessions
- [x] exact backend binding
- [x] live namespace evidence
- [x] tested workspace read isolation
- [x] unsafe generic in-process strict path blocked

**Decision:** scoped WP02 runtime foundation `PASS`.
