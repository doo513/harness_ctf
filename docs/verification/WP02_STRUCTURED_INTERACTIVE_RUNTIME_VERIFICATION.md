# WP02 — Structured / Interactive Runtime Verification

**Status:** `PASS` for the scoped runtime foundation, including the remediated persistent-read contract

## 1. Implemented logic

Pinned Core commit: `75834ac1ecb6c022771c2efee1f19495f356ee76` on `doo513/base_harness:ctf/structured-session-runtime`.

The upstream operational extension provides:

- `ExecutionBackend.run_argv()` and `SandboxedArgvToolSpec`;
- argv-preserving Linux namespace execution; legacy `run_shell()` remains compatibility-only;
- backend-owned persistent `ExecutionSession` and `SandboxedSessionToolSpec`;
- session operations `create/send/read/interrupt/status/close`;
- exact session-ID binding to tool/backend ownership;
- ephemeral resume policy: stale/dead sessions fail closed rather than being recreated;
- namespace-root lifetime tied to the session lifecycle;
- positive `read(wait_seconds=x)` as a bounded observation window that accumulates output arriving anywhere before the deadline; `wait_seconds=0` remains an immediate non-blocking drain.

`VerifiedCTFProfile` reuses these exact Core tool/backend types; it does not implement a second CTF-side process manager.

## 2. Failure → diagnosis → remediation evidence

### Earlier structured-runtime regressions

- Initial upstream argv refactor removed `_run_shell_unchecked`; compatibility tests/probes failed. The compatibility method was restored and the full Core gate was rerun.
- Existing strict-isolation error-text compatibility also failed once after wording changed; policy was not weakened and compatibility wording was restored.

### Persistent-session race found by downstream integration

CTF integration run `32016757858` failed a Base persistent-session test: a process emitted startup `ready`, then later responded to `ping`, but one `read(wait_seconds=1.0)` observed only `ready`. A later run passed without code changes, so the failure was treated as a nondeterministic race rather than dismissed.

Root cause: the old `PopenExecutionSession.read()` used `wait_seconds` only to wait for the **first** readable fd. Startup output could therefore terminate the read before the delayed command response arrived.

Remediation did **not** add a hidden 20/50 ms quiet heuristic. The existing argument now has explicit semantics: positive `wait_seconds` is the total bounded observation window. The read drains current data, continues observing stdout/stderr until deadline/EOF/byte-limit, and performs a final non-blocking drain at the boundary.

## 3. Upstream validation evidence

Upstream run `32017301630`, tested code SHA `75834ac1ecb6c022771c2efee1f19495f356ee76`:

- full pytest: **220 passed / 7 skipped**;
- Core freeze: PASS, `new_stage_created=false`;
- Stage02 backend/execution binding: PASS;
- privileged live namespace persistent-session probe: PASS;
- `bounded_wait_accumulates_delayed_response=true`;
- interactive I/O true;
- outside-workspace read blocked;
- network policy DENY;
- Stage04/05/06/07/08 probes: PASS.

The regression shape is deterministic: child prints `ready`, receives `ping`, waits 150 ms, then prints `E:ping`; one `read(wait_seconds=0.5)` must contain both while the process is still alive.

Upstream verification record: `docs/tracks/operational-extensions/SESSION_READ_WINDOW_REMEDIATION.md`.

## 4. Downstream re-pin and full-chain validation

`harness_ctf/base_harness.lock.json` and the CI checkout now pin exactly `75834ac1...`.

A first re-pin run failed because `ctf_harness.locking.EXPECTED_BASE_COMMIT` still contained the old reviewed SHA. This was a deliberate freeze-constant failure, not a runtime failure. The reviewed baseline constant was updated only after the upstream remediation gate had passed.

Final downstream stability run `32017690564`:

- exact Base revision check: PASS;
- Base regression: **220 passed / 7 skipped**;
- Base invariant probes: PASS, including the delayed-response live session regression;
- CTF regression: **24 passed**;
- P1 crash: PASS;
- P2 x86_64 RIP control: PASS;
- P3 local proof: PASS;
- P4 target-environment compatibility: PASS;
- P5 remote behavior: PASS;
- P6 Core-integrated external completion: PASS.

## 5. Appropriateness evaluation

The remediation is appropriate because the latency contract is explicit and caller-controlled. A hidden settle/grace delay would remain probabilistic; waiting for EOF would break long-lived sessions. A bounded observation window preserves interactive semantics without making reads unbounded.

The cost is also explicit: a positive wait may consume the full requested window for a still-running session. Higher-level protocol adapters should use framing/completion rules and the smallest suitable window rather than assuming a one-second read is free.

## 6. Structural logic / truth review

### Preserved invariants

- same attested backend object owns persistent execution;
- generic in-process WRITE/EXTERNAL tools remain blocked in strict mode;
- live workspace filesystem isolation remains tested;
- network DENY remains tested;
- session output remains observation, never automatic fact authority;
- session handles remain ephemeral across process restart;
- no Stage09/new Core stage was created.

### Remaining limitations

- a bounded observation window does not prove application-protocol completeness; protocol-specific framing still belongs above the raw session layer;
- long-lived interactive protocols may require multiple reads;
- production evidence is currently Ubuntu 24.04 hosted-runner evidence, not proof for every kernel/runtime/platform.

## 7. Truthfulness statement

**Supported by execution evidence:** structured argv, backend-bound persistent sessions, delayed-response accumulation under a bounded read window, tested namespace workspace isolation and network denial, and downstream P1–P6 compatibility on the pinned SHA.

**Not supported:** universal OS/kernel behavior, arbitrary debugger/protocol correctness, or durable live-session recovery across harness restarts.

## 8. Exit gate

- [x] structured argv
- [x] backend-owned persistent sessions
- [x] exact backend binding
- [x] live namespace evidence
- [x] workspace read isolation
- [x] unsafe generic strict path blocked
- [x] deterministic delayed-response race regression
- [x] exact fixed Base SHA re-pinned downstream
- [x] full CTF P1–P6 regression on remediated SHA

**Decision:** scoped WP02 runtime foundation `PASS`.
