# 03 — Doctor Evidence

Status: **PASS**

## Scope

Provide a read-only preflight diagnostic that detects configuration/runtime readiness problems without changing the machine or Harness state.

## Implemented artifacts

- `src/ctf_harness/doctor/checks.py`
- `src/ctf_harness/doctor/__init__.py`
- Doctor CLI integration through the operator command layer
- `tests/test_doctor.py`

## Checks implemented

- active model profile/provider;
- required model credential or external-process command;
- active competition site/provider and credential reference;
- MCP transport/protocol/auth/allowlist configuration;
- Python runtime and common local analysis commands such as GDB, GCC, strings, QEMU user mode, and Docker.

## Safety / authority evidence

Doctor explicitly performs no:

- software installation;
- configuration mutation;
- paid model request;
- flag submission;
- MCP tool invocation;
- Harness truth-state write.

`DoctorReport.descriptor()` records `mutations_performed=false` and `credential_values_persisted=false`.

## Direct test evidence

`tests/test_doctor.py` verifies:

1. missing model/site credentials produce FAIL and `ready=false`;
2. injected credentials and discovered required tools produce readiness while optional missing tools remain WARN;
3. credential values are absent from the report;
4. an unavailable external-process adapter command fails readiness.

## Final regression evidence

GitHub Actions run `32202024136` completed compile, Base regression, Base invariant probes, CTF regression, and every controlled integration probe successfully. This demonstrates that adding the diagnostic layer did not mutate or bypass the operational runtime paths it inspects.

## Non-claims

Doctor reports configuration/local capability readiness. It is not a substitute for live remote-provider health checks and intentionally avoids side-effecting validation.
