# Operational Readiness Evidence Index

Status: **PASS — implementation and repository CI verified**

Verification code commit: `e1a64902c39a05d6f954c74981467f63b4f80d85`

Verification run: GitHub Actions `verify` run `32202024136`, job `95917655734`.

The operational-readiness work was implemented in dependency order and reviewed after each stage. These artifacts record what was implemented, which authority boundaries were preserved, what direct tests cover the stage, and what the final repository regression gate demonstrated.

## Evidence set

1. [Configuration & Model Gateway](01_CONFIGURATION_MODEL_GATEWAY_EVIDENCE.md)
2. [Site Access Logic](02_SITE_ACCESS_EVIDENCE.md)
3. [Doctor](03_DOCTOR_EVIDENCE.md)
4. [MCP Logic](04_MCP_EVIDENCE.md)
5. [Operator Interface](05_OPERATOR_INTERFACE_EVIDENCE.md)
6. [Integration Review & Regression Gate](06_INTEGRATION_REVIEW_EVIDENCE.md)

## Final regression evidence

- Base Harness pytest: `220 passed, 7 skipped`.
- CTF Harness pytest: `235 passed`.
- Base invariant probes: PASS.
- Agent foundation, SolveEngine, AnalysisSandbox, Pwn operational vertical: PASS.
- Competition remote TCP SolveEngine vertical: PASS (`model_calls=5`, `tool_calls=4`, external-oracle completion only, general Internet disabled).
- Crypto/Reverse controlled verticals: PASS.
- Pwn crash/control/local-proof/environment/remote-behavior/flag-completion/recovery probes: PASS.
- QEMU AArch64 and operational remote TCP runner probes: PASS.
- Evaluation arm/integrity/corpus/executor/runtime probes: PASS.

## Authority statement

This evidence establishes **operational integration and regression readiness**, not CTF solve-rate improvement. Deterministic CI does not exercise a paid production LLM or fresh private challenge corpus, and the evaluation probes intentionally continue to report `effectiveness_measured=false` where applicable.
