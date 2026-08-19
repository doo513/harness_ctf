# 01 — Configuration & Model Gateway Evidence

Status: **PASS**

## Scope

Provide strict operator configuration and a provider-neutral Model Gateway without changing the existing Agent, Verifier, Kernel, Proof, or completion-oracle authority model.

## Implemented artifacts

- `src/ctf_harness/configuration/models.py`
- `src/ctf_harness/configuration/loader.py`
- `src/ctf_harness/configuration/model_gateway.py`
- `tests/test_configuration_model_gateway.py`
- `config/harness.example.toml`

Supported provider adapters:

- OpenAI Responses
- Anthropic Messages
- Gemini generateContent
- existing external-process ModelAdapter

The gateway only constructs ModelAdapters. Model output is normalized to the existing Decision `{kind, payload}` contract before the existing controller/runtime consumes it.

## Security / authority evidence

- Raw inline secret fields are rejected by configuration parsing.
- Credentials are referenced through environment variables or explicitly scoped external-process environment names.
- Adapter descriptors do not persist credential values.
- Credentialed HTTP redirects are disabled.
- Custom base URLs must be absolute HTTP(S), cannot contain userinfo/query/fragment, and plaintext HTTP is restricted to loopback.
- Provider-specific configuration confusion fails closed.
- Provider error text is redacted before surfacing.
- Model Gateway has no truth, verification, proof, or completion authority.
- Provider `max_tokens` is a per-request output cap; it is not represented as the SolveEngine whole-run token budget.

## Direct test evidence

`tests/test_configuration_model_gateway.py` verifies:

1. inline secret rejection;
2. active-profile selection and environment override;
3. missing credential fail-closed behavior;
4. insecure/credential-bearing custom URL rejection;
5. provider-shape confusion rejection;
6. OpenAI Decision normalization, non-persistence of keys, usage telemetry, output cap, and storage-disabled request shape;
7. Anthropic/Gemini use the same gateway Decision contract;
8. unsupported providers are rejected by an explicit registry.

## Final regression evidence

GitHub Actions run `32202024136` completed successfully after this stage was integrated with all later stages. Base pytest finished `220 passed, 7 skipped`; CTF pytest finished `235 passed`. Agent foundation and SolveEngine probes also passed, demonstrating that the provider abstraction did not replace the existing controller/runtime authority path.

## Non-claims

CI uses controlled/fake model behavior for deterministic verification. A live production-provider credentialed smoke test is external validation and is not claimed by this artifact.
