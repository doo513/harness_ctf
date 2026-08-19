# WP13-WP17 Remaining Implementation Plan

This branch implements the remaining roadmap stages from `harness_ctf_evidence_based_reuse_direction_proposal` while preserving the current Harness authority model.

Implementation order:

1. WP13 DomainPlaybook and tactical progress projection
2. Gate A0 production-model adapter boundary (credential-gated empirical probe)
3. AnalysisSandbox with RO admitted input / RW work split and deny-by-default network
4. WP14 Pwn operational vertical slice probe
5. WP15 CompetitionAdapter, CredentialResolver, InstanceProvider, SubmissionPolicy
6. WP16/17 need-driven runtime/domain registry scaffolding and cross-domain contract

Every stage must retain:

- ChallengeManifest / OperationalChallengeRef as challenge identity authority
- Base ActionRuntime as executable tool authority
- Observation/Hypothesis as non-authoritative tactical state
- verifier-backed HarnessState.facts as semantic truth authority
- external oracle as completion authority

Empirical production-model execution remains OPEN unless a provider credential is supplied at runtime; missing credentials must fail closed rather than silently falling back to a controlled fixture.
