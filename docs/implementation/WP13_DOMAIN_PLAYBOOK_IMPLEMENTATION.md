# WP13–WP19 Remaining Roadmap Implementation

## Basis

This implementation follows the evidence-based reuse proposal: preserve the current Harness authority model and absorb only useful operational abstractions from the older prototype.

Core authority remains:

```text
ChallengeManifest / OperationalChallengeRef
→ Harness-owned execution tools / TargetRunner
→ Observation / Evidence
→ Hypothesis (speculative)
→ claim-specific Verifier
→ HarnessState.facts
→ External completion oracle
```

## WP13 — DomainPlaybook + AnalysisSandbox

Implemented:

- advisory `DomainPlaybook` contract (`question / expected_information / capability / pivot`);
- Pwn staged playbook without hard-coded command sequences;
- `SUPPORTED` hypothesis transition as tactical state only;
- playbook projection into governed Agent context;
- challenge/source/tool text explicitly treated as untrusted content;
- separate `AnalysisSandbox` with admitted input copy/hash binding, read-only input, writable work/generated/artifacts, deny-by-default production network;
- `analysis_exec` remains analysis execution only and has no TargetRunner/truth authority.

## Gate A0 — production-model boundary

Implemented:

- bounded JSON-over-stdin/stdout `ExternalProcessModelAdapter`;
- no shell execution;
- timeout/output-size limits;
- environment inheritance disabled by default;
- explicit credential environment forwarding only;
- credential values are not stored in adapter descriptors;
- empirical probe fails closed as `OPEN` when no production adapter command/revision is supplied.

Actual production-provider execution is not claimed by repository CI because CI has no provider credential.

## WP14 — Pwn operational vertical slice

Implemented controlled live wiring fixture:

```text
real x86_64 ELF
→ deterministic Pwn recon
→ AnalysisSandbox payload generation
→ TargetRunner execution
→ observed target behavior
→ external oracle acceptance
```

The fixture proves runtime wiring and authority preservation. It is deliberately not evidence of autonomous model intelligence because the actor is deterministic.

## WP15 — Competition integration

Implemented:

- `CompetitionAdapter` contract;
- native CTFd adapter for metadata/file/submission operations;
- same-origin request scope and rejection of URL credentials;
- `CredentialRef → CredentialResolver → transient SecretHandle`;
- defense-in-depth `SecretRedactor`;
- `InstanceProvider` separated from platform metadata, with static connection provider baseline;
- normalized platform snapshot → `ChallengeManifest` input → existing admission/operational identity path;
- robust `nc host port` / `tcp://...` normalization through existing `RemoteTargetSpec` validation;
- `SubmissionGuard` with manual/confirm/auto mode, budget, candidate hash dedupe and rejected-candidate memory.

Competition data remains platform snapshot/observation only; it does not become a second challenge-identity authority.

## WP16 — need-driven runtime generalization

No speculative full-system VM abstraction was added. Existing TargetRunner provider design remains the runtime extension point. New QEMU-system/VM/browser providers should be added only when a real challenge requires them and can satisfy equivalent runtime identity/isolation contracts.

## WP17 — cross-domain foundation

Implemented:

- `DomainRegistry` for Pwn/Reverse/Crypto/Web/Forensics/Misc advisory playbooks;
- `DomainModuleRegistry` for semantic domain assets;
- existing Pwn claims/verifiers/progress/playbook bound through `PwnDomainModule` without moving or weakening existing verifier authority;
- deterministic bounded cross-domain `ReconDigest`;
- multi-domain low-confidence classification evidence;
- non-authoritative `FlagCandidateExtractor`.

Web/Crypto/Reverse semantic verifiers and real domain E2E solves are not falsely claimed; this stage establishes their common extension contract.

## WP18 — evaluation / ablation foundation

Reuses existing WP08 evaluation infrastructure. Added a deterministic single-factor `AblationPlan` for:

- Playbook;
- AnalysisSandbox;
- semantic verification;
- hypothesis guard;
- typed recovery;
- task progress.

The plan explicitly carries `effectiveness_claim = none_until_empirical_runs`; real model/corpus A/B execution remains empirical work.

## WP19 — optional multi-agent foundation

Implemented only the dependency-safe evidence exchange boundary:

```text
Verified channel
→ already-existing Harness fact required

Tentative channel
→ hypothesis/evidence provenance
```

`EvidenceBus` cannot create Facts or enable completion. Coordinator/parallel solver execution remains optional and should be justified by measured single-agent bottlenecks.

## Verification policy

Mandatory CI must prove:

1. Base regression/invariant probes remain green;
2. CTF regression remains green;
3. controlled Agent foundation remains green;
4. live minimal SolveEngine target execution succeeds;
5. Gate A0 without provider configuration fails closed and remains `OPEN`;
6. live AnalysisSandbox blocks admitted-input mutation and network egress while permitting generated work;
7. live controlled native Pwn vertical reaches external oracle acceptance;
8. all previous Pwn semantic/proof/recovery/evaluation probes remain green.

Final PASS/OPEN decisions are recorded only after the workflow completes.