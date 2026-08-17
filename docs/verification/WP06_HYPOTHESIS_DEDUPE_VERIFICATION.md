# WP06 — Hypothesis / Dedupe Verification

**Status:** `PARTIAL`

## 1. Implemented logic

`HypothesisPool` fingerprints category + target + vulnerability class + primitive + evidence digest. It records attempt count, last failure signature and refuted state. Same hypothesis + same failure + unchanged evidence returns `should_repeat=False`; changed evidence permits reconsideration.

## 2. Evidence verification

**E-WP06-01:** CI `32012528321` regression verifies identical failure/evidence is not repeated.  
**E-WP06-02:** a changed evidence digest permits another attempt.  
**E-WP06-03:** refutation moves the hypothesis status to `REFUTED`.

## 3. Appropriateness evaluation

A speculative sidecar is appropriate because dedupe metadata is planning state, not verified truth. The pool does not expose Core fact commit authority.

## 4. Structural logic / truth review

- fingerprint includes evidence digest, reducing accidental reopening without information change.
- current implementation is in-memory only.
- it is not yet wired into AgentRuntime action selection, so no production execution currently enforces `should_repeat`.
- it is not yet synchronized with Core `refuted_hypotheses` persistence/resume.

## 5. Truthfulness statement

Proven: isolated dedupe/refutation logic behaves as tested.  
Not proven: whole-harness repeated-failure rate is reduced.

## 6. Exit gate

- [x] deterministic fingerprint
- [x] same-failure/no-new-evidence guard logic
- [x] refuted status
- [ ] runtime/controller integration
- [ ] durable persistence/resume
- [ ] benchmark repeated-failure metric

**Decision:** `PARTIAL`.
