# WP07 — CTF Recovery / Progress Verification

**Status:** `PARTIAL` — progress projection integrated, CTF recovery adapter not yet runtime-wired

## 1. Implemented logic

- CTF failure names map to existing Core FailureKind names plus recovery targets; unknown names fail closed.
- `VerifiedCTFProfile.task_progress_snapshot()` derives task milestones from Core `state.facts` and `state.completed`.
- milestones are independent verified facts; no lower milestone is invented merely because a later one exists.

## 2. Evidence verification

**E-WP07-01:** CI `32012528321` tests ENVIRONMENT_MISMATCH→ENV_ERROR and FLAG_REJECTED→return_to_proof; unknown failure rejected.  
**E-WP07-02:** progress test with `arch + remote_behavior` returns only `artifact_profiled + remote_behavior_verified`; no missing milestones are inferred.  
**E-WP07-03:** Core Stage06 probe in same run reports all passed, implicit task authority 0, regressions credited 0, snapshot mutations 0.  
**E-WP07-04:** Core Stage05 A/B/C/D benchmark still reports generic replan and typed-targeted completion rate both 1.0 on recoverable scenarios, with only 1 step + 1 tool-call joint-success savings for typed routing; negative false successes 0. This evidence is intentionally not overstated.

## 3. Appropriateness evaluation

Reusing Core failure/recovery semantics is preferable to a second recovery kernel. Deriving progress from verified Core facts preserves the existing activity/epistemic/task separation.

## 4. Structural logic / truth review

- **Progress authority:** Actor narrative/classification cannot directly grant milestones.
- **Recovery truth:** mapping code alone does not prove recovery effectiveness.
- **Integration gap:** CTF failure adapter is not yet connected to the runtime failure classification path.
- **Empirical gap:** existing Stage05 recovery benchmark is constructed Core evidence, not CTF-corpus evidence.

## 5. Truthfulness statement

Proven: CTF progress projection obeys the tested Core monotonic-authority model and mapping helpers are deterministic/fail-closed.  
Not proven: CTF-specific recovery improves solve rate or cost.

## 6. Exit gate

- [x] CTF→Core failure map
- [x] verified-fact task progress projection
- [x] no inferred milestone chain
- [ ] runtime recovery-adapter integration
- [ ] no-repeat enforcement integrated with hypothesis pool
- [ ] CTF A/B recovery evidence

**Decision:** `PARTIAL`.
