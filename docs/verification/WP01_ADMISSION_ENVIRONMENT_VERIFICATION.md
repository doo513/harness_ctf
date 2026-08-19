# WP01 — Admission / Environment Verification

**Status:** `PARTIAL` — admission identity PASS, reproducible runner artifact OPEN

## 1. Implemented logic

- `ChallengeManifest` requires challenge/event/revision and a `sha256:<64hex>` runner digest.
- artifact references/endpoints/tools must be unique.
- `manifest_fingerprint()` requires the artifact-hash key set to exactly equal manifest artifact refs; missing/extra artifacts fail closed.
- artifact admission rejects symlinks/non-regular files, uses `O_NOFOLLOW` where available, reads an opened fd, hashes admitted bytes and can enforce expected SHA-256.
- `EnvironmentFingerprint` records runner digest, machine/system/Python, network mode and canonical tool inventory.

## 2. Evidence verification

**E-WP01-01:** CTF CI `32012528321` passes tests for deterministic manifest fingerprint and missing-hash rejection.  
**E-WP01-02:** changed artifact bytes fail expected-hash admission.  
**E-WP01-03:** symlink admission is rejected.  
**E-WP01-04:** unfrozen runner identifier such as `latest` is rejected by manifest model.  
**E-WP01-05:** equivalent tool inventories produce the same environment digest.

## 3. Appropriateness evaluation

Admission establishes identity before reasoning. Requiring exact artifact sets prevents a manifest fingerprint from silently ignoring an input. Rejecting symlinks also removes an avoidable path-identity ambiguity.

## 4. Structural logic / truth review

- **Logical consistency:** fingerprint is deterministic for the serialized inputs it receives.
- **Truth boundary:** a file path can change after admission; the durable truth is the admitted byte hash, not continuing path identity. Downstream code must use/hash-bind admitted bytes.
- **TOCTOU:** admission hashes one opened descriptor, so the recorded digest describes bytes actually read. It is not a filesystem immutability guarantee after close.
- **Environment truth gap:** schema requires a runner digest, but this repository has not yet produced and frozen a benchmark runner image. Therefore environment reproducibility is not yet demonstrated end-to-end.

## 5. Truthfulness statement

Proven: manifest/artifact/environment identity functions fail closed for tested malformed or incomplete identities.  
Not proven: rebuilding the same CTF runner produces the same image, nor that benchmark machines are yet bound to a published image digest.

## 6. Exit gate

- [x] exact artifact set required
- [x] artifact tamper mismatch blocked
- [x] symlink admission blocked
- [x] deterministic environment descriptor
- [ ] runner image built and digest frozen
- [ ] benchmark runner launch bound to that digest

**Decision:** `PARTIAL`.
