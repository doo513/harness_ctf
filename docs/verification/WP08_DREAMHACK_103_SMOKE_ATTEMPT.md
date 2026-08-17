# WP08 — Dreamhack Challenge 103 Smoke Benchmark Attempt

**Status:** `BLOCKED BEFORE ADMISSION — NO BENCHMARK RESULT RECORDED`

## Purpose

Attempt to use Dreamhack Wargame challenge `103` as a first real-world smoke input for the WP08 evaluation path.

This is **not** counted as the fresh/private Pwn pilot benchmark. Dreamhack challenge 103 is a public wargame challenge, and no freshness/private-corpus claim is made.

## Input supplied

- Challenge URL: `https://dreamhack.io/wargame/challenges/103`
- An authenticated Dreamhack session value was supplied out-of-band in the conversation.
- The session value is intentionally **not persisted** in this repository, document, workflow, artifact, or benchmark manifest.

## Attempted acquisition

1. Direct public page retrieval through the available web fetch path returned HTTP 405 for the challenge detail URL.
2. Public web indexing exposed Dreamhack challenge-list pages but did not expose challenge 103 detail/artifact/VM metadata.
3. The local work container could not resolve `dreamhack.io` through external DNS, so an authenticated `requests/curl` path could not be used.
4. The available web fetch interface does not support attaching the supplied Dreamhack session cookie.
5. No connected browser-automation plugin capable of applying the authenticated session was available.

## Why the benchmark was stopped

WP08 admission requires the actual challenge manifest/artifact bytes and, for a remote proof run, the exact authorized challenge endpoint. None was acquired through an authenticated execution path.

The following were therefore **not fabricated or substituted**:

- challenge title/category;
- downloadable handout bytes;
- artifact SHA-256 values;
- VM host/port;
- external flag-oracle response;
- Minimal/Verified outcome records.

Public writeups or search-derived solutions were not used as a replacement input because that would contaminate the intended smoke evaluation and would not prove that the harness solved the supplied challenge.

## Result

```text
challenge_admitted = false
minimal_arm_executed = false
verified_arm_executed = false
independent_adjudication = false
benchmark_result_recorded = false
effectiveness_measured = false
```

## Unblocking condition

Any one of the following is sufficient to resume the smoke benchmark without exposing the session token:

1. provide/upload the Dreamhack challenge handout downloaded from the authenticated page and provide the active challenge `nc host port` endpoint; or
2. provide a connected browser/HTTP execution channel that can apply the authenticated Dreamhack session without persisting it in GitHub.

Once the real handout and endpoint are available, the intended path is:

```text
artifact admission
→ manifest/corpus identity
→ same fixed experiment contract
→ Minimal arm
→ Verified arm
→ independent flag adjudication
→ paired benchmark record
```

## Truthfulness decision

**Decision:** `BLOCKED / NO RESULT`.

This attempt demonstrates an input-acquisition limitation only. It provides no evidence for or against harness solve-rate effectiveness.
