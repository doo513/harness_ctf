# 02 — Site Access Logic Evidence

Status: **PASS**

## Scope

Expose competition-site access from configuration while reusing the existing `CompetitionAdapter` / CTFd boundary and keeping platform data outside Harness truth authority.

## Implemented artifacts

- `src/ctf_harness/site_access/gateway.py`
- `src/ctf_harness/competition/credentials.py` (reused)
- `src/ctf_harness/competition/ctfd.py` (reused)
- `tests/test_site_access_gateway.py`

## Structural decision

`SiteAccessGateway` resolves configured site providers. `SiteSession` wraps the existing competition adapter instead of reimplementing HTTP/platform behavior.

This preserves the existing same-origin checks, transient credential resolution, and competition snapshot semantics.

## Security / authority evidence

- Inline site secrets are rejected.
- Credential values are resolved transiently and excluded from gateway/session descriptors.
- Challenge/platform records remain platform snapshots and do not become verified Harness Facts.
- Flag submission is disabled unless the selected site profile explicitly sets `allow_submit=true`.
- When submission is disabled, no POST is emitted by the controlled test transport.
- Site access has no truth or completion authority; final completion remains external-oracle controlled.

## Direct test evidence

`tests/test_site_access_gateway.py` verifies:

1. inline credential rejection;
2. reuse of the existing CTFd boundary;
3. transient environment credential resolution without descriptor leakage;
4. default submission denial and absence of POST side effect;
5. explicit submission enablement.

## Final regression evidence

GitHub Actions run `32202024136` passed the complete repository gate, including the controlled competition remote TCP SolveEngine probe. The probe admitted an exact endpoint, kept `general_internet=false` and `external_retrieval=false`, executed four remote TCP tool operations, and completed only through the external oracle.

## Non-claims

This stage verifies the CTFd integration boundary and policy behavior. It does not claim interoperability with every CTF platform; additional platforms remain provider extensions.
