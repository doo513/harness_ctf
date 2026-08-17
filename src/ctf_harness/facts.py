from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CTFFactView:
    """Read-only projection of one Core-owned CTF fact.

    This type deliberately exposes no commit/update API. Truth authority remains
    exclusively in base_harness HarnessState.facts.
    """

    key: str
    value: Any
    evidence_refs: tuple[str, ...]
    authority: str


def ctf_fact_views(state: Any) -> tuple[CTFFactView, ...]:
    facts = getattr(state, "facts", None)
    if not isinstance(facts, dict):
        raise TypeError("state.facts must be the Core fact mapping")
    views: list[CTFFactView] = []
    for key in sorted(facts):
        if not isinstance(key, str) or not key.startswith("ctf."):
            continue
        claim = facts[key]
        refs = tuple(str(ref) for ref in (getattr(claim, "evidence_refs", ()) or ()))
        authority = getattr(claim, "authority", "")
        authority_value = getattr(authority, "value", authority)
        views.append(CTFFactView(
            key=key,
            value=getattr(claim, "value", None),
            evidence_refs=refs,
            authority=str(authority_value),
        ))
    return tuple(views)
