from __future__ import annotations

from collections.abc import Iterable

from .models import CategoryAssessment, CategoryCandidate


_DOMAINS = ("pwn", "reverse", "crypto", "web", "forensics", "misc")


def assess_from_recon(
    *,
    file_type: str,
    category_hint: str | None = None,
    indicators: Iterable[str] = (),
    filenames: Iterable[str] = (),
    evidence_refs=(),
) -> CategoryAssessment:
    """Rank plausible domains from low-confidence features; never authoritative."""
    scores = {name: 0.0 for name in _DOMAINS}
    normalized_type = str(file_type).strip().lower()
    if normalized_type == "elf":
        scores["pwn"] += .55
        scores["reverse"] += .35
    elif normalized_type in {"pe", "mach-o", "macho", "native_executable"}:
        scores["reverse"] += .50
        scores["pwn"] += .20
    elif normalized_type in {"pcap", "pcapng", "png", "jpeg", "jpg", "pdf", "zip"}:
        scores["forensics"] += .45
        scores["misc"] += .15
    elif normalized_type in {"source", "text"}:
        scores["misc"] += .10

    hint = str(category_hint).strip().lower() if category_hint is not None else None
    if hint in scores:
        scores[hint] += .35

    feature_weights = {
        "web_route": {"web": .35},
        "auth": {"web": .18},
        "sql": {"web": .25},
        "crypto_rsa": {"crypto": .45},
        "crypto_symmetric": {"crypto": .40},
        "native_executable": {"reverse": .20, "pwn": .15},
        "network": {"web": .10, "pwn": .05},
        "flag_shape": {"misc": .03},
        "python_source": {"web": .05, "crypto": .05, "misc": .05},
    }
    for indicator in set(str(item) for item in indicators):
        for domain, weight in feature_weights.get(indicator, {}).items():
            scores[domain] += weight

    filename_tokens = " ".join(str(name).lower() for name in filenames)
    keyword_weights = {
        "libc": {"pwn": .15},
        "overflow": {"pwn": .15},
        "rop": {"pwn": .15},
        "cipher": {"crypto": .12},
        "rsa": {"crypto": .15},
        "server": {"web": .08},
        "app.py": {"web": .10},
        "pcap": {"forensics": .15},
        "memory": {"forensics": .08},
    }
    for token, weights in keyword_weights.items():
        if token in filename_tokens:
            for domain, weight in weights.items():
                scores[domain] += weight

    total = sum(scores.values()) or 1.0
    ranked = tuple(
        CategoryCandidate(domain, round(score / total, 6))
        for domain, score in sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        if score > 0
    )
    return CategoryAssessment(ranked, tuple(evidence_refs))
