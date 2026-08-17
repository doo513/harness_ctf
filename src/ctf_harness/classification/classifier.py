from .models import CategoryAssessment, CategoryCandidate

def assess_from_recon(*, file_type: str, category_hint: str | None = None, evidence_refs=()) -> CategoryAssessment:
    scores={"pwn":0.0,"reverse":0.0,"crypto":0.0,"web":0.0,"forensics":0.0,"misc":0.0}
    if file_type == "ELF": scores["pwn"] += .55; scores["reverse"] += .35
    if category_hint in scores: scores[category_hint] += .35
    total=sum(scores.values()) or 1.0
    ranked=tuple(CategoryCandidate(k, round(v/total,6)) for k,v in sorted(scores.items(), key=lambda kv:(-kv[1],kv[0])) if v>0)
    return CategoryAssessment(ranked, tuple(evidence_refs))
