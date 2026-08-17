import hashlib,json
from .models import Hypothesis,HypothesisStatus
def fingerprint(h:Hypothesis)->str:
    raw=json.dumps([h.category,h.target,h.vulnerability_class,h.primitive,h.evidence_digest],separators=(",",":"),ensure_ascii=False).encode(); return hashlib.sha256(raw).hexdigest()
class HypothesisPool:
    def __init__(self):self._by_fp={}
    def add(self,h:Hypothesis)->str:
        fp=fingerprint(h)
        if fp not in self._by_fp:self._by_fp[fp]=h
        return fp
    def should_repeat(self,fp:str,failure_signature:str,evidence_digest:str)->bool:
        h=self._by_fp[fp]
        if h.evidence_digest!=evidence_digest:return True
        return h.last_failure_signature!=failure_signature
    def record_failure(self,fp:str,failure_signature:str,*,refuted=False):
        h=self._by_fp[fp];h.attempt_count+=1;h.last_failure_signature=failure_signature
        if refuted:h.status=HypothesisStatus.REFUTED
