from __future__ import annotations
import hashlib,time
from dataclasses import dataclass
from typing import Callable
@dataclass(frozen=True)
class FlagSubmissionReceipt:
    candidate_hash:str
    challenge_id:str
    target:str
    submitted_at_ns:int
    accepted:bool
    oracle_response_ref:str|None=None
class ExternalFlagOracle:
    """Submission adapter only; it does not mutate Core completion state."""
    def __init__(self,submit:Callable[[str],tuple[bool,str|None]]):self._submit=submit
    def submit(self,challenge_id:str,target:str,candidate:str)->FlagSubmissionReceipt:
        accepted,ref=self._submit(candidate); return FlagSubmissionReceipt(hashlib.sha256(candidate.encode()).hexdigest(),challenge_id,target,time.time_ns(),bool(accepted),ref)
