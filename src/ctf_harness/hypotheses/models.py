from dataclasses import dataclass
from enum import Enum
class HypothesisStatus(str,Enum):OPEN="open";SUPPORTED="supported";REFUTED="refuted";PROVED="proved"
@dataclass
class Hypothesis:
    id:str; category:str; target:str; vulnerability_class:str; primitive:str; claim:str; evidence_digest:str
    status:HypothesisStatus=HypothesisStatus.OPEN
    attempt_count:int=0
    last_failure_signature:str|None=None
