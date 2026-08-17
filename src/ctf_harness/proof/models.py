from dataclasses import dataclass
from enum import IntEnum
class ProofLevel(IntEnum):
    P0_SURFACE=0; P1_PRIMITIVE=1; P2_CONTROL=2; P3_LOCAL=3; P4_ENVIRONMENT=4; P5_REMOTE=5; P6_ACCEPTED=6
@dataclass(frozen=True)
class ProofReceipt:
    proof_id:str
    hypothesis_id:str|None
    proof_level_candidate:ProofLevel
    environment:str
    artifact_ref:str|None
    command_or_request_ref:str|None
    expected_effect:str
    observed_effect:str
    verifier:str
    environment_fingerprint:str
    passed:bool
