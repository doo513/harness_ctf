from .models import ProofLevel
LEVEL_KEYS=((ProofLevel.P0_SURFACE,{"ctf.pwn.arch"}),(ProofLevel.P1_PRIMITIVE,{"ctf.pwn.crash_reproducible"}),(ProofLevel.P2_CONTROL,{"ctf.pwn.control_flow"}),(ProofLevel.P3_LOCAL,{"ctf.pwn.local_exploit"}),(ProofLevel.P4_ENVIRONMENT,{"ctf.environment.compatible"}),(ProofLevel.P5_REMOTE,{"ctf.pwn.remote_behavior"}))
def proof_level_from_verified_keys(keys,*,completed:bool=False)->ProofLevel|None:
    if completed:return ProofLevel.P6_ACCEPTED
    present=set(keys); achieved=[level for level,required in LEVEL_KEYS if required.issubset(present)]
    return max(achieved,default=None)
