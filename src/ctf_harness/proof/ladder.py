from .models import ProofLevel

# P0-P5 are a contiguous proof path. A later semantic fact must not skip the
# proof gates before it. P6 is special: an external task oracle acceptance is
# final truth even when some optional local evidence was unavailable.
LEVEL_KEYS = (
    (ProofLevel.P0_SURFACE, {"ctf.pwn.arch"}),
    (ProofLevel.P1_PRIMITIVE, {"ctf.pwn.crash_reproducible"}),
    (ProofLevel.P2_CONTROL, {"ctf.pwn.control_flow"}),
    (ProofLevel.P3_LOCAL, {"ctf.pwn.local_exploit"}),
    (ProofLevel.P4_ENVIRONMENT, {"ctf.environment.compatible"}),
    (ProofLevel.P5_REMOTE, {"ctf.pwn.remote_behavior"}),
)


def proof_level_from_verified_keys(keys, *, completed: bool = False) -> ProofLevel | None:
    if completed:
        return ProofLevel.P6_ACCEPTED
    present = set(keys)
    achieved = None
    for level, required in LEVEL_KEYS:
        if not required.issubset(present):
            break
        achieved = level
    return achieved
