from dataclasses import dataclass
@dataclass(frozen=True)
class ClaimSpec:
    key_prefix: str
    verification_level: str
    verifier: str
PWN_CLAIM_SPECS=(ClaimSpec("ctf.pwn.arch","LOGICAL","pwn_arch"),ClaimSpec("ctf.pwn.bits","LOGICAL","pwn_bits"),ClaimSpec("ctf.pwn.endianness","LOGICAL","pwn_endianness"),ClaimSpec("ctf.pwn.nx","LOGICAL","pwn_nx"),ClaimSpec("ctf.pwn.pie","LOGICAL","pwn_pie"),ClaimSpec("ctf.pwn.canary_present","LOGICAL","pwn_canary_present"))
def resolve_claim_spec(key: str) -> ClaimSpec | None:
    matches=[spec for spec in PWN_CLAIM_SPECS if key.startswith(spec.key_prefix)]
    return max(matches,key=lambda spec:len(spec.key_prefix)) if matches else None
