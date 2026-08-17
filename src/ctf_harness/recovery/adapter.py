from dataclasses import dataclass
@dataclass(frozen=True)
class RecoveryMapping:core_failure:str;target:str
_MAP={"RECON_INCOMPLETE":RecoveryMapping("MISSING_INFO","targeted_recon"),"CATEGORY_MISCLASSIFIED":RecoveryMapping("HYPOTHESIS_REFUTED","category_switch"),"TOOL_FAILURE":RecoveryMapping("TOOL_ERROR","repair_or_substitute"),"INTERACTIVE_STALL":RecoveryMapping("NO_PROGRESS","restart_or_switch"),"PRIMITIVE_NOT_REPRODUCIBLE":RecoveryMapping("VERIFICATION_FAILED","alternate_primitive"),"LOCAL_PROOF_FAILED":RecoveryMapping("VERIFICATION_FAILED","proof_strategy_switch"),"ENVIRONMENT_MISMATCH":RecoveryMapping("ENV_ERROR","environment_adaptation"),"REMOTE_PROOF_FAILED":RecoveryMapping("VERIFICATION_FAILED","inspect_environment_diff"),"FLAG_REJECTED":RecoveryMapping("VERIFICATION_FAILED","return_to_proof"),"NO_INFORMATION_GAIN":RecoveryMapping("NO_PROGRESS","strategy_switch"),"BUDGET_EXHAUSTED":RecoveryMapping("BUDGET_EXCEEDED","checkpoint_stop")}
def map_failure(kind:str)->RecoveryMapping:
    try:return _MAP[kind]
    except KeyError as exc:raise ValueError("unknown CTF failure kind") from exc
