from __future__ import annotations
import json
from typing import Any
from harness.core.verification import VerificationLevel,VerificationResult
from ctf_harness.verifiers.pwn.core import _registered_observation_artifacts

def _parse_probe(payload:dict[str,Any])->dict[str,Any]:
 output=payload.get("output")
 if not isinstance(output,dict) or output.get("returncode")!=0 or output.get("timed_out") is not False:raise ValueError("crash probe wrapper did not complete successfully")
 stdout=output.get("stdout")
 if not isinstance(stdout,str):raise ValueError("crash probe stdout is unavailable")
 try:record=json.loads(stdout.strip())
 except json.JSONDecodeError as exc:raise ValueError("crash probe stdout is not canonical JSON") from exc
 if not isinstance(record,dict) or record.get("kind")!="pwn_crash_probe" or record.get("schema_version")!=1:raise ValueError("crash probe schema mismatch")
 for field in ("target_sha256","input_sha256"):
  value=record.get(field)
  if not isinstance(value,str) or len(value)!=64 or any(ch not in "0123456789abcdef" for ch in value):raise ValueError(f"invalid {field}")
 return record
class CrashReproducibleVerifier:
 name="pwn_crash_reproducible";level=VerificationLevel.EXECUTION;covers=("ctf_semantic",);claim_key="ctf.pwn.crash_reproducible"
 def verify(self,candidate:Any,context:dict)->VerificationResult:
  refs=list(context.get("claim_evidence_refs") or [])
  if context.get("claim_key")!=self.claim_key:return VerificationResult(False,self.level,"verifier is not bound to this exact claim key",evidence_refs=refs)
  if len(set(refs))<2:return VerificationResult(False,self.level,"reproducible crash requires at least two independent evidence artifacts",evidence_refs=refs)
  try:records=[_parse_probe(payload) for _,payload in _registered_observation_artifacts(context,source="pwn_crash_probe")]
  except Exception as exc:return VerificationResult(False,self.level,f"{type(exc).__name__}: {exc}",evidence_refs=refs)
  first=records[0];identity=(first["target_sha256"],first["input_sha256"],first.get("signal"))
  if first.get("timed_out") is not False or not isinstance(first.get("signal"),int) or first["signal"]<=0:return VerificationResult(False,self.level,"probe did not observe a terminating signal",evidence_refs=refs)
  for record in records[1:]:
   if (record["target_sha256"],record["input_sha256"],record.get("signal"))!=identity:return VerificationResult(False,self.level,"crash evidence is not reproducible for the same target/input/signal",evidence_refs=refs)
   if record.get("timed_out") is not False:return VerificationResult(False,self.level,"timed-out execution is not a reproduced crash",evidence_refs=refs)
  expected={"target_sha256":identity[0],"input_sha256":identity[1],"signal":identity[2]}
  if candidate!=expected:return VerificationResult(False,self.level,"candidate does not exactly bind target/input/signal",evidence_refs=refs,details={"expected":expected})
  return VerificationResult(True,self.level,"same target/input reproduced the same terminating signal in independent executions",evidence_refs=refs,details=expected,confidence=1.0)
