from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any
from harness.core.storage import ArtifactStore
from harness.core.verification import VerificationLevel, VerificationResult

def _registered_observation_artifacts(context:dict,*,source:str):
    state=context.get("state"); artifact_root=context.get("artifact_root"); refs=list(context.get("claim_evidence_refs") or [])
    if not isinstance(state,dict) or not artifact_root or not refs:raise ValueError("registered claim evidence is unavailable")
    artifacts=set(state.get("artifacts") or []); evidence=set(state.get("evidence_refs") or []); observations=state.get("observations") or []
    by_ref={item.get("artifact_ref"):item for item in observations if isinstance(item,dict) and isinstance(item.get("artifact_ref"),str)}
    loaded=[]
    for ref in refs:
        if ref not in artifacts or ref not in evidence:raise ValueError("claim evidence is not registered in Core state")
        obs=by_ref.get(ref)
        if not obs or obs.get("source")!=source or obs.get("ok") is not True:raise ValueError(f"claim evidence is not a successful {source} observation")
        raw=ArtifactStore.verified_read_bytes_from_root(artifact_root,ref)
        try:payload=json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError,json.JSONDecodeError) as exc:raise ValueError("observation artifact is not valid JSON") from exc
        if not isinstance(payload,dict) or payload.get("ok") is not True or payload.get("error") is not None:raise ValueError("observation artifact does not record a successful ToolResult")
        loaded.append((ref,payload))
    return loaded

@dataclass(frozen=True)
class StaticReconFieldVerifier:
    name:str; claim_key:str; field:str
    level=VerificationLevel.LOGICAL; covers=("ctf_semantic",)
    def verify(self,candidate:Any,context:dict)->VerificationResult:
        refs=list(context.get("claim_evidence_refs") or [])
        if context.get("claim_key")!=self.claim_key:return VerificationResult(False,self.level,"verifier is not bound to this exact claim key",evidence_refs=refs)
        try:loaded=_registered_observation_artifacts(context,source="pwn_recon")
        except Exception as exc:return VerificationResult(False,self.level,f"{type(exc).__name__}: {exc}",evidence_refs=refs)
        values=[];hashes=set()
        for _,payload in loaded:
            output=payload.get("output")
            if not isinstance(output,dict):return VerificationResult(False,self.level,"pwn_recon output is not an object",evidence_refs=refs)
            if output.get("kind")!="pwn_recon_snapshot" or output.get("schema_version")!=1:return VerificationResult(False,self.level,"pwn_recon schema/kind mismatch",evidence_refs=refs)
            digest=output.get("artifact_sha256")
            if not isinstance(digest,str) or len(digest)!=64 or any(ch not in "0123456789abcdef" for ch in digest):return VerificationResult(False,self.level,"pwn_recon artifact digest is invalid",evidence_refs=refs)
            hashes.add(digest);values.append(output.get(self.field))
        if len(hashes)!=1:return VerificationResult(False,self.level,"claim evidence mixes multiple artifact identities",evidence_refs=refs)
        if not values or any(v!=values[0] for v in values[1:]):return VerificationResult(False,self.level,"claim evidence contains conflicting recon values",evidence_refs=refs)
        actual=values[0]
        if actual is None:return VerificationResult(False,self.level,"recon evidence is intentionally inconclusive for this field",evidence_refs=refs)
        ok=candidate==actual
        return VerificationResult(ok,self.level,f"deterministic pwn_recon {self.field}={actual!r}" if ok else f"candidate {candidate!r} disagrees with deterministic pwn_recon {actual!r}",evidence_refs=refs,details={"artifact_sha256":next(iter(hashes)),"field":self.field,"actual":actual},confidence=1.0 if ok else None)

def static_pwn_verifiers():
    return [StaticReconFieldVerifier("pwn_arch","ctf.pwn.arch","architecture"),StaticReconFieldVerifier("pwn_bits","ctf.pwn.bits","bits"),StaticReconFieldVerifier("pwn_endianness","ctf.pwn.endianness","endianness"),StaticReconFieldVerifier("pwn_nx","ctf.pwn.nx","nx"),StaticReconFieldVerifier("pwn_pie","ctf.pwn.pie","pie")]
