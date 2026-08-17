from __future__ import annotations
import base64
from pathlib import Path
from typing import Sequence
from harness.core.sandbox import ExecutionResult,IsolationAttestation
from harness.core.tools import SandboxedArgvToolSpec,SideEffect
_PROBE_SCRIPT=r'''import base64,hashlib,json,pathlib,subprocess,sys
path=pathlib.Path(sys.argv[1]);data=base64.b64decode(sys.argv[2],validate=True);timeout=float(sys.argv[3]);target=path.read_bytes();body={"schema_version":1,"kind":"pwn_crash_probe","target_sha256":hashlib.sha256(target).hexdigest(),"input_sha256":hashlib.sha256(data).hexdigest(),"timed_out":False,"returncode":None,"signal":None,"stdout_sha256":None,"stderr_sha256":None}
try:
 p=subprocess.run([str(path)],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,shell=False);body["returncode"]=p.returncode;body["signal"]=-p.returncode if p.returncode<0 else None;body["stdout_sha256"]=hashlib.sha256(p.stdout).hexdigest();body["stderr_sha256"]=hashlib.sha256(p.stderr).hexdigest()
except subprocess.TimeoutExpired as e:
 body["timed_out"]=True;body["stdout_sha256"]=hashlib.sha256(e.stdout or b"").hexdigest();body["stderr_sha256"]=hashlib.sha256(e.stderr or b"").hexdigest()
print(json.dumps(body,sort_keys=True,separators=(",",":")))'''
def _safe_target(workspace:Path,value:str)->str:
 if not isinstance(value,str) or not value.strip():raise ValueError("crash probe target must be a non-empty relative path")
 raw=Path(value)
 if raw.is_absolute():raise ValueError("crash probe target must be workspace-relative")
 unresolved=(workspace/raw).resolve(strict=False)
 try:unresolved.relative_to(workspace)
 except ValueError as exc:raise ValueError("crash probe target escapes workspace") from exc
 resolved=(workspace/raw).resolve(strict=True)
 try:resolved.relative_to(workspace)
 except ValueError as exc:raise ValueError("crash probe target escapes workspace") from exc
 if not resolved.is_file():raise ValueError("crash probe target must be a regular file")
 return str(resolved.relative_to(workspace))
class CrashProbeBackend:
 name="ctf_pwn_crash_probe"
 def __init__(self,delegate,*,probe_timeout_seconds:float=2.0):
  self.delegate=delegate;self.probe_timeout_seconds=float(probe_timeout_seconds)
  if self.probe_timeout_seconds<=0:raise ValueError("probe timeout must be positive")
 def isolation_attestation(self,*,workspace:Path)->IsolationAttestation:
  a=self.delegate.isolation_attestation(workspace=workspace);e=dict(a.evidence);e.update({"semantic_adapter":self.name,"delegate_backend":getattr(self.delegate,"name",type(self.delegate).__name__)});return IsolationAttestation(a.filesystem_isolated,a.network_isolated,a.environment_sanitized,a.source,e)
 def run_argv(self,*,workspace:Path,argv:Sequence[str],timeout_seconds:float,env=None)->ExecutionResult:
  request=list(argv)
  if len(request)!=2:return ExecutionResult(2,"","crash probe request must contain target and input_b64")
  root=Path(workspace).resolve()
  try:target=_safe_target(root,request[0]);raw=base64.b64decode(request[1],validate=True)
  except Exception as exc:return ExecutionResult(2,"",f"invalid crash probe request: {type(exc).__name__}: {exc}")
  helper=["/usr/bin/python3","-c",_PROBE_SCRIPT,f"./{target}",base64.b64encode(raw).decode("ascii"),repr(self.probe_timeout_seconds)]
  return self.delegate.run_argv(workspace=root,argv=helper,timeout_seconds=max(float(timeout_seconds),self.probe_timeout_seconds+1.0),env=env)
 def run_shell(self,**kwargs):raise RuntimeError("CrashProbeBackend does not expose arbitrary shell execution")
 def open_argv_session(self,**kwargs):raise RuntimeError("CrashProbeBackend does not expose persistent sessions")
def make_crash_probe_tool(workspace:str|Path,*,backend,timeout_seconds:float=5.0,probe_timeout_seconds:float=2.0)->SandboxedArgvToolSpec:
 adapter=CrashProbeBackend(backend,probe_timeout_seconds=probe_timeout_seconds)
 return SandboxedArgvToolSpec(name="pwn_crash_probe",description="Run a fixed sandboxed crash probe for [workspace-relative target, base64 input].",execution_backend=adapter,execution_workspace=Path(workspace).resolve(),timeout_seconds=timeout_seconds,argv_arg="argv",side_effect=SideEffect.WRITE,idempotent=False,failure_modes=["invalid_target","invalid_input","probe_timeout","sandbox_violation"],provenance={"kind":"deterministic_domain_probe","domain":"pwn","schema":"pwn_crash_probe.v1"},require_zero_exit=True)
