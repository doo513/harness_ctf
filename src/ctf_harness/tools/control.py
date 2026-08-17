from __future__ import annotations

import base64
from pathlib import Path
from typing import Sequence

from harness.core.sandbox import ExecutionResult, IsolationAttestation
from harness.core.tools import SandboxedArgvToolSpec, SideEffect

_PROBE_SCRIPT = r'''import base64,hashlib,json,pathlib,re,subprocess,sys,tempfile
exec_path=sys.argv[1]
path=pathlib.Path(exec_path)
data=base64.b64decode(sys.argv[2],validate=True)
timeout=float(sys.argv[3])
target=path.read_bytes()
body={"schema_version":1,"kind":"pwn_control_probe_x86_64","target_sha256":hashlib.sha256(target).hexdigest(),"input_sha256":hashlib.sha256(data).hexdigest(),"register":"rip","value":None,"input_offset":None,"gdb_returncode":None,"timed_out":False}
fd,input_path=tempfile.mkstemp(prefix="vsh-gdb-input-",dir="/vsh-tmp")
try:
 import os
 os.write(fd,data);os.close(fd);fd=-1
 cmd=["/usr/bin/gdb","-q","-nx","-batch","-ex","set pagination off","-ex",f"run < {input_path}","-ex",'printf "VSH_RIP=0x%lx\\n", $rip',"--args",exec_path]
 try:
  p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,shell=False)
  body["gdb_returncode"]=p.returncode
  merged=(p.stdout+b"\n"+p.stderr).decode("utf-8",errors="replace")
  matches=re.findall(r"VSH_RIP=0x([0-9a-fA-F]+)",merged)
  if matches:
   value=int(matches[-1],16);body["value"]=value
   needle=value.to_bytes(8,"little",signed=False)
   first=data.find(needle)
   if first>=0 and data.find(needle,first+1)<0:body["input_offset"]=first
 except subprocess.TimeoutExpired:
  body["timed_out"]=True
finally:
 import os
 if fd>=0:os.close(fd)
 try:os.unlink(input_path)
 except FileNotFoundError:pass
print(json.dumps(body,sort_keys=True,separators=(",",":")))'''


def _safe_target(workspace: Path, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("control probe target must be a non-empty relative path")
    raw = Path(value)
    if raw.is_absolute():
        raise ValueError("control probe target must be workspace-relative")
    resolved = (workspace / raw).resolve(strict=True)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("control probe target escapes workspace") from exc
    if not resolved.is_file():
        raise ValueError("control probe target must be a regular file")
    return str(resolved.relative_to(workspace))


class ControlProbeBackend:
    name = "ctf_pwn_control_probe_x86_64"

    def __init__(self, delegate, *, probe_timeout_seconds: float = 5.0):
        self.delegate = delegate
        self.probe_timeout_seconds = float(probe_timeout_seconds)
        if self.probe_timeout_seconds <= 0:
            raise ValueError("probe timeout must be positive")

    def isolation_attestation(self, *, workspace: Path) -> IsolationAttestation:
        att = self.delegate.isolation_attestation(workspace=workspace)
        evidence = dict(att.evidence)
        evidence.update({"semantic_adapter": self.name, "delegate_backend": getattr(self.delegate, "name", type(self.delegate).__name__)})
        return IsolationAttestation(att.filesystem_isolated, att.network_isolated, att.environment_sanitized, att.source, evidence)

    def run_argv(self, *, workspace: Path, argv: Sequence[str], timeout_seconds: float, env=None) -> ExecutionResult:
        request = list(argv)
        if len(request) != 2:
            return ExecutionResult(2, "", "control probe request must contain target and input_b64")
        root = Path(workspace).resolve()
        try:
            target = _safe_target(root, request[0])
            raw = base64.b64decode(request[1], validate=True)
        except Exception as exc:
            return ExecutionResult(2, "", f"invalid control probe request: {type(exc).__name__}: {exc}")
        helper = ["/usr/bin/python3", "-c", _PROBE_SCRIPT, f"./{target}", base64.b64encode(raw).decode("ascii"), repr(self.probe_timeout_seconds)]
        return self.delegate.run_argv(workspace=root, argv=helper, timeout_seconds=max(float(timeout_seconds), self.probe_timeout_seconds + 2.0), env=env)

    def run_shell(self, **kwargs):
        raise RuntimeError("ControlProbeBackend does not expose arbitrary shell execution")

    def open_argv_session(self, **kwargs):
        raise RuntimeError("ControlProbeBackend does not expose persistent sessions")


def make_control_probe_tool(workspace: str | Path, *, backend, timeout_seconds: float = 10.0, probe_timeout_seconds: float = 5.0) -> SandboxedArgvToolSpec:
    adapter = ControlProbeBackend(backend, probe_timeout_seconds=probe_timeout_seconds)
    return SandboxedArgvToolSpec(
        name="pwn_control_probe",
        description="Use a fixed GDB probe to bind x86_64 RIP to a unique 8-byte sequence in one supplied input.",
        execution_backend=adapter,
        execution_workspace=Path(workspace).resolve(),
        timeout_seconds=timeout_seconds,
        argv_arg="argv",
        side_effect=SideEffect.WRITE,
        idempotent=False,
        failure_modes=["invalid_target", "invalid_input", "gdb_missing", "probe_timeout", "sandbox_violation"],
        provenance={"kind":"deterministic_domain_probe", "domain":"pwn", "schema":"pwn_control_probe_x86_64.v1"},
        require_zero_exit=True,
    )
