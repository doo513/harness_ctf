from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Mapping, Sequence

from harness.core.sandbox import ExecutionResult, IsolationAttestation
from harness.core.tools import SandboxedArgvToolSpec, SideEffect

from ctf_harness.operational.models import RuntimeKind
from ctf_harness.target.runners import NativeRunner, TargetRunner


_PROBE_SCRIPT = r'''import base64,hashlib,json,pathlib,re,subprocess,sys,tempfile
def canonical_hash(value):
 raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode("utf-8")
 return hashlib.sha256(raw).hexdigest()
target_path=pathlib.Path(sys.argv[1])
data=base64.b64decode(sys.argv[2],validate=True)
timeout=float(sys.argv[3])
launch=json.loads(base64.b64decode(sys.argv[4],validate=True).decode("utf-8"))
if not isinstance(launch,dict): raise RuntimeError("launch descriptor is not an object")
expected_target=launch.get("target_sha256")
if hashlib.sha256(target_path.read_bytes()).hexdigest()!=expected_target: raise RuntimeError("target identity changed before execution")
runtime=launch.get("runtime")
runtime_fingerprint=launch.get("runtime_fingerprint")
if not isinstance(runtime,dict) or canonical_hash(runtime)!=runtime_fingerprint: raise RuntimeError("runtime descriptor fingerprint mismatch")
if runtime.get("runtime_kind")!="native": raise RuntimeError("x86_64 control probe currently supports native runtime only")
argv=launch.get("argv")
if not isinstance(argv,list) or not argv or any(not isinstance(x,str) or not x or "\x00" in x for x in argv): raise RuntimeError("launch argv malformed")
launch_fingerprint=canonical_hash({"target_sha256":expected_target,"runtime_fingerprint":runtime_fingerprint,"argv":argv})
if launch_fingerprint!=launch.get("launch_fingerprint"): raise RuntimeError("launch fingerprint mismatch")
body={"schema_version":2,"kind":"pwn_control_probe_x86_64","target_sha256":expected_target,"input_sha256":hashlib.sha256(data).hexdigest(),"runtime":runtime,"runtime_fingerprint":runtime_fingerprint,"launch_argv":argv,"launch_fingerprint":launch_fingerprint,"register":"rip","value":None,"input_offset":None,"gdb_returncode":None,"timed_out":False}
fd,input_path=tempfile.mkstemp(prefix="vsh-gdb-input-",dir="/vsh-tmp")
try:
 import os
 os.write(fd,data);os.close(fd);fd=-1
 cmd=["/usr/bin/gdb","-q","-nx","-batch","-ex","set pagination off","-ex",f"run < {input_path}","-ex",'printf "VSH_RIP=0x%lx\\n", $rip',"--args",*argv]
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
    unresolved = (workspace / raw).resolve(strict=False)
    try:
        unresolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("control probe target escapes workspace") from exc
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

    def __init__(
        self,
        delegate,
        *,
        probe_timeout_seconds: float = 5.0,
        runners: Mapping[str, TargetRunner] | None = None,
        default_profile_id: str = "native-default",
        expected_target_sha256: Mapping[str, str] | None = None,
    ):
        self.delegate = delegate
        self.probe_timeout_seconds = float(probe_timeout_seconds)
        if self.probe_timeout_seconds <= 0:
            raise ValueError("probe timeout must be positive")
        configured = dict(runners or {"native-default": NativeRunner("native-default")})
        if not configured:
            raise ValueError("at least one target runner is required")
        for key, runner in configured.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("runner profile keys must be non-empty strings")
            if getattr(runner, "profile_id", None) != key:
                raise ValueError("runner registry key must equal runner.profile_id")
        if default_profile_id not in configured:
            raise ValueError("default target runner profile is not registered")
        self.runners = configured
        self.default_profile_id = default_profile_id
        self.expected_target_sha256 = dict(expected_target_sha256 or {})

    def isolation_attestation(self, *, workspace: Path) -> IsolationAttestation:
        att = self.delegate.isolation_attestation(workspace=workspace)
        evidence = dict(att.evidence)
        evidence.update(
            {
                "semantic_adapter": self.name,
                "delegate_backend": getattr(self.delegate, "name", type(self.delegate).__name__),
                "target_runner_profiles": sorted(self.runners),
            }
        )
        return IsolationAttestation(
            att.filesystem_isolated,
            att.network_isolated,
            att.environment_sanitized,
            att.source,
            evidence,
        )

    def run_argv(
        self,
        *,
        workspace: Path,
        argv: Sequence[str],
        timeout_seconds: float,
        env=None,
    ) -> ExecutionResult:
        request = list(argv)
        if len(request) not in (2, 3):
            return ExecutionResult(
                2,
                "",
                "control probe request must contain target, input_b64, and optional runtime_profile_id",
            )
        root = Path(workspace).resolve()
        try:
            target = _safe_target(root, request[0])
            raw = base64.b64decode(request[1], validate=True)
            profile_id = request[2] if len(request) == 3 else self.default_profile_id
            if profile_id not in self.runners:
                raise ValueError("requested target runtime profile is not registered")
            runner = self.runners[profile_id]
            if runner.runtime_kind is not RuntimeKind.NATIVE:
                raise ValueError(
                    "x86_64 control probe currently supports only native target runtime profiles"
                )
            launch = runner.build_launch(
                workspace=root,
                target_relpath=target,
                expected_target_sha256=self.expected_target_sha256.get(target),
            )
            launch_payload = {
                "target_sha256": launch.target_sha256,
                "runtime": launch.runtime_descriptor(),
                "runtime_fingerprint": launch.runtime_fingerprint(),
                "argv": list(launch.argv),
                "launch_fingerprint": launch.launch_fingerprint(),
            }
        except Exception as exc:
            return ExecutionResult(
                2,
                "",
                f"invalid control probe request: {type(exc).__name__}: {exc}",
            )

        encoded_launch = base64.b64encode(
            json.dumps(
                launch_payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).decode("ascii")
        helper = [
            "/usr/bin/python3",
            "-c",
            _PROBE_SCRIPT,
            f"./{target}",
            base64.b64encode(raw).decode("ascii"),
            repr(self.probe_timeout_seconds),
            encoded_launch,
        ]
        return self.delegate.run_argv(
            workspace=root,
            argv=helper,
            timeout_seconds=max(float(timeout_seconds), self.probe_timeout_seconds + 2.0),
            env=env,
        )

    def run_shell(self, **kwargs):
        raise RuntimeError("ControlProbeBackend does not expose arbitrary shell execution")

    def open_argv_session(self, **kwargs):
        raise RuntimeError("ControlProbeBackend does not expose persistent sessions")


def make_control_probe_tool(
    workspace: str | Path,
    *,
    backend,
    timeout_seconds: float = 10.0,
    probe_timeout_seconds: float = 5.0,
    runners: Mapping[str, TargetRunner] | None = None,
    default_profile_id: str = "native-default",
    expected_target_sha256: Mapping[str, str] | None = None,
) -> SandboxedArgvToolSpec:
    adapter = ControlProbeBackend(
        backend,
        probe_timeout_seconds=probe_timeout_seconds,
        runners=runners,
        default_profile_id=default_profile_id,
        expected_target_sha256=expected_target_sha256,
    )
    return SandboxedArgvToolSpec(
        name="pwn_control_probe",
        description=(
            "Use a fixed GDB probe to bind x86_64 RIP to a unique 8-byte sequence "
            "under one registered native target runtime profile."
        ),
        execution_backend=adapter,
        execution_workspace=Path(workspace).resolve(),
        timeout_seconds=timeout_seconds,
        argv_arg="argv",
        side_effect=SideEffect.WRITE,
        idempotent=False,
        failure_modes=[
            "invalid_target",
            "invalid_input",
            "invalid_runtime_profile",
            "runtime_identity_mismatch",
            "unsupported_runtime",
            "gdb_missing",
            "probe_timeout",
            "sandbox_violation",
        ],
        provenance={
            "kind": "deterministic_domain_probe",
            "domain": "pwn",
            "schema": "pwn_control_probe_x86_64.v2",
        },
        require_zero_exit=True,
    )
