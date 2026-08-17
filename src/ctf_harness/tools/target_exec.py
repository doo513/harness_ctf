from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Mapping, Sequence

from harness.core.sandbox import ExecutionResult, IsolationAttestation
from harness.core.tools import SandboxedArgvToolSpec, SideEffect

from ctf_harness.target.runners import NativeRunner, TargetRunner


_EXEC_SCRIPT = r'''import base64,hashlib,json,os,pathlib,subprocess,sys

def canonical_hash(value):
 raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),default=str).encode("utf-8")
 return hashlib.sha256(raw).hexdigest()
def sha_file(path):
 h=hashlib.sha256()
 with pathlib.Path(path).open("rb") as f:
  while True:
   chunk=f.read(1024*1024)
   if not chunk: break
   h.update(chunk)
 return h.hexdigest()
def tree_fingerprint(root):
 root=pathlib.Path(root).resolve(strict=True);entries=[]
 for item in sorted(root.rglob("*"),key=lambda p:p.relative_to(root).as_posix()):
  rel=item.relative_to(root).as_posix()
  if item.is_symlink():
   target=os.readlink(item)
   if not target or "\x00" in target or pathlib.Path(target).is_absolute(): raise RuntimeError("runtime tree contains unsupported symbolic link: "+rel)
   resolved=(item.parent/target).resolve(strict=True)
   try: resolved.relative_to(root)
   except ValueError as e: raise RuntimeError("runtime tree symbolic link escapes tree: "+rel) from e
   entries.append({"kind":"symlink","path":rel,"target":target});continue
  if item.is_dir(): continue
  if not item.is_file(): raise RuntimeError("runtime tree contains non-regular entry: "+rel)
  entries.append({"kind":"file","path":rel,"sha256":sha_file(item)})
 return canonical_hash({"entries":entries})

target_path=pathlib.Path(sys.argv[1]);data=base64.b64decode(sys.argv[2],validate=True);timeout=float(sys.argv[3]);launch=json.loads(base64.b64decode(sys.argv[4],validate=True).decode("utf-8"))
expected_target=launch.get("target_sha256")
if sha_file(target_path)!=expected_target: raise RuntimeError("target identity changed before execution")
runtime=launch.get("runtime");runtime_fp=launch.get("runtime_fingerprint")
if not isinstance(runtime,dict) or canonical_hash(runtime)!=runtime_fp: raise RuntimeError("runtime descriptor fingerprint mismatch")
for artifact in runtime.get("runtime_artifacts",[]):
 role=artifact.get("role");path=artifact.get("path");expected=artifact.get("sha256")
 if not isinstance(path,str) or not isinstance(expected,str): raise RuntimeError("runtime artifact descriptor malformed")
 actual=tree_fingerprint(path) if role=="sysroot" else sha_file(path)
 if actual!=expected: raise RuntimeError("runtime artifact identity changed before execution: "+str(role))
argv=launch.get("argv")
if not isinstance(argv,list) or not argv or any(not isinstance(x,str) or not x or "\x00" in x for x in argv): raise RuntimeError("launch argv malformed")
launch_fp=canonical_hash({"target_sha256":expected_target,"runtime_fingerprint":runtime_fp,"argv":argv})
if launch_fp!=launch.get("launch_fingerprint"): raise RuntimeError("launch fingerprint mismatch")
body={"schema_version":1,"kind":"ctf_target_execution","target_sha256":expected_target,"input_sha256":hashlib.sha256(data).hexdigest(),"runtime":runtime,"runtime_fingerprint":runtime_fp,"launch_argv":argv,"launch_fingerprint":launch_fp,"timed_out":False,"returncode":None,"signal":None,"stdout_b64":"","stderr_b64":"","stdout_sha256":None,"stderr_sha256":None}
try:
 p=subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,shell=False)
 body["returncode"]=p.returncode;body["signal"]=-p.returncode if p.returncode<0 else None
 body["stdout_b64"]=base64.b64encode(p.stdout).decode("ascii");body["stderr_b64"]=base64.b64encode(p.stderr).decode("ascii")
 body["stdout_sha256"]=hashlib.sha256(p.stdout).hexdigest();body["stderr_sha256"]=hashlib.sha256(p.stderr).hexdigest()
except subprocess.TimeoutExpired as e:
 body["timed_out"]=True
 out=e.stdout or b"";err=e.stderr or b""
 body["stdout_b64"]=base64.b64encode(out).decode("ascii");body["stderr_b64"]=base64.b64encode(err).decode("ascii")
 body["stdout_sha256"]=hashlib.sha256(out).hexdigest();body["stderr_sha256"]=hashlib.sha256(err).hexdigest()
print(json.dumps(body,sort_keys=True,separators=(",",":")))'''


def _safe_target(workspace: Path, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target_exec target must be a non-empty relative path")
    raw = Path(value)
    if raw.is_absolute():
        raise ValueError("target_exec target must be workspace-relative")
    resolved = (workspace / raw).resolve(strict=True)
    try:
        relative = resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("target_exec target escapes workspace") from exc
    if not resolved.is_file():
        raise ValueError("target_exec target must be a regular file")
    return relative.as_posix()


class TargetExecutionBackend:
    name = "ctf_target_exec"

    def __init__(
        self,
        delegate,
        *,
        execution_timeout_seconds: float = 5.0,
        runners: Mapping[str, TargetRunner] | None = None,
        default_profile_id: str = "native-default",
        expected_target_sha256: Mapping[str, str] | None = None,
    ):
        self.delegate = delegate
        self.execution_timeout_seconds = float(execution_timeout_seconds)
        if self.execution_timeout_seconds <= 0:
            raise ValueError("execution timeout must be positive")
        configured = dict(runners or {"native-default": NativeRunner("native-default")})
        if not configured:
            raise ValueError("at least one target runner is required")
        for profile_id, runner in configured.items():
            if getattr(runner, "profile_id", None) != profile_id:
                raise ValueError("runner registry key must equal runner.profile_id")
        if default_profile_id not in configured:
            raise ValueError("default target runner profile is not registered")
        self.runners = configured
        self.default_profile_id = default_profile_id
        self.expected_target_sha256 = dict(expected_target_sha256 or {})

    def isolation_attestation(self, *, workspace: Path) -> IsolationAttestation:
        att = self.delegate.isolation_attestation(workspace=workspace)
        evidence = dict(att.evidence)
        evidence.update({
            "semantic_adapter": self.name,
            "delegate_backend": getattr(self.delegate, "name", type(self.delegate).__name__),
            "target_runner_profiles": sorted(self.runners),
        })
        return IsolationAttestation(
            att.filesystem_isolated,
            att.network_isolated,
            att.environment_sanitized,
            att.source,
            evidence,
        )

    def run_argv(self, *, workspace: Path, argv: Sequence[str], timeout_seconds: float, env=None) -> ExecutionResult:
        request = list(argv)
        if len(request) not in (2, 3):
            return ExecutionResult(2, "", "target_exec requires target, input_b64, and optional runtime_profile_id")
        root = Path(workspace).resolve()
        try:
            target = _safe_target(root, request[0])
            raw = base64.b64decode(request[1], validate=True)
            profile_id = request[2] if len(request) == 3 else self.default_profile_id
            if profile_id not in self.runners:
                raise ValueError("requested target runtime profile is not registered")
            launch = self.runners[profile_id].build_launch(
                workspace=root,
                target_relpath=target,
                expected_target_sha256=self.expected_target_sha256.get(target),
            )
            payload = {
                "target_sha256": launch.target_sha256,
                "runtime": launch.runtime_descriptor(),
                "runtime_fingerprint": launch.runtime_fingerprint(),
                "argv": list(launch.argv),
                "launch_fingerprint": launch.launch_fingerprint(),
            }
        except Exception as exc:
            return ExecutionResult(2, "", f"invalid target_exec request: {type(exc).__name__}: {exc}")

        encoded = base64.b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode("ascii")
        helper = [
            "/usr/bin/python3",
            "-c",
            _EXEC_SCRIPT,
            f"./{target}",
            base64.b64encode(raw).decode("ascii"),
            repr(self.execution_timeout_seconds),
            encoded,
        ]
        return self.delegate.run_argv(
            workspace=root,
            argv=helper,
            timeout_seconds=max(float(timeout_seconds), self.execution_timeout_seconds + 1.0),
            env=env,
        )

    def run_shell(self, **kwargs):
        raise RuntimeError("TargetExecutionBackend does not expose arbitrary shell execution")

    def open_argv_session(self, **kwargs):
        raise RuntimeError("TargetExecutionBackend does not expose persistent sessions")


def make_target_exec_tool(
    workspace: str | Path,
    *,
    backend,
    timeout_seconds: float = 8.0,
    execution_timeout_seconds: float = 5.0,
    runners: Mapping[str, TargetRunner] | None = None,
    default_profile_id: str = "native-default",
    expected_target_sha256: Mapping[str, str] | None = None,
) -> SandboxedArgvToolSpec:
    adapter = TargetExecutionBackend(
        backend,
        execution_timeout_seconds=execution_timeout_seconds,
        runners=runners,
        default_profile_id=default_profile_id,
        expected_target_sha256=expected_target_sha256,
    )
    return SandboxedArgvToolSpec(
        name="target_exec",
        description="Execute one admitted workspace target with base64 stdin through a registered TargetRunner profile; returns runtime-bound structured observation.",
        execution_backend=adapter,
        execution_workspace=Path(workspace).resolve(),
        timeout_seconds=timeout_seconds,
        argv_arg="argv",
        side_effect=SideEffect.WRITE,
        idempotent=False,
        failure_modes=["invalid_target", "invalid_input", "invalid_runtime_profile", "runtime_identity_mismatch", "execution_timeout", "sandbox_violation"],
        provenance={"kind": "runtime_bound_target_execution", "schema": "ctf_target_execution.v1"},
        require_zero_exit=True,
    )
