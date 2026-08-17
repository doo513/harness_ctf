from __future__ import annotations
import base64,hashlib,json,tempfile
from pathlib import Path
from harness.core.sandbox import LinuxNamespaceSandboxBackend,NetworkPolicy
from harness.core.storage import ArtifactStore
from harness.core.tools import ActionRuntime,ToolCall
from ctf_harness.tools.crash import make_crash_probe_tool
from ctf_harness.verifiers.pwn.crash import CrashReproducibleVerifier

def main()->int:
 with tempfile.TemporaryDirectory(prefix="ctf-crash-probe-") as td:
  root=Path(td);workspace=root/"workspace";workspace.mkdir();target=workspace/"crash.sh";target.write_text("#!/bin/sh\nkill -SEGV $$\n",encoding="utf-8");target.chmod(0o755)
  data=b"same-input\n";b64=base64.b64encode(data).decode("ascii");target_sha=hashlib.sha256(target.read_bytes()).hexdigest();input_sha=hashlib.sha256(data).hexdigest()
  backend=LinuxNamespaceSandboxBackend(network_policy=NetworkPolicy.DENY);att=backend.isolation_attestation(workspace=workspace)
  if att.source!="runtime_probe":raise RuntimeError(f"live namespace attestation unavailable: {att.evidence}")
  runtime=ActionRuntime({"pwn_crash_probe":make_crash_probe_tool(workspace,backend=backend)},strict_isolation=True,network_policy=NetworkPolicy.DENY)
  results=[runtime.execute(ToolCall("pwn_crash_probe",{"argv":["crash.sh",b64]})) for _ in range(2)];assert all(r.ok for r in results),[r.error for r in results]
  store=ArtifactStore(root/"artifacts");refs=[];obs=[]
  for i,r in enumerate(results):
   ref=store.put_json(f"crash-{i}.json",{"ok":r.ok,"output":r.output,"error":r.error});refs.append(ref);obs.append({"source":"pwn_crash_probe","ok":True,"artifact_ref":ref})
  ctx={"state":{"artifacts":refs,"evidence_refs":refs,"observations":obs},"artifact_root":str(store.root),"claim_evidence_refs":refs,"claim_key":"ctf.pwn.crash_reproducible"};candidate={"target_sha256":target_sha,"input_sha256":input_sha,"signal":11};v=CrashReproducibleVerifier();accepted=v.verify(candidate,ctx);assert accepted.verified,accepted.reason;assert not v.verify({**candidate,"signal":6},ctx).verified
  one=dict(ctx);one["claim_evidence_refs"]=[refs[0]];assert not v.verify(candidate,one).verified
  print(json.dumps({"probe":"pwn-crash-semantic-live","all_passed":True,"attestation_source":att.source,"signal":11,"evidence_count":2,"target_sha256":target_sha,"input_sha256":input_sha},sort_keys=True,indent=2))
 return 0
if __name__=="__main__":raise SystemExit(main())
