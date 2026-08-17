from __future__ import annotations
import hashlib,json,struct
from pathlib import Path
import pytest
from ctf_harness.locking import BaseLock,EXPECTED_BASE_COMMIT
from ctf_harness.manifest.models import ChallengeManifest
from ctf_harness.manifest.fingerprint import manifest_fingerprint
from ctf_harness.admission.artifact import admit_artifact
from ctf_harness.admission.environment import capture_environment
from ctf_harness.recon.pwn import inspect_elf_bytes,inspect_elf
from ctf_harness.tools.recon import make_pwn_recon_handler
from ctf_harness.classification.classifier import assess_from_recon
from ctf_harness.claims.pwn import PWN_CLAIM_SPECS,resolve_claim_spec
from ctf_harness.verifiers.pwn.static import StaticPwnVerifier
from ctf_harness.verifiers.pwn.offset import cyclic,recover_offset
from ctf_harness.proof.models import ProofLevel
from ctf_harness.proof.ladder import proof_level_from_verified_keys
from ctf_harness.proof.environment_diff import compare_environments
from ctf_harness.proof.flag_oracle import ExternalFlagOracle
from ctf_harness.hypotheses.models import Hypothesis,HypothesisStatus
from ctf_harness.hypotheses.pool import HypothesisPool
from ctf_harness.recovery.adapter import map_failure
from ctf_harness.progress.pwn import pwn_progress_snapshot

RUNNER="sha256:"+"a"*64

def root():return Path(__file__).resolve().parents[1]
def elf64(e_type=2,extra=b""):
    d=bytearray(64);d[:4]=b"\x7fELF";d[4]=2;d[5]=1;d[6]=1
    struct.pack_into("<H",d,16,e_type);struct.pack_into("<H",d,18,62);struct.pack_into("<Q",d,24,0x401000);struct.pack_into("<Q",d,32,64);struct.pack_into("<H",d,52,64);struct.pack_into("<H",d,54,56);struct.pack_into("<H",d,56,0)
    return bytes(d)+extra

def test_wp00_pin_and_no_core_fork():
    lock=BaseLock.load(root()/"base_harness.lock.json");lock.validate();assert lock.commit==EXPECTED_BASE_COMMIT;assert lock.branch=="ctf/structured-session-runtime";assert not (root()/"src/harness").exists();assert not (root()/"src/ctf_harness/tools/sessions.py").exists()

def test_wp01_manifest_and_admission(tmp_path):
    p=tmp_path/"c";p.write_bytes(b"abc");a=admit_artifact(p)
    m=ChallengeManifest(challenge_id="p1",event="private",description="x",artifact_refs=(str(p),),runner_image_digest=RUNNER,challenge_revision="r1")
    assert manifest_fingerprint(m,{str(p):a.sha256})==manifest_fingerprint(m,dict({str(p):a.sha256}))
    with pytest.raises(ValueError):manifest_fingerprint(m,{})
    p.write_bytes(b"changed")
    with pytest.raises(ValueError,match="SHA-256 mismatch"):admit_artifact(p,a.sha256)
    link=tmp_path/"link"
    try:link.symlink_to(p)
    except OSError:pytest.skip("symlink unavailable")
    with pytest.raises(ValueError,match="symbolic links"):admit_artifact(link)

def test_wp01_frozen_environment_identity():
    a=capture_environment(runner_image_digest=RUNNER,network_allowed=False,tool_inventory=("gdb","file","gdb"));b=capture_environment(runner_image_digest=RUNNER,network_allowed=False,tool_inventory=("file","gdb"));assert a.digest()==b.digest()
    with pytest.raises(ValueError):ChallengeManifest(challenge_id="x",event="e",description="d",challenge_revision="r",runner_image_digest="latest")

def test_wp03_conservative_recon_and_classification():
    e=inspect_elf_bytes(elf64(2));dyn=inspect_elf_bytes(elf64(3));canary=inspect_elf_bytes(elf64(2,b"__stack_chk_fail"))
    assert e.architecture=="x86_64" and e.pie is False and e.nx is None and e.canary_present is None
    assert dyn.pie is None;assert canary.canary_present is True
    a=assess_from_recon(file_type="ELF");assert a.authoritative is False and a.candidates[0].category=="pwn"

def test_wp03_recon_workspace_confinement(tmp_path):
    w=tmp_path/"w";o=tmp_path/"o";w.mkdir();o.mkdir();(w/"t").write_bytes(elf64());h=make_pwn_recon_handler(w);assert h("t")["architecture"]=="x86_64"
    (o/"s").write_bytes(elf64());link=w/"escape"
    try:link.symlink_to(o/"s")
    except OSError:pytest.skip("symlink unavailable")
    with pytest.raises(ValueError,match="escapes workspace"):h("escape")

def test_wp04_small_vocabulary_and_helpers_fail_closed():
    assert resolve_claim_spec("ctf.pwn.arch") is not None;assert resolve_claim_spec("ctf.pwn.crash_reproducible") is None;assert resolve_claim_spec("ctf.flag_valid") is None
    assert {s.verification_level for s in PWN_CLAIM_SPECS}=={"LOGICAL"}
    snap=inspect_elf_bytes(elf64());v=StaticPwnVerifier();assert v.verify("ctf.pwn.arch","x86_64",snap)[0];assert not v.verify("ctf.pwn.arch","arm",snap)[0];assert not v.verify("ctf.pwn.nx",False,snap)[0];assert not v.verify("ctf.pwn.canary_present",False,snap)[0]
    pat=cyclic(256);assert recover_offset(pat[99:103],pattern_length=256)==99;assert resolve_claim_spec("ctf.pwn.offset") is None

def test_wp05_proof_and_oracle_boundaries():
    assert proof_level_from_verified_keys({"ctf.pwn.remote_behavior"})==ProofLevel.P5_REMOTE;assert proof_level_from_verified_keys({"ctf.pwn.remote_behavior"},completed=False)!=ProofLevel.P6_ACCEPTED;assert proof_level_from_verified_keys(set(),completed=True)==ProofLevel.P6_ACCEPTED
    diff=compare_environments({"libc":"A"},{"libc":"B"});assert diff.adaptation_required
    oracle=ExternalFlagOracle(lambda c:(c=="FLAG{ok}","oracle:1"));r=oracle.submit("c","remote","FLAG{ok}");assert r.accepted and "FLAG{ok}" not in repr(r)

def test_wp06_dedupe():
    h=Hypothesis("h","pwn","bin","overflow","ret","control","ev1");p=HypothesisPool();fp=p.add(h);p.record_failure(fp,"same");assert not p.should_repeat(fp,"same","ev1");assert p.should_repeat(fp,"same","ev2");p.record_failure(fp,"refuted",refuted=True);assert h.status==HypothesisStatus.REFUTED

def test_wp07_recovery_and_non_inferred_progress():
    assert map_failure("ENVIRONMENT_MISMATCH").core_failure=="ENV_ERROR";assert map_failure("FLAG_REJECTED").target=="return_to_proof"
    with pytest.raises(ValueError):map_failure("UNKNOWN")
    assert pwn_progress_snapshot(["ctf.pwn.arch","ctf.pwn.remote_behavior"])=={"milestones":["artifact_profiled","remote_behavior_verified"],"score":2.0};assert pwn_progress_snapshot([],completed=True)=={"milestones":["flag_accepted"],"score":1.0}

def test_wp02_profile_uses_exact_upstream_runtime(tmp_path):
    from harness.core.sandbox import RecordingIsolatedTestBackend
    from harness.core.tools import SandboxedArgvToolSpec,SandboxedSessionToolSpec
    from ctf_harness.profile import VerifiedCTFProfile
    b=RecordingIsolatedTestBackend();tools=VerifiedCTFProfile(workspace=tmp_path,execution_backend=b).tools();assert isinstance(tools["argv"],SandboxedArgvToolSpec);assert isinstance(tools["session"],SandboxedSessionToolSpec);assert tools["argv"].execution_backend is b and tools["session"].execution_backend is b

def test_wp04_registry_names_resolve_to_real_verifiers(tmp_path):
    from harness.core.sandbox import RecordingIsolatedTestBackend
    from ctf_harness.profile import VerifiedCTFProfile
    p=VerifiedCTFProfile(workspace=tmp_path,execution_backend=RecordingIsolatedTestBackend());r=p.claim_verification_registry();names={v.name for v in p.verifiers()}
    for s in PWN_CLAIM_SPECS:assert set(r.resolve(s.key_prefix).allowed_verifiers)<=names
    assert r.resolve("ctf.web.sqli") is None;assert r.resolve("ctf.pwn.crash_reproducible") is None;assert r.resolve("ctf.flag_valid") is None

def test_wp04_core_bound_evidence_integrity_and_provenance(tmp_path):
    from harness.core.storage import ArtifactStore
    from ctf_harness.verifiers.pwn.core import static_pwn_verifiers
    store=ArtifactStore(tmp_path/"a");snap=inspect_elf_bytes(elf64()).dump();payload={"ok":True,"output":snap,"error":None};ref=store.put_json("r.json",payload)
    ctx={"state":{"artifacts":[ref],"evidence_refs":[ref],"observations":[{"source":"pwn_recon","ok":True,"artifact_ref":ref}]},"artifact_root":str(store.root),"claim_evidence_refs":[ref],"claim_key":"ctf.pwn.arch"};v=next(x for x in static_pwn_verifiers() if x.name=="pwn_arch")
    assert v.verify("x86_64",ctx).verified;assert not v.verify("arm",ctx).verified
    look=dict(ctx);look["state"]={"artifacts":[ref],"evidence_refs":[ref],"observations":[]};assert not v.verify("x86_64",look).verified
    store.resolve(ref).write_text(json.dumps(payload)+"tamper");assert not v.verify("x86_64",ctx).verified

def test_wp04_mixed_artifact_identity_rejected(tmp_path):
    from harness.core.storage import ArtifactStore
    from ctf_harness.verifiers.pwn.core import static_pwn_verifiers
    s=ArtifactStore(tmp_path/"a");one=inspect_elf_bytes(elf64()).dump();two=dict(one);two["artifact_sha256"]="b"*64;r1=s.put_json("1.json",{"ok":True,"output":one,"error":None});r2=s.put_json("2.json",{"ok":True,"output":two,"error":None});v=next(x for x in static_pwn_verifiers() if x.name=="pwn_arch")
    ctx={"state":{"artifacts":[r1,r2],"evidence_refs":[r1,r2],"observations":[{"source":"pwn_recon","ok":True,"artifact_ref":r1},{"source":"pwn_recon","ok":True,"artifact_ref":r2}]},"artifact_root":str(s.root),"claim_evidence_refs":[r1,r2],"claim_key":"ctf.pwn.arch"};assert not v.verify("x86_64",ctx).verified
