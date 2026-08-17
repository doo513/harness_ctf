MILESTONES=(("artifact_profiled",{"ctf.pwn.arch"}),("primitive_verified",{"ctf.pwn.crash_reproducible"}),("control_verified",{"ctf.pwn.control_flow"}),("local_exploit_verified",{"ctf.pwn.local_exploit"}),("environment_compatible",{"ctf.environment.compatible"}),("remote_behavior_verified",{"ctf.pwn.remote_behavior"}))
def pwn_progress_snapshot(verified_keys,*,completed:bool=False):
    keys=set(verified_keys);achieved=[name for name,required in MILESTONES if required.issubset(keys)]
    if completed:achieved.append("flag_accepted")
    return {"milestones":achieved,"score":float(len(achieved))}
