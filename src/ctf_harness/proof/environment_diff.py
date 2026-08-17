from dataclasses import dataclass
@dataclass(frozen=True)
class EnvironmentDiff:
    differences:tuple[tuple[str,object,object],...]
    @property
    def adaptation_required(self)->bool:return bool(self.differences)
def compare_environments(local:dict,remote:dict)->EnvironmentDiff:
    keys=sorted(set(local)|set(remote)); return EnvironmentDiff(tuple((k,local.get(k),remote.get(k)) for k in keys if local.get(k)!=remote.get(k)))
