from dataclasses import dataclass
from ctf_harness.facts import ctf_fact_views

@dataclass
class FakeClaim:
    value: object
    evidence_refs: tuple[str, ...] = ()
    authority: str = "verifier"

class FakeState:
    facts = {
        "ctf.pwn.arch": FakeClaim("x86_64", ("artifact://1",)),
        "software.test": FakeClaim("pass", ("artifact://2",)),
    }

def test_ctf_fact_view_is_read_only_projection():
    views = ctf_fact_views(FakeState())
    assert len(views) == 1
    assert views[0].key == "ctf.pwn.arch"
    assert views[0].value == "x86_64"
    assert views[0].evidence_refs == ("artifact://1",)
    assert not hasattr(views[0], "commit")
    assert not hasattr(views[0], "update")
