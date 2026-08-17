from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ctf_harness.host_tools.ida import IdaCapabilityProvider
from ctf_harness.tools.capabilities import CapabilityCatalog, CapabilityResult


class FakeProvider:
    capabilities = ("decompile_function",)

    def __init__(self, provider_id: str, priority: int, *, available=True, fail=False):
        self.provider_id = provider_id
        self.revision = "r1"
        self.priority = priority
        self._available = available
        self.fail = fail

    def available(self):
        return self._available

    def invoke(self, capability, args):
        if self.fail:
            raise RuntimeError("controlled failure")
        return CapabilityResult(capability, self.provider_id, self.revision, {"args": args})

    def descriptor(self):
        return {
            "provider_id": self.provider_id,
            "revision": self.revision,
            "capabilities": list(self.capabilities),
            "priority": self.priority,
        }


class FakeTransport:
    def __init__(self):
        self.requests = []

    def available(self):
        return True

    def request(self, payload):
        self.requests.append(payload)
        return {"decompile": "int main(void) { return 0; }"}

    def descriptor(self):
        return {"transport": "fake", "revision": "fixture"}


def test_capability_catalog_fallback_is_harness_owned() -> None:
    catalog = CapabilityCatalog((
        FakeProvider("preferred", 100, fail=True),
        FakeProvider("fallback", 50),
    ))
    result = catalog.execute("decompile_function", {"symbol": "main"})
    assert result["provider_id"] == "fallback"
    assert result["truth_authority"] == "none"
    assert result["fallback_failures"] == [{"provider_id": "preferred", "error_class": "RuntimeError"}]
    tool = catalog.make_tool()
    assert tool.name == "host_capability"
    assert tool.provenance["truth_authority"] == "none"
    assert catalog.descriptor()["execution_authority"] == "base_action_runtime_only_when_tool_registered"


def test_ida_provider_revalidates_admitted_artifact_and_returns_observation(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"ELF-fixture")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    transport = FakeTransport()
    provider = IdaCapabilityProvider(
        workspace=tmp_path,
        expected_sha256={"chal": digest},
        transport=transport,
    )
    result = provider.invoke("decompile_function", {"artifact_ref": "chal", "function": "main"})
    rendered = result.descriptor()
    assert rendered["provider_id"] == "ida"
    assert rendered["truth_authority"] == "none"
    assert rendered["payload"]["output_authority"] == "observation_only"
    request = transport.requests[0]
    assert request["artifact_ref"] == "chal"
    assert request["artifact_sha256"] == digest
    assert request["args"] == {"function": "main"}

    target.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="identity changed"):
        provider.invoke("decompile_function", {"artifact_ref": "chal", "function": "main"})


def test_ida_provider_rejects_unadmitted_artifact(tmp_path: Path) -> None:
    target = tmp_path / "chal"
    target.write_bytes(b"x")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    provider = IdaCapabilityProvider(
        workspace=tmp_path,
        expected_sha256={"chal": digest},
        transport=FakeTransport(),
    )
    with pytest.raises(ValueError, match="not admitted"):
        provider.invoke("list_strings", {"artifact_ref": "other"})
