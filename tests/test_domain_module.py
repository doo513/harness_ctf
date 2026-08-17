from ctf_harness.domains.module import DomainModuleRegistry
from ctf_harness.domains.pwn import PwnDomainModule


def test_pwn_domain_module_unifies_existing_assets_without_new_authority() -> None:
    module = PwnDomainModule()
    desc = module.descriptor()
    assert desc["domain"] == "pwn"
    assert desc["authority"] == "registration_only"
    assert desc["truth_authority"] == "existing_verifiers_only"
    assert desc["completion_authority"] == "none"
    assert "ctf.pwn.crash_reproducible" in desc["claim_key_prefixes"]
    assert "pwn_crash_reproducible" in desc["verifier_names"]


def test_domain_module_registry_is_not_truth_or_execution_authority() -> None:
    registry = DomainModuleRegistry((PwnDomainModule(),))
    desc = registry.descriptor()
    assert desc["domains"][0]["domain"] == "pwn"
    assert desc["truth_authority"] == "none"
    assert desc["execution_authority"] == "none"
