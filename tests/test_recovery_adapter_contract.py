import pytest

from ctf_harness.recovery.adapter import to_core_failure


def test_retry_safe_requires_explicit_boolean():
    with pytest.raises(ValueError, match="retry_safe must be a boolean"):
        to_core_failure(
            "ENVIRONMENT_MISMATCH",
            message="controlled mismatch",
            retry_safe="false",
        )
