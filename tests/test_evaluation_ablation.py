from ctf_harness.evaluation.ablation import AblationFeature, AblationPlan, OperationalFeatureSet


def test_single_factor_ablation_changes_exactly_one_feature_per_arm() -> None:
    plan = AblationPlan.single_factor(
        features=(AblationFeature.PLAYBOOK, AblationFeature.ANALYSIS_SANDBOX, AblationFeature.TYPED_RECOVERY)
    )
    assert [arm.arm_id for arm in plan.arms] == [
        "full",
        "without-playbook",
        "without-analysis_sandbox",
        "without-typed_recovery",
    ]
    baseline = plan.baseline.descriptor()
    for arm in plan.arms[1:]:
        candidate = arm.features.descriptor()
        changed = [key for key in baseline if baseline[key] != candidate[key]]
        assert changed == [arm.ablated_feature.value]
    assert plan.descriptor()["effectiveness_claim"] == "none_until_empirical_runs"
    assert len(plan.fingerprint()) == 64


def test_ablation_cannot_claim_disabled_baseline_feature() -> None:
    baseline = OperationalFeatureSet(playbook=False)
    try:
        AblationPlan.single_factor(baseline=baseline, features=(AblationFeature.PLAYBOOK,))
    except ValueError as exc:
        assert "cannot ablate disabled" in str(exc)
    else:
        raise AssertionError("disabled baseline feature must reject ablation arm")
