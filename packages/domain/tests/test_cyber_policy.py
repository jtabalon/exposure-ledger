import pytest
from exposure_ledger import (
    ActionLevel,
    AssessmentOperation,
    AssessmentRequest,
    AssistanceClass,
    AuthorizationStatus,
    CyberPolicy,
    PolicyResult,
)


def test_synthetic_assessment_is_allowed_and_auditable() -> None:
    decision = CyberPolicy.decide(
        AssessmentRequest(
            operation=AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT,
            target_scope="bundled synthetic fixture",
            authorization_scope="local operator",
            authorization_status=AuthorizationStatus.CONFIRMED,
        )
    )

    assert decision.result is PolicyResult.ALLOWED
    assert decision.standard_version == "0.1"
    assert decision.rule_version == "assessment-request-v1"
    assert decision.assistance_class is AssistanceClass.C1
    assert decision.action_level is ActionLevel.A1
    assert decision.target_scope == "bundled synthetic fixture"
    assert decision.authorization_scope == "local operator"
    assert decision.reason == "C1 assistance at A1 is permitted for the confirmed target scope."


@pytest.mark.parametrize(
    ("assistance_class", "action_level", "expected"),
    [
        (assistance_class, action_level, expected)
        for assistance_class, action_expectations in {
            AssistanceClass.C0: {
                ActionLevel.A0: PolicyResult.ALLOWED,
                ActionLevel.A1: PolicyResult.ALLOWED,
                ActionLevel.A2: PolicyResult.RESTRICTED,
                ActionLevel.A3: PolicyResult.BLOCKED,
                ActionLevel.A4: PolicyResult.BLOCKED,
            },
            AssistanceClass.C1: {
                ActionLevel.A0: PolicyResult.ALLOWED,
                ActionLevel.A1: PolicyResult.ALLOWED,
                ActionLevel.A2: PolicyResult.RESTRICTED,
                ActionLevel.A3: PolicyResult.BLOCKED,
                ActionLevel.A4: PolicyResult.BLOCKED,
            },
            AssistanceClass.C2: dict.fromkeys(ActionLevel, PolicyResult.BLOCKED),
            AssistanceClass.C3: dict.fromkeys(ActionLevel, PolicyResult.BLOCKED),
        }.items()
        for action_level, expected in action_expectations.items()
    ],
)
def test_decision_table_applies_the_first_release_capability_ceiling(
    assistance_class: AssistanceClass,
    action_level: ActionLevel,
    expected: PolicyResult,
) -> None:
    assert CyberPolicy.decision_table()[assistance_class, action_level] is expected


@pytest.mark.parametrize(
    ("policy_request", "reason"),
    [
        (
            AssessmentRequest(
                operation=AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT,
                target_scope="bundled synthetic fixture",
                authorization_scope="local operator",
                authorization_status=AuthorizationStatus.CONFIRMED,
                operation_chain=("unrecognized_operation",),
            ),
            (
                "Assistance Class or Action Level is materially uncertain; the Assessment "
                "request is conservatively classified C3/A4 and blocked."
            ),
        ),
        (
            AssessmentRequest(
                operation=AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT,
                target_scope="bundled synthetic fixture",
                authorization_scope=None,
                authorization_status=AuthorizationStatus.UNCERTAIN,
            ),
            "Authorization is materially uncertain; the Assessment request is blocked.",
        ),
    ],
)
def test_material_uncertainty_fails_closed(
    policy_request: AssessmentRequest,
    reason: str,
) -> None:
    decision = CyberPolicy.decide(policy_request)

    assert decision.result is PolicyResult.BLOCKED
    assert decision.reason == reason
    if "unrecognized_operation" in policy_request.operation_chain:
        assert decision.assistance_class is AssistanceClass.C3
        assert decision.action_level is ActionLevel.A4
    else:
        assert decision.assistance_class is AssistanceClass.C1
        assert decision.action_level is ActionLevel.A1


def test_multi_step_escalation_uses_the_strictest_classification() -> None:
    decision = CyberPolicy.decide(
        AssessmentRequest(
            operation=AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT,
            target_scope="bundled synthetic fixture",
            authorization_scope="local operator",
            authorization_status=AuthorizationStatus.CONFIRMED,
            operation_chain=(AssessmentOperation.SCAN_ARBITRARY_HOSTS,),
        )
    )

    assert decision.result is PolicyResult.BLOCKED
    assert decision.assistance_class is AssistanceClass.C2
    assert decision.action_level is ActionLevel.A4
    assert decision.reason == (
        "C2 assistance and A4 action in the operation chain are outside the first-release "
        "capability ceiling."
    )
