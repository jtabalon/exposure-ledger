import pytest
from exposure_ledger import (
    ActionLevel,
    AssessmentOperation,
    AssessmentPolicyRequest,
    AssistanceClass,
    AuthorizationStatus,
    CyberPolicy,
    OperationClassification,
    PolicyResult,
)


def test_benign_read_of_an_authorized_target_is_allowed_and_auditable() -> None:
    decision = CyberPolicy.decide(
        AssessmentPolicyRequest(
            assistance_class=AssistanceClass.C0,
            action_level=ActionLevel.A1,
            target_scope="bundled synthetic fixture",
            authorization_scope="local operator",
            authorization_status=AuthorizationStatus.CONFIRMED,
        )
    )

    assert decision.result is PolicyResult.ALLOWED
    assert decision.standard_version == "0.1"
    assert decision.rule_version == "assessment-request-v1"
    assert decision.assistance_class is AssistanceClass.C0
    assert decision.action_level is ActionLevel.A1
    assert decision.target_scope == "bundled synthetic fixture"
    assert decision.authorization_scope == "local operator"
    assert decision.reason == "C0 assistance at A1 is permitted for the confirmed target scope."


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
    decision = CyberPolicy.decide(
        AssessmentPolicyRequest(
            assistance_class=assistance_class,
            action_level=action_level,
            target_scope="public repository example/project at abc123",
            authorization_scope="operator-approved public repository",
            authorization_status=AuthorizationStatus.CONFIRMED,
        )
    )

    assert decision.result is expected


@pytest.mark.parametrize(
    ("policy_request", "reason"),
    [
        (
            AssessmentPolicyRequest(
                assistance_class=None,
                action_level=ActionLevel.A1,
                target_scope="public repository example/project at abc123",
                authorization_scope="operator-approved public repository",
                authorization_status=AuthorizationStatus.CONFIRMED,
            ),
            "Assistance Class is materially uncertain; the Assessment request is blocked.",
        ),
        (
            AssessmentPolicyRequest(
                assistance_class=AssistanceClass.C1,
                action_level=None,
                target_scope="public repository example/project at abc123",
                authorization_scope="operator-approved public repository",
                authorization_status=AuthorizationStatus.CONFIRMED,
            ),
            "Action Level is materially uncertain; the Assessment request is blocked.",
        ),
        (
            AssessmentPolicyRequest(
                assistance_class=AssistanceClass.C1,
                action_level=ActionLevel.A1,
                target_scope="public repository example/project at abc123",
                authorization_scope=None,
                authorization_status=AuthorizationStatus.UNCERTAIN,
            ),
            "Authorization is materially uncertain; the Assessment request is blocked.",
        ),
    ],
)
def test_material_uncertainty_fails_closed(
    policy_request: AssessmentPolicyRequest,
    reason: str,
) -> None:
    decision = CyberPolicy.decide(policy_request)

    assert decision.result is PolicyResult.BLOCKED
    assert decision.reason == reason


def test_multi_step_escalation_uses_the_strictest_classification() -> None:
    decision = CyberPolicy.decide(
        AssessmentPolicyRequest(
            assistance_class=AssistanceClass.C0,
            action_level=ActionLevel.A0,
            target_scope="public repository example/project at abc123",
            authorization_scope="operator-approved public repository",
            authorization_status=AuthorizationStatus.CONFIRMED,
            operation_chain=(
                OperationClassification(AssistanceClass.C1, ActionLevel.A1),
                OperationClassification(AssistanceClass.C2, ActionLevel.A4),
            ),
        )
    )

    assert decision.result is PolicyResult.BLOCKED
    assert decision.assistance_class is AssistanceClass.C2
    assert decision.action_level is ActionLevel.A4
    assert decision.reason == (
        "C2 assistance and A4 action in the operation chain are outside the first-release "
        "capability ceiling."
    )


def test_assessment_operations_are_classified_by_application_owned_rules() -> None:
    decision = CyberPolicy.decide_assessment(
        operation=AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT,
        target_scope="bundled synthetic fixture",
        authorization_scope="local operator",
        authorization_status=AuthorizationStatus.CONFIRMED,
    )

    assert decision.assistance_class is AssistanceClass.C1
    assert decision.action_level is ActionLevel.A1
    assert decision.result is PolicyResult.ALLOWED


def test_unknown_assessment_operation_fails_closed() -> None:
    decision = CyberPolicy.decide_assessment(
        operation="unrecognized_operation",
        target_scope="bundled synthetic fixture",
        authorization_scope="local operator",
        authorization_status=AuthorizationStatus.CONFIRMED,
    )

    assert decision.result is PolicyResult.BLOCKED
    assert decision.reason == (
        "Assistance Class is materially uncertain; the Assessment request is blocked."
    )
