"""Deterministic cyber-policy decisions for Assessment requests."""

from dataclasses import dataclass
from enum import StrEnum

CYBER_POLICY_STANDARD_VERSION = "0.1"
ASSESSMENT_POLICY_RULE_VERSION = "assessment-request-v1"


class AssistanceClass(StrEnum):
    C0 = "C0"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"


class ActionLevel(StrEnum):
    A0 = "A0"
    A1 = "A1"
    A2 = "A2"
    A3 = "A3"
    A4 = "A4"


class AssessmentOperation(StrEnum):
    SYNTHETIC_EXPOSURE_ASSESSMENT = "synthetic_exposure_assessment"
    SUMMARIZE_PUBLIC_ADVISORY = "summarize_public_advisory"
    DRAFT_DEPENDENCY_PATCH = "draft_dependency_patch"
    GENERATE_EXPLOIT = "generate_exploit"
    SCAN_ARBITRARY_HOSTS = "scan_arbitrary_hosts"
    EXTRACT_CREDENTIALS = "extract_credentials"


class AuthorizationStatus(StrEnum):
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"
    DENIED = "denied"


class PolicyResult(StrEnum):
    ALLOWED = "allowed"
    RESTRICTED = "restricted"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class OperationClassification:
    assistance_class: AssistanceClass
    action_level: ActionLevel


_OPERATION_CLASSIFICATIONS = {
    AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT: OperationClassification(
        AssistanceClass.C1, ActionLevel.A1
    ),
    AssessmentOperation.SUMMARIZE_PUBLIC_ADVISORY: OperationClassification(
        AssistanceClass.C0, ActionLevel.A0
    ),
    AssessmentOperation.DRAFT_DEPENDENCY_PATCH: OperationClassification(
        AssistanceClass.C0, ActionLevel.A2
    ),
    AssessmentOperation.GENERATE_EXPLOIT: OperationClassification(
        AssistanceClass.C2, ActionLevel.A2
    ),
    AssessmentOperation.SCAN_ARBITRARY_HOSTS: OperationClassification(
        AssistanceClass.C2, ActionLevel.A4
    ),
    AssessmentOperation.EXTRACT_CREDENTIALS: OperationClassification(
        AssistanceClass.C3, ActionLevel.A4
    ),
}


@dataclass(frozen=True, slots=True)
class AssessmentPolicyRequest:
    assistance_class: AssistanceClass | None
    action_level: ActionLevel | None
    target_scope: str | None
    authorization_scope: str | None
    authorization_status: AuthorizationStatus
    operation_chain: tuple[OperationClassification, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    standard_version: str
    assistance_class: AssistanceClass | None
    action_level: ActionLevel | None
    target_scope: str | None
    authorization_scope: str | None
    result: PolicyResult
    rule_version: str
    reason: str


class CyberPolicy:
    """Apply the project-owned first-release capability ceiling."""

    @classmethod
    def decide_assessment(
        cls,
        *,
        operation: AssessmentOperation | str,
        target_scope: str | None,
        authorization_scope: str | None,
        authorization_status: AuthorizationStatus,
        operation_chain: tuple[AssessmentOperation | str, ...] = (),
    ) -> PolicyDecision:
        classification = _classify_operation(operation)
        chain = tuple(_classify_operation(item) for item in operation_chain)
        if classification is None or any(item is None for item in chain):
            return cls.decide(
                AssessmentPolicyRequest(
                    assistance_class=None,
                    action_level=None,
                    target_scope=target_scope,
                    authorization_scope=authorization_scope,
                    authorization_status=authorization_status,
                )
            )
        return cls.decide(
            AssessmentPolicyRequest(
                assistance_class=classification.assistance_class,
                action_level=classification.action_level,
                target_scope=target_scope,
                authorization_scope=authorization_scope,
                authorization_status=authorization_status,
                operation_chain=tuple(item for item in chain if item is not None),
            )
        )

    @staticmethod
    def decide(request: AssessmentPolicyRequest) -> PolicyDecision:
        if request.assistance_class is None:
            return _decision(
                request,
                result=PolicyResult.BLOCKED,
                reason=(
                    "Assistance Class is materially uncertain; the Assessment request is blocked."
                ),
            )
        if request.action_level is None:
            return _decision(
                request,
                result=PolicyResult.BLOCKED,
                reason="Action Level is materially uncertain; the Assessment request is blocked.",
            )
        if not request.target_scope or not request.target_scope.strip():
            return _decision(
                request,
                result=PolicyResult.BLOCKED,
                reason="Target scope is materially uncertain; the Assessment request is blocked.",
            )
        if (
            request.authorization_status is AuthorizationStatus.UNCERTAIN
            or not request.authorization_scope
            or not request.authorization_scope.strip()
        ):
            return _decision(
                request,
                result=PolicyResult.BLOCKED,
                reason="Authorization is materially uncertain; the Assessment request is blocked.",
            )
        if request.authorization_status is AuthorizationStatus.DENIED:
            return _decision(
                request,
                result=PolicyResult.BLOCKED,
                reason=(
                    "Authorization is denied for the target scope; the Assessment request is "
                    "blocked."
                ),
            )

        classifications = (
            OperationClassification(request.assistance_class, request.action_level),
            *request.operation_chain,
        )
        assistance_class = max(
            (classification.assistance_class for classification in classifications),
            key=list(AssistanceClass).index,
        )
        action_level = max(
            (classification.action_level for classification in classifications),
            key=list(ActionLevel).index,
        )

        if assistance_class in {AssistanceClass.C2, AssistanceClass.C3} and action_level in {
            ActionLevel.A3,
            ActionLevel.A4,
        }:
            request_part = "operation chain" if request.operation_chain else "Assessment request"
            return _decision(
                request,
                assistance_class=assistance_class,
                action_level=action_level,
                result=PolicyResult.BLOCKED,
                reason=(
                    f"{assistance_class} assistance and {action_level} action in the "
                    f"{request_part} are outside the first-release capability ceiling."
                ),
            )
        if assistance_class in {AssistanceClass.C2, AssistanceClass.C3}:
            return _decision(
                request,
                assistance_class=assistance_class,
                action_level=action_level,
                result=PolicyResult.BLOCKED,
                reason=(
                    f"{assistance_class} assistance is outside the first-release capability "
                    "ceiling."
                ),
            )
        if action_level in {ActionLevel.A3, ActionLevel.A4}:
            return _decision(
                request,
                assistance_class=assistance_class,
                action_level=action_level,
                result=PolicyResult.BLOCKED,
                reason=f"{action_level} actions are prohibited by the first-release policy.",
            )
        if action_level is ActionLevel.A2:
            return _decision(
                request,
                assistance_class=assistance_class,
                action_level=action_level,
                result=PolicyResult.RESTRICTED,
                reason="A2 actions are restricted pending the approved human-review milestone.",
            )

        return _decision(
            request,
            assistance_class=assistance_class,
            action_level=action_level,
            result=PolicyResult.ALLOWED,
            reason=(
                f"{assistance_class} assistance at {action_level} is permitted for the "
                "confirmed target scope."
            ),
        )


def _decision(
    request: AssessmentPolicyRequest,
    *,
    result: PolicyResult,
    reason: str,
    assistance_class: AssistanceClass | None = None,
    action_level: ActionLevel | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        standard_version=CYBER_POLICY_STANDARD_VERSION,
        assistance_class=assistance_class or request.assistance_class,
        action_level=action_level or request.action_level,
        target_scope=request.target_scope,
        authorization_scope=request.authorization_scope,
        result=result,
        rule_version=ASSESSMENT_POLICY_RULE_VERSION,
        reason=reason,
    )


def _classify_operation(
    operation: AssessmentOperation | str,
) -> OperationClassification | None:
    try:
        normalized = AssessmentOperation(operation)
    except ValueError:
        return None
    return _OPERATION_CLASSIFICATIONS[normalized]
