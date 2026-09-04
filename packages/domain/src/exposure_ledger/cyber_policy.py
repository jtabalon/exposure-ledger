"""Deterministic cyber-policy decisions for Assessment requests."""

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

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
    PUBLIC_REPOSITORY_EXPOSURE_ASSESSMENT = "public_repository_exposure_assessment"
    PUBLIC_OSV_LOOKUP = "public_osv_lookup"
    PUBLIC_FIRST_PARTY_ADVISORY_LOOKUP = "public_first_party_advisory_lookup"
    PUBLIC_CISA_KEV_LOOKUP = "public_cisa_kev_lookup"
    PUBLIC_FIRST_EPSS_LOOKUP = "public_first_epss_lookup"
    EMBED_RETRIEVED_EVIDENCE = "embed_retrieved_evidence"
    PRODUCE_EXPOSURE_RECOMMENDATION = "produce_exposure_recommendation"
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
class AssessmentRequest:
    operation: AssessmentOperation | str
    target_scope: str | None
    authorization_scope: str | None
    authorization_status: AuthorizationStatus
    operation_chain: tuple[AssessmentOperation | str, ...] = ()


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    standard_version: str
    assistance_class: AssistanceClass
    action_level: ActionLevel
    target_scope: str | None
    authorization_scope: str | None
    result: PolicyResult
    rule_version: str
    reason: str


@dataclass(frozen=True, slots=True)
class _Classification:
    assistance_class: AssistanceClass
    action_level: ActionLevel


_OPERATION_CLASSIFICATIONS: Final = {
    AssessmentOperation.SYNTHETIC_EXPOSURE_ASSESSMENT: _Classification(
        AssistanceClass.C1, ActionLevel.A1
    ),
    AssessmentOperation.PUBLIC_REPOSITORY_EXPOSURE_ASSESSMENT: _Classification(
        AssistanceClass.C1, ActionLevel.A1
    ),
    AssessmentOperation.PUBLIC_OSV_LOOKUP: _Classification(AssistanceClass.C1, ActionLevel.A1),
    AssessmentOperation.PUBLIC_FIRST_PARTY_ADVISORY_LOOKUP: _Classification(
        AssistanceClass.C1, ActionLevel.A1
    ),
    AssessmentOperation.PUBLIC_CISA_KEV_LOOKUP: _Classification(AssistanceClass.C1, ActionLevel.A1),
    AssessmentOperation.PUBLIC_FIRST_EPSS_LOOKUP: _Classification(
        AssistanceClass.C1, ActionLevel.A1
    ),
    AssessmentOperation.EMBED_RETRIEVED_EVIDENCE: _Classification(
        AssistanceClass.C1, ActionLevel.A1
    ),
    AssessmentOperation.PRODUCE_EXPOSURE_RECOMMENDATION: _Classification(
        AssistanceClass.C1, ActionLevel.A0
    ),
    AssessmentOperation.SUMMARIZE_PUBLIC_ADVISORY: _Classification(
        AssistanceClass.C0, ActionLevel.A0
    ),
    AssessmentOperation.DRAFT_DEPENDENCY_PATCH: _Classification(AssistanceClass.C0, ActionLevel.A2),
    AssessmentOperation.GENERATE_EXPLOIT: _Classification(AssistanceClass.C2, ActionLevel.A2),
    AssessmentOperation.SCAN_ARBITRARY_HOSTS: _Classification(AssistanceClass.C2, ActionLevel.A4),
    AssessmentOperation.EXTRACT_CREDENTIALS: _Classification(AssistanceClass.C3, ActionLevel.A4),
}

_ASSISTANCE_ORDER: Final = {value: index for index, value in enumerate(AssistanceClass)}
_ACTION_ORDER: Final = {value: index for index, value in enumerate(ActionLevel)}


class CyberPolicy:
    """Classify operations and apply the project-owned capability ceiling."""

    @staticmethod
    def decision_table() -> MappingProxyType[tuple[AssistanceClass, ActionLevel], PolicyResult]:
        """Expose the immutable standard matrix for auditing and safety evaluation."""
        return MappingProxyType(
            {
                (assistance_class, action_level): _result_for(assistance_class, action_level)
                for assistance_class in AssistanceClass
                for action_level in ActionLevel
            }
        )

    @staticmethod
    def decide(request: AssessmentRequest) -> PolicyDecision:
        classifications = tuple(
            _classify_operation(operation)
            for operation in (request.operation, *request.operation_chain)
        )
        known_classifications = tuple(
            classification for classification in classifications if classification is not None
        )
        assistance_class = max(
            (classification.assistance_class for classification in known_classifications),
            key=_ASSISTANCE_ORDER.__getitem__,
            default=AssistanceClass.C3,
        )
        action_level = max(
            (classification.action_level for classification in known_classifications),
            key=_ACTION_ORDER.__getitem__,
            default=ActionLevel.A4,
        )
        if any(classification is None for classification in classifications):
            return _decision(
                request,
                assistance_class=AssistanceClass.C3,
                action_level=ActionLevel.A4,
                result=PolicyResult.BLOCKED,
                reason=(
                    "Assistance Class or Action Level is materially uncertain; the Assessment "
                    "request is conservatively classified C3/A4 and blocked."
                ),
            )
        if not request.target_scope or not request.target_scope.strip():
            return _decision(
                request,
                assistance_class=assistance_class,
                action_level=action_level,
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
                assistance_class=assistance_class,
                action_level=action_level,
                result=PolicyResult.BLOCKED,
                reason="Authorization is materially uncertain; the Assessment request is blocked.",
            )
        if request.authorization_status is AuthorizationStatus.DENIED:
            return _decision(
                request,
                assistance_class=assistance_class,
                action_level=action_level,
                result=PolicyResult.BLOCKED,
                reason=(
                    "Authorization is denied for the target scope; the Assessment request is "
                    "blocked."
                ),
            )

        result = _result_for(assistance_class, action_level)
        return _decision(
            request,
            assistance_class=assistance_class,
            action_level=action_level,
            result=result,
            reason=_reason_for(
                assistance_class,
                action_level,
                result,
                composed=bool(request.operation_chain),
            ),
        )


def _result_for(
    assistance_class: AssistanceClass,
    action_level: ActionLevel,
) -> PolicyResult:
    if assistance_class in {AssistanceClass.C2, AssistanceClass.C3}:
        return PolicyResult.BLOCKED
    if action_level in {ActionLevel.A3, ActionLevel.A4}:
        return PolicyResult.BLOCKED
    if action_level is ActionLevel.A2:
        return PolicyResult.RESTRICTED
    return PolicyResult.ALLOWED


def _reason_for(
    assistance_class: AssistanceClass,
    action_level: ActionLevel,
    result: PolicyResult,
    *,
    composed: bool,
) -> str:
    subject = "operation chain" if composed else "Assessment request"
    if assistance_class in {AssistanceClass.C2, AssistanceClass.C3} and action_level in {
        ActionLevel.A3,
        ActionLevel.A4,
    }:
        return (
            f"{assistance_class} assistance and {action_level} action in the {subject} are "
            "outside the first-release capability ceiling."
        )
    if assistance_class in {AssistanceClass.C2, AssistanceClass.C3}:
        return f"{assistance_class} assistance is outside the first-release capability ceiling."
    if action_level in {ActionLevel.A3, ActionLevel.A4}:
        return f"{action_level} actions are prohibited by the first-release policy."
    if result is PolicyResult.RESTRICTED:
        return "A2 actions are restricted pending the approved human-review milestone."
    return (
        f"{assistance_class} assistance at {action_level} is permitted for the confirmed "
        "target scope."
    )


def _decision(
    request: AssessmentRequest,
    *,
    assistance_class: AssistanceClass,
    action_level: ActionLevel,
    result: PolicyResult,
    reason: str,
) -> PolicyDecision:
    return PolicyDecision(
        standard_version=CYBER_POLICY_STANDARD_VERSION,
        assistance_class=assistance_class,
        action_level=action_level,
        target_scope=request.target_scope,
        authorization_scope=request.authorization_scope,
        result=result,
        rule_version=ASSESSMENT_POLICY_RULE_VERSION,
        reason=reason,
    )


def _classify_operation(operation: AssessmentOperation | str) -> _Classification | None:
    try:
        normalized = AssessmentOperation(operation)
    except ValueError:
        return None
    return _OPERATION_CLASSIFICATIONS[normalized]
