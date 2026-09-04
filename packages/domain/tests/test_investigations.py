from dataclasses import replace
from uuid import UUID

import pytest
from exposure_ledger import (
    ActionLevel,
    AssistanceClass,
    AvailableEvidence,
    ClaimDraft,
    ClaimEvidenceCitation,
    ClaimKind,
    ClaimValidator,
    EvidenceFollowUpArguments,
    EvidenceFollowUpProposal,
    EvidenceFollowUpTool,
    EvidenceGap,
    EvidenceGapKind,
    EvidenceRelationship,
    EvidenceType,
    FollowUpAuthorizationContext,
    FollowUpValidator,
    InvestigationBudget,
    InvestigationStoppingCondition,
)

EVIDENCE_ID = UUID("00000000-0000-0000-0000-000000000081")


def test_stopping_conditions_use_a_closed_vocabulary() -> None:
    with pytest.raises(ValueError):
        InvestigationStoppingCondition("misspelled_condition")


def test_wall_time_budget_rejects_subsecond_limits() -> None:
    with pytest.raises(ValueError, match="at least 1s"):
        InvestigationBudget(wall_time_seconds=0.5)


def test_default_revision_limits_match_the_documented_safety_ceilings() -> None:
    budget = InvestigationBudget()

    assert budget.max_generation_model_calls == 5
    assert budget.max_tool_calls == 15
    assert budget.max_graph_transitions == 12
    assert budget.wall_time_seconds == 120


@pytest.mark.parametrize(
    "budget",
    [
        InvestigationBudget(max_generation_model_calls=5),
        InvestigationBudget(max_tool_calls=15),
        InvestigationBudget(max_graph_transitions=12),
        InvestigationBudget(wall_time_seconds=120),
    ],
)
def test_documented_safety_ceilings_are_accepted(budget: InvestigationBudget) -> None:
    assert budget


@pytest.mark.parametrize(
    "budget_arguments",
    [
        {"max_generation_model_calls": 6},
        {"max_tool_calls": 16},
        {"max_graph_transitions": 13},
        {"wall_time_seconds": 121},
    ],
)
def test_revision_limits_cannot_exceed_documented_safety_ceilings(
    budget_arguments: dict[str, int],
) -> None:
    with pytest.raises(ValueError, match="cannot exceed"):
        InvestigationBudget(**budget_arguments)


def test_one_scoped_c1_a1_evidence_search_is_authorized() -> None:
    exposure_id = UUID("00000000-0000-0000-0000-000000000042")
    proposal = EvidenceFollowUpProposal(
        tool=EvidenceFollowUpTool.SEARCH_CAPTURED_EXPOSURE_EVIDENCE,
        target=f"exposure:{exposure_id}",
        arguments=EvidenceFollowUpArguments(
            source_identity="osv",
            evidence_type=EvidenceType.AFFECTED,
        ),
        assistance_class=AssistanceClass.C1,
        action_level=ActionLevel.A1,
    )

    authorization = FollowUpValidator.authorize(
        gap=EvidenceGap(
            identity="gap-fixed-version",
            kind=EvidenceGapKind.INSUFFICIENT,
            description="The first fixed version is not supported by the retrieved passages.",
        ),
        proposal=proposal,
        context=FollowUpAuthorizationContext(
            exposure_id=exposure_id,
            allowed_source_identities=("osv",),
            generation_model_calls=1,
            tool_calls=2,
            graph_transitions=5,
            remaining_wall_time_seconds=90,
            budget=InvestigationBudget(),
        ),
    )

    assert authorization.authorized is True
    assert authorization.executed is False
    assert authorization.reason == "follow_up_authorized"
    assert authorization.policy_decision.assistance_class is AssistanceClass.C1
    assert authorization.policy_decision.action_level is ActionLevel.A1


@pytest.mark.parametrize(
    ("proposal_change", "expected_issue"),
    [
        (
            {"target": "exposure:00000000-0000-0000-0000-000000000099"},
            "follow_up_target_outside_exposure",
        ),
        ({"assistance_class": AssistanceClass.C0}, "follow_up_assistance_class_mismatch"),
        ({"action_level": ActionLevel.A0}, "follow_up_action_level_mismatch"),
    ],
)
def test_follow_up_authorization_independently_rejects_scope_and_classification_changes(
    proposal_change: dict[str, object], expected_issue: str
) -> None:
    exposure_id = UUID("00000000-0000-0000-0000-000000000042")
    proposal = EvidenceFollowUpProposal(
        tool=EvidenceFollowUpTool.SEARCH_CAPTURED_EXPOSURE_EVIDENCE,
        target=f"exposure:{exposure_id}",
        arguments=EvidenceFollowUpArguments("osv", EvidenceType.AFFECTED),
        assistance_class=AssistanceClass.C1,
        action_level=ActionLevel.A1,
    )
    authorization = FollowUpValidator.authorize(
        gap=EvidenceGap("gap", EvidenceGapKind.MISSING, "More evidence is required."),
        proposal=replace(proposal, **proposal_change),
        context=FollowUpAuthorizationContext(
            exposure_id=exposure_id,
            allowed_source_identities=("osv",),
            generation_model_calls=1,
            tool_calls=2,
            graph_transitions=5,
            remaining_wall_time_seconds=90,
            budget=InvestigationBudget(),
        ),
    )

    assert authorization.authorized is False
    assert expected_issue in authorization.issues


def test_follow_up_authorization_rejects_unenumerated_arguments() -> None:
    exposure_id = UUID("00000000-0000-0000-0000-000000000042")
    authorization = FollowUpValidator.authorize(
        gap=EvidenceGap("gap", "invented", "More evidence is required."),
        proposal=EvidenceFollowUpProposal(
            tool=EvidenceFollowUpTool.SEARCH_CAPTURED_EXPOSURE_EVIDENCE,
            target=f"exposure:{exposure_id}",
            arguments=EvidenceFollowUpArguments("attacker", "run_shell"),
            assistance_class=AssistanceClass.C1,
            action_level=ActionLevel.A1,
        ),
        context=FollowUpAuthorizationContext(
            exposure_id=exposure_id,
            allowed_source_identities=("osv",),
            generation_model_calls=1,
            tool_calls=2,
            graph_transitions=5,
            remaining_wall_time_seconds=90,
            budget=InvestigationBudget(),
        ),
    )

    assert authorization.authorized is False
    assert authorization.issues == (
        "evidence_gap_kind_invalid",
        "follow_up_source_not_allowed",
        "follow_up_evidence_type_invalid",
    )


def _evidence() -> tuple[AvailableEvidence, ...]:
    return (
        AvailableEvidence(
            record_id=EVIDENCE_ID,
            record_identity="sha256:evidence",
            content_digest="sha256:" + "a" * 64,
            source_identity="osv",
            source_adapter_version="osv-v1",
            passage_identities=("osv:affected",),
        ),
    )


def test_material_fact_requires_a_retrieved_supporting_evidence_record() -> None:
    validation = ClaimValidator.validate(
        claims=(
            ClaimDraft(
                identity="claim-version",
                kind=ClaimKind.FACT,
                text="Package feature-lib 5.1.0 is within the published affected range.",
                material=True,
                limitation=None,
                citations=(
                    ClaimEvidenceCitation(
                        evidence_record_id=EVIDENCE_ID,
                        passage_identities=("osv:affected",),
                        relationship=EvidenceRelationship.SUPPORTS,
                    ),
                ),
            ),
        ),
        available_evidence=_evidence(),
        authoritative_conflict=False,
    )

    assert validation.material_claims_supported is True
    assert validation.authoritative_conflict is False
    assert validation.issues == ()
    assert validation.claims[0].citations[0].evidence_record_identity == "sha256:evidence"


def test_unsupported_material_fact_is_preserved_and_forces_an_evidence_gap() -> None:
    validation = ClaimValidator.validate(
        claims=(
            ClaimDraft(
                identity="claim-reachability",
                kind=ClaimKind.FACT,
                text="The vulnerable behavior is reachable at runtime.",
                material=True,
                limitation=None,
                citations=(
                    ClaimEvidenceCitation(
                        evidence_record_id=EVIDENCE_ID,
                        passage_identities=("osv:affected",),
                        relationship=EvidenceRelationship.CONTEXTUAL,
                    ),
                ),
            ),
        ),
        available_evidence=_evidence(),
        authoritative_conflict=False,
    )

    assert validation.material_claims_supported is False
    assert validation.claims[0].supported is False
    assert validation.issues == ("claim-reachability:material_claim_missing_support",)


def test_every_fact_must_relate_to_retrieved_evidence() -> None:
    validation = ClaimValidator.validate(
        claims=(
            ClaimDraft(
                identity="claim-context",
                kind=ClaimKind.FACT,
                text="This is a non-material contextual fact.",
                material=False,
                limitation=None,
                citations=(),
            ),
        ),
        available_evidence=_evidence(),
        authoritative_conflict=False,
    )

    assert validation.material_claims_supported is False
    assert validation.claims[0].supported is False
    assert validation.issues == ("claim-context:claim_evidence_required",)


def test_inference_cites_its_inputs_and_exposes_a_limitation() -> None:
    validation = ClaimValidator.validate(
        claims=(
            ClaimDraft(
                identity="claim-usage",
                kind=ClaimKind.INFERENCE,
                text="Static context suggests feature-lib may be used by the service.",
                material=True,
                limitation="Static evidence does not prove runtime reachability.",
                citations=(
                    ClaimEvidenceCitation(
                        evidence_record_id=EVIDENCE_ID,
                        passage_identities=("osv:affected",),
                        relationship=EvidenceRelationship.CONTEXTUAL,
                    ),
                ),
            ),
        ),
        available_evidence=_evidence(),
        authoritative_conflict=False,
    )

    assert validation.material_claims_supported is True
    assert validation.claims[0].supported is True
    assert validation.claims[0].limitation == (
        "Static evidence does not prove runtime reachability."
    )


def test_inference_without_a_limitation_or_known_input_fails_closed() -> None:
    validation = ClaimValidator.validate(
        claims=(
            ClaimDraft(
                identity="claim-usage",
                kind=ClaimKind.INFERENCE,
                text="Static context suggests feature-lib may be used by the service.",
                material=True,
                limitation=None,
                citations=(
                    ClaimEvidenceCitation(
                        evidence_record_id=UUID("00000000-0000-0000-0000-000000000099"),
                        passage_identities=("unretrieved",),
                        relationship=EvidenceRelationship.CONTEXTUAL,
                    ),
                ),
            ),
        ),
        available_evidence=_evidence(),
        authoritative_conflict=False,
    )

    assert validation.material_claims_supported is False
    assert validation.claims[0].citations == ()
    assert validation.issues == (
        "claim-usage:unknown_evidence_record",
        "claim-usage:inference_limitation_required",
        "claim-usage:inference_inputs_required",
    )
