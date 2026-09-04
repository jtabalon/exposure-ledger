from uuid import UUID

from exposure_ledger import (
    AvailableEvidence,
    ClaimDraft,
    ClaimEvidenceCitation,
    ClaimKind,
    ClaimValidator,
    EvidenceRelationship,
)

EVIDENCE_ID = UUID("00000000-0000-0000-0000-000000000081")


def _evidence() -> tuple[AvailableEvidence, ...]:
    return (
        AvailableEvidence(
            record_id=EVIDENCE_ID,
            record_identity="sha256:evidence",
            content_digest="sha256:" + "a" * 64,
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
