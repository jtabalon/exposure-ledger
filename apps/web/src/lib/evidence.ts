export type EvidenceRelationship = "supports" | "contradicts" | "contextual"

export type ClaimEvidenceRelationship = {
  claimId: string
  relationship: EvidenceRelationship
}

export type ClaimLinkedEvidence = {
  id: string
  relationships: readonly ClaimEvidenceRelationship[]
}

export const evidenceRelationshipLabels: Record<EvidenceRelationship, string> = {
  supports: "Supporting",
  contradicts: "Contradicting",
  contextual: "Contextual",
}

export function evidenceForClaim<T extends ClaimLinkedEvidence>(
  evidence: readonly T[],
  claimId: string,
): T[] {
  return evidence.filter((record) =>
    record.relationships.some((relationship) => relationship.claimId === claimId),
  )
}

export function claimsForEvidence<T extends { id: string }>(
  claims: readonly T[],
  evidence: ClaimLinkedEvidence,
): T[] {
  const claimIds = new Set(evidence.relationships.map(({ claimId }) => claimId))
  return claims.filter((claim) => claimIds.has(claim.id))
}

export function relationshipsForClaim(
  evidence: ClaimLinkedEvidence,
  claimId: string,
): EvidenceRelationship[] {
  return evidence.relationships
    .filter((relationship) => relationship.claimId === claimId)
    .map((relationship) => relationship.relationship)
}
