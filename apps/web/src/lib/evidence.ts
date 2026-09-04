export type EvidenceRelationship = "supports" | "contradicts" | "contextual"

export type ClaimLinkedEvidence = {
  id: string
  claimIds: readonly string[]
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
  return evidence.filter((record) => record.claimIds.includes(claimId))
}

export function claimsForEvidence<T extends { id: string }>(
  claims: readonly T[],
  evidence: ClaimLinkedEvidence,
): T[] {
  const claimIds = new Set(evidence.claimIds)
  return claims.filter((claim) => claimIds.has(claim.id))
}
