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
