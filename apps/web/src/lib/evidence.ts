export type ClaimLinkedEvidence = {
  id: string
  claimIds: readonly string[]
}

export function evidenceForClaim<T extends ClaimLinkedEvidence>(
  evidence: readonly T[],
  claimId: string,
): T[] {
  return evidence.filter((record) => record.claimIds.includes(claimId))
}
