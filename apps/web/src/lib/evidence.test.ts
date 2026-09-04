import { describe, expect, it } from "vitest"

import { claimsForEvidence, evidenceForClaim, relationshipsForClaim } from "./evidence"

describe("evidenceForClaim", () => {
  it("returns only evidence related to the selected Claim in source order", () => {
    const evidence = [
      {
        id: "ev-vendor",
        relationships: [{ claimId: "claim-version", relationship: "supports" as const }],
      },
      {
        id: "ev-osv",
        relationships: [
          { claimId: "claim-version", relationship: "supports" as const },
          { claimId: "claim-action", relationship: "contextual" as const },
        ],
      },
      {
        id: "ev-epss",
        relationships: [{ claimId: "claim-priority", relationship: "supports" as const }],
      },
    ]

    expect(evidenceForClaim(evidence, "claim-version").map(({ id }) => id)).toEqual([
      "ev-vendor",
      "ev-osv",
    ])
  })
})

describe("claimsForEvidence", () => {
  it("returns every Claim that uses the selected Evidence Record", () => {
    const claims = [
      { id: "claim-version" },
      { id: "claim-action" },
      { id: "claim-priority" },
    ]

    expect(
      claimsForEvidence(claims, {
        id: "ev-osv",
        relationships: [
          { claimId: "claim-version", relationship: "supports" },
          { claimId: "claim-action", relationship: "contextual" },
        ],
      }).map(({ id }) => id),
    ).toEqual(["claim-version", "claim-action"])
  })
})

describe("relationshipsForClaim", () => {
  it("preserves different relationship roles for Claims sharing one Evidence Record", () => {
    const evidence = {
      id: "ev-shared",
      relationships: [
        { claimId: "claim-one", relationship: "supports" as const },
        { claimId: "claim-two", relationship: "contradicts" as const },
      ],
    }

    expect(relationshipsForClaim(evidence, "claim-one")).toEqual(["supports"])
    expect(relationshipsForClaim(evidence, "claim-two")).toEqual(["contradicts"])
  })
})
