import { describe, expect, it } from "vitest"

import { claimsForEvidence, evidenceForClaim } from "./evidence"

describe("evidenceForClaim", () => {
  it("returns only evidence related to the selected Claim in source order", () => {
    const evidence = [
      { id: "ev-vendor", claimIds: ["claim-version"] },
      { id: "ev-osv", claimIds: ["claim-version", "claim-action"] },
      { id: "ev-epss", claimIds: ["claim-priority"] },
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
        claimIds: ["claim-version", "claim-action"],
      }).map(({ id }) => id),
    ).toEqual(["claim-version", "claim-action"])
  })
})
