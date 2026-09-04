import { describe, expect, it } from "vitest"

import { evidenceForClaim } from "./evidence"

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
