import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { demoInvestigation } from "@/lib/demo-investigation"

import { InvestigationWorkbench } from "./investigation-workbench"

const workbenchProps = {
  assessmentRuns: [],
  assessmentRunsError: null,
  assetSnapshots: [],
  assetSnapshotsError: null,
  exposures: [],
  exposuresError: null,
  policyDecisions: [],
  policyDecisionsError: null,
}

describe("InvestigationWorkbench", () => {
  it("names every evidence relationship and preserves an authoritative conflict", () => {
    const investigation = {
      ...demoInvestigation,
      exposure: {
        ...demoInvestigation.exposure,
        authoritativeConflict: true,
        advisoryGuidance: [
          {
            source: "Synthetic maintainer advisory",
            authority: "Maintainer · Tier 1",
            affectedRange: ">=2.1.0, <2.4.3",
            fixedVersion: "2.4.3",
            relationship: "contradicts" as const,
          },
          {
            source: "Synthetic public vulnerability record",
            authority: "Public database · Tier 1",
            affectedRange: ">=2.1.0, <2.4.2",
            fixedVersion: "2.4.2",
            relationship: "contradicts" as const,
          },
        ],
      },
      recommendation: {
        ...demoInvestigation.recommendation,
        label: "More Evidence Required",
      },
      evidence: demoInvestigation.evidence.map((record, index) => ({
        ...record,
        relationship: (["supports", "contradicts", "contextual"] as const)[index % 3],
        claimIds: [demoInvestigation.claims[0].id],
      })),
    }

    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain("Material conflict")
    expect(html).toContain("No Source was selected as the winner")
    expect(html).toContain("More Evidence Required")
    expect(html).toContain("Supporting")
    expect(html).toContain("Contradicting")
    expect(html).toContain("Contextual")
    expect(html).toContain("Synthetic maintainer advisory")
    expect(html).toContain("2.4.3")
    expect(html).toContain("Synthetic public vulnerability record")
    expect(html).toContain("2.4.2")
  })

  it("presents hybrid component ranks and the complete Embedding Space identity", () => {
    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={demoInvestigation} {...workbenchProps} />,
    )

    expect(html).toContain(demoInvestigation.retrieval.query)
    expect(html).toContain("Hybrid · RRF")
    expect(html).toContain("Full-text rank")
    expect(html).toContain("Vector rank")
    expect(html).toContain("Fused rank")
    expect(html).toContain("PostgreSQL full-text + pgvector")
    expect(html).toContain("Rank 1 is the strongest fused result")
    expect(html).toContain(demoInvestigation.retrieval.configurationVersion)
    expect(html).toContain("Embedding Space")
    expect(html).toContain(demoInvestigation.retrieval.embeddingSpace.identity)
    expect(html).toContain(demoInvestigation.retrieval.embeddingSpace.modelArtifact)
    expect(html).toContain(demoInvestigation.retrieval.embeddingSpace.artifactDigest)
    expect(html).toContain(demoInvestigation.retrieval.embeddingSpace.retrievalInstruction)
    expect(html).toContain(demoInvestigation.retrieval.embeddingSpace.normalizer)
    expect(html).toContain(demoInvestigation.retrieval.embeddingSpace.passageConstructionVersion)
  })
})
