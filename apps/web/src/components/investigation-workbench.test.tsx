import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { InvestigationWorkbench } from "./investigation-workbench"
import { demoInvestigation } from "../lib/demo-investigation"

describe("InvestigationWorkbench", () => {
  it("presents the exact retrieval query and only lexical ranking", () => {
    const html = renderToStaticMarkup(
      <InvestigationWorkbench
        investigation={demoInvestigation}
        assessmentRuns={[]}
        assessmentRunsError={null}
        assetSnapshots={[]}
        assetSnapshotsError={null}
        exposures={[]}
        exposuresError={null}
        policyDecisions={[]}
        policyDecisionsError={null}
      />,
    )

    expect(html).toContain(demoInvestigation.retrieval.query)
    expect(html).toContain("Lexical · top")
    expect(html).toContain("Lexical rank")
    expect(html).toContain("PostgreSQL full-text search")
    expect(html).toContain("Rank 1 is the strongest lexical match")
    expect(html).toContain(demoInvestigation.retrieval.configurationVersion)
    expect(html).not.toContain("RRF")
    expect(html).not.toContain("Vector")
    expect(html).not.toContain("Fused")
    expect(html).not.toContain("qwen3-embedding")
  })
})
