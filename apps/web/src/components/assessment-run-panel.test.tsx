import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { AssessmentRunPanel } from "./assessment-run-panel"

describe("AssessmentRunPanel", () => {
  it("shows a blocked Policy Decision and that no worker task was created", () => {
    const html = renderToStaticMarkup(
      <AssessmentRunPanel
        assessmentRuns={[]}
        error={null}
        policyDecisions={[
          {
            id: "b6c40321-24f3-4c13-8913-d7788dfbeb7f",
            assessmentRunId: null,
            standardVersion: "0.1",
            assistanceClass: "C2",
            actionLevel: "A1",
            targetScope: "public repository example/project at abc123",
            authorizationScope: "operator-approved public repository",
            result: "blocked",
            ruleVersion: "assessment-request-v1",
            reason: "C2 assistance is outside the first-release capability ceiling.",
            createdAt: "2026-09-03T20:00:00Z",
          },
        ]}
        policyDecisionsError={null}
      />,
    )

    expect(html).toContain("Policy Decision ledger")
    expect(html).toContain("C2 assistance is outside the first-release capability ceiling.")
    expect(html).toContain("No worker task created")
    expect(html).toContain("Standard 0.1 · Rule assessment-request-v1")
  })
})
