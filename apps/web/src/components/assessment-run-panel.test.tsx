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
            enforcementPoint: "request",
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

  it("shows a typed dependency format rejection", () => {
    const policyDecision = {
      id: "b6c40321-24f3-4c13-8913-d7788dfbeb7f",
      assessmentRunId: "53451f9d-c0b6-4838-8155-0194e104f41d",
      standardVersion: "0.1",
      assistanceClass: "C1" as const,
      actionLevel: "A1" as const,
      targetScope: "https://github.com/example/project@0123456789abcdef0123456789abcdef01234567",
      authorizationScope: "local operator",
      result: "allowed" as const,
      ruleVersion: "assessment-request-v1",
      reason: "Read-only public repository assessment is allowed.",
      createdAt: "2026-09-03T20:00:00Z",
      enforcementPoint: "request" as const,
    }
    const html = renderToStaticMarkup(
      <AssessmentRunPanel
        assessmentRuns={[
          {
            id: "53451f9d-c0b6-4838-8155-0194e104f41d",
            mode: "repository",
            scenario: "complete",
            label: "example/project@0123456789ab",
            synthetic: false,
            status: "failed",
            createdAt: "2026-09-03T20:00:00Z",
            startedAt: "2026-09-03T20:00:01Z",
            completedAt: "2026-09-03T20:00:02Z",
            errorCode: "unpinned_requirement",
            errorMessage: "requirement demo must pin exactly one version with ==",
            assetSnapshotId: null,
            policyDecision,
          },
        ]}
        error={null}
        policyDecisions={[policyDecision]}
        policyDecisionsError={null}
      />,
    )

    expect(html).toContain("unpinned_requirement")
    expect(html).toContain("requirement demo must pin exactly one version with ==")
  })
})
