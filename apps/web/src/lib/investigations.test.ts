import { describe, expect, it } from "vitest"

import {
  summarizeRevisionHistory,
  type InvestigationRevision,
} from "./investigations"

function revision(
  revisionNumber: number,
  recommendation: InvestigationRevision["recommendation"]["value"],
  promptVersion: string,
): InvestigationRevision {
  return {
    id: `revision-${revisionNumber}`,
    revisionNumber,
    assessmentRunId: `assessment-${revisionNumber}`,
    assetSnapshotId: "snapshot-1",
    status: "complete",
    stoppingCondition: "completed",
    recommendation: { value: recommendation },
    configuration: {
      applicationRelease: "0.1.0",
      graphVersion: "bounded-investigation-v1",
      promptVersion,
      policyVersion: "0.1",
      parserVersion: "uv-lock-v1",
      retrievalConfigurationVersion: "postgres-hybrid-rrf-v1",
      sourcePolicyVersion: "explicit-source-allowlist-v1",
      sourceAdapterVersions: ["osv=osv-v1"],
      generationModel: {
        provider: "local",
        modelArtifact: "generation-v1",
        artifactDigest: "sha256:generation",
      },
      embeddingSpace: { identity: "sha256:embedding" },
    },
    createdAt: `2026-09-04T1${revisionNumber}:00:00Z`,
  } as InvestigationRevision
}

describe("summarizeRevisionHistory", () => {
  it("names Recommendation and pinned-version changes between immutable Revisions", () => {
    const entries = summarizeRevisionHistory("investigation-1", [
      revision(2, "monitor", "claims-recommendation-v2"),
      revision(1, "planned_remediation", "claims-recommendation-v1"),
    ])

    expect(entries[0].changes).toEqual([
      "Recommendation: Planned Remediation → Monitor",
      "Prompt: claims-recommendation-v1 → claims-recommendation-v2",
    ])
    expect(entries[0].assessmentRunId).toBe("assessment-2")
    expect(entries[0].stoppingCondition).toBe("completed")
    expect(entries[1].changes).toEqual(["Initial Revision"])
  })
})
