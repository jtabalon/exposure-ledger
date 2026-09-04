import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { ExposureQueuePanel } from "./exposure-queue-panel"

describe("ExposureQueuePanel", () => {
  it("explains deterministic package-specific ranks and Investigation selection", () => {
    const sharedVulnerability = {
      id: "a09718cb-dbc7-42ec-af07-47bca728617f",
      aliases: ["CVE-2026-4000", "GHSA-4444-5555-6666", "PYSEC-2026-40"],
    }
    const html = renderToStaticMarkup(
      <ExposureQueuePanel
        error={null}
        exposures={[
          {
            id: "3a52632a-f999-42cb-ab01-3d77694321f1",
            assessmentRunId: "dce99257-c986-48f5-98e8-8b00be9137d4",
            assetSnapshotId: "cb5e7f2e-5a41-4dd0-99f2-b707b9c12c14",
            vulnerabilityRecord: sharedVulnerability,
            package: {
              name: "feature-lib",
              version: "5.1.0",
              direct: true,
              source: { registry: "https://pypi.org/simple" },
              dependencyPaths: [["demo-app", "feature-lib"]],
            },
            rank: 1,
            selectedForInvestigation: true,
            ranking: {
              severity: "high",
              directDependency: true,
              dependencyDepth: 1,
              fixedVersionAvailable: true,
              score: 69,
            },
          },
          {
            id: "3f607e81-1939-4491-a198-477ac131d9de",
            assessmentRunId: "dce99257-c986-48f5-98e8-8b00be9137d4",
            assetSnapshotId: "cb5e7f2e-5a41-4dd0-99f2-b707b9c12c14",
            vulnerabilityRecord: sharedVulnerability,
            package: {
              name: "http-x",
              version: "2.3.0",
              direct: true,
              source: { registry: "https://pypi.org/simple" },
              dependencyPaths: [["demo-app", "http-x"]],
            },
            rank: 2,
            selectedForInvestigation: true,
            ranking: {
              severity: "high",
              directDependency: true,
              dependencyDepth: 1,
              fixedVersionAvailable: false,
              score: 59,
            },
          },
          {
            id: "5ee45be7-5a29-4f23-abce-179295b164b5",
            assessmentRunId: "dce99257-c986-48f5-98e8-8b00be9137d4",
            assetSnapshotId: "cb5e7f2e-5a41-4dd0-99f2-b707b9c12c14",
            vulnerabilityRecord: {
              id: "93a9a321-9267-4b78-bbf4-ce3e97de98ad",
              aliases: ["PYSEC-2026-41"],
            },
            package: {
              name: "flat-pkg",
              version: "1.0.0",
              direct: null,
              source: { manifest: "requirements.txt" },
              dependencyPaths: null,
            },
            rank: 3,
            selectedForInvestigation: true,
            ranking: {
              severity: "unknown",
              directDependency: null,
              dependencyDepth: null,
              fixedVersionAvailable: false,
              score: 0,
            },
          },
        ]}
      />,
    )

    expect(html).toContain("Ranked Exposure queue")
    expect(html).toContain("feature-lib")
    expect(html).toContain("http-x")
    expect(html).toContain("CVE-2026-4000")
    expect(html).toContain("GHSA-4444-5555-6666")
    expect(html).toContain("Selected for Investigation")
    expect(html).toContain("High OSV severity")
    expect(html).toContain("Direct dependency")
    expect(html).toContain("Dependency depth 1")
    expect(html).toContain("Fixed version published")
    expect(html).toContain("No fixed version in OSV")
    expect(html).toContain("Deterministic score 69")
    expect(html).toContain("Dependency provenance unknown")
    expect(html).toContain("Dependency depth unknown")
    expect(html).toContain("Dependency paths unknown for this manifest")
  })
})
