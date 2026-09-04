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
            kev: {
              state: "available",
              listed: true,
              observedAt: "2026-09-03T10:15:30Z",
              detail: null,
            },
            epss: {
              state: "available",
              score: 0.42,
              percentile: 0.97,
              observedAt: "2026-09-03T00:00:00Z",
              detail: null,
            },
            ranking: {
              severity: "high",
              directDependency: true,
              dependencyDepth: 1,
              fixedVersionAvailable: true,
              score: 69,
            },
            evidenceRecords: [
              {
                id: "54138e43-cb27-4d61-abdb-10e2c54bde64",
                identity: "sha256:evidence-feature-lib",
                source: {
                  identity: "osv",
                  authority: "Open Source Vulnerabilities",
                  location: "https://api.osv.dev/v1/vulns/PYSEC-2026-40",
                },
                capturedAt: "2026-09-03T12:30:00Z",
                contentDigest: "sha256:provider-payload",
                attribution: "Open Source Vulnerabilities (OSV)",
                aliases: ["CVE-2026-4000", "PYSEC-2026-40"],
                payloadIdentity: "PYSEC-2026-40",
                content: '{"id":"PYSEC-2026-40"}',
                passages: [
                  {
                    id: "91126ae4-09df-4212-a5f0-e78bb02edee5",
                    identity: "sha256:affected-feature-lib",
                    kind: "affected",
                    selector: "/affected/0",
                    content:
                      '{"package":{"ecosystem":"PyPI","name":"feature_lib"},"ranges":[{"events":[{"introduced":"5.0"},{"fixed":"5.2"}],"type":"ECOSYSTEM"}]}',
                  },
                ],
              },
            ],
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
            kev: {
              state: "available",
              listed: false,
              observedAt: "2026-09-03T10:15:30Z",
              detail: null,
            },
            epss: {
              state: "missing",
              score: null,
              percentile: null,
              observedAt: null,
              detail: "FIRST EPSS returned no score.",
            },
            ranking: {
              severity: "high",
              directDependency: true,
              dependencyDepth: 1,
              fixedVersionAvailable: false,
              score: 59,
            },
            evidenceRecords: [],
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
            kev: {
              state: "unavailable",
              listed: null,
              observedAt: null,
              detail: "CISA KEV timed out.",
            },
            epss: {
              state: "stale",
              score: 0.01,
              percentile: 0.4,
              observedAt: "2026-08-01T00:00:00Z",
              detail: "FIRST EPSS observation is stale.",
            },
            ranking: {
              severity: "unknown",
              directDependency: null,
              dependencyDepth: null,
              fixedVersionAvailable: false,
              score: 0,
            },
            evidenceRecords: [],
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
    expect(html).toContain("Evidence trace")
    expect(html).toContain("Known exploitation · CISA KEV")
    expect(html).toContain("Listed")
    expect(html).toContain("Not listed")
    expect(html).toContain("Exploit probability · FIRST EPSS")
    expect(html).toContain("42.0% probability")
    expect(html).toContain("97th percentile")
    expect(html).toContain("Observed 2026-09-03T10:15:30Z")
    expect(html).toContain("EPSS evidence missing")
    expect(html).toContain("KEV Source unavailable")
    expect(html).toContain("Stale observation")
    expect(html).toContain("PYSEC-2026-40")
    expect(html).toContain("sha256:provider-payload")
    expect(html).toContain("Open Source Vulnerabilities (OSV)")
    expect(html).toContain("Affected-range passage")
    expect(html).toContain("introduced")
  })
})
