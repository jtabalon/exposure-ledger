import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { demoInvestigation } from "@/lib/demo-investigation"
import type { WorkbenchInvestigation } from "@/lib/workbench-investigation"

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
  revisionHistory: [],
  dispositions: [],
  dispositionWritesEnabled: false,
  recordDispositionAction: async () => ({ status: "idle" as const, message: "" }),
}

describe("InvestigationWorkbench", () => {
  it("labels retained unsupported factual Claims while keeping contextual Evidence selectable", () => {
    const claim = {
      ...demoInvestigation.claims[0],
      text: "The vulnerable behavior is reachable at runtime.",
      supported: false,
      material: true,
    }
    const investigation: WorkbenchInvestigation = {
      ...demoInvestigation,
      claims: [claim],
      validation: {
        materialClaimsSupported: false,
        validationIssues: [`${claim.id}:material_claim_missing_support`],
      },
      evidence: [{
        ...demoInvestigation.evidence[0],
        relationships: [{ claimId: claim.id, relationship: "contextual" }],
      }],
    }

    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain("Claims and validation")
    expect(html).not.toContain("What the evidence supports")
    expect(html).toContain('aria-label="Claim validation: Unsupported Claim"')
    expect(html).toContain("Material")
    expect(html).toContain(claim.text)
    expect(html).toContain(`${claim.id}:material_claim_missing_support`)
    expect(html).toContain("Claim support requirements not satisfied")
    expect(html).toContain("evidence entails a Claim or that a human verified it")
    expect(html).toContain('aria-pressed="true" aria-controls="evidence-trace"')
    expect(html).toContain('id="evidence-heading" aria-live="polite"')
    expect(html).toContain('aria-label="Review C1: Unsupported Claim"')
    expect(html).toContain('aria-label="Evidence relationship: Contextual"')
    expect(html).toContain(investigation.evidence[0].passage.replaceAll('"', "&quot;"))
  })

  it("labels passing Claim checks without claiming human verification or semantic proof", () => {
    const investigation: WorkbenchInvestigation = {
      ...demoInvestigation,
      validation: { materialClaimsSupported: true, validationIssues: [] },
      claims: [{ ...demoInvestigation.claims[0], supported: true, material: false }],
    }
    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain('aria-label="Claim validation: Support requirements met"')
    expect(html).toContain("Claim support requirements satisfied")
    expect(html).toContain("Non-material")
    expect(html).not.toContain('aria-label="Claim validation: Unsupported Claim"')
  })

  it("preserves citation diagnostics even when a Claim meets support requirements", () => {
    const investigation: WorkbenchInvestigation = {
      ...demoInvestigation,
      validation: {
        materialClaimsSupported: true,
        validationIssues: ["claim-version:unknown_evidence_passage"],
      },
      claims: [{ ...demoInvestigation.claims[0], supported: true }],
    }
    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain("Support requirements met")
    expect(html).toContain("claim-version:unknown_evidence_passage")
    expect(html).not.toContain("Claim checks passed")
    expect(html).not.toContain("Passes structural checks")
  })

  it("displays the effective rejected Recommendation and its reason separately from limitations", () => {
    const investigation: WorkbenchInvestigation = {
      ...demoInvestigation,
      recommendation: {
        label: "More Evidence Required",
        accepted: false,
        reason: "material_claims_unsupported",
        summary: "The proposed conclusion needs more evidence.",
        reasons: ["The runtime Claim has contextual evidence only."],
        limitations: ["No runtime observation was captured."],
      },
    }
    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain("Recommendation not accepted")
    expect(html).toContain("Effective Recommendation")
    expect(html).toContain("More Evidence Required")
    expect(html).toContain("Recommendation not accepted; effective value shown above")
    expect(html).toContain("material_claims_unsupported")
    expect(html).toContain(investigation.recommendation.reasons[0])
    expect(html).toContain("Recommendation limitations")
    expect(html).toContain(investigation.recommendation.limitations[0])
    expect(html).not.toContain("Recommendation accepted by validation")
  })

  it("shows an accepted Recommendation's validation reason without a downgrade label", () => {
    const html = renderToStaticMarkup(
      <InvestigationWorkbench
        investigation={{
          ...demoInvestigation,
          recommendation: {
            ...demoInvestigation.recommendation,
            accepted: true,
            reason: "evidence_requirements_satisfied",
          },
        }}
        {...workbenchProps}
      />,
    )

    expect(html).toContain("Recommendation accepted by validation")
    expect(html).toContain("evidence_requirements_satisfied")
    expect(html).not.toContain("Recommendation not accepted")
  })

  it("keeps captured Evidence available in an incomplete Revision without Claims", () => {
    const investigation: WorkbenchInvestigation = {
      ...demoInvestigation,
      claims: [],
      validation: { materialClaimsSupported: false, validationIssues: [] },
      stoppingReason: "Evidence acquisition stopped before Claim generation.",
    }
    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain("No Claims were retained.")
    expect(html).toContain(investigation.stoppingReason)
    expect(html).toContain("Evidence available to this Revision")
    expect(html).toContain(investigation.evidence[0].source)
    expect(html).not.toContain("Claim support requirements satisfied")
    expect(html).toContain("Recommendation not accepted")
    expect(html).not.toContain("Proposed Recommendation rejected")
    expect(html).not.toContain("Recommendation downgraded")
  })

  it.each([
    ["unavailable", null, "Unknown", "KEV Source unavailable"],
    ["not_collected", null, "Unknown", "KEV not collected"],
    ["missing", null, "Unknown", "KEV evidence missing"],
    ["malformed", null, "Unknown", "KEV response malformed"],
    ["available", null, "Unknown", "KEV value missing"],
    ["available", false, "Not listed", "Current observation"],
    ["available", true, "Listed", "Current observation"],
    ["stale", false, "Last observed: Not listed", "Stale observation"],
    ["stale", true, "Last observed: Listed", "Stale observation"],
  ] as const)("preserves %s KEV state with listed=%s", (state, listed, value, label) => {
    const investigation: WorkbenchInvestigation = {
      ...demoInvestigation,
      exposure: {
        ...demoInvestigation.exposure,
        kev: { state, listed, observedAt: "2026-09-01T12:00:00Z", detail: "Captured KEV state" },
        dependencyPaths: null,
      },
    }
    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )
    const kevRow = html.match(/<dt[^>]*>KEV<\/dt>[\s\S]*?<\/dd>/)?.[0]

    expect(kevRow).toContain(value)
    expect(kevRow).toContain(label)
    expect(kevRow).toContain('dateTime="2026-09-01T12:00:00Z"')
    expect(kevRow).toContain("Captured KEV state")
    if (listed === null) expect(kevRow).not.toContain("Not listed")
    if (state !== "available") expect(kevRow).not.toContain("Current observation")
    expect(html).toContain("Dependency Paths unknown")
    expect(html).not.toContain('aria-label="Dependency Path 1"')
  })

  it("renders every known Dependency Path and preserves unknown EPSS", () => {
    const investigation: WorkbenchInvestigation = {
      ...demoInvestigation,
      exposure: {
        ...demoInvestigation.exposure,
        dependencyPaths: [["project-one", "cipherleaf"], ["project-two", "cipherleaf"]],
        epss: { state: "unavailable", score: null, percentile: null, observedAt: null, detail: null },
      },
    }
    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain('aria-label="Dependency Path 1"')
    expect(html).toContain('aria-label="Dependency Path 2"')
    expect(html).toContain("project-one")
    expect(html).toContain("project-two")
    const epssRow = html.match(/<dt[^>]*>EPSS<\/dt>[\s\S]*?<\/dd>/)?.[0]
    expect(epssRow).toContain("Unknown")
    expect(epssRow).toContain("EPSS Source unavailable")
    expect(epssRow).not.toContain("percentile")
  })

  it("renders live Revision configuration without substituting demo versions or generation models", () => {
    const configuration = {
      ...demoInvestigation.configuration,
      applicationRelease: "release-live-32",
      graphVersion: "graph-live-32",
      promptVersion: "prompt-live-32",
      policyVersion: "policy-live-32",
      parserVersion: "parser-live-32",
      retrievalConfigurationVersion: "retrieval-live-32",
      sourcePolicyVersion: "source-policy-live-32",
      sourceAdapterVersions: ["adapter-live-32"],
      generationModel: {
        provider: "provider-live-32",
        modelArtifact: "model-live-32",
        artifactDigest: "sha256:generation-live-32",
      },
    }
    const html = renderToStaticMarkup(
      <InvestigationWorkbench
        investigation={{
          ...demoInvestigation,
          meta: { ...demoInvestigation.meta, mode: "live" },
          configuration,
        }}
        {...workbenchProps}
      />,
    )

    for (const value of [
      configuration.applicationRelease, configuration.graphVersion, configuration.promptVersion,
      configuration.policyVersion, configuration.parserVersion,
      configuration.retrievalConfigurationVersion, configuration.sourcePolicyVersion,
      ...configuration.sourceAdapterVersions, ...Object.values(configuration.generationModel),
    ]) expect(html).toContain(value)
    expect(html).not.toContain("prompt demo-001")
    expect(html).not.toContain("graph v0.1")
    expect(html).not.toContain("gpt-oss:20b")
  })

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
        relationships: [
          {
            claimId: demoInvestigation.claims[0].id,
            relationship: (["supports", "contradicts", "contextual"] as const)[index % 3],
          },
        ],
      })),
    }

    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain("Material conflict")
    expect(html).toContain("No Source was selected as the winner")
    expect(html).toContain("More Evidence Required")
    expect(html).toContain("needs more evidence")
    expect(html).not.toContain("requires action")
    expect(html).toContain("Supporting")
    expect(html).toContain("Contradicting")
    expect(html).toContain("Contextual")
    expect(html).toContain("Synthetic maintainer advisory")
    expect(html).toContain("2.4.3")
    expect(html).toContain("Synthetic public vulnerability record")
    expect(html).toContain("2.4.2")
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Record disposition/)
  })

  it("does not prescribe action when no remediation is indicated", () => {
    const investigation = {
      ...demoInvestigation,
      recommendation: {
        ...demoInvestigation.recommendation,
        label: "No Remediation Indicated",
      },
    }

    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={investigation} {...workbenchProps} />,
    )

    expect(html).toContain("has no indicated remediation")
    expect(html).not.toContain("requires action")
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
    expect(html.indexOf("sha256:21df…0c91")).toBeLessThan(
      html.indexOf("sha256:65bc…8a20"),
    )
  })

  it("distinguishes a live local Revision from the precomputed demonstration", () => {
    const live = {
      ...demoInvestigation,
      meta: { ...demoInvestigation.meta, mode: "live" as const },
    }

    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={live} {...workbenchProps} />,
    )

    expect(html).toContain("Live local revision")
    expect(html).toContain("This Revision was generated by the local Investigation runner.")
    expect(html).not.toContain("Synthetic precomputed demo")
  })

  it("distinguishes the model proposal from deterministic authorization and stopping", () => {
    const incomplete = {
      ...demoInvestigation,
      meta: { ...demoInvestigation.meta, status: "incomplete" as const },
      stoppingReason: "The proposed Evidence Gap follow-up failed deterministic validation.",
      evidenceGap: {
        identity: "gap-fixed-version",
        kind: "insufficient",
        description: "The fixed version is not supported by the retrieved passages.",
      },
      followUp: {
        tool: "search_captured_exposure_evidence",
        target: "exposure:EXP-1042",
        sourceIdentity: "osv",
        evidenceType: "affected",
        proposedAssistanceClass: "C1",
        proposedActionLevel: "A1",
        authorized: false,
        executed: false,
        reason: "follow_up_target_outside_exposure",
        issues: ["follow_up_target_outside_exposure"],
        policyAssistanceClass: "C1",
        policyActionLevel: "A1",
        policyResult: "allowed",
      },
    }

    const html = renderToStaticMarkup(
      <InvestigationWorkbench investigation={incomplete} {...workbenchProps} />,
    )

    expect(html).toContain("Model proposal")
    expect(html).toContain("Deterministic authorization")
    expect(html).toContain("Not authorized")
    expect(html).toContain(incomplete.stoppingReason)
    expect(html).not.toContain("chain-of-thought")
  })

  it("presents immutable Revision history separately from human Dispositions", () => {
    const html = renderToStaticMarkup(
      <InvestigationWorkbench
        investigation={{
          ...demoInvestigation,
          meta: { ...demoInvestigation.meta, mode: "live" as const, revision: "REV-0002" },
        }}
        {...workbenchProps}
        revisionHistory={[
          {
            investigationId: "investigation-1",
            id: "revision-2",
            revisionNumber: 2,
            assessmentRunId: "assessment-2",
            assetSnapshotId: "snapshot-1",
            createdAt: "2026-09-04T15:00:00Z",
            status: "complete",
            stoppingCondition: "completed",
            recommendation: "Monitor",
            changes: [
              "Recommendation: Planned Remediation → Monitor",
              "Prompt: claims-recommendation-v1 → claims-recommendation-v2",
            ],
          },
          {
            investigationId: "investigation-1",
            id: "revision-1",
            revisionNumber: 1,
            assessmentRunId: "assessment-1",
            assetSnapshotId: "snapshot-1",
            createdAt: "2026-09-04T14:00:00Z",
            status: "complete",
            stoppingCondition: "completed",
            recommendation: "Planned Remediation",
            changes: ["Initial Revision"],
          },
        ]}
        dispositions={[
          {
            id: "disposition-1",
            investigationId: "investigation-1",
            investigationRevisionId: "revision-1",
            exposureId: "exposure-1",
            assetSnapshotId: "snapshot-1",
            kind: "remediate",
            author: "AppSec reviewer",
            rationale: "The published fixed version is approved for rollout.",
            expirationDate: null,
            reviewDate: null,
            createdAt: "2026-09-04T16:00:00Z",
          },
        ]}
        dispositionWritesEnabled
      />,
    )

    expect(html).toContain("Investigation history")
    expect(html).toContain("Creation circumstances")
    expect(html).toContain("Recommendation: Planned Remediation → Monitor")
    expect(html).toContain("Prompt: claims-recommendation-v1 → claims-recommendation-v2")
    expect(html).toContain("System Recommendation")
    expect(html).toContain("Human Dispositions")
    expect(html).toContain("Remediate")
    expect(html).toContain("AppSec reviewer")
    expect(html).toContain("Risk acceptance requires a rationale")
    expect(html).toContain("Authenticated as the configured local operator")
    expect(html).toContain('name="kind"')
    expect(html).toContain('value="accept_risk"')
    expect(html).toContain('name="reviewDate"')
  })
})
