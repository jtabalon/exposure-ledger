import { describe, expect, it } from "vitest"

import type { AssetSnapshot } from "./asset-snapshots"
import { demoInvestigation } from "./demo-investigation"
import { claimsForEvidence, evidenceForClaim, relationshipsForClaim } from "./evidence"
import type { Exposure, KevSignal } from "./exposures"
import {
  revisionToWorkbench,
  summarizeRevisionHistory,
  type InvestigationRevision,
} from "./investigations"

function revision(
  revisionNumber = 1,
  recommendation: InvestigationRevision["recommendation"]["value"] = "planned_remediation",
  promptVersion = "claims-recommendation-v1",
): InvestigationRevision {
  return {
    investigationId: "investigation-1",
    id: `revision-${revisionNumber}`,
    revisionNumber,
    assessmentRunId: `assessment-${revisionNumber}`,
    assetSnapshotId: "snapshot-1",
    exposureId: "exposure-1",
    status: "complete",
    stoppingCondition: "completed",
    stoppingReason: null,
    evidenceGap: null,
    followUp: null,
    evidenceState: {
      materialClaimsSupported: true,
      authoritativeConflict: false,
      validationIssues: [],
      retrieved: {
        query: "cipherleaf 2.4.1 affected fixed upgrade",
        passages: [
          {
            evidenceRecordId: "evidence-1",
            evidenceRecordIdentity: "osv:record-1",
            evidenceRecordDigest: "sha256:evidence",
            passageIdentity: "osv:affected:1",
            passage: "Releases before 2.4.3 are affected.",
            sourceIdentity: "osv",
            sourceAuthority: "Public database",
            sourceLocation: "https://example.test/advisory",
            capturedAt: "2026-09-04T10:00:00Z",
            fullTextRank: 1,
            fullTextScore: 0.9,
            vectorRank: 2,
            vectorScore: 0.8,
            fusedRank: 1,
            fusedScore: 0.03,
          },
        ],
      },
    },
    claims: [
      {
        identity: "claim-affected",
        kind: "fact",
        text: "Version 2.4.1 is in the published affected range.",
        material: true,
        supported: true,
        limitation: null,
        citations: [
          {
            evidenceRecordId: "evidence-1",
            evidenceRecordIdentity: "osv:record-1",
            passageIdentities: ["osv:affected:1"],
            relationship: "supports",
          },
        ],
      },
    ],
    recommendation: {
      value: recommendation,
      accepted: true,
      reason: "evidence_requirements_satisfied",
      summary: "Plan an upgrade to the published fixed release.",
      reasons: ["The installed version is affected."],
      limitations: ["Runtime reachability has not been established."],
    },
    outputPolicyDecision: { assistanceClass: "C1", actionLevel: "A0", result: "allowed" },
    events: [
      {
        stage: "validate_claims",
        mode: "deterministic",
        detail: "Claim citations checked.",
        occurredAt: "2026-09-04T11:00:00Z",
      },
    ],
    measurements: { generationModelCalls: 1, toolCalls: 1, graphTransitions: 4 },
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
      embeddingSpace: {
        identity: "sha256:embedding",
        provider: "local",
        modelArtifact: "embedding-v2",
        artifactDigest: "sha256:embedding-artifact",
        dimensions: 768,
        retrievalInstruction: "Represent the query for captured passage retrieval: ",
        normalizer: "l2-v2",
        passageConstructionVersion: "source-aware-passage-v2",
      },
    },
    createdAt: `2026-09-04T1${revisionNumber}:00:00Z`,
  }
}

const exposure: Exposure = {
  id: "exposure-1",
  assessmentRunId: "assessment-1",
  assetSnapshotId: "snapshot-1",
  vulnerabilityRecord: { id: "vulnerability-1", aliases: ["DEMO-2026-0042"] },
  package: {
    name: "cipherleaf",
    version: "2.4.1",
    direct: false,
    source: {},
    dependencyPaths: [
      ["harbor-api", "auth-gateway", "cipherleaf"],
      ["harbor-api", "session-service", "cipherleaf"],
    ],
  },
  ranking: {
    severity: "high",
    directDependency: false,
    dependencyDepth: 2,
    fixedVersionAvailable: true,
    score: 4,
  },
  rank: 1,
  selectedForInvestigation: true,
  authoritativeConflict: false,
  kev: {
    state: "available",
    listed: false,
    observedAt: "2026-09-04T10:00:00Z",
    detail: "No matching Vulnerability Record in the captured catalog.",
  },
  epss: {
    state: "available",
    score: 0.013,
    percentile: 0.732,
    observedAt: "2026-09-04T10:00:00Z",
    detail: "Captured Source observation.",
  },
  evidenceRecords: [],
}

const snapshot: AssetSnapshot = {
  id: "snapshot-1",
  repository: "https://github.com/example/harbor-api",
  commit: "1234567",
  projectRoot: ".",
  lockfilePath: "uv.lock",
  lockfileDigest: "sha256:lockfile",
  environmentProfile: {
    pythonVersion: "3.12",
    operatingSystem: "linux",
    architecture: "amd64",
    selectedExtras: [],
  },
  packages: [exposure.package],
  parserVersion: "uv-lock-v1",
  capturedAt: "2026-09-04T10:00:00Z",
}

describe("revisionToWorkbench", () => {
  it("preserves a supported material Claim and its captured Evidence Record", () => {
    const input = revision()
    const result = revisionToWorkbench(input, exposure, snapshot)

    expect(result.claims).toEqual([
      {
        id: "claim-affected",
        label: "C1",
        kind: "fact",
        text: input.claims[0].text,
        material: true,
        supported: true,
        limitation: undefined,
      },
    ])
    expect(result.validation).toEqual({ materialClaimsSupported: true, validationIssues: [] })
    expect(result.recommendation).toEqual({
      label: "Planned Remediation",
      accepted: true,
      reason: "evidence_requirements_satisfied",
      summary: input.recommendation.summary,
      reasons: input.recommendation.reasons,
      limitations: input.recommendation.limitations,
    })
    expect(result.evidence[0]).toMatchObject({
      id: "evidence-1:osv:affected:1",
      passage: input.evidenceState.retrieved.passages[0].passage,
      digest: "sha256:evidence",
      relationships: [{ claimId: "claim-affected", relationship: "supports" }],
    })
  })

  it("retains a contextual-only unsupported factual Claim and a rejected Recommendation", () => {
    const input = revision()
    input.claims[0].text = "The vulnerable behavior is reachable at runtime."
    input.claims[0].supported = false
    input.claims[0].citations[0].relationship = "contextual"
    input.evidenceState.materialClaimsSupported = false
    input.evidenceState.validationIssues = ["claim-affected:material_claim_missing_support"]
    input.recommendation = {
      ...input.recommendation,
      value: "more_evidence_required",
      accepted: false,
      reason: "material_claims_unsupported",
      summary: "More Evidence Required because material Claims lack supporting citations.",
      reasons: ["material_claims_unsupported", ...input.evidenceState.validationIssues],
    }

    const result = revisionToWorkbench(input, exposure, snapshot)

    expect(result.claims[0]).toMatchObject({
      kind: "fact",
      text: "The vulnerable behavior is reachable at runtime.",
      supported: false,
      material: true,
    })
    expect(result.meta.status).toBe("complete")
    expect(result.validation).toEqual({
      materialClaimsSupported: false,
      validationIssues: ["claim-affected:material_claim_missing_support"],
    })
    expect(result.recommendation).toEqual({
      label: "More Evidence Required",
      accepted: false,
      reason: "material_claims_unsupported",
      summary: input.recommendation.summary,
      reasons: input.recommendation.reasons,
      limitations: input.recommendation.limitations,
    })
    expect(evidenceForClaim(result.evidence, "claim-affected")).toEqual(result.evidence)
    expect(claimsForEvidence(result.claims, result.evidence[0])).toEqual(result.claims)
    expect(relationshipsForClaim(result.evidence[0], "claim-affected")).toEqual(["contextual"])
  })

  it("preserves multiple relationship roles for shared evidence without linking other passages", () => {
    const input = revision()
    input.claims.push({
      ...input.claims[0],
      identity: "claim-context",
      kind: "inference",
      material: false,
      limitation: "Static source context does not establish runtime reachability.",
      citations: [{ ...input.claims[0].citations[0], relationship: "contextual" }],
    })
    input.claims[0].citations.push({
      ...input.claims[0].citations[0],
      relationship: "contradicts",
      passageIdentities: ["osv:affected:2"],
    })
    input.evidenceState.retrieved.passages.push({
      ...input.evidenceState.retrieved.passages[0],
      passageIdentity: "osv:affected:2",
      passage: "A conflicting captured affected range.",
    })

    const result = revisionToWorkbench(input, exposure, snapshot)

    expect(result.evidence[0].relationships).toEqual([
      { claimId: "claim-affected", relationship: "supports" },
      { claimId: "claim-context", relationship: "contextual" },
    ])
    expect(result.evidence[1].relationships).toEqual([
      { claimId: "claim-affected", relationship: "contradicts" },
    ])
    expect(result.claims[1]).toMatchObject({
      material: false,
      supported: true,
      limitation: input.claims[1].limitation,
    })
    expect(evidenceForClaim(result.evidence, "claim-affected")).toHaveLength(2)
    expect(evidenceForClaim(result.evidence, "claim-context")).toHaveLength(1)
  })

  it("retains an incomplete Revision without Claims and its stopping diagnostics", () => {
    const input = revision()
    input.status = "incomplete"
    input.stoppingCondition = "evidence_gap"
    input.stoppingReason = "No eligible captured passages support a material Claim."
    input.claims = []
    input.evidenceState.materialClaimsSupported = false
    input.evidenceState.authoritativeConflict = null
    input.evidenceState.validationIssues = ["no_claims"]
    input.evidenceGap = {
      identity: "gap-1",
      kind: "missing",
      description: "Supporting evidence is missing.",
    }
    input.recommendation = {
      ...input.recommendation,
      value: "more_evidence_required",
      accepted: false,
      reason: "material_claims_unsupported",
    }

    const result = revisionToWorkbench(input, exposure, snapshot)

    expect(result.meta.status).toBe("incomplete")
    expect(result.claims).toEqual([])
    expect(result.evidence[0].relationships).toEqual([])
    expect(result.stoppingReason).toBe(input.stoppingReason)
    expect(result.evidenceGap).toEqual(input.evidenceGap)
    expect(result.exposure.authoritativeConflict).toBeNull()
    expect(result.validation).toEqual({ materialClaimsSupported: false, validationIssues: ["no_claims"] })
    expect(result.recommendation.accepted).toBe(false)
  })

  it.each<{ state: KevSignal["state"]; listed: boolean | null }>([
    { state: "not_collected", listed: null },
    { state: "unavailable", listed: null },
    { state: "missing", listed: null },
    { state: "malformed", listed: null },
    { state: "stale", listed: false },
    { state: "stale", listed: true },
    { state: "available", listed: false },
    { state: "available", listed: true },
  ])("preserves KEV $state with listed=$listed", ({ state, listed }) => {
    const input: Exposure = {
      ...exposure,
      kev: {
        state,
        listed,
        observedAt: listed === null ? null : "2026-09-04T10:00:00Z",
        detail: `${state} catalog observation`,
      },
    }

    const result = revisionToWorkbench(revision(), input, snapshot)

    expect(result.exposure.kev).toEqual(input.kev)
  })

  it("preserves unknown Dependency Paths and EPSS without inventing a path or score", () => {
    const input: Exposure = {
      ...exposure,
      package: { ...exposure.package, direct: null, dependencyPaths: null },
      epss: {
        state: "unavailable",
        score: null,
        percentile: null,
        observedAt: null,
        detail: "The EPSS Source was unavailable.",
      },
    }

    const result = revisionToWorkbench(revision(), input, snapshot)

    expect(result.exposure.dependencyType).toBe("Unknown")
    expect(result.exposure.dependencyPaths).toBeNull()
    expect(result.exposure.epss).toEqual(input.epss)
  })

  it("retains all Dependency Paths and exact observed EPSS values", () => {
    const result = revisionToWorkbench(revision(), exposure, snapshot)

    expect(result.exposure.dependencyPaths).toEqual(exposure.package.dependencyPaths)
    expect(result.exposure.dependencyPaths).toHaveLength(2)
    expect(result.exposure.epss).toEqual(exposure.epss)
    expect(result.exposure.epss.percentile).toBe(0.732)
  })

  it("retains the complete live Revision configuration and Embedding Space", () => {
    const input = revision()
    const result = revisionToWorkbench(input, exposure, snapshot)

    expect(result.meta.mode).toBe("live")
    expect(result.configuration).toEqual(input.configuration)
    expect(result.retrieval.configurationVersion).toBe(input.configuration.retrievalConfigurationVersion)
    expect(result.retrieval.sourcePolicyVersion).toBe(input.configuration.sourcePolicyVersion)
    expect(result.retrieval.embeddingSpace).toEqual(input.configuration.embeddingSpace)
    expect(result.configuration.promptVersion).not.toBe(demoInvestigation.configuration.promptVersion)
  })
})

describe("demoInvestigation", () => {
  it("marks the contradiction-only material fact unsupported while retaining a labeled inference", () => {
    expect(demoInvestigation.claims.find(({ id }) => id === "claim-fix")).toMatchObject({
      kind: "fact",
      material: true,
      supported: false,
    })
    expect(demoInvestigation.claims.find(({ id }) => id === "claim-usage")).toMatchObject({
      kind: "inference",
      supported: true,
      limitation: expect.any(String),
    })
    expect(demoInvestigation.validation).toEqual({
      materialClaimsSupported: false,
      validationIssues: ["claim-fix:material_claim_missing_support"],
    })
    expect(demoInvestigation.recommendation).toMatchObject({
      label: "More Evidence Required",
      accepted: false,
      reason: "authoritative_evidence_conflict",
    })
  })
})

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
