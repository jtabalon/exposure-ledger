import type { EvidenceRelationship } from "./evidence"
import type { EpssSignal, KevSignal } from "./exposures"

export type { EvidenceRelationship } from "./evidence"

export type ClaimKind = "fact" | "inference"

export type InvestigationClaim = {
  id: string
  label: string
  kind: ClaimKind
  text: string
  material: boolean
  supported: boolean
  limitation?: string
}

export type WorkbenchEvidenceRecord = {
  id: string
  source: string
  authority: string
  capturedAt: string
  relationships: { claimId: string; relationship: EvidenceRelationship }[]
  passage: string
  fullTextRank: number | null
  fullTextScore: number | null
  vectorRank: number | null
  vectorScore: number | null
  fusedRank: number
  fusedScore: number
  digest: string
}

export type InvestigationStage = {
  label: string
  mode: "deterministic" | "retrieval" | "model" | "policy"
  detail: string
}

export type InvestigationConfiguration = {
  applicationRelease: string
  graphVersion: string
  promptVersion: string
  policyVersion: string
  parserVersion: string
  retrievalConfigurationVersion: string
  sourcePolicyVersion: string
  sourceAdapterVersions: string[]
  generationModel: {
    provider: string
    modelArtifact: string
    artifactDigest: string
  }
  embeddingSpace: {
    identity: string
    provider: string
    modelArtifact: string
    artifactDigest: string
    dimensions: number
    retrievalInstruction: string
    normalizer: string
    passageConstructionVersion: string
  }
}

export type WorkbenchInvestigation = {
  stoppingReason?: string
  evidenceGap?: {
    identity: string
    kind: string
    description: string
  }
  followUp?: {
    tool: string
    target: string
    sourceIdentity: string
    evidenceType: string
    proposedAssistanceClass: string
    proposedActionLevel: string
    authorized: boolean
    executed: boolean
    reason: string
    issues: string[]
    policyAssistanceClass: string
    policyActionLevel: string
    policyResult: string
  }
  meta: {
    mode: "live" | "precomputed"
    status: "complete" | "incomplete"
    repository: string
    commit: string
    projectRoot: string
    environment: string
    revision: string
    capturedAt: string
  }
  exposure: {
    id: string
    vulnerability: string
    aliases: string[]
    packageName: string
    installedVersion: string
    affectedRange: string
    fixedVersion: string
    authoritativeConflict: boolean | null
    advisoryGuidance: {
      source: string
      authority: string
      affectedRange: string
      fixedVersion: string
      relationship: EvidenceRelationship
    }[]
    dependencyType: string
    dependencyPaths: string[][] | null
    kev: KevSignal
    epss: EpssSignal
    cvss: string
  }
  validation: {
    materialClaimsSupported: boolean
    validationIssues: string[]
  }
  recommendation: {
    label: string
    accepted: boolean
    reason: string
    summary: string
    reasons: string[]
    limitations: string[]
  }
  policy: {
    assistanceClass: string
    actionLevel: string
    decision: string
  }
  configuration: InvestigationConfiguration
  retrieval: {
    query: string
    configurationVersion: string
    sourcePolicyVersion: string
    evidenceTypes: string[]
    embeddingSpace: InvestigationConfiguration["embeddingSpace"]
  }
  stages: InvestigationStage[]
  claims: InvestigationClaim[]
  evidence: WorkbenchEvidenceRecord[]
}
