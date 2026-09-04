import { apiBaseUrl, loadCollection } from "./assessment-runs"
import type { AssetSnapshot } from "./asset-snapshots"
import type { DemoInvestigation, EvidenceRelationship } from "./demo-investigation"
import type { Exposure } from "./exposures"

type RevisionCitation = {
  evidenceRecordId: string
  evidenceRecordIdentity: string
  passageIdentities: string[]
  relationship: EvidenceRelationship
}

export type InvestigationRevision = {
  investigationId: string
  revisionNumber: number
  id: string
  assessmentRunId: string
  exposureId: string
  assetSnapshotId: string
  status: "complete" | "incomplete"
  stoppingCondition: string
  evidenceState: {
    materialClaimsSupported: boolean
    authoritativeConflict: boolean | null
    validationIssues: string[]
    retrieved: {
      query: string
      passages: {
        evidenceRecordId: string
        evidenceRecordIdentity: string
        evidenceRecordDigest: string
        passageIdentity: string
        passage: string
        sourceIdentity: string
        sourceAuthority: string
        sourceLocation: string
        capturedAt: string
        fullTextRank: number | null
        fullTextScore: number | null
        vectorRank: number | null
        vectorScore: number | null
        fusedRank: number
        fusedScore: number
      }[]
    }
  }
  claims: {
    identity: string
    kind: "fact" | "inference"
    text: string
    material: boolean
    limitation: string | null
    supported: boolean
    citations: RevisionCitation[]
  }[]
  recommendation: {
    value:
      | "urgent_remediation"
      | "planned_remediation"
      | "monitor"
      | "no_remediation_indicated"
      | "more_evidence_required"
    accepted: boolean
    reason: string
    summary: string
    reasons: string[]
    limitations: string[]
  }
  outputPolicyDecision: {
    assistanceClass: string
    actionLevel: string
    result: string
  }
  events: {
    stage: string
    mode: "deterministic" | "retrieval" | "model" | "policy"
    detail: string
    occurredAt: string
  }[]
  measurements: {
    generationModelCalls: number
    toolCalls: number
    graphTransitions: number
  }
  configuration: {
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
    embeddingSpace: DemoInvestigation["retrieval"]["embeddingSpace"]
  }
  createdAt: string
}

export type InvestigationRevisionCollection = {
  items: InvestigationRevision[]
  error: string | null
}

export const dispositionKinds = [
  "remediate",
  "monitor",
  "not_affected",
  "accept_risk",
  "request_more_evidence",
] as const

export type DispositionKind = (typeof dispositionKinds)[number]

export type Disposition = {
  id: string
  investigationId: string
  investigationRevisionId: string
  exposureId: string
  assetSnapshotId: string
  kind: DispositionKind
  author: string
  rationale: string | null
  expirationDate: string | null
  reviewDate: string | null
  createdAt: string
}

export type InvestigationHistory = {
  investigationId: string
  exposureId: string
  assetSnapshotId: string
  revisions: InvestigationRevision[]
  dispositions: Disposition[]
}

export type RevisionHistoryEntry = {
  investigationId: string
  id: string
  revisionNumber: number
  assessmentRunId: string
  assetSnapshotId: string
  createdAt: string
  status: InvestigationRevision["status"]
  stoppingCondition: string
  recommendation: string
  changes: string[]
}

export type DispositionActionState = {
  status: "idle" | "success" | "error"
  message: string
}

export type DispositionTarget = {
  investigationId: string
  investigationRevisionId: string
}

export async function loadAssessmentInvestigationRevisions(
  assessmentRunId: string,
): Promise<InvestigationRevisionCollection> {
  return loadCollection<InvestigationRevision>(
    `assessment-runs/${assessmentRunId}/investigation-revisions`,
    "Investigation Revision",
  )
}

export async function loadInvestigationHistory(
  exposureId: string,
): Promise<{ item: InvestigationHistory | null; error: string | null }> {
  try {
    const response = await fetch(`${apiBaseUrl()}/api/v1/exposures/${exposureId}/investigation`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    })
    if (!response.ok) {
      return { item: null, error: `Investigation history API returned HTTP ${response.status}.` }
    }
    const item = (await response.json()) as InvestigationHistory
    if (!Array.isArray(item.revisions) || !Array.isArray(item.dispositions)) {
      return { item: null, error: "Investigation history API returned an invalid response." }
    }
    return { item, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown connection error"
    return { item: null, error: `Investigation history API unavailable: ${message}` }
  }
}

const recommendationLabels: Record<
  InvestigationRevision["recommendation"]["value"],
  string
> = {
  urgent_remediation: "Urgent Remediation",
  planned_remediation: "Planned Remediation",
  monitor: "Monitor",
  no_remediation_indicated: "No Remediation Indicated",
  more_evidence_required: "More Evidence Required",
}

const versionFields: {
  label: string
  value: (revision: InvestigationRevision) => string
}[] = [
  { label: "Application", value: (revision) => revision.configuration.applicationRelease },
  { label: "Graph", value: (revision) => revision.configuration.graphVersion },
  { label: "Prompt", value: (revision) => revision.configuration.promptVersion },
  { label: "Policy", value: (revision) => revision.configuration.policyVersion },
  { label: "Parser", value: (revision) => revision.configuration.parserVersion },
  {
    label: "Retrieval",
    value: (revision) => revision.configuration.retrievalConfigurationVersion,
  },
  { label: "Source policy", value: (revision) => revision.configuration.sourcePolicyVersion },
  {
    label: "Source adapters",
    value: (revision) => revision.configuration.sourceAdapterVersions.join(", "),
  },
  {
    label: "Generation artifact",
    value: (revision) =>
      `${revision.configuration.generationModel.provider}/${revision.configuration.generationModel.modelArtifact}@${revision.configuration.generationModel.artifactDigest}`,
  },
  {
    label: "Embedding Space",
    value: (revision) => revision.configuration.embeddingSpace.identity,
  },
]

export function summarizeRevisionHistory(
  investigationId: string,
  revisions: InvestigationRevision[],
): RevisionHistoryEntry[] {
  return revisions.map((revision, index) => {
    const previous = revisions[index + 1]
    const changes: string[] = []
    if (previous) {
      if (revision.recommendation.value !== previous.recommendation.value) {
        changes.push(
          `Recommendation: ${recommendationLabels[previous.recommendation.value]} → ${recommendationLabels[revision.recommendation.value]}`,
        )
      }
      for (const field of versionFields) {
        const currentValue = field.value(revision)
        const previousValue = field.value(previous)
        if (currentValue !== previousValue) {
          changes.push(`${field.label}: ${previousValue} → ${currentValue}`)
        }
      }
      if (changes.length === 0) changes.push("Configuration and Recommendation unchanged")
    } else {
      changes.push("Initial Revision")
    }
    return {
      investigationId,
      id: revision.id,
      revisionNumber: revision.revisionNumber,
      assessmentRunId: revision.assessmentRunId,
      assetSnapshotId: revision.assetSnapshotId,
      createdAt: revision.createdAt,
      status: revision.status,
      stoppingCondition: revision.stoppingCondition,
      recommendation: recommendationLabels[revision.recommendation.value],
      changes,
    }
  })
}

export function revisionToWorkbench(
  revision: InvestigationRevision,
  exposure: Exposure,
  snapshot: AssetSnapshot,
): DemoInvestigation {
  const claimLabels = new Map(
    revision.claims.map((claim, index) => [claim.identity, `C${index + 1}`]),
  )
  return {
    meta: {
      mode: "live",
      status: revision.status,
      repository: snapshot.repository.replace("https://github.com/", ""),
      commit: snapshot.commit,
      projectRoot: snapshot.projectRoot,
      environment: [
        `Python ${snapshot.environmentProfile.pythonVersion}`,
        snapshot.environmentProfile.operatingSystem,
        snapshot.environmentProfile.architecture,
        snapshot.environmentProfile.selectedExtras.length
          ? snapshot.environmentProfile.selectedExtras.join(", ")
          : "default extras",
      ].join(" · "),
      revision: `REV-${String(revision.revisionNumber).padStart(4, "0")}`,
      capturedAt: revision.createdAt,
    },
    exposure: {
      id: exposure.id,
      vulnerability: exposure.vulnerabilityRecord.aliases[0] ?? "Unknown vulnerability",
      aliases: exposure.vulnerabilityRecord.aliases,
      packageName: exposure.package.name,
      installedVersion: exposure.package.version,
      affectedRange: "See captured affected-range evidence",
      fixedVersion: exposure.ranking.fixedVersionAvailable ? "Published fix available" : "Unknown",
      authoritativeConflict: revision.evidenceState.authoritativeConflict,
      advisoryGuidance: exposure.evidenceRecords
        .filter((record) => record.relationship === "contradicts")
        .map((record) => ({
          source: record.source.identity,
          authority: record.source.authority,
          affectedRange: "Conflicting captured guidance",
          fixedVersion: "Unresolved",
          relationship: record.relationship,
        })),
      dependencyType:
        exposure.package.direct === null
          ? "Unknown"
          : exposure.package.direct
            ? "Direct"
            : "Transitive",
      dependencyPath: exposure.package.dependencyPaths?.[0] ?? [exposure.package.name],
      kev: exposure.kev.listed ?? false,
      epssPercentile:
        exposure.epss.percentile === null
          ? "Unknown"
          : `${Math.round(exposure.epss.percentile * 100)}th`,
      cvss: exposure.ranking.severity,
    },
    recommendation: {
      label: recommendationLabels[revision.recommendation.value],
      summary: revision.recommendation.summary,
      reasons: [...revision.recommendation.reasons, ...revision.recommendation.limitations],
    },
    policy: {
      assistanceClass: revision.outputPolicyDecision.assistanceClass,
      actionLevel: revision.outputPolicyDecision.actionLevel,
      decision: revision.outputPolicyDecision.result,
    },
    retrieval: {
      query: revision.evidenceState.retrieved.query,
      configurationVersion: revision.configuration.retrievalConfigurationVersion,
      sourcePolicyVersion: revision.configuration.sourcePolicyVersion,
      evidenceTypes: Array.from(
        new Set(
          revision.evidenceState.retrieved.passages.map((passage) =>
            passage.passageIdentity.split(":").at(-2) ?? "evidence",
          ),
        ),
      ),
      embeddingSpace: revision.configuration.embeddingSpace,
    },
    stages: revision.events.map((event) => ({
      label: event.stage.replaceAll("_", " "),
      mode: event.mode,
      detail: event.detail,
    })),
    claims: revision.claims.map((claim) => ({
      id: claim.identity,
      label: claimLabels.get(claim.identity) ?? claim.identity,
      kind: claim.kind,
      text: claim.text,
      limitation: claim.limitation ?? undefined,
    })),
    evidence: revision.evidenceState.retrieved.passages.map((passage) => {
      const linkedClaims = revision.claims.filter((claim) =>
        claim.citations.some(
          (citation) =>
            citation.evidenceRecordId === passage.evidenceRecordId &&
            citation.passageIdentities.includes(passage.passageIdentity),
        ),
      )
      return {
        id: `${passage.evidenceRecordId}:${passage.passageIdentity}`,
        source: passage.sourceIdentity,
        authority: passage.sourceAuthority,
        capturedAt: passage.capturedAt,
        relationships: linkedClaims.flatMap((claim) =>
          claim.citations
            .filter(
              (citation) =>
                citation.evidenceRecordId === passage.evidenceRecordId &&
                citation.passageIdentities.includes(passage.passageIdentity),
            )
            .map((citation) => ({
              claimId: claim.identity,
              relationship: citation.relationship,
            })),
        ),
        passage: passage.passage,
        fullTextRank: passage.fullTextRank,
        fullTextScore: passage.fullTextScore,
        vectorRank: passage.vectorRank,
        vectorScore: passage.vectorScore,
        fusedRank: passage.fusedRank,
        fusedScore: passage.fusedScore,
        digest: passage.evidenceRecordDigest,
      }
    }),
  }
}
