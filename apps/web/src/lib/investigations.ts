import { loadCollection } from "./assessment-runs"
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
  stoppingReason: string | null
  evidenceGap: {
    identity: string
    kind: string
    description: string
  } | null
  followUp: {
    proposal: {
      tool: string
      target: string
      arguments: { sourceIdentity: string; evidenceType: string }
      assistanceClass: string
      actionLevel: string
    }
    authorization: {
      authorized: boolean
      executed: boolean
      reason: string
      issues: string[]
      policyDecision: {
        assistanceClass: string
        actionLevel: string
        result: string
      }
    }
  } | null
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

export async function loadAssessmentInvestigationRevisions(
  assessmentRunId: string,
): Promise<InvestigationRevisionCollection> {
  return loadCollection<InvestigationRevision>(
    `assessment-runs/${assessmentRunId}/investigation-revisions`,
    "Investigation Revision",
  )
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

export function revisionToWorkbench(
  revision: InvestigationRevision,
  exposure: Exposure,
  snapshot: AssetSnapshot,
): DemoInvestigation {
  const claimLabels = new Map(
    revision.claims.map((claim, index) => [claim.identity, `C${index + 1}`]),
  )
  return {
    stoppingReason: revision.stoppingReason ?? undefined,
    evidenceGap: revision.evidenceGap ?? undefined,
    followUp: revision.followUp
      ? {
          tool: revision.followUp.proposal.tool,
          target: revision.followUp.proposal.target,
          sourceIdentity: revision.followUp.proposal.arguments.sourceIdentity,
          evidenceType: revision.followUp.proposal.arguments.evidenceType,
          proposedAssistanceClass: revision.followUp.proposal.assistanceClass,
          proposedActionLevel: revision.followUp.proposal.actionLevel,
          authorized: revision.followUp.authorization.authorized,
          executed: revision.followUp.authorization.executed,
          reason: revision.followUp.authorization.reason,
          issues: revision.followUp.authorization.issues,
          policyAssistanceClass:
            revision.followUp.authorization.policyDecision.assistanceClass,
          policyActionLevel: revision.followUp.authorization.policyDecision.actionLevel,
          policyResult: revision.followUp.authorization.policyDecision.result,
        }
      : undefined,
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
