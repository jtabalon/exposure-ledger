import { loadCollection } from "./assessment-runs"
import type { PackageInstance } from "./asset-snapshots"
import type { EvidenceRelationship } from "./evidence"

export type VulnerabilityRecord = {
  id: string
  aliases: string[]
}

export type EvidencePassage = {
  id: string
  identity: string
  kind: string
  selector: string
  content: string
}

export type EvidenceRecord = {
  id: string
  identity: string
  source: {
    identity: string
    authority: string
    location: string
  }
  capturedAt: string
  contentDigest: string
  attribution: string
  aliases: string[]
  payloadIdentity: string
  content: string
  passages: EvidencePassage[]
  relationship: EvidenceRelationship
}

export type ExposureRanking = {
  severity: "critical" | "high" | "moderate" | "low" | "unknown"
  directDependency: boolean | null
  dependencyDepth: number | null
  fixedVersionAvailable: boolean
  score: number
}

export type SourceObservationState =
  | "available"
  | "stale"
  | "missing"
  | "malformed"
  | "unavailable"
  | "not_collected"

export type KevSignal = {
  state: SourceObservationState
  listed: boolean | null
  observedAt: string | null
  detail: string | null
}

export type EpssSignal = {
  state: SourceObservationState
  score: number | null
  percentile: number | null
  observedAt: string | null
  detail: string | null
}

export type Exposure = {
  id: string
  assessmentRunId: string
  assetSnapshotId: string
  vulnerabilityRecord: VulnerabilityRecord
  package: PackageInstance
  ranking: ExposureRanking
  rank: number
  selectedForInvestigation: boolean
  authoritativeConflict: boolean
  kev: KevSignal
  epss: EpssSignal
  evidenceRecords: EvidenceRecord[]
}

export type ExposureCollection = {
  items: Exposure[]
  error: string | null
}

export async function loadAssessmentExposures(
  assessmentRunId: string,
): Promise<ExposureCollection> {
  return loadCollection<Exposure>(
    `assessment-runs/${assessmentRunId}/exposures`,
    "Exposure",
  )
}
