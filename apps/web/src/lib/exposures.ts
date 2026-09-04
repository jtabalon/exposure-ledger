import { loadCollection } from "./assessment-runs"
import type { PackageInstance } from "./asset-snapshots"

export type VulnerabilityRecord = {
  id: string
  aliases: string[]
}

export type ExposureRanking = {
  severity: "critical" | "high" | "moderate" | "low" | "unknown"
  directDependency: boolean | null
  dependencyDepth: number | null
  fixedVersionAvailable: boolean
  score: number
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
