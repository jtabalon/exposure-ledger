import { connection } from "next/server"

import { InvestigationWorkbench } from "@/components/investigation-workbench"
import { loadAssessmentRuns, loadPolicyDecisions } from "@/lib/assessment-runs"
import { loadAssetSnapshots } from "@/lib/asset-snapshots"
import { demoInvestigation } from "@/lib/demo-investigation"
import { loadAssessmentExposures } from "@/lib/exposures"

export default async function Home() {
  await connection()
  const [assessmentRuns, assetSnapshots, policyDecisions] = await Promise.all([
    loadAssessmentRuns(),
    loadAssetSnapshots(),
    loadPolicyDecisions(),
  ])
  const latestRepositoryRun = assessmentRuns.items.find(
    (run) => run.mode === "repository" && run.status === "completed",
  )
  const exposures = latestRepositoryRun
    ? await loadAssessmentExposures(latestRepositoryRun.id)
    : { items: [], error: null }

  return (
    <InvestigationWorkbench
      investigation={demoInvestigation}
      assessmentRuns={assessmentRuns.items}
      assessmentRunsError={assessmentRuns.error}
      assetSnapshots={assetSnapshots.items}
      assetSnapshotsError={assetSnapshots.error}
      exposures={exposures.items}
      exposuresError={exposures.error}
      policyDecisions={policyDecisions.items}
      policyDecisionsError={policyDecisions.error}
    />
  )
}
