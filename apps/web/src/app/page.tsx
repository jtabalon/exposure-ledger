import { connection } from "next/server"

import { InvestigationWorkbench } from "@/components/investigation-workbench"
import { loadAssessmentRuns, loadPolicyDecisions } from "@/lib/assessment-runs"
import { loadAssetSnapshots } from "@/lib/asset-snapshots"
import { demoInvestigation } from "@/lib/demo-investigation"

export default async function Home() {
  await connection()
  const [assessmentRuns, assetSnapshots, policyDecisions] = await Promise.all([
    loadAssessmentRuns(),
    loadAssetSnapshots(),
    loadPolicyDecisions(),
  ])

  return (
    <InvestigationWorkbench
      investigation={demoInvestigation}
      assessmentRuns={assessmentRuns.items}
      assessmentRunsError={assessmentRuns.error}
      assetSnapshots={assetSnapshots.items}
      assetSnapshotsError={assetSnapshots.error}
      policyDecisions={policyDecisions.items}
      policyDecisionsError={policyDecisions.error}
    />
  )
}
