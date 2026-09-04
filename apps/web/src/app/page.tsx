import { connection } from "next/server"

import { InvestigationWorkbench } from "@/components/investigation-workbench"
import { loadAssessmentRuns } from "@/lib/assessment-runs"
import { demoInvestigation } from "@/lib/demo-investigation"

export default async function Home() {
  await connection()
  const assessmentRuns = await loadAssessmentRuns()

  return (
    <InvestigationWorkbench
      investigation={demoInvestigation}
      assessmentRuns={assessmentRuns.items}
      assessmentRunsError={assessmentRuns.error}
    />
  )
}
