import { connection } from "next/server"

import { InvestigationWorkbench } from "@/components/investigation-workbench"
import { loadAssessmentRuns, loadPolicyDecisions } from "@/lib/assessment-runs"
import { demoInvestigation } from "@/lib/demo-investigation"

export default async function Home() {
  await connection()
  const [assessmentRuns, policyDecisions] = await Promise.all([
    loadAssessmentRuns(),
    loadPolicyDecisions(),
  ])

  return (
    <InvestigationWorkbench
      investigation={demoInvestigation}
      assessmentRuns={assessmentRuns.items}
      assessmentRunsError={assessmentRuns.error}
      policyDecisions={policyDecisions.items}
      policyDecisionsError={policyDecisions.error}
    />
  )
}
