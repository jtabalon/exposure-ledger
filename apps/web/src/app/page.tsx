import { connection } from "next/server"

import { recordDisposition } from "@/app/actions"
import { InvestigationWorkbench } from "@/components/investigation-workbench"
import { loadAssessmentRuns, loadPolicyDecisions } from "@/lib/assessment-runs"
import { loadAssetSnapshots } from "@/lib/asset-snapshots"
import { demoInvestigation } from "@/lib/demo-investigation"
import { loadAssessmentExposures } from "@/lib/exposures"
import {
  loadAssessmentInvestigationRevisions,
  loadInvestigationHistory,
  revisionToWorkbench,
  summarizeRevisionHistory,
} from "@/lib/investigations"
import { localDispositionWritesEnabled } from "@/lib/local-dispositions"

export default async function Home() {
  await connection()
  const [assessmentRuns, assetSnapshots, policyDecisions] = await Promise.all([
    loadAssessmentRuns(),
    loadAssetSnapshots(),
    loadPolicyDecisions(),
  ])
  const latestRepositoryRun = assessmentRuns.items.find((run) => run.mode === "repository")
  const [exposures, revisions] = latestRepositoryRun
    ? await Promise.all([
        loadAssessmentExposures(latestRepositoryRun.id),
        loadAssessmentInvestigationRevisions(latestRepositoryRun.id),
      ])
    : [{ items: [], error: null }, { items: [], error: null }]
  const latestRevision = revisions.items[0]
  const liveExposure = exposures.items.find((item) => item.id === latestRevision?.exposureId)
  const history = liveExposure
    ? await loadInvestigationHistory(liveExposure.id)
    : { item: null, error: null }
  const selectedRevision = history.item?.revisions[0] ?? latestRevision
  const liveSnapshot = assetSnapshots.items.find(
    (item) => item.id === selectedRevision?.assetSnapshotId,
  )
  const investigation =
    selectedRevision && liveExposure && liveSnapshot
      ? revisionToWorkbench(selectedRevision, liveExposure, liveSnapshot)
      : demoInvestigation
  const dispositionWritesEnabled = localDispositionWritesEnabled()
  const dispositionAction = recordDisposition.bind(
    null,
    history.item && selectedRevision
      ? {
          investigationId: history.item.investigationId,
          investigationRevisionId: selectedRevision.id,
        }
      : null,
  )
  const osvFailure =
    latestRepositoryRun?.errorCode === "osv_unavailable"
      ? `${latestRepositoryRun.errorMessage ?? "The OSV Source is unavailable."} No Source content is substituted or inferred.`
      : null

  return (
    <InvestigationWorkbench
      investigation={investigation}
      assessmentRuns={assessmentRuns.items}
      assessmentRunsError={assessmentRuns.error}
      assetSnapshots={assetSnapshots.items}
      assetSnapshotsError={assetSnapshots.error}
      exposures={exposures.items}
      exposuresError={exposures.error ?? osvFailure}
      policyDecisions={policyDecisions.items}
      policyDecisionsError={policyDecisions.error}
      revisionHistory={summarizeRevisionHistory(
        history.item?.investigationId ?? "",
        history.item?.revisions ?? [],
      )}
      dispositions={history.item?.dispositions ?? []}
      investigationHistoryError={history.error}
      dispositionWritesEnabled={dispositionWritesEnabled}
      recordDispositionAction={dispositionAction}
    />
  )
}
