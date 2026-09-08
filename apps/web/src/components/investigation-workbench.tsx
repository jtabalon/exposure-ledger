"use client"

import { useActionState, useMemo, useState, type ReactNode } from "react"
import {
  Activity,
  ArrowRight,
  BookOpenText,
  Bot,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  ClipboardCheck,
  Database,
  ExternalLink,
  FileSearch,
  FlaskConical,
  GitBranch,
  History,
  Layers3,
  Library,
  Network,
  PackageCheck,
  Radar,
  Search,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
} from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { AssessmentRunPanel } from "@/components/assessment-run-panel"
import { AssetSnapshotPanel } from "@/components/asset-snapshot-panel"
import { ExposureQueuePanel } from "@/components/exposure-queue-panel"
import type { AssessmentRun, PolicyDecision } from "@/lib/assessment-runs"
import type { AssetSnapshot } from "@/lib/asset-snapshots"
import type { EpssSignal, Exposure, KevSignal } from "@/lib/exposures"
import {
  epssObservationValue,
  kevObservationValue,
  sourceObservationLabel,
} from "@/lib/source-observations"
import {
  claimsForEvidence,
  evidenceForClaim,
  evidenceRelationshipLabels,
  relationshipsForClaim,
} from "@/lib/evidence"
import type {
  InvestigationConfiguration,
  WorkbenchInvestigation,
  EvidenceRelationship,
  InvestigationStage,
} from "@/lib/workbench-investigation"
import type {
  Disposition,
  DispositionActionState,
  DispositionKind,
  RevisionHistoryEntry,
} from "@/lib/investigations"
import { cn } from "@/lib/utils"

const stageIcons: Record<InvestigationStage["mode"], typeof CheckCircle2> = {
  deterministic: PackageCheck,
  retrieval: Search,
  model: Sparkles,
  policy: ShieldCheck,
}

const relationshipStyles: Record<EvidenceRelationship, string> = {
  supports: "border-emerald-700/20 bg-emerald-700/7 text-emerald-800",
  contradicts: "border-red-700/20 bg-red-700/7 text-red-800",
  contextual: "border-amber-700/20 bg-amber-700/7 text-amber-800",
}

const revisionStatusStyles = {
  complete: "border-emerald-700/25 bg-emerald-600/8 text-emerald-800",
  incomplete: "border-amber-700/25 bg-amber-600/8 text-amber-800",
} as const

const dispositionLabels: Record<DispositionKind, string> = {
  remediate: "Remediate",
  monitor: "Monitor",
  not_affected: "Not affected",
  accept_risk: "Accept risk",
  request_more_evidence: "Request more evidence",
}

const initialDispositionState: DispositionActionState = { status: "idle", message: "" }

const utcTimestamp = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
})

function formatTimestamp(value: string): string {
  return `${utcTimestamp.format(new Date(value))} UTC`
}

function recommendationOutcome(label: string) {
  switch (label) {
    case "More Evidence Required":
      return " needs more evidence"
    case "No Remediation Indicated":
      return " has no indicated remediation"
    case "Monitor":
      return " should be monitored"
    default:
      return " requires action"
  }
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
      {children}
    </div>
  )
}

function FactRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="grid grid-cols-[104px_1fr] gap-3 border-b py-3 last:border-b-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm leading-5 font-medium text-foreground">{value}</dd>
    </div>
  )
}

function SourceObservation({ observation }: { observation: KevSignal | EpssSignal }) {
  const isKev = "listed" in observation
  const hasValue = isKev
    ? observation.listed !== null
    : observation.score !== null && observation.percentile !== null

  return (
    <div>
      <span>{isKev ? kevObservationValue(observation) : epssObservationValue(observation)}</span>
      <span className="mt-1 block text-xs text-muted-foreground">
        {sourceObservationLabel(isKev ? "KEV" : "EPSS", observation.state, hasValue)}
      </span>
      {observation.observedAt ? (
        <time dateTime={observation.observedAt} className="mt-1 block font-mono text-[10px]">
          Observed {observation.observedAt}
        </time>
      ) : null}
      {observation.detail ? (
        <span className="mt-1 block text-xs text-muted-foreground">{observation.detail}</span>
      ) : null}
    </div>
  )
}

function RevisionConfiguration({ configuration }: { configuration: InvestigationConfiguration }) {
  const fields = [
    ["Application", configuration.applicationRelease],
    ["Graph", configuration.graphVersion],
    ["Prompt", configuration.promptVersion],
    ["Policy", configuration.policyVersion],
    ["Parser", configuration.parserVersion],
    ["Retrieval", configuration.retrievalConfigurationVersion],
    ["Source policy", configuration.sourcePolicyVersion],
    ["Source adapters", configuration.sourceAdapterVersions.join(", ") || "None recorded"],
    ["Generation provider", configuration.generationModel.provider],
    ["Generation artifact", configuration.generationModel.modelArtifact],
    ["Generation digest", configuration.generationModel.artifactDigest],
    ["Embedding Space", configuration.embeddingSpace.identity],
  ]

  return (
    <details className="min-w-0" aria-label="Revision configuration">
      <summary className="cursor-pointer font-medium text-foreground">
        Revision configuration
      </summary>
      <dl className="mt-3 grid gap-x-4 gap-y-2 sm:grid-cols-[120px_1fr]">
        {fields.map(([label, value]) => (
          <div key={label} className="contents">
            <dt>{label}</dt>
            <dd className="break-all font-mono">{value}</dd>
          </div>
        ))}
      </dl>
    </details>
  )
}

function InvestigationDecisionHistory({
  revisionHistory,
  dispositions,
  historyError,
  dispositionWritesEnabled,
  recordDispositionAction,
}: {
  revisionHistory: RevisionHistoryEntry[]
  dispositions: Disposition[]
  historyError?: string | null
  dispositionWritesEnabled: boolean
  recordDispositionAction: (
    state: DispositionActionState,
    formData: FormData,
  ) => Promise<DispositionActionState>
}) {
  const [kind, setKind] = useState<DispositionKind>("remediate")
  const [state, formAction, pending] = useActionState(
    recordDispositionAction,
    initialDispositionState,
  )
  const currentRevision = revisionHistory[0]
  const revisionNumbers = new Map(
    revisionHistory.map((revision) => [revision.id, revision.revisionNumber]),
  )

  return (
    <section
      id="investigation-history"
      aria-labelledby="investigation-history-heading"
      className="border-b bg-background px-4 py-6 sm:px-6 lg:px-8"
    >
      <div className="mx-auto grid max-w-[1600px] gap-6 xl:grid-cols-[1.35fr_0.9fr]">
        <div>
          <SectionLabel>
            <History className="size-3.5" aria-hidden="true" />
            Investigation history
          </SectionLabel>
          <div className="mb-4 flex items-end justify-between gap-4">
            <div>
              <h2 id="investigation-history-heading" className="text-lg font-semibold">
                Immutable Revisions
              </h2>
              <p className="mt-1 text-xs leading-5 text-muted-foreground">
                Each reassessment appends a complete record. Prior conclusions never change.
              </p>
            </div>
            <span className="font-mono text-xs text-muted-foreground">
              {revisionHistory.length} total
            </span>
          </div>
          {historyError ? (
            <div role="alert" className="border-l-2 border-red-600 bg-red-600/7 p-3 text-xs">
              {historyError}
            </div>
          ) : revisionHistory.length === 0 ? (
            <div className="border border-dashed p-3 text-xs text-muted-foreground">
              Revision history is available after a live Investigation completes.
            </div>
          ) : (
            <ol className="space-y-3" aria-label="Investigation Revision history">
              {revisionHistory.map((revision) => (
                <li key={revision.id} className="rounded-md border bg-card p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="font-mono text-sm font-semibold">
                        REV-{String(revision.revisionNumber).padStart(4, "0")}
                      </div>
                      <div className="mt-1 font-mono text-[10px] text-muted-foreground">
                        {revision.id}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[9px] uppercase",
                          revisionStatusStyles[revision.status],
                        )}
                      >
                        {revision.status === "complete" ? (
                          <CheckCircle2 className="size-3" aria-hidden="true" />
                        ) : (
                          <TriangleAlert className="size-3" aria-hidden="true" />
                        )}
                        {revision.status}
                      </Badge>
                      <Badge
                        variant="secondary"
                        className={cn(
                          "text-[9px]",
                          revision.stoppingCondition === "completed"
                            ? "text-emerald-800"
                            : "text-amber-800",
                        )}
                      >
                        <CircleDot className="size-3" aria-hidden="true" />
                        {revision.stoppingCondition.replaceAll("_", " ")}
                      </Badge>
                    </div>
                  </div>
                  <dl className="mt-3 grid gap-2 border-y py-3 text-xs sm:grid-cols-2">
                    <div>
                      <dt className="text-muted-foreground">System Recommendation</dt>
                      <dd className="mt-0.5 font-semibold">{revision.recommendation}</dd>
                    </div>
                    <div>
                      <dt className="text-muted-foreground">Created</dt>
                      <dd className="mt-0.5 font-mono">{formatTimestamp(revision.createdAt)}</dd>
                    </div>
                  </dl>
                  <details className="mt-3 text-xs" open={revision === currentRevision}>
                    <summary className="cursor-pointer font-semibold">Creation circumstances</summary>
                    <dl className="mt-2 grid gap-x-3 gap-y-1 text-[10px] text-muted-foreground sm:grid-cols-[112px_1fr]">
                      <dt>Assessment Run</dt>
                      <dd className="break-all font-mono">{revision.assessmentRunId}</dd>
                      <dt>Asset Snapshot</dt>
                      <dd className="break-all font-mono">{revision.assetSnapshotId}</dd>
                      <dt>Changes</dt>
                      <dd>
                        <ul className="space-y-1">
                          {revision.changes.map((change) => (
                            <li key={change}>{change}</li>
                          ))}
                        </ul>
                      </dd>
                    </dl>
                  </details>
                </li>
              ))}
            </ol>
          )}
        </div>

        <div id="dispositions">
          <SectionLabel>
            <ClipboardCheck className="size-3.5" aria-hidden="true" />
            Human Dispositions
          </SectionLabel>
          <h2 className="text-lg font-semibold">Recorded decisions</h2>
          <p className="mt-1 text-xs leading-5 text-muted-foreground">
            A Disposition is a human decision event. It does not replace the system Recommendation
            and applies only to this Asset Snapshot and Environment Profile.
          </p>

          {dispositions.length ? (
            <ol className="mt-4 space-y-2" aria-label="Human Dispositions">
              {dispositions.map((disposition) => (
                <li key={disposition.id} className="rounded-md border bg-card p-3 text-xs">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-semibold">{dispositionLabels[disposition.kind]}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">
                      REV-
                      {String(
                        revisionNumbers.get(disposition.investigationRevisionId) ?? "?",
                      ).padStart(4, "0")}
                    </span>
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    {disposition.author} · {formatTimestamp(disposition.createdAt)}
                  </div>
                  {disposition.rationale ? (
                    <p className="mt-2 leading-5">{disposition.rationale}</p>
                  ) : null}
                  {disposition.expirationDate || disposition.reviewDate ? (
                    <div className="mt-2 font-mono text-[10px] text-muted-foreground">
                      {disposition.expirationDate ? (
                        <span>Expires {disposition.expirationDate}</span>
                      ) : null}
                      {disposition.expirationDate && disposition.reviewDate ? (
                        <span aria-hidden="true"> · </span>
                      ) : null}
                      {disposition.reviewDate ? (
                        <span>Review by {disposition.reviewDate}</span>
                      ) : null}
                    </div>
                  ) : null}
                </li>
              ))}
            </ol>
          ) : (
            <p className="mt-4 border border-dashed p-3 text-xs text-muted-foreground">
              No human Dispositions have been recorded for this Investigation.
            </p>
          )}

          {dispositionWritesEnabled && currentRevision ? (
            <form action={formAction} className="mt-4 space-y-3 rounded-md border bg-card p-4">
              <h3 className="text-sm font-semibold">Record a Disposition</h3>
              <p className="text-xs text-muted-foreground">
                Authenticated as the configured local operator. This decision will be pinned to REV-
                {String(currentRevision.revisionNumber).padStart(4, "0")} by the server.
              </p>
              <label className="block text-xs font-medium">
                Decision
                <select
                  name="kind"
                  value={kind}
                  onChange={(event) => setKind(event.target.value as DispositionKind)}
                  className="mt-1 block h-9 w-full rounded-md border bg-background px-3 text-sm"
                >
                  {Object.entries(dispositionLabels).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block text-xs font-medium">
                Rationale {kind === "accept_risk" ? "(required)" : "(optional)"}
                <textarea
                  name="rationale"
                  required={kind === "accept_risk"}
                  maxLength={4000}
                  rows={3}
                  className="mt-1 block w-full rounded-md border bg-background px-3 py-2 text-sm"
                />
              </label>
              <fieldset className="grid gap-3 sm:grid-cols-2">
                <legend className="mb-2 text-xs text-muted-foreground sm:col-span-2">
                  Optional decision dates. Risk acceptance requires a rationale plus an expiration
                  or review date.
                </legend>
                <label className="text-xs font-medium">
                  Expiration date
                  <input
                    type="date"
                    name="expirationDate"
                    className="mt-1 block h-9 w-full rounded-md border bg-background px-3 text-sm"
                  />
                </label>
                <label className="text-xs font-medium">
                  Review date
                  <input
                    type="date"
                    name="reviewDate"
                    className="mt-1 block h-9 w-full rounded-md border bg-background px-3 text-sm"
                  />
                </label>
              </fieldset>
              {state.message ? (
                <p
                  aria-live="polite"
                  className={cn(
                    "flex items-center gap-1.5 text-xs",
                    state.status === "error" ? "text-red-700" : "text-emerald-700",
                  )}
                >
                  {state.status === "error" ? (
                    <TriangleAlert className="size-3.5" aria-hidden="true" />
                  ) : (
                    <CheckCircle2 className="size-3.5" aria-hidden="true" />
                  )}
                  <span>{state.message}</span>
                </p>
              ) : null}
              <Button type="submit" disabled={pending} size="sm">
                {pending ? "Recording…" : "Append human Disposition"}
              </Button>
            </form>
          ) : (
            <p className="mt-4 border border-dashed p-3 text-xs leading-5 text-muted-foreground">
              This deployment is read-only. Human Disposition writes are available only to the
              authenticated OS-local operator when local writes are explicitly enabled.
            </p>
          )}
        </div>
      </div>
    </section>
  )
}

export function InvestigationWorkbench({
  investigation,
  assessmentRuns,
  assessmentRunsError,
  assetSnapshots,
  assetSnapshotsError,
  exposures,
  exposuresError,
  policyDecisions,
  policyDecisionsError,
  revisionHistory,
  dispositions,
  investigationHistoryError,
  dispositionWritesEnabled,
  recordDispositionAction,
}: {
  investigation: WorkbenchInvestigation
  assessmentRuns: AssessmentRun[]
  assessmentRunsError: string | null
  assetSnapshots: AssetSnapshot[]
  assetSnapshotsError: string | null
  exposures: Exposure[]
  exposuresError: string | null
  policyDecisions: PolicyDecision[]
  policyDecisionsError: string | null
  revisionHistory: RevisionHistoryEntry[]
  dispositions: Disposition[]
  investigationHistoryError?: string | null
  dispositionWritesEnabled: boolean
  recordDispositionAction: (
    state: DispositionActionState,
    formData: FormData,
  ) => Promise<DispositionActionState>
}) {
  const [selectedClaimId, setSelectedClaimId] = useState<string | null>(
    investigation.claims[0]?.id ?? null,
  )
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null)
  const selectedClaim = investigation.claims.find(({ id }) => id === selectedClaimId)
  const selectedEvidence = investigation.evidence.find(({ id }) => id === selectedEvidenceId)
  const claimsLinkedToSelectedEvidence = new Set(
    selectedEvidence
      ? claimsForEvidence(investigation.claims, selectedEvidence).map(({ id }) => id)
      : [],
  )
  const navigation = [
    { label: "Assessment Runs", icon: Activity, count: String(assessmentRuns.length), active: true },
    { label: "Asset Snapshots", icon: Database, count: String(assetSnapshots.length) },
    { label: "Exposures", icon: Radar, count: String(exposures.length) },
    { label: "Investigations", icon: FileSearch, count: "8" },
    { label: "Evaluations", icon: FlaskConical, count: "v0.3" },
  ]
  const relatedEvidence = useMemo(
    () =>
      selectedClaimId
        ? evidenceForClaim(investigation.evidence, selectedClaimId).toSorted(
            (left, right) => left.fusedRank - right.fusedRank,
          )
        : investigation.evidence.toSorted((left, right) => left.fusedRank - right.fusedRank),
    [investigation.evidence, selectedClaimId],
  )

  function selectClaim(claimId: string) {
    setSelectedClaimId(claimId)
    setSelectedEvidenceId(null)
  }

  function selectEvidence(evidenceId: string, claimIds: string[]) {
    setSelectedEvidenceId(evidenceId)
    const firstClaimId = claimIds[0]
    if (firstClaimId && (!selectedClaimId || !claimIds.includes(selectedClaimId))) {
      setSelectedClaimId(firstClaimId)
    }
  }

  return (
    <div className="min-h-screen bg-background lg:grid lg:grid-cols-[232px_minmax(0,1fr)]">
      <aside className="hidden min-h-screen border-r bg-[oklch(0.24_0.025_70)] text-stone-100 lg:flex lg:flex-col">
        <div className="flex h-18 items-center gap-3 border-b border-white/10 px-5">
          <div className="grid size-8 place-items-center rounded-md border border-teal-300/25 bg-teal-300/10 text-teal-200">
            <Layers3 className="size-4" aria-hidden="true" />
          </div>
          <div>
            <div className="text-sm font-semibold tracking-tight">Exposure Ledger</div>
            <div className="font-mono text-[10px] tracking-[0.12em] text-stone-400 uppercase">
              Investigation lab
            </div>
          </div>
        </div>

        <nav aria-label="Primary" className="flex-1 px-3 py-5">
          <div className="mb-3 px-2 text-[10px] font-semibold tracking-[0.16em] text-stone-500 uppercase">
            Workspace
          </div>
          <ul className="space-y-1">
            {navigation.map((item) => (
              <li key={item.label}>
                <button
                  type="button"
                  className={cn(
                    "flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors",
                    item.active
                      ? "bg-white/10 text-white"
                      : "text-stone-400 hover:bg-white/5 hover:text-stone-200",
                  )}
                >
                  <item.icon className="size-4" aria-hidden="true" />
                  <span className="flex-1">{item.label}</span>
                  <span className="font-mono text-[10px] text-stone-500">{item.count}</span>
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <div className="border-t border-white/10 p-4">
          <div className="rounded-md border border-white/10 bg-black/10 p-3">
            <div className="mb-2 flex items-center gap-2 text-xs font-medium text-stone-200">
              <CircleDot className="size-3.5 text-emerald-300" aria-hidden="true" />
              Local inference
            </div>
            <div className="space-y-1 font-mono text-[10px] leading-4 text-stone-500">
              <div>{investigation.configuration.generationModel.modelArtifact}</div>
              <div>{investigation.retrieval.embeddingSpace.modelArtifact}</div>
              <div>PostgreSQL hybrid retrieval</div>
            </div>
          </div>
        </div>
      </aside>

      <main className="min-w-0">
        <div className="border-b bg-card/80 backdrop-blur">
          <div className="flex min-h-12 items-center justify-between gap-4 px-4 sm:px-6">
            <div className="flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
              <span className="hidden sm:inline">Investigations</span>
              <ChevronRight className="hidden size-3 sm:block" aria-hidden="true" />
              <span className="truncate font-mono text-foreground">
                {investigation.exposure.id}
              </span>
              <ChevronRight className="size-3" aria-hidden="true" />
              <span className="font-mono">{investigation.meta.revision}</span>
            </div>
            <Badge
              variant="outline"
              className="shrink-0 border-amber-600/30 bg-amber-600/8 text-[10px] font-semibold tracking-[0.1em] text-amber-800 uppercase"
            >
              {investigation.meta.mode === "live"
                ? "Live local revision"
                : "Synthetic precomputed demo"}
            </Badge>
          </div>
        </div>

        <AssetSnapshotPanel snapshots={assetSnapshots} error={assetSnapshotsError} />

        <ExposureQueuePanel exposures={exposures} error={exposuresError} />

        <AssessmentRunPanel
          assessmentRuns={assessmentRuns}
          error={assessmentRunsError}
          policyDecisions={policyDecisions}
          policyDecisionsError={policyDecisionsError}
        />

        <div className="hairline-grid border-b bg-card/55 px-4 py-6 sm:px-6 lg:px-8 lg:py-7">
          <div className="mx-auto max-w-[1600px]">
            <div className="flex flex-col gap-5 xl:flex-row xl:items-end xl:justify-between">
              <div className="min-w-0">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <Badge className="border-transparent bg-[var(--urgent)] text-white hover:bg-[var(--urgent)]">
                    <TriangleAlert className="size-3" aria-hidden="true" />
                    {investigation.recommendation.label}
                  </Badge>
                  {!investigation.recommendation.accepted ? (
                    <Badge variant="outline" className="border-red-700/30 bg-red-700/7 text-red-800">
                      Recommendation not accepted
                    </Badge>
                  ) : null}
                  <Badge variant="outline" className="bg-card font-mono">
                    {investigation.exposure.vulnerability}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {investigation.meta.status === "complete"
                      ? "Ready for review"
                      : "Incomplete · review evidence gaps"}
                  </span>
                </div>
                <h1 className="text-balance text-2xl leading-tight font-semibold tracking-[-0.025em] sm:text-3xl">
                  {investigation.exposure.packageName} {investigation.exposure.installedVersion}
                  <span className="font-normal text-muted-foreground">
                    {recommendationOutcome(investigation.recommendation.label)}
                  </span>
                </h1>
                <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1.5">
                    <GitBranch className="size-3.5" aria-hidden="true" />
                    {investigation.meta.repository}@{investigation.meta.commit}
                  </span>
                  <span className="flex items-center gap-1.5 font-mono">
                    <History className="size-3.5" aria-hidden="true" />
                    {investigation.meta.capturedAt}
                  </span>
                </div>
              </div>

              <div className="flex shrink-0 items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="bg-card"
                  onClick={() => document.querySelector("#investigation-history")?.scrollIntoView()}
                >
                  <BookOpenText data-icon="inline-start" />
                  Revision history
                </Button>
                <Button
                  size="sm"
                  disabled={!dispositionWritesEnabled || revisionHistory.length === 0}
                  onClick={() => document.querySelector("#dispositions form")?.scrollIntoView()}
                >
                  Record disposition
                  <ArrowRight data-icon="inline-end" />
                </Button>
              </div>
            </div>

            <ol
              className="mt-6 grid gap-2 sm:grid-cols-2 xl:grid-cols-4"
              aria-label="Investigation stages"
            >
              {investigation.stages.map((stage) => {
                const Icon = stageIcons[stage.mode]
                return (
                  <li
                    key={stage.label}
                    className="flex items-start gap-3 border-l-2 border-primary/25 bg-card/75 px-3 py-2.5"
                  >
                    <Icon className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
                    <div>
                      <div className="text-xs font-semibold">{stage.label}</div>
                      <div className="mt-0.5 text-[11px] leading-4 text-muted-foreground">
                        {stage.detail}
                      </div>
                    </div>
                  </li>
                )
              })}
            </ol>

            {(investigation.evidenceGap || investigation.stoppingReason) && (
              <div className="mt-4 grid gap-3 lg:grid-cols-2">
                {investigation.evidenceGap && (
                  <section className="rounded-md border bg-card p-4" aria-label="Model proposal">
                    <SectionLabel>
                      <Bot className="size-3.5" aria-hidden="true" />
                      Model proposal
                    </SectionLabel>
                    <div className="text-sm font-semibold">{investigation.evidenceGap.description}</div>
                    <div className="mt-2 font-mono text-[10px] text-muted-foreground">
                      {investigation.evidenceGap.kind} · {investigation.evidenceGap.identity}
                    </div>
                    {investigation.followUp && (
                      <dl className="mt-3 border-t pt-2 text-xs">
                        <FactRow label="Tool" value={investigation.followUp.tool} />
                        <FactRow label="Target" value={investigation.followUp.target} />
                        <FactRow
                          label="Arguments"
                          value={`${investigation.followUp.sourceIdentity} · ${investigation.followUp.evidenceType}`}
                        />
                        <FactRow
                          label="Proposed"
                          value={`${investigation.followUp.proposedAssistanceClass}/${investigation.followUp.proposedActionLevel}`}
                        />
                      </dl>
                    )}
                  </section>
                )}

                <section
                  className="rounded-md border bg-card p-4"
                  aria-label="Deterministic authorization"
                >
                  <SectionLabel>
                    <ShieldCheck className="size-3.5" aria-hidden="true" />
                    Deterministic authorization
                  </SectionLabel>
                  {investigation.followUp ? (
                    <>
                      <div className="text-sm font-semibold">
                        {investigation.followUp.authorized
                          ? investigation.followUp.executed
                            ? "Authorized and executed once"
                            : "Authorized"
                          : "Not authorized"}
                      </div>
                      <p className="mt-2 text-xs leading-5 text-muted-foreground">
                        Independently classified {investigation.followUp.policyAssistanceClass}/
                        {investigation.followUp.policyActionLevel} · {investigation.followUp.policyResult}
                        {" · "}
                        {investigation.followUp.reason}
                      </p>
                    </>
                  ) : (
                    <div className="text-sm font-semibold">No follow-up was proposed</div>
                  )}
                  {investigation.stoppingReason && (
                    <p className="mt-3 border-l-2 border-amber-500/40 pl-3 text-xs leading-5 text-amber-900">
                      {investigation.stoppingReason}
                    </p>
                  )}
                </section>
              </div>
            )}
          </div>
        </div>

        <InvestigationDecisionHistory
          revisionHistory={revisionHistory}
          dispositions={dispositions}
          historyError={investigationHistoryError}
          dispositionWritesEnabled={dispositionWritesEnabled}
          recordDispositionAction={recordDispositionAction}
        />

        <div className="mx-auto grid max-w-[1600px] divide-y border-x bg-card xl:grid-cols-[0.86fr_1.08fr_1.22fr] xl:divide-x xl:divide-y-0">
          <section aria-labelledby="exposure-heading" className="min-w-0 p-5 lg:p-6">
            <SectionLabel>
              <Network className="size-3.5" aria-hidden="true" />
              Exposure
            </SectionLabel>
            <h2 id="exposure-heading" className="sr-only">
              Exposure details
            </h2>

            <div className="border-y">
              <dl>
                <FactRow
                  label="Affected range"
                  value={
                    <span className="font-mono text-xs">
                      {investigation.exposure.authoritativeConflict
                        ? "Conflicting guidance — compare Sources"
                        : investigation.exposure.authoritativeConflict === null
                          ? "Not checked — evidence acquisition stopped"
                          : investigation.exposure.affectedRange}
                    </span>
                  }
                />
                <FactRow
                  label="First fix"
                  value={
                    <span className="font-mono">
                      {investigation.exposure.authoritativeConflict
                        ? "Unresolved"
                        : investigation.exposure.authoritativeConflict === null
                          ? "Not checked"
                          : investigation.exposure.fixedVersion}
                    </span>
                  }
                />
                <FactRow label="Dependency" value={investigation.exposure.dependencyType} />
                <FactRow
                  label="KEV"
                  value={<SourceObservation observation={investigation.exposure.kev} />}
                />
                <FactRow
                  label="EPSS"
                  value={<SourceObservation observation={investigation.exposure.epss} />}
                />
                <FactRow label="CVSS" value={investigation.exposure.cvss} />
              </dl>
            </div>

            {investigation.exposure.authoritativeConflict === null ? (
              <div
                role="status"
                className="mt-4 border-l-2 border-amber-600 bg-amber-500/8 p-3 text-xs leading-5"
              >
                Evidence acquisition stopped before authoritative conflict could be checked.
              </div>
            ) : investigation.exposure.authoritativeConflict ? (
              <div
                role="status"
                className="mt-4 border-l-2 border-red-700 bg-red-700/7 p-3 text-xs leading-5 text-red-950"
              >
                <div className="flex items-center gap-2 font-semibold">
                  <TriangleAlert className="size-3.5" aria-hidden="true" />
                  Material conflict
                </div>
                <p className="mt-1">
                  Authoritative Sources disagree. No Source was selected as the winner.
                </p>
                <dl className="mt-3 space-y-2">
                  {investigation.exposure.advisoryGuidance.map((guidance) => (
                    <div key={`${guidance.source}-${guidance.fixedVersion}`} className="border-t pt-2">
                      <dt className="font-semibold">{guidance.source}</dt>
                      <dd className="text-red-950/75">{guidance.authority}</dd>
                      <dd className="font-mono">
                        {guidance.affectedRange} · first fix {guidance.fixedVersion} ·{" "}
                        {evidenceRelationshipLabels[guidance.relationship]}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            ) : null}

            <div className="mt-6">
              <SectionLabel>
                <GitBranch className="size-3.5" aria-hidden="true" />
                Dependency Paths
              </SectionLabel>
              {investigation.exposure.dependencyPaths?.some((path) => path.length > 0) ? (
                <div className="space-y-4">
                  {investigation.exposure.dependencyPaths.map((path, pathIndex) => (
                    <ol key={pathIndex} aria-label={`Dependency Path ${pathIndex + 1}`}>
                      {path.map((dependency, index) => (
                        <li
                          key={`${index}-${dependency}`}
                          className="relative flex items-center gap-3 pb-3 last:pb-0"
                        >
                          {index < path.length - 1 ? (
                            <span
                              className="absolute top-5 left-[7px] h-[calc(100%-12px)] w-px bg-border"
                              aria-hidden="true"
                            />
                          ) : null}
                          <span
                            className="z-10 size-3.5 rounded-full border-2 border-card bg-primary/45"
                            aria-hidden="true"
                          />
                          <span
                            className={cn(
                              "font-mono text-xs",
                              index === path.length - 1 && "font-semibold text-primary",
                            )}
                          >
                            {dependency}
                          </span>
                        </li>
                      ))}
                    </ol>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">Dependency Paths unknown</p>
              )}
            </div>

            <div className="mt-6 border-l-2 border-[var(--urgent)] bg-[var(--urgent-soft)] p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-[var(--urgent)]">
                <ClipboardCheck className="size-4" aria-hidden="true" />
                Effective Recommendation
              </div>
              <p className="mb-2 text-sm font-semibold">{investigation.recommendation.label}</p>
              <div
                role="status"
                className={cn(
                  "mb-3 border-l-2 p-3 text-xs leading-5",
                  investigation.recommendation.accepted
                    ? "border-primary/30 bg-primary/5"
                    : "border-red-700 bg-red-700/7 text-red-950",
                )}
              >
                <p className="font-semibold">
                  {investigation.recommendation.accepted
                    ? "Recommendation accepted by validation"
                    : "Recommendation not accepted; effective value shown above"}
                </p>
                <p className="mt-1 break-words">{investigation.recommendation.reason}</p>
              </div>
              <p className="text-sm leading-6 text-[var(--ink-soft)]">
                {investigation.recommendation.summary}
              </p>
              <ul className="mt-3 space-y-2">
                {investigation.recommendation.reasons.map((reason) => (
                  <li key={reason} className="text-xs leading-5 text-muted-foreground">
                    {reason}
                  </li>
                ))}
              </ul>
              {investigation.recommendation.limitations.length > 0 ? (
                <div className="mt-3 border-t pt-3">
                  <p className="text-xs font-semibold">Recommendation limitations</p>
                  <ul className="mt-2 space-y-2 text-xs leading-5 text-muted-foreground">
                    {investigation.recommendation.limitations.map((limitation) => (
                      <li key={limitation}>{limitation}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>

            <div className="mt-6 rounded-md border bg-muted/45 p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-xs font-semibold">Policy decision</span>
                <span className="flex items-center gap-1 text-xs font-medium text-emerald-700">
                  <CheckCircle2 className="size-3.5" aria-hidden="true" />
                  {investigation.policy.decision}
                </span>
              </div>
              <div className="font-mono text-[10px] leading-5 text-muted-foreground">
                {investigation.policy.assistanceClass}
                <br />
                {investigation.policy.actionLevel}
              </div>
            </div>
          </section>

          <section aria-labelledby="claims-heading" className="min-w-0 p-5 lg:p-6">
            <div className="mb-4 flex items-end justify-between gap-4">
              <div>
                <SectionLabel>
                  <Library className="size-3.5" aria-hidden="true" />
                  Atomic claims
                </SectionLabel>
                <h2 id="claims-heading" className="text-lg font-semibold tracking-tight">
                  Claims and validation
                </h2>
              </div>
              <span className="font-mono text-xs text-muted-foreground">
                {investigation.claims.length} claims
              </span>
            </div>

            <div className="mb-4 space-y-2 text-xs leading-5 text-muted-foreground">
              <p>
                Support status is recorded by deterministic validation. It does not establish that
                evidence entails a Claim or that a human verified it.
              </p>
              <p className="font-semibold text-foreground">
                {investigation.validation.materialClaimsSupported
                  ? "Claim support requirements satisfied"
                  : "Claim support requirements not satisfied"}
              </p>
              {investigation.validation.validationIssues.length > 0 ? (
                <ul aria-label="Claim validation diagnostics" className="space-y-1 text-red-800">
                  {investigation.validation.validationIssues.map((issue, index) => (
                    <li key={`${index}-${issue}`} className="break-words">{issue}</li>
                  ))}
                </ul>
              ) : null}
            </div>

            <div className="space-y-2" aria-label="Investigation claims">
              {investigation.claims.length === 0 ? (
                <div role="status" className="border-l-2 border-amber-600 bg-amber-600/8 p-4">
                  <p className="text-sm font-semibold">No Claims were retained.</p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">
                    This Revision preserves its evidence state without inventing a conclusion.
                  </p>
                </div>
              ) : null}
              {investigation.claims.map((claim) => {
                const selected = claim.id === selectedClaimId
                const linkedToSelectedEvidence = claimsLinkedToSelectedEvidence.has(claim.id)
                const evidenceCount = evidenceForClaim(investigation.evidence, claim.id).length
                return (
                  <button
                    key={claim.id}
                    type="button"
                    aria-pressed={selected}
                    aria-controls="evidence-trace"
                    onClick={() => selectClaim(claim.id)}
                    className={cn(
                      "group w-full rounded-md border p-4 text-left transition-[background-color,border-color,transform] duration-150 ease-out focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                      selected
                        ? "border-primary/40 bg-accent/55"
                        : linkedToSelectedEvidence
                          ? "border-primary/30 bg-primary/5 ring-2 ring-primary/10"
                        : "bg-card hover:-translate-y-px hover:border-primary/20 hover:bg-muted/30",
                      !claim.supported && "border-red-700/45 bg-red-700/5",
                    )}
                  >
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={cn(
                            "grid size-6 place-items-center rounded-sm font-mono text-[10px] font-bold",
                            selected
                              ? "bg-primary text-primary-foreground"
                              : "bg-muted text-muted-foreground",
                          )}
                        >
                          {claim.label}
                        </span>
                        <Badge
                          variant="outline"
                          className={cn(
                            "h-5 text-[9px] tracking-[0.08em] uppercase",
                            claim.kind === "inference" &&
                              "border-amber-700/25 bg-amber-600/8 text-amber-800",
                          )}
                        >
                          {claim.kind}
                        </Badge>
                        <Badge
                          variant="outline"
                          aria-label={`Claim validation: ${claim.supported ? "Support requirements met" : "Unsupported Claim"}`}
                          className={cn(
                            "h-5 text-[9px]",
                            claim.supported
                              ? "border-primary/25 text-primary"
                              : "border-red-700 bg-red-700 text-white",
                          )}
                        >
                          {!claim.supported ? (
                            <TriangleAlert className="size-3" aria-hidden="true" />
                          ) : null}
                          {claim.supported ? "Support requirements met" : "Unsupported Claim"}
                        </Badge>
                        <span className="text-[10px] text-muted-foreground">
                          {claim.material ? "Material" : "Non-material"}
                        </span>
                      </div>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {evidenceCount} evidence record{evidenceCount === 1 ? "" : "s"}
                      </span>
                    </div>
                    <p className="text-sm leading-6 text-[var(--ink-soft)]">{claim.text}</p>
                    {claim.limitation ? (
                      <p className="mt-3 border-l-2 border-amber-500/35 pl-3 text-xs leading-5 text-amber-900/75">
                        {claim.limitation}
                      </p>
                    ) : null}
                  </button>
                )
              })}
            </div>
          </section>

          <section
            id="evidence-trace"
            aria-labelledby="evidence-heading"
            className="min-w-0 bg-[oklch(0.986_0.005_86)] p-5 lg:p-6"
          >
            <div className="mb-4 flex items-end justify-between gap-4">
              <div>
                <SectionLabel>
                  <Database className="size-3.5" aria-hidden="true" />
                  Evidence trace
                </SectionLabel>
                <h2 id="evidence-heading" aria-live="polite" className="text-lg font-semibold tracking-tight">
                  {selectedClaim
                    ? `Evidence used by ${selectedClaim.label}`
                    : "Evidence available to this Revision"}
                </h2>
              </div>
              <Badge variant="secondary" className="font-mono text-[10px]">
                Hybrid · RRF · top {relatedEvidence.length}
              </Badge>
            </div>

            <div className="mb-4 rounded-md border border-primary/15 bg-primary/5 p-3 text-xs leading-5 text-muted-foreground">
              <span className="font-semibold text-foreground">Retrieval query:</span>{" "}
              <span className="font-mono">{investigation.retrieval.query}</span>
              <span className="mt-1 block text-[10px]">
                PostgreSQL full-text + pgvector · {investigation.retrieval.configurationVersion} ·{" "}
                {investigation.retrieval.sourcePolicyVersion}
              </span>
              <span className="mt-1 block text-[10px]">
                Rank 1 is the strongest fused result. A missing component rank means the passage
                was outside that component&apos;s candidate list.
              </span>
              <details className="mt-2 border-t border-primary/10 pt-2 text-[10px]">
                <summary className="cursor-pointer font-semibold text-foreground">
                  Embedding Space
                </summary>
                <dl className="mt-2 grid gap-x-3 gap-y-1 sm:grid-cols-[112px_1fr]">
                  <dt>Identity</dt>
                  <dd className="break-all font-mono">
                    {investigation.retrieval.embeddingSpace.identity}
                  </dd>
                  <dt>Provider</dt>
                  <dd className="font-mono">{investigation.retrieval.embeddingSpace.provider}</dd>
                  <dt>Artifact</dt>
                  <dd className="font-mono">
                    {investigation.retrieval.embeddingSpace.modelArtifact}
                  </dd>
                  <dt>Artifact digest</dt>
                  <dd className="break-all font-mono">
                    {investigation.retrieval.embeddingSpace.artifactDigest}
                  </dd>
                  <dt>Dimensions</dt>
                  <dd className="font-mono">
                    {investigation.retrieval.embeddingSpace.dimensions}
                  </dd>
                  <dt>Instruction</dt>
                  <dd className="font-mono">
                    {investigation.retrieval.embeddingSpace.retrievalInstruction}
                  </dd>
                  <dt>Normalizer</dt>
                  <dd className="font-mono">{investigation.retrieval.embeddingSpace.normalizer}</dd>
                  <dt>Passage version</dt>
                  <dd className="font-mono">
                    {investigation.retrieval.embeddingSpace.passageConstructionVersion}
                  </dd>
                </dl>
              </details>
            </div>

            <div className="space-y-3">
              {relatedEvidence.map((record) => {
                const selected = record.id === selectedEvidenceId
                const selectedRelationships = selectedClaimId
                  ? relationshipsForClaim(record, selectedClaimId)
                  : []
                return (
                  <article
                    key={record.id}
                    className={cn(
                      "rounded-md border bg-card p-4 transition-[border-color,box-shadow] duration-150 ease-out",
                      selected && "border-primary/50 ring-2 ring-primary/10",
                    )}
                  >
                    <button
                      type="button"
                      onClick={() =>
                        selectEvidence(
                          record.id,
                          Array.from(
                            new Set(record.relationships.map(({ claimId }) => claimId)),
                          ),
                        )
                      }
                      aria-pressed={selected}
                      className="w-full text-left focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="min-w-0">
                          <div className="truncate text-sm font-semibold">{record.source}</div>
                          <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-muted-foreground">
                            <span>{record.authority}</span>
                            <span aria-hidden="true">·</span>
                            <span className="font-mono">{record.capturedAt}</span>
                          </div>
                        </div>
                        <div className="flex shrink-0 flex-wrap justify-end gap-1">
                          {selectedRelationships.map((relationship, index) => (
                            <Badge
                              key={`${relationship}-${index}`}
                              variant="outline"
                              aria-label={`Evidence relationship: ${evidenceRelationshipLabels[relationship]}`}
                              className={cn(
                                "text-[9px] tracking-[0.08em] uppercase",
                                relationshipStyles[relationship],
                              )}
                            >
                              {evidenceRelationshipLabels[relationship]}
                            </Badge>
                          ))}
                        </div>
                      </div>

                      <blockquote className="my-4 border-l-2 border-primary/25 pl-4 text-sm leading-6 text-[var(--ink-soft)]">
                        {record.passage}
                      </blockquote>

                      <div className="grid grid-cols-3 gap-2 border-y py-2">
                        <div>
                          <div className="text-[9px] tracking-[0.1em] text-muted-foreground uppercase">
                            Full-text rank
                          </div>
                          <div className="mt-0.5 font-mono text-xs">
                            {record.fullTextRank === null ? "Not ranked" : `#${record.fullTextRank}`}
                          </div>
                        </div>
                        <div>
                          <div className="text-[9px] tracking-[0.1em] text-muted-foreground uppercase">
                            Vector rank
                          </div>
                          <div className="mt-0.5 font-mono text-xs">
                            {record.vectorRank === null ? "Not ranked" : `#${record.vectorRank}`}
                          </div>
                        </div>
                        <div>
                          <div className="text-[9px] tracking-[0.1em] text-muted-foreground uppercase">
                            Fused rank
                          </div>
                          <div className="mt-0.5 font-mono text-xs">
                            #{record.fusedRank}
                          </div>
                        </div>
                      </div>

                      <div className="mt-3 flex items-center justify-between gap-3">
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {record.digest}
                        </span>
                        <span className="flex items-center gap-1 text-[10px] font-medium text-primary">
                          Inspect capture
                          <ExternalLink className="size-3" aria-hidden="true" />
                        </span>
                      </div>
                    </button>

                    <div className="mt-3 flex items-center gap-1.5 border-t pt-3 text-[10px] text-muted-foreground">
                      <span>Used by</span>
                      {Array.from(new Set(record.relationships.map(({ claimId }) => claimId))).map(
                        (claimId) => {
                          const claim = investigation.claims.find(({ id }) => id === claimId)
                          if (!claim) return null
                          return (
                            <button
                              key={claimId}
                              type="button"
                              onClick={() => selectClaim(claimId)}
                              aria-label={`Review ${claim.label}: ${claim.supported ? "Support requirements met" : "Unsupported Claim"}`}
                              aria-controls="evidence-trace"
                              aria-pressed={claimId === selectedClaimId}
                              className={cn(
                                "rounded-sm border px-1.5 py-0.5 font-mono font-semibold transition-colors hover:border-primary/40 hover:text-primary",
                                claimId === selectedClaimId &&
                                  "border-primary/35 bg-primary/8 text-primary",
                              )}
                            >
                              {claim.label}
                            </button>
                          )
                        },
                      )}
                    </div>
                  </article>
                )
              })}
            </div>

            <div className="mt-5 flex items-center gap-2 border-t pt-4 text-xs text-muted-foreground">
              <Bot className="size-3.5" aria-hidden="true" />
              <span>Structured output only. Model reasoning is not retained.</span>
            </div>
          </section>
        </div>

        <footer className="mx-auto flex max-w-[1600px] flex-col gap-3 border-x border-b bg-card px-5 py-4 text-[10px] text-muted-foreground lg:px-6">
          <span>
            {investigation.meta.mode === "live"
              ? "This Revision was generated by the local Investigation runner."
              : "This screen contains synthetic data for interface evaluation."}
          </span>
          <RevisionConfiguration configuration={investigation.configuration} />
        </footer>
      </main>
    </div>
  )
}
