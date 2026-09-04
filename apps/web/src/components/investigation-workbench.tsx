"use client"

import { useMemo, useState, type ReactNode } from "react"
import {
  Activity,
  ArrowRight,
  BookOpenText,
  Bot,
  Check,
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
import type { Exposure } from "@/lib/exposures"
import {
  claimsForEvidence,
  evidenceForClaim,
  evidenceRelationshipLabels,
  relationshipsForClaim,
} from "@/lib/evidence"
import type {
  DemoInvestigation,
  EvidenceRelationship,
  InvestigationStage,
} from "@/lib/demo-investigation"
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
}: {
  investigation: DemoInvestigation
  assessmentRuns: AssessmentRun[]
  assessmentRunsError: string | null
  assetSnapshots: AssetSnapshot[]
  assetSnapshotsError: string | null
  exposures: Exposure[]
  exposuresError: string | null
  policyDecisions: PolicyDecision[]
  policyDecisionsError: string | null
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
              <div>gpt-oss:20b</div>
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
                <Button variant="outline" size="sm" className="bg-card">
                  <BookOpenText data-icon="inline-start" />
                  Revision history
                </Button>
                <Button size="sm">
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
          </div>
        </div>

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
                <FactRow label="KEV" value={investigation.exposure.kev ? "Listed" : "Not listed"} />
                <FactRow
                  label="EPSS"
                  value={`${investigation.exposure.epssPercentile} percentile`}
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
                Dependency path
              </SectionLabel>
              <ol className="space-y-0">
                {investigation.exposure.dependencyPath.map((dependency, index) => (
                  <li
                    key={dependency}
                    className="relative flex items-center gap-3 pb-3 last:pb-0"
                  >
                    {index < investigation.exposure.dependencyPath.length - 1 ? (
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
                        index === investigation.exposure.dependencyPath.length - 1 &&
                          "font-semibold text-primary",
                      )}
                    >
                      {dependency}
                    </span>
                  </li>
                ))}
              </ol>
            </div>

            <div className="mt-6 border-l-2 border-[var(--urgent)] bg-[var(--urgent-soft)] p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-[var(--urgent)]">
                <ClipboardCheck className="size-4" aria-hidden="true" />
                Recommended action
              </div>
              <p className="text-sm leading-6 text-[var(--ink-soft)]">
                {investigation.recommendation.summary}
              </p>
              <ul className="mt-3 space-y-2">
                {investigation.recommendation.reasons.map((reason) => (
                  <li key={reason} className="flex gap-2 text-xs leading-5 text-muted-foreground">
                    <Check className="mt-0.5 size-3.5 shrink-0 text-primary" aria-hidden="true" />
                    {reason}
                  </li>
                ))}
              </ul>
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
                  What the evidence supports
                </h2>
              </div>
              <span className="font-mono text-xs text-muted-foreground">
                {investigation.claims.length} claims
              </span>
            </div>

            <div className="space-y-2" aria-label="Investigation claims">
              {investigation.claims.length === 0 ? (
                <div role="status" className="border-l-2 border-amber-600 bg-amber-600/8 p-4">
                  <p className="text-sm font-semibold">No validated Claims were retained.</p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">
                    This incomplete Revision preserves the stopping condition and evidence state
                    without inventing a conclusion.
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
                    onClick={() => selectClaim(claim.id)}
                    className={cn(
                      "group w-full rounded-md border p-4 text-left transition-[background-color,border-color,transform] duration-150 ease-out focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                      selected
                        ? "border-primary/40 bg-accent/55"
                        : linkedToSelectedEvidence
                          ? "border-primary/30 bg-primary/5 ring-2 ring-primary/10"
                        : "bg-card hover:-translate-y-px hover:border-primary/20 hover:bg-muted/30",
                    )}
                  >
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2">
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
            aria-labelledby="evidence-heading"
            className="min-w-0 bg-[oklch(0.986_0.005_86)] p-5 lg:p-6"
          >
            <div className="mb-4 flex items-end justify-between gap-4">
              <div>
                <SectionLabel>
                  <Database className="size-3.5" aria-hidden="true" />
                  Evidence trace
                </SectionLabel>
                <h2 id="evidence-heading" className="text-lg font-semibold tracking-tight">
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

        <footer className="mx-auto flex max-w-[1600px] flex-col gap-2 border-x border-b bg-card px-5 py-4 text-[10px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between lg:px-6">
          <span>
            {investigation.meta.mode === "live"
              ? "This Revision was generated by the local Investigation runner."
              : "This screen contains synthetic data for interface evaluation."}
          </span>
          <span className="font-mono">
            graph v0.1 · policy v0.1 · prompt demo-001 · retrieval{" "}
            {investigation.retrieval.configurationVersion}
          </span>
        </footer>
      </main>
    </div>
  )
}
