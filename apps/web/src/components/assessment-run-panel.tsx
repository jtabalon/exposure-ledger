"use client"

import { useState, type ReactNode } from "react"
import { Activity, Database, ShieldCheck } from "lucide-react"

import { Badge } from "./ui/badge"
import type {
  AssessmentRunErrorCode,
  AssessmentRun,
  AssessmentRunStatus,
  PolicyDecision,
  PolicyResult,
} from "../lib/assessment-runs"
import { cn } from "../lib/utils"

const statusStyles: Record<AssessmentRunStatus, string> = {
  queued: "border-amber-700/25 bg-amber-600/8 text-amber-800",
  running: "border-sky-700/25 bg-sky-600/8 text-sky-800",
  completed: "border-emerald-700/25 bg-emerald-600/8 text-emerald-800",
  failed: "border-red-700/25 bg-red-600/8 text-red-800",
}

const policyStyles: Record<PolicyResult, string> = {
  allowed: "border-emerald-700/25 bg-emerald-600/8 text-emerald-800",
  restricted: "border-amber-700/25 bg-amber-600/8 text-amber-800",
  blocked: "border-red-700/25 bg-red-600/8 text-red-800",
}

const utcTimestamp = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
})

function formatTimestamp(value: string): string {
  return `${utcTimestamp.format(new Date(value))} UTC`
}

function assessmentRunFailureGuidance(code: AssessmentRunErrorCode): string {
  if (code === "osv_unavailable") {
    return "Verify the OSV Source is reachable, then create a new Assessment Run. No evidence was substituted."
  }
  if (code === "invalid_osv_response") {
    return "The OSV Source response was rejected. Retry later; do not treat this run as evidence-bearing."
  }
  if (code === "osv_lookup_policy_blocked") {
    return "Review the recorded OSV tool-call Policy Decision before creating a new Assessment Run."
  }
  if (
    code === "archive_too_large" ||
    code === "archive_too_many_files" ||
    code === "archive_compression_ratio_exceeded" ||
    code === "lockfile_too_large" ||
    code === "dependency_graph_too_large" ||
    code === "environment_marker_too_complex"
  ) {
    return "Choose a smaller repository revision or lockfile, then create a new Assessment Run."
  }
  if (code === "ambiguous_project_root") {
    return "Select exactly one project root and one supported dependency file, then create a new Assessment Run."
  }
  if (
    code === "invalid_project_file" ||
    code === "invalid_requirements" ||
    code === "project_file_not_found" ||
    code === "project_file_too_large" ||
    code === "unpinned_requirement" ||
    code === "unsupported_package_source" ||
    code === "unsupported_project_file" ||
    code === "unsupported_requirement_directive" ||
    code === "unsupported_requirement_source" ||
    code === "unsupported_version_constraint"
  ) {
    return "Choose supported, fully pinned dependency data and valid project metadata, then create a new Assessment Run."
  }
  if (
    code === "invalid_repository" ||
    code === "invalid_repository_path" ||
    code === "repository_target_rejected" ||
    code === "repository_address_rejected" ||
    code === "repository_redirect_rejected" ||
    code === "unsafe_archive_path" ||
    code === "unsafe_archive_link"
  ) {
    return "Use a canonical public GitHub repository and safe in-repository selections."
  }
  if (code === "repository_address_unavailable" || code === "repository_unavailable") {
    return "Verify public GitHub is reachable, then create a new Assessment Run."
  }
  return "Review the rejection details, correct the request, and create a new Assessment Run."
}

function failureHeading(code: AssessmentRunErrorCode): string {
  if (code === "osv_unavailable") return "OSV Source unavailable"
  if (code === "invalid_osv_response") return "OSV Source response rejected"
  if (code === "osv_lookup_policy_blocked") return "OSV lookup blocked by Policy Decision"
  return "Asset Snapshot rejected"
}

function DetailRow({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="grid grid-cols-[104px_1fr] gap-3 border-b py-3 last:border-b-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="text-sm leading-5 font-medium text-foreground">{value}</dd>
    </div>
  )
}

export function AssessmentRunPanel({
  assessmentRuns,
  error,
  policyDecisions,
  policyDecisionsError,
}: {
  assessmentRuns: AssessmentRun[]
  error: string | null
  policyDecisions: PolicyDecision[]
  policyDecisionsError: string | null
}) {
  const [selectedId, setSelectedId] = useState(assessmentRuns[0]?.id ?? null)
  const selected = assessmentRuns.find(({ id }) => id === selectedId) ?? assessmentRuns[0]

  return (
    <section
      aria-labelledby="assessment-runs-heading"
      className="border-b bg-background px-4 py-5 sm:px-6 lg:px-8"
    >
      <div className="mx-auto grid max-w-[1600px] gap-4 xl:grid-cols-[0.9fr_1.1fr]">
        <div>
          <div className="mb-3 flex items-center justify-between gap-4">
            <div>
              <div className="mb-3 flex items-center gap-2 text-[11px] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
                <Activity className="size-3.5" aria-hidden="true" />
                Assessment Runs
              </div>
              <h2 id="assessment-runs-heading" className="text-lg font-semibold">
                Durable local activity
              </h2>
            </div>
            <span className="font-mono text-xs text-muted-foreground">
              {assessmentRuns.length} total
            </span>
          </div>

          {error ? (
            <div
              role="alert"
              className="border-l-2 border-red-600 bg-red-600/7 p-3 text-xs leading-5 text-red-900"
            >
              {error}
            </div>
          ) : assessmentRuns.length === 0 ? (
            <div className="border border-dashed p-3 text-xs leading-5 text-muted-foreground">
              No Assessment Runs yet. Create one through
              <code className="ml-1 font-mono text-foreground">
                POST /api/v1/assessment-runs
              </code>
              .
            </div>
          ) : (
            <ul className="space-y-2" aria-label="Available Assessment Runs">
              {assessmentRuns.map((assessmentRun) => {
                const isSelected = assessmentRun.id === selected?.id
                return (
                  <li key={assessmentRun.id}>
                    <button
                      type="button"
                      aria-pressed={isSelected}
                      onClick={() => setSelectedId(assessmentRun.id)}
                      className={cn(
                        "flex w-full items-center gap-3 rounded-md border p-3 text-left transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                        isSelected
                          ? "border-primary/40 bg-accent/55"
                          : "bg-card hover:border-primary/20",
                      )}
                    >
                      <Database className="size-4 shrink-0 text-primary" aria-hidden="true" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-semibold">
                          {assessmentRun.label}
                        </span>
                        <span className="block truncate font-mono text-[10px] text-muted-foreground">
                          {assessmentRun.id}
                        </span>
                      </span>
                      <Badge variant="outline" className="border-amber-600/30 text-[9px]">
                        {assessmentRun.synthetic ? "SYNTHETIC" : "LIVE REPOSITORY"}
                      </Badge>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </div>

        <div className="rounded-md border bg-card p-4">
          {selected ? (
            <>
              <div className="flex flex-wrap items-start justify-between gap-3 border-b pb-3">
                <div>
                  <div className="text-sm font-semibold">{selected.label}</div>
                  <div className="mt-1 font-mono text-[10px] text-muted-foreground">
                    {selected.id}
                  </div>
                </div>
                <Badge
                  variant="outline"
                  className={cn(
                    "text-[9px] tracking-[0.08em] uppercase",
                    statusStyles[selected.status],
                  )}
                >
                  {selected.status}
                </Badge>
              </div>
              <dl className="grid gap-x-5 sm:grid-cols-2">
                <DetailRow
                  label="Mode"
                  value={selected.synthetic ? "Synthetic" : "Live repository"}
                />
                <DetailRow label="Created" value={formatTimestamp(selected.createdAt)} />
                <DetailRow
                  label="Started"
                  value={
                    selected.startedAt
                      ? formatTimestamp(selected.startedAt)
                      : "Waiting for worker"
                  }
                />
                <DetailRow
                  label="Finished"
                  value={
                    selected.completedAt ? formatTimestamp(selected.completedAt) : "Not finished"
                  }
                />
                <DetailRow
                  label="Policy"
                  value={`${selected.policyDecision.assistanceClass} / ${selected.policyDecision.actionLevel} · ${selected.policyDecision.result}`}
                />
                <DetailRow
                  label="Scope"
                  value={selected.policyDecision.targetScope ?? "Uncertain"}
                />
              </dl>
              <p className="mt-3 text-xs leading-5 text-muted-foreground">
                {selected.policyDecision.reason}
              </p>
              {selected.mode === "repository" && selected.errorCode ? (
                <div
                  role="alert"
                  className="mt-3 border-l-2 border-red-600 bg-red-600/7 p-3 text-xs leading-5 text-red-900"
                >
                  <div className="font-semibold">{failureHeading(selected.errorCode)}</div>
                  <div className="mt-1 font-mono text-[10px]">{selected.errorCode}</div>
                  {selected.errorMessage ? <p className="mt-1">{selected.errorMessage}</p> : null}
                  <p className="mt-2">{assessmentRunFailureGuidance(selected.errorCode)}</p>
                </div>
              ) : selected.errorMessage ? (
                <p className="mt-3 text-xs text-red-800">{selected.errorMessage}</p>
              ) : null}
            </>
          ) : (
            <div className="grid min-h-28 place-items-center text-sm text-muted-foreground">
              Select an Assessment Run to inspect it.
            </div>
          )}
        </div>

        <div className="border-t pt-4 xl:col-span-2">
          <div className="mb-3 flex items-center justify-between gap-4">
            <div>
              <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
                <ShieldCheck className="size-3.5" aria-hidden="true" />
                Cyber policy
              </div>
              <h3 className="text-base font-semibold">Policy Decision ledger</h3>
            </div>
            <span className="font-mono text-xs text-muted-foreground">
              {policyDecisions.length} total
            </span>
          </div>

          {policyDecisionsError ? (
            <div
              role="alert"
              className="border-l-2 border-red-600 bg-red-600/7 p-3 text-xs leading-5 text-red-900"
            >
              {policyDecisionsError}
            </div>
          ) : policyDecisions.length === 0 ? (
            <p className="text-xs text-muted-foreground">No Policy Decisions recorded yet.</p>
          ) : (
            <ul className="grid gap-2 lg:grid-cols-2" aria-label="Policy Decisions">
              {policyDecisions.map((decision) => (
                <li key={decision.id} className="rounded-md border bg-card p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 font-mono text-xs">
                      <span>{decision.assistanceClass}</span>
                      <span aria-hidden="true">/</span>
                      <span>{decision.actionLevel}</span>
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[9px] tracking-[0.08em] uppercase",
                        policyStyles[decision.result],
                      )}
                    >
                      {decision.result}
                    </Badge>
                  </div>
                  <p className="mt-2 text-xs leading-5 text-foreground">{decision.reason}</p>
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[10px] text-muted-foreground">
                    <span>{decision.targetScope ?? "Target scope uncertain"}</span>
                    <span>
                      {decision.assessmentRunId
                        ? `Run ${decision.assessmentRunId}`
                        : "No worker task created"}
                    </span>
                    <span>
                      Standard {decision.standardVersion} · Rule {decision.ruleVersion}
                    </span>
                    <span>
                      {decision.enforcementPoint === "request" ? "Request gate" : "Tool-call gate"}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  )
}
