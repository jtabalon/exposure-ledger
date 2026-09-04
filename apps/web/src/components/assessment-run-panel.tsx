"use client"

import { useState, type ReactNode } from "react"
import { Activity, Database } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import type { AssessmentRun, AssessmentRunStatus } from "@/lib/assessment-runs"
import { cn } from "@/lib/utils"

const statusStyles: Record<AssessmentRunStatus, string> = {
  queued: "border-amber-700/25 bg-amber-600/8 text-amber-800",
  running: "border-sky-700/25 bg-sky-600/8 text-sky-800",
  completed: "border-emerald-700/25 bg-emerald-600/8 text-emerald-800",
  failed: "border-red-700/25 bg-red-600/8 text-red-800",
}

const utcTimestamp = new Intl.DateTimeFormat("en-US", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "UTC",
})

function formatTimestamp(value: string): string {
  return `${utcTimestamp.format(new Date(value))} UTC`
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
}: {
  assessmentRuns: AssessmentRun[]
  error: string | null
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
                        SYNTHETIC
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
                <DetailRow label="Mode" value="Synthetic only" />
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
              </dl>
              {selected.errorMessage ? (
                <p className="mt-3 text-xs text-red-800">{selected.errorMessage}</p>
              ) : null}
            </>
          ) : (
            <div className="grid min-h-28 place-items-center text-sm text-muted-foreground">
              Select an Assessment Run to inspect it.
            </div>
          )}
        </div>
      </div>
    </section>
  )
}
