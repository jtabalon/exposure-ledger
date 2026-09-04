"use client"

import { useState } from "react"
import { Boxes, Fingerprint, GitCommitHorizontal, LockKeyhole } from "lucide-react"

import type { AssetSnapshot } from "../lib/asset-snapshots"
import { cn } from "../lib/utils"
import { Badge } from "./ui/badge"

function repositoryLabel(repository: string): string {
  return repository.replace("https://github.com/", "")
}

function sourceLabel(source: Record<string, unknown>): string {
  return Object.entries(source)
    .map(([kind, value]) => `${kind}: ${String(value)}`)
    .join(", ")
}

export function AssetSnapshotPanel({
  snapshots,
  error,
}: {
  snapshots: AssetSnapshot[]
  error: string | null
}) {
  const [selectedId, setSelectedId] = useState(snapshots[0]?.id ?? null)
  const selected = snapshots.find(({ id }) => id === selectedId) ?? snapshots[0]

  return (
    <section
      aria-labelledby="asset-snapshots-heading"
      className="border-b bg-card/55 px-4 py-5 sm:px-6 lg:px-8"
    >
      <div className="mx-auto max-w-[1600px]">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
              <Fingerprint className="size-3.5" aria-hidden="true" />
              Immutable Asset Snapshot
            </div>
            <h2 id="asset-snapshots-heading" className="text-lg font-semibold">
              Repository scope and resolved dependencies
            </h2>
          </div>
          <span className="font-mono text-xs text-muted-foreground">
            {snapshots.length} captured
          </span>
        </div>

        {error ? (
          <div
            role="alert"
            className="border-l-2 border-red-600 bg-red-600/7 p-3 text-xs leading-5 text-red-900"
          >
            {error}
          </div>
        ) : snapshots.length === 0 ? (
          <div className="border border-dashed p-3 text-xs leading-5 text-muted-foreground">
            No Asset Snapshots yet. Create a repository Assessment through
            <code className="ml-1 font-mono text-foreground">
              POST /api/v1/assessment-runs
            </code>
            .
          </div>
        ) : (
          <div className="grid gap-4 xl:grid-cols-[0.65fr_1.35fr]">
            <ul className="space-y-2" aria-label="Available Asset Snapshots">
              {snapshots.map((snapshot) => {
                const isSelected = snapshot.id === selected?.id
                return (
                  <li key={snapshot.id}>
                    <button
                      type="button"
                      aria-pressed={isSelected}
                      onClick={() => setSelectedId(snapshot.id)}
                      className={cn(
                        "w-full rounded-md border p-3 text-left transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none",
                        isSelected
                          ? "border-primary/40 bg-accent/55"
                          : "bg-card hover:border-primary/20",
                      )}
                    >
                      <span className="block truncate text-sm font-semibold">
                        {repositoryLabel(snapshot.repository)}
                      </span>
                      <span className="mt-1 block truncate font-mono text-[10px] text-muted-foreground">
                        {snapshot.commit}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>

            {selected ? (
              <div className="rounded-md border bg-card p-4">
                <div className="grid gap-3 border-b pb-4 md:grid-cols-2">
                  <div>
                    <div className="mb-1 flex items-center gap-2 text-[10px] tracking-[0.1em] text-muted-foreground uppercase">
                      <GitCommitHorizontal className="size-3" aria-hidden="true" />
                      Repository commit
                    </div>
                    <div className="font-mono text-xs break-all">{selected.commit}</div>
                  </div>
                  <div>
                    <div className="mb-1 flex items-center gap-2 text-[10px] tracking-[0.1em] text-muted-foreground uppercase">
                      <LockKeyhole className="size-3" aria-hidden="true" />
                      Selected lockfile
                    </div>
                    <div className="font-mono text-xs">{selected.lockfilePath}</div>
                    <div className="mt-1 truncate font-mono text-[9px] text-muted-foreground">
                      {selected.lockfileDigest}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 border-b py-3 text-xs">
                  <span className="font-medium">
                    {`Python ${selected.environmentProfile.pythonVersion} · ${selected.environmentProfile.operatingSystem} · ${selected.environmentProfile.architecture}`}
                  </span>
                  <Badge variant="outline" className="font-mono text-[9px]">
                    root {selected.projectRoot}
                  </Badge>
                  {selected.environmentProfile.selectedExtras.map((extra) => (
                    <Badge key={extra} variant="outline" className="text-[9px]">
                      {extra}
                    </Badge>
                  ))}
                </div>

                <div className="mt-3 flex items-center gap-2 text-[10px] tracking-[0.1em] text-muted-foreground uppercase">
                  <Boxes className="size-3" aria-hidden="true" />
                  {selected.packages.length} normalized packages · {selected.parserVersion}
                </div>
                <ul className="mt-2 divide-y" aria-label="Normalized dependencies">
                  {selected.packages.map((packageInstance) => {
                    const source = sourceLabel(packageInstance.source)
                    return (
                    <li
                      key={`${packageInstance.name}-${packageInstance.version}-${source}`}
                      className="grid gap-1 py-2 text-xs sm:grid-cols-[150px_80px_180px_1fr] sm:gap-3"
                    >
                      <span className="font-mono font-semibold">
                        {packageInstance.name} {packageInstance.version}
                      </span>
                      <span>{packageInstance.direct ? "Direct" : "Transitive"}</span>
                      <span className="truncate font-mono text-[10px] text-muted-foreground">
                        {source}
                      </span>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        {packageInstance.dependencyPaths
                          .map((path) => path.join(" → "))
                          .join("; ")}
                      </span>
                    </li>
                    )
                  })}
                </ul>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </section>
  )
}
