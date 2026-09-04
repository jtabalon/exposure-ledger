import { ArrowDownUp, PackageSearch, ShieldCheck } from "lucide-react"

import type { Exposure } from "../lib/exposures"
import { Badge } from "./ui/badge"

function severityLabel(value: Exposure["ranking"]["severity"]): string {
  return value === "unknown"
    ? "Unknown OSV severity"
    : `${value.charAt(0).toUpperCase()}${value.slice(1)} OSV severity`
}

export function ExposureQueuePanel({
  exposures,
  error,
}: {
  exposures: Exposure[]
  error: string | null
}) {
  return (
    <section
      aria-labelledby="exposure-queue-heading"
      className="border-b bg-background px-4 py-5 sm:px-6 lg:px-8"
    >
      <div className="mx-auto max-w-[1600px]">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold tracking-[0.14em] text-muted-foreground uppercase">
              <ArrowDownUp className="size-3.5" aria-hidden="true" />
              Deterministic discovery
            </div>
            <h2 id="exposure-queue-heading" className="text-lg font-semibold">
              Ranked Exposure queue
            </h2>
          </div>
          <span className="font-mono text-xs text-muted-foreground">
            {exposures.length} package-specific candidates
          </span>
        </div>
        <p className="mb-4 max-w-4xl text-xs leading-5 text-muted-foreground">
          Score = OSV severity (0/10/20/30/40) + direct dependency (20) + published
          fix (10) + dependency proximity (max 10). Stable aliases and package identity break
          ties; generation models are not used.
        </p>

        {error ? (
          <div
            role="alert"
            className="border-l-2 border-red-600 bg-red-600/7 p-3 text-xs leading-5 text-red-900"
          >
            {error}
          </div>
        ) : exposures.length === 0 ? (
          <div className="border border-dashed p-3 text-xs leading-5 text-muted-foreground">
            No OSV Exposures were discovered for the latest completed repository Assessment Run.
          </div>
        ) : (
          <ol className="grid gap-3 xl:grid-cols-2" aria-label="Ranked Exposures">
            {exposures.map((exposure) => (
              <li key={exposure.id} className="rounded-md border bg-card p-4">
                <div className="flex items-start gap-3">
                  <div className="grid size-9 shrink-0 place-items-center rounded-md border bg-accent/45 font-mono text-sm font-semibold text-primary">
                    {exposure.rank}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 className="flex items-center gap-2 text-sm font-semibold">
                        <PackageSearch className="size-4 text-primary" aria-hidden="true" />
                        <span className="font-mono">
                          {exposure.package.name} {exposure.package.version}
                        </span>
                      </h3>
                      {exposure.selectedForInvestigation ? (
                        <Badge className="border-transparent bg-teal-700 text-[9px] text-white">
                          <ShieldCheck className="size-3" aria-hidden="true" />
                          Selected for Investigation
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-[9px]">
                          Queued after top five
                        </Badge>
                      )}
                    </div>

                    <div className="mt-2 flex flex-wrap gap-1.5" aria-label="Vulnerability aliases">
                      {exposure.vulnerabilityRecord.aliases.map((alias) => (
                        <Badge key={alias} variant="outline" className="font-mono text-[9px]">
                          {alias}
                        </Badge>
                      ))}
                    </div>

                    <ul className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                      <li>{severityLabel(exposure.ranking.severity)}</li>
                      <li>
                        {exposure.ranking.directDependency
                          ? "Direct dependency"
                          : "Transitive dependency"}
                      </li>
                      <li>Dependency depth {exposure.ranking.dependencyDepth}</li>
                      <li>
                        {exposure.ranking.fixedVersionAvailable
                          ? "Fixed version published"
                          : "No fixed version in OSV"}
                      </li>
                      <li className="font-mono font-medium text-foreground">
                        Deterministic score {exposure.ranking.score}
                      </li>
                    </ul>

                    <div className="mt-2 font-mono text-[10px] text-muted-foreground">
                      {exposure.package.dependencyPaths
                        .map((path) => path.join(" → "))
                        .join("; ")}
                    </div>
                  </div>
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  )
}
