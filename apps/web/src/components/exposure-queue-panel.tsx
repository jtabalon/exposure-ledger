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
          ties; unknown provenance adds no directness or proximity points, and generation models
          are not used.
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
            No OSV Exposures were discovered for the latest repository Assessment Run.
          </div>
        ) : (
          <ol className="grid gap-3 xl:grid-cols-2" aria-label="Ranked Exposures">
            {exposures.map((exposure, index) => (
              <li key={exposure.id} className="rounded-md border bg-card p-4">
                <details open={index === 0}>
                  <summary className="mb-3 cursor-pointer text-xs font-semibold text-primary">
                    Inspect Exposure and Evidence trace
                  </summary>
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
                        {exposure.ranking.directDependency === null
                          ? "Dependency provenance unknown"
                          : exposure.ranking.directDependency
                            ? "Direct dependency"
                            : "Transitive dependency"}
                      </li>
                      <li>
                        {exposure.ranking.dependencyDepth === null
                          ? "Dependency depth unknown"
                          : `Dependency depth ${exposure.ranking.dependencyDepth}`}
                      </li>
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
                        ? exposure.package.dependencyPaths
                            .map((path) => path.join(" → "))
                            .join("; ")
                        : "Dependency paths unknown for this manifest"}
                    </div>
                  </div>
                </div>
                <div className="mt-4 border-t pt-4">
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                    <h4 className="text-xs font-semibold">Evidence trace</h4>
                    <span className="font-mono text-[10px] text-muted-foreground">
                      {exposure.evidenceRecords.length} immutable OSV record
                      {exposure.evidenceRecords.length === 1 ? "" : "s"}
                    </span>
                  </div>
                  {exposure.evidenceRecords.length === 0 ? (
                    <div
                      role="status"
                      className="border-l-2 border-amber-600 bg-amber-600/7 p-3 text-xs text-amber-900"
                    >
                      Evidence unavailable. No Source content is substituted or inferred.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {exposure.evidenceRecords.map((evidence) => (
                        <article key={evidence.id} className="rounded-md border bg-muted/25 p-3">
                          <div className="flex flex-wrap items-start justify-between gap-2">
                            <div>
                              <div className="text-xs font-semibold">{evidence.attribution}</div>
                              <a
                                href={evidence.source.location}
                                target="_blank"
                                rel="noreferrer"
                                className="mt-1 block break-all font-mono text-[10px] text-primary underline-offset-2 hover:underline"
                              >
                                {evidence.source.location}
                              </a>
                            </div>
                            <Badge variant="outline" className="font-mono text-[9px]">
                              {evidence.payloadIdentity}
                            </Badge>
                          </div>
                          <dl className="mt-3 grid gap-2 text-[10px] sm:grid-cols-2">
                            <div>
                              <dt className="text-muted-foreground">Captured</dt>
                              <dd className="font-mono">{evidence.capturedAt}</dd>
                            </div>
                            <div>
                              <dt className="text-muted-foreground">Source identity</dt>
                              <dd className="font-mono">{evidence.source.identity}</dd>
                            </div>
                            <div className="sm:col-span-2">
                              <dt className="text-muted-foreground">Content digest</dt>
                              <dd className="break-all font-mono">{evidence.contentDigest}</dd>
                            </div>
                          </dl>
                          <div className="mt-3 flex flex-wrap gap-1.5" aria-label="Evidence aliases">
                            {evidence.aliases.map((alias) => (
                              <Badge key={alias} variant="outline" className="font-mono text-[9px]">
                                {alias}
                              </Badge>
                            ))}
                          </div>
                          <div className="mt-3 space-y-2">
                            {evidence.passages.map((passage) => (
                              <div key={passage.id}>
                                <div className="mb-1 text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">
                                  Affected-range passage · {passage.selector}
                                </div>
                                <pre className="overflow-x-auto rounded border bg-card p-2 font-mono text-[10px] leading-4 whitespace-pre-wrap">
                                  {passage.content}
                                </pre>
                              </div>
                            ))}
                          </div>
                          <details className="mt-3">
                            <summary className="cursor-pointer text-[10px] font-medium text-muted-foreground">
                              Full captured OSV payload
                            </summary>
                            <pre className="mt-2 overflow-x-auto rounded border bg-card p-2 font-mono text-[10px] leading-4 whitespace-pre-wrap">
                              {evidence.content}
                            </pre>
                          </details>
                        </article>
                      ))}
                    </div>
                  )}
                </div>
                </details>
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  )
}
