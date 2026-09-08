import type { EpssSignal, KevSignal, SourceObservationState } from "./exposures"

export function sourceObservationLabel(
  source: "KEV" | "EPSS",
  state: SourceObservationState,
  hasValue = true,
): string {
  switch (state) {
    case "available":
      return hasValue ? "Current observation" : `${source} value missing`
    case "stale":
      return "Stale observation"
    case "missing":
      return `${source} evidence missing`
    case "malformed":
      return `${source} response malformed`
    case "unavailable":
      return `${source} Source unavailable`
    case "not_collected":
      return `${source} not collected`
  }
}

export function kevObservationValue(signal: KevSignal): string {
  if (signal.listed === null) return "Unknown"
  const value = signal.listed ? "Listed" : "Not listed"
  if (signal.state === "available") return value
  if (signal.state === "stale") return `Last observed: ${value}`
  return "Unknown"
}

export function epssObservationValue(signal: EpssSignal): string {
  if (signal.score === null || signal.percentile === null) return "Unknown"
  const value = `${(signal.score * 100).toFixed(1)}% probability · ${ordinal(Math.round(signal.percentile * 100))} percentile`
  if (signal.state === "available") return value
  if (signal.state === "stale") return `Last observed: ${value}`
  return "Unknown"
}

function ordinal(value: number): string {
  const remainder = value % 100
  if (remainder >= 11 && remainder <= 13) return `${value}th`
  switch (value % 10) {
    case 1:
      return `${value}st`
    case 2:
      return `${value}nd`
    case 3:
      return `${value}rd`
    default:
      return `${value}th`
  }
}
