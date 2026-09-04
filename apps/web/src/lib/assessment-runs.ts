export type AssessmentRunStatus = "queued" | "running" | "completed" | "failed"

export type AssessmentRun = {
  id: string
  mode: "synthetic"
  scenario: "complete" | "worker_failure"
  label: string
  synthetic: true
  status: AssessmentRunStatus
  createdAt: string
  startedAt: string | null
  completedAt: string | null
  errorCode: string | null
  errorMessage: string | null
}

export type AssessmentRunCollection = {
  items: AssessmentRun[]
  error: string | null
}

function apiBaseUrl(): string {
  const configured = process.env.EXPOSURE_LEDGER_API_URL ?? "http://localhost:8000"
  let parsed: URL
  try {
    parsed = new URL(configured)
  } catch {
    throw new Error("EXPOSURE_LEDGER_API_URL must be a valid absolute URL")
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("EXPOSURE_LEDGER_API_URL must use HTTP or HTTPS")
  }
  return parsed.toString().replace(/\/$/, "")
}

export async function loadAssessmentRuns(): Promise<AssessmentRunCollection> {
  try {
    const response = await fetch(`${apiBaseUrl()}/api/v1/assessment-runs`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    })
    if (!response.ok) {
      return {
        items: [],
        error: `Assessment API returned HTTP ${response.status}.`,
      }
    }
    const data = (await response.json()) as { items?: AssessmentRun[] }
    if (!Array.isArray(data.items)) {
      return { items: [], error: "Assessment API returned an invalid response." }
    }
    return { items: data.items, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown connection error"
    return { items: [], error: `Assessment API unavailable: ${message}` }
  }
}
