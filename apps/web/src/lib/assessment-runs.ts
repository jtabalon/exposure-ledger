export type AssessmentRunStatus = "queued" | "running" | "completed" | "failed"
export type PolicyResult = "allowed" | "restricted" | "blocked"

export type PolicyDecision = {
  id: string
  assessmentRunId: string | null
  standardVersion: string
  assistanceClass: "C0" | "C1" | "C2" | "C3" | null
  actionLevel: "A0" | "A1" | "A2" | "A3" | "A4" | null
  targetScope: string | null
  authorizationScope: string | null
  result: PolicyResult
  ruleVersion: string
  reason: string
  createdAt: string
}

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
  policyDecision: PolicyDecision
}

export type AssessmentRunCollection = {
  items: AssessmentRun[]
  error: string | null
}

export type PolicyDecisionCollection = {
  items: PolicyDecision[]
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

export async function loadPolicyDecisions(): Promise<PolicyDecisionCollection> {
  try {
    const response = await fetch(`${apiBaseUrl()}/api/v1/policy-decisions`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    })
    if (!response.ok) {
      return {
        items: [],
        error: `Policy API returned HTTP ${response.status}.`,
      }
    }
    const data = (await response.json()) as { items?: PolicyDecision[] }
    if (!Array.isArray(data.items)) {
      return { items: [], error: "Policy API returned an invalid response." }
    }
    return { items: data.items, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown connection error"
    return { items: [], error: `Policy API unavailable: ${message}` }
  }
}
