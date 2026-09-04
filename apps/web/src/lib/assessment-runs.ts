export type AssessmentRunStatus = "queued" | "running" | "completed" | "failed"
export type PolicyResult = "allowed" | "restricted" | "blocked"
export type AssetSnapshotRejectionCode =
  | "ambiguous_dependency"
  | "ambiguous_project_root"
  | "archive_compression_ratio_exceeded"
  | "archive_too_large"
  | "archive_too_many_files"
  | "dependency_graph_too_large"
  | "environment_marker_too_complex"
  | "invalid_archive"
  | "invalid_commit"
  | "invalid_lockfile"
  | "invalid_project_file"
  | "invalid_requirements"
  | "invalid_repository"
  | "invalid_repository_path"
  | "lockfile_not_found"
  | "lockfile_too_large"
  | "project_file_not_found"
  | "project_file_too_large"
  | "repository_address_rejected"
  | "repository_address_unavailable"
  | "repository_redirect_rejected"
  | "repository_target_rejected"
  | "repository_unavailable"
  | "unknown_extra"
  | "unpinned_requirement"
  | "unsafe_archive_link"
  | "unsafe_archive_path"
  | "unsupported_environment"
  | "unsupported_environment_marker"
  | "unsupported_lockfile"
  | "unsupported_package_source"
  | "unsupported_project_file"
  | "unsupported_requirement_directive"
  | "unsupported_requirement_source"
  | "unsupported_version_constraint"
export type AssessmentRunErrorCode =
  | AssetSnapshotRejectionCode
  | "policy_gate_unavailable"
  | "repository_fetch_policy_blocked"
  | "synthetic_worker_failure"
  | "worker_execution_failed"

export type PolicyDecision = {
  id: string
  assessmentRunId: string | null
  standardVersion: string
  assistanceClass: "C0" | "C1" | "C2" | "C3"
  actionLevel: "A0" | "A1" | "A2" | "A3" | "A4"
  targetScope: string | null
  authorizationScope: string | null
  result: PolicyResult
  ruleVersion: string
  reason: string
  createdAt: string
  enforcementPoint: "request" | "tool_call"
}

export type AssessmentRun = {
  id: string
  mode: "repository" | "synthetic"
  scenario: "complete" | "worker_failure"
  label: string
  synthetic: boolean
  status: AssessmentRunStatus
  createdAt: string
  startedAt: string | null
  completedAt: string | null
  errorCode: AssessmentRunErrorCode | null
  errorMessage: string | null
  assetSnapshotId: string | null
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

export async function loadCollection<T>(
  resource: string,
  contractName: "Assessment" | "Asset Snapshot" | "Policy",
): Promise<{ items: T[]; error: string | null }> {
  try {
    const response = await fetch(`${apiBaseUrl()}/api/v1/${resource}`, {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    })
    if (!response.ok) {
      return {
        items: [],
        error: `${contractName} API returned HTTP ${response.status}.`,
      }
    }
    const data = (await response.json()) as { items?: T[] }
    if (!Array.isArray(data.items)) {
      return { items: [], error: `${contractName} API returned an invalid response.` }
    }
    return { items: data.items, error: null }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown connection error"
    return { items: [], error: `${contractName} API unavailable: ${message}` }
  }
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
  return loadCollection<AssessmentRun>("assessment-runs", "Assessment")
}

export async function loadPolicyDecisions(): Promise<PolicyDecisionCollection> {
  return loadCollection<PolicyDecision>("policy-decisions", "Policy")
}
