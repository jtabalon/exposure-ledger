import "server-only"

import { apiBaseUrl } from "./assessment-runs"

const loopbackHosts = new Set(["127.0.0.1", "[::1]", "localhost"])

export function localDispositionWritesEnabled(): boolean {
  const configured = process.env.EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS
  const enabled = configured === "true" || (configured === undefined && process.env.NODE_ENV !== "production")
  return enabled && loopbackHosts.has(new URL(apiBaseUrl()).hostname)
}
