import { afterEach, describe, expect, it, vi } from "vitest"

vi.mock("server-only", () => ({}))

const originalApiUrl = process.env.EXPOSURE_LEDGER_API_URL
const originalWritesEnabled = process.env.EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS

afterEach(() => {
  if (originalApiUrl === undefined) delete process.env.EXPOSURE_LEDGER_API_URL
  else process.env.EXPOSURE_LEDGER_API_URL = originalApiUrl
  if (originalWritesEnabled === undefined)
    delete process.env.EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS
  else process.env.EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS = originalWritesEnabled
})

describe("localDispositionWritesEnabled", () => {
  it.each(["http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"])(
    "allows the explicitly enabled loopback API at %s",
    async (apiUrl) => {
      process.env.EXPOSURE_LEDGER_API_URL = apiUrl
      process.env.EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS = "true"

      const { localDispositionWritesEnabled } = await import("./local-dispositions")

      expect(localDispositionWritesEnabled()).toBe(true)
    },
  )

  it("rejects an explicitly enabled non-loopback API", async () => {
    process.env.EXPOSURE_LEDGER_API_URL = "https://exposure-ledger.example"
    process.env.EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS = "true"

    const { localDispositionWritesEnabled } = await import("./local-dispositions")

    expect(localDispositionWritesEnabled()).toBe(false)
  })
})
