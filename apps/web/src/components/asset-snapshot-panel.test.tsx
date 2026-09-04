import { renderToStaticMarkup } from "react-dom/server"
import { describe, expect, it } from "vitest"

import { AssetSnapshotPanel } from "./asset-snapshot-panel"

describe("AssetSnapshotPanel", () => {
  it("shows immutable scope and normalized dependency data", () => {
    const html = renderToStaticMarkup(
      <AssetSnapshotPanel
        error={null}
        snapshots={[
          {
            id: "d9583057-9338-49b9-bd28-a10a69e27084",
            repository: "https://github.com/example/exposure-fixture",
            commit: "0123456789abcdef0123456789abcdef01234567",
            projectRoot: "services/api",
            lockfilePath: "services/api/uv.lock",
            lockfileDigest:
              "sha256:390d60e25c213f27f05ab252c870719ddece955b9af3689a9d77dc546edab685",
            environmentProfile: {
              pythonVersion: "3.12.2",
              operatingSystem: "linux",
              architecture: "x86_64",
              selectedExtras: ["security"],
            },
            packages: [
              {
                name: "http-x",
                version: "2.3.0",
                direct: true,
                source: { registry: "https://pypi.org/simple" },
                dependencyPaths: [["demo-app", "http-x"]],
              },
              {
                name: "leaf-lib",
                version: "1.0.0",
                direct: false,
                source: { registry: "https://pypi.org/simple" },
                dependencyPaths: [["demo-app", "http-x", "leaf-lib"]],
              },
            ],
            parserVersion: "uv-lock-v1",
            capturedAt: "2026-09-03T20:00:00Z",
          },
        ]}
      />,
    )

    expect(html).toContain("Immutable Asset Snapshot")
    expect(html).toContain("example/exposure-fixture")
    expect(html).toContain("0123456789abcdef0123456789abcdef01234567")
    expect(html).toContain("services/api/uv.lock")
    expect(html).toContain("Python 3.12.2 · linux · x86_64")
    expect(html).toContain("security")
    expect(html).toContain("http-x")
    expect(html).toContain("Direct")
    expect(html).toContain("demo-app → http-x → leaf-lib")
    expect(html).toContain("Transitive")
  })
})
