import { loadCollection } from "./assessment-runs"

export type EnvironmentProfile = {
  pythonVersion: string
  operatingSystem: "linux" | "macos" | "windows"
  architecture: "aarch64" | "amd64" | "arm64" | "x86_64"
  selectedExtras: string[]
}

export type PackageInstance = {
  name: string
  version: string
  direct: boolean | null
  source: Record<string, unknown>
  dependencyPaths: string[][] | null
}

export type AssetSnapshot = {
  id: string
  repository: string
  commit: string
  projectRoot: string
  lockfilePath: string
  lockfileDigest: string
  environmentProfile: EnvironmentProfile
  packages: PackageInstance[]
  parserVersion: string
  capturedAt: string
}

export type AssetSnapshotCollection = {
  items: AssetSnapshot[]
  error: string | null
}

export async function loadAssetSnapshots(): Promise<AssetSnapshotCollection> {
  return loadCollection<AssetSnapshot>("asset-snapshots", "Asset Snapshot")
}
