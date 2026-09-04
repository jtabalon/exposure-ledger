import type { EvidenceRelationship } from "./evidence"

export type ClaimKind = "fact" | "inference"
export type { EvidenceRelationship } from "./evidence"

export type InvestigationClaim = {
  id: string
  label: string
  kind: ClaimKind
  text: string
  limitation?: string
}

export type DemoEvidenceRecord = {
  id: string
  source: string
  authority: string
  capturedAt: string
  relationship: EvidenceRelationship
  claimIds: string[]
  passage: string
  lexicalRank: number
  lexicalScore: number
  digest: string
}

export type InvestigationStage = {
  label: string
  mode: "deterministic" | "retrieval" | "model" | "policy"
  detail: string
}

export type DemoInvestigation = {
  meta: {
    repository: string
    commit: string
    projectRoot: string
    environment: string
    revision: string
    capturedAt: string
  }
  exposure: {
    id: string
    vulnerability: string
    aliases: string[]
    packageName: string
    installedVersion: string
    affectedRange: string
    fixedVersion: string
    authoritativeConflict: boolean
    advisoryGuidance: {
      source: string
      authority: string
      affectedRange: string
      fixedVersion: string
      relationship: EvidenceRelationship
    }[]
    dependencyType: string
    dependencyPath: string[]
    kev: boolean
    epssPercentile: string
    cvss: string
  }
  recommendation: {
    label: string
    summary: string
    reasons: string[]
  }
  policy: {
    assistanceClass: string
    actionLevel: string
    decision: string
  }
  retrieval: {
    query: string
    configurationVersion: string
    sourcePolicyVersion: string
    evidenceTypes: string[]
  }
  stages: InvestigationStage[]
  claims: InvestigationClaim[]
  evidence: DemoEvidenceRecord[]
}

export const demoInvestigation: DemoInvestigation = {
  meta: {
    repository: "northstar-labs/harbor-api",
    commit: "4f92c7d",
    projectRoot: "services/api",
    environment: "Python 3.12 · macOS arm64 · default extras",
    revision: "REV-0007",
    capturedAt: "2026-08-28 16:42 UTC",
  },
  exposure: {
    id: "EXP-1042",
    vulnerability: "DEMO-2026-0042",
    aliases: ["DEMO-GHSA-42AA", "DEMO-OSV-1042"],
    packageName: "cipherleaf",
    installedVersion: "2.4.1",
    affectedRange: ">=2.1.0, <2.4.3",
    fixedVersion: "2.4.3",
    authoritativeConflict: true,
    advisoryGuidance: [
      {
        source: "Synthetic maintainer advisory",
        authority: "Maintainer · Tier 1",
        affectedRange: ">=2.1.0, <2.4.3",
        fixedVersion: "2.4.3",
        relationship: "supports",
      },
      {
        source: "Synthetic public vulnerability record",
        authority: "Public database · Tier 1",
        affectedRange: ">=2.1.0, <2.4.2",
        fixedVersion: "2.4.2",
        relationship: "contradicts",
      },
    ],
    dependencyType: "Transitive",
    dependencyPath: ["harbor-api", "auth-gateway", "cipherleaf"],
    kev: true,
    epssPercentile: "96th",
    cvss: "8.1 · High",
  },
  recommendation: {
    label: "More Evidence Required",
    summary:
      "Confirm the affected range and first patched release before choosing remediation.",
    reasons: [
      "The resolved version falls inside the affected range.",
      "Authoritative Sources disagree on the first patched release.",
      "No Source was selected as the winner; the conflict remains open.",
    ],
  },
  policy: {
    assistanceClass: "C1 · Low-risk dual use",
    actionLevel: "A1 · Read",
    decision: "Allowed",
  },
  retrieval: {
    query: "cipherleaf 2.4.1 affected fixed upgrade",
    configurationVersion: "postgres-lexical-v1",
    sourcePolicyVersion: "explicit-source-allowlist-v1",
    evidenceTypes: ["dependency", "affected", "remediation", "exploitation", "usage"],
  },
  stages: [
    { label: "Matched", mode: "deterministic", detail: "Version range and aliases normalized" },
    {
      label: "Retrieved",
      mode: "retrieval",
      detail: "PostgreSQL full-text search completed",
    },
    { label: "Interpreted", mode: "model", detail: "Claims synthesized locally" },
    { label: "Validated", mode: "policy", detail: "Citations and safety policy passed" },
  ],
  claims: [
    {
      id: "claim-version",
      label: "C1",
      kind: "fact",
      text: "The Asset Snapshot resolves cipherleaf 2.4.1, which is inside the published affected range.",
    },
    {
      id: "claim-fix",
      label: "C2",
      kind: "fact",
      text: "The maintainer identifies version 2.4.3 as the first patched release.",
    },
    {
      id: "claim-priority",
      label: "C3",
      kind: "fact",
      text: "The demonstration vulnerability is marked as known exploited and has a high synthetic EPSS percentile.",
    },
    {
      id: "claim-usage",
      label: "C4",
      kind: "inference",
      text: "Static imports suggest the affected package is loaded by the authentication path.",
      limitation: "Import presence is context, not proof of runtime reachability or exploitability.",
    },
  ],
  evidence: [
    {
      id: "ev-lock",
      source: "uv.lock at 4f92c7d",
      authority: "Asset Snapshot",
      capturedAt: "2026-08-28 16:40 UTC",
      relationship: "supports",
      claimIds: ["claim-version"],
      passage: 'name = "cipherleaf" · version = "2.4.1" · via auth-gateway',
      lexicalRank: 1,
      lexicalScore: 0.941,
      digest: "sha256:65bc…8a20",
    },
    {
      id: "ev-vendor",
      source: "Synthetic maintainer advisory",
      authority: "Maintainer · Tier 1",
      capturedAt: "2026-08-28 16:41 UTC",
      relationship: "supports",
      claimIds: ["claim-version", "claim-fix"],
      passage:
        "Releases from 2.1.0 through 2.4.2 are affected. Consumers should upgrade to cipherleaf 2.4.3 or later.",
      lexicalRank: 2,
      lexicalScore: 0.887,
      digest: "sha256:21df…0c91",
    },
    {
      id: "ev-osv",
      source: "Synthetic public vulnerability record",
      authority: "Public database · Tier 1",
      capturedAt: "2026-08-28 16:41 UTC",
      relationship: "contradicts",
      claimIds: ["claim-version", "claim-fix"],
      passage:
        "The public record lists releases before 2.4.2 as affected and names 2.4.2 as fixed.",
      lexicalRank: 3,
      lexicalScore: 0.844,
      digest: "sha256:44ea…a1c2",
    },
    {
      id: "ev-cisa",
      source: "Synthetic KEV record",
      authority: "Government · Tier 1",
      capturedAt: "2026-08-28 16:41 UTC",
      relationship: "supports",
      claimIds: ["claim-priority"],
      passage:
        "This synthetic record exists only to demonstrate how known-exploitation evidence changes investigation priority.",
      lexicalRank: 4,
      lexicalScore: 0.802,
      digest: "sha256:8aa1…9f13",
    },
    {
      id: "ev-source",
      source: "services/api/auth/session.py",
      authority: "Repository context",
      capturedAt: "2026-08-28 16:40 UTC",
      relationship: "contextual",
      claimIds: ["claim-usage"],
      passage: "from cipherleaf.tokens import verify_session",
      lexicalRank: 5,
      lexicalScore: 0.734,
      digest: "sha256:d10c…4b27",
    },
  ],
}
