# Threat Model

**Status:** Initial design baseline
**Last reviewed:** 2026-09-03

## Scope and Assumptions

The first release performs live, read-only exposure investigation over arbitrary public GitHub repositories in a local installation. It parses supported Python dependency files and limited static usage signals, retrieves allowlisted public vulnerability information, and uses locally hosted generation and embedding models to produce evidence-backed Recommendations. Static usage signals provide context and never assert runtime reachability. The initial hosted demo serves curated, precomputed Investigation Revisions and does not run assessments. The system never executes analyzed repository content or takes external remediation action.

## Assets

- Integrity and provenance of Investigations, Claims, Evidence Records, and Policy Decisions
- Confidentiality of source-provider credentials and any future hosted-model credentials
- Availability and compute budget of the local application and hosted demo
- Integrity of the cyber-safety policy, prompts, tool schemas, and evaluation results
- User trust in citations, uncertainty, and Recommendations
- PostgreSQL records and immutable Investigation history
- Retained dependency manifests, normalized dependency data, and source excerpts used as Evidence Records

## Trust Boundaries

1. Anonymous browser to public web application and API.
2. API and worker to PostgreSQL.
3. Worker to untrusted repository archives and files.
4. Worker to allowlisted vulnerability Sources and GitHub.
5. Worker to the local model runtime; a future hosted model provider creates a separate external boundary.
6. Application processes to telemetry and secret storage.

## Threat Actors

- An anonymous visitor attempting denial of service, cost exhaustion, or policy bypass
- A malicious repository owner planting executable content, parser exploits, prompt injection, or misleading evidence
- A compromised, poisoned, stale, or conflicting external Source
- A local model runtime, model artifact, or future model provider returning unsupported, manipulated, or policy-violating output
- A supply-chain attacker compromising an application dependency or build artifact
- An operator accidentally expanding tool permissions or exposing credentials

## Principal Threats and Controls

| Threat | Primary controls | Residual risk |
| --- | --- | --- |
| Arbitrary repository used for compute or source-API denial of service | Live runs remain local; repository limits, rate limits, and job ceilings; hosted demo serves precomputed revisions only | A local operator can still exhaust workstation or upstream-source capacity |
| SSRF or target expansion through repository URLs, redirects, or retrieved links | Canonical target validation, domain allowlists, redirect checks, independently enforced network egress | Compromise of an allowlisted service remains possible |
| Archive bombs, path traversal, oversized repositories, or malicious lockfiles | Immutable source archives, compressed and expanded size limits, file-count and path validation, parser limits, no execution | Parser vulnerabilities may remain |
| Repository code execution or dependency supply-chain compromise | Never install, import, build, hook, or execute analyzed content; isolate parsing from secrets | Static parsing cannot prove runtime reachability |
| Unnecessary retention of malicious or sensitive repository content | Retain only supported manifests, normalized results, hashes, and excerpts actually used as Evidence Records; delete the full archive after processing | Retained excerpts can still contain hostile or sensitive text |
| Indirect prompt injection in code, documentation, advisories, or tool output | Treat all retrieved text as quoted data, narrow typed tools, C0-C1/A0-A1 capability ceiling, output validation, adversarial evals | Prompt injection cannot be considered fully solved |
| Poisoned, stale, or contradictory evidence | Source allowlist and authority hierarchy, immutable captures with digests and timestamps, preserve contradictions, explicit uncertainty | Authoritative Sources can publish incorrect information |
| Incompatible or poisoned semantic representations | Versioned Embedding Spaces, pinned model artifacts and retrieval instructions, no cross-space comparison, retrieval evaluation before promotion | A compromised or weak embedding model may still degrade recall within one space |
| Hallucinated or unsupported Claims | Atomic Claims, evidence relationships, deterministic citation validation, `Needs Evidence` on failure | Semantic entailment checks can produce false decisions |
| Multi-step policy bypass or excessive agency | Classify requests, tool calls, retrieved content, and output; bounded graph transitions and tool calls; no general shell, SQL, HTTP, or filesystem tools | Novel compositions may evade semantic classifiers |
| Credential disclosure through prompts, logs, or repository access | Keep reusable secrets outside model-visible state, redact telemetry, minimum source-provider scopes, no access to unrelated files | Future hosted-model use introduces provider-side retention risk |
| Disclosure of model reasoning or sensitive intermediate context | Do not persist or display chain-of-thought; retain only auditable prompts, evidence references, validated outputs, and operational measurements; keep telemetry local by default | Validated outputs may still reproduce sensitive retrieved content |
| Tampering with Investigation history or safety policy | Immutable revisions, database constraints, recorded prompt/model/policy versions, change-controlled migrations | A fully compromised database administrator can alter records |
| Model runtime or Source outage | Local health checks, idempotent retries, partial Evidence preservation, explicit unavailable state, fail closed | The product may be temporarily unable to recommend action |

## Required Security Tests

- Reject non-approved hosted repository targets and unsafe URL schemes, hosts, redirects, and addresses.
- Reject traversal paths, symlinks escaping the workspace, oversized archives, excessive file counts, and decompression bombs.
- Require explicit project-root selection when multiple supported lockfiles exist, and never merge mutually exclusive Environment Profiles.
- Preserve unknown dependency relationships as unknown when a flat requirements file lacks trustworthy provenance metadata.
- Demonstrate that lockfiles, source files, advisories, and tool output cannot add instructions or tools.
- Demonstrate that no analyzed repository content is executed, imported, installed, or built.
- Exercise every Assistance Class and Action Level, including multi-step escalation.
- Verify graph, tool, time, and monetary ceilings fail closed with a visible incomplete Revision.
- Verify every material Claim has valid supporting Evidence Records or is explicitly labeled as an inference.
- Verify secrets and authorization headers are absent from model context, logs, events, and traces.
- Verify retries are idempotent and cannot mutate prior Evidence Records or Investigation Revisions.
- Verify vulnerability aliases coalesce without merging distinct package-specific Exposures, and verify Dispositions never carry forward automatically to a new Asset Snapshot.
- Verify the hosted demo remains usable under rate-limit and upstream-failure scenarios.

## Review Triggers

Review this threat model before adding a new Source, parser, model provider, tool, Action Level, hosted target class, authentication system, external write, repository execution capability, or deployment boundary.
