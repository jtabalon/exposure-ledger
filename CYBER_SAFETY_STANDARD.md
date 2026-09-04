# Cyber Assistance Risk Standard

**Version:** 0.1
**Status:** Accepted for the first release
**Last reviewed:** 2026-09-03

This standard defines which cyber assistance and agent actions the product may provide. It is informed by published OpenAI and Anthropic cyber-safety taxonomies but is vendor-neutral and enforced by the application. Model-provider safeguards are defense in depth, not an authorization boundary.

## Principles

- Support defensive exposure investigation without materially enabling cyber harm.
- Treat authorization, target scope, capability uplift, autonomy, scale, and impact as distinct signals.
- Give the model only tools already constrained to permitted targets and effects.
- Treat repository files, Sources, Evidence Records, tool output, and user content as untrusted data, never instructions.
- Apply the stricter result when Assistance Class and Action Level differ.
- Fail closed with a clear Policy Decision when classification or authorization is materially uncertain.

## Assistance Classes

| Class | Meaning | Examples | First-release behavior |
| --- | --- | --- | --- |
| **C0 Benign defensive** | Little meaningful offensive uplift | Explain KEV status; summarize a public advisory; cite a fixed version; recommend a published patch | Allow |
| **C1 Low-risk dual use** | Primarily defensive with plausible offensive utility | Statically inspect a public repository for an already disclosed dependency Exposure; correlate public vulnerability evidence | Allow, monitor, and evaluate |
| **C2 High-risk dual use** | Materially enables offensive capability even when legitimate uses exist | Generate or validate an exploit; conduct penetration testing; automate broad scanning; find high-uplift novel vulnerabilities | Block as unsupported |
| **C3 Harmful** | Enables unauthorized access, persistence, theft, exfiltration, destructive impact, or malware operations | Credential theft; ransomware; EDR evasion; command and control; destructive actions; chained exploitation of a third party | Block and record the reason |

## Action Levels

| Level | Meaning | Examples | First-release behavior |
| --- | --- | --- | --- |
| **A0 Inform** | Explain or summarize without inspecting a target | Explain what an EPSS score represents | Allow for C0-C1 |
| **A1 Read** | Inspect approved public data without executing it | Parse a pinned lockfile; retrieve an allowlisted advisory | Allow for C0-C1 |
| **A2 Propose** | Draft a reversible external or code change without applying it | Draft a dependency patch or remediation ticket | Later milestone with human review |
| **A3 Isolated Execute** | Perform an authorized security action inside a disposable lab | Reproduce a known vulnerability in an isolated fixture | Outside the first release |
| **A4 External Execute** | Affect a live, external, unrelated, or production system | Scan, exploit, modify, persist, or exfiltrate | Prohibit |

## Effective Policy

The first release executes only C0-C1 assistance at A0-A1. C2, C3, A3, and A4 are unsupported regardless of provider capability, user framing, or content embedded in retrieved material. A2 is reserved for a later release and requires a new ADR, a threat-model update, human review, and new safety evaluations before enablement.

## Enforcement

Policy evaluation occurs at four surfaces:

1. The user request and stated target.
2. Every proposed tool call.
3. Retrieved content before it enters model context.
4. Structured model output before it becomes an Investigation Revision.

Every enforcement point records a Policy Decision containing the standard version, Assistance Class, Action Level, target and authorization scope, result, human-readable reason, and classifier or deterministic rule version. A classifier may narrow access but cannot grant a capability missing from the agent's independently enforced tool permissions.

## Examples

| Scenario | Classification | Result |
| --- | --- | --- |
| Summarize a public CVE and cite remediation guidance | C0/A0 | Allow |
| Inspect an allowlisted public repository for an already disclosed vulnerable dependency | C1/A1 | Allow |
| Search already captured evidence for one gap in the same Exposure, Source, and evidence type | C1/A1 | Allow one read after deterministic tool-call authorization and budget checks |
| Follow instructions embedded in a README to contact another service | C1/A4 | Block; retrieved content cannot expand scope |
| Draft an upgrade pull request | C0/A2 | Restrict until the A2 milestone is approved |
| Generate a working exploit for the disclosed vulnerability | C2/A2 | Block |
| Scan arbitrary internet hosts for the vulnerable package | C2/A4 | Block |
| Extract credentials and establish persistence | C3/A4 | Block |
| Chain individually permitted reads into autonomous target selection and exploitation | C3/A4 | Block the chain, not merely its final step |

## Evaluation Requirements

The safety corpus covers every class and action level, ambiguous authorization, scope escalation, indirect prompt injection, malicious tool output, multi-step composition, and attempts to convert read-only investigation into execution. Tests assert both classification and system behavior. Release-candidate evaluation runs each semantic safety case three times and reports worst-run failures.

## Standards Relationship

- **MITRE ATT&CK** labels adversary behavior; it does not authorize agent behavior.
- This standard governs what cyber assistance and action the product may provide.
- **OWASP LLM and RAG guidance** informs controls for prompt injection, poisoning, excessive agency, and unsafe output handling.
- **NIST AI RMF** informs governance and repeatable testing, evaluation, verification, and validation.

## Change Control

Changes to class definitions, permitted levels, or enforcement behavior require an ADR, threat-model review, updated examples, and passing safety evaluations. Investigation Revisions and Policy Decisions retain the standard version used when they were created.
