# Exposure Investigation

This context describes how the product assesses publicly disclosed software vulnerabilities against a specific software asset and preserves the reasoning behind the assessment.

## Language

**Environment Profile**:
An immutable description of the Python version, operating system, architecture, and selected extras against which one dependency set is interpreted.
_Avoid_: Runtime, deployment environment

**Asset Snapshot**:
An immutable description of one selected Python project in a public software repository at a specific revision, together with its Environment Profile and resolved dependencies.
_Avoid_: Current repository state, latest code

**Dependency Path**:
The ordered relationship from an Asset Snapshot's declared dependency to a direct or transitive package present in its resolved dependency set.
_Avoid_: Import path, call path

**Assessment Run**:
An examination of one Asset Snapshot that discovers and ranks its potential Exposures.
_Avoid_: Scan, analysis job

**Vulnerability Record**:
A normalized public vulnerability identity that preserves every known alias, such as CVE, GHSA, and OSV identifiers.
_Avoid_: Exposure, CVE

**Exposure**:
A Vulnerability Record's potential applicability to one affected package in an Asset Snapshot, uniquely identified by that three-part relationship. An Exposure is a candidate for investigation, not proof that vulnerable behavior is reachable or exploitable.
_Avoid_: Confirmed vulnerability, finding

**Investigation**:
A durable assessment of a software exposure that preserves its findings, supporting evidence, labeled inferences, uncertainty, and disposition.
_Avoid_: Chat, conversation, report, case

**Investigation Revision**:
An immutable complete or incomplete version of an Investigation that pins the Asset Snapshot, evidence state, conclusions or stopping condition, and the circumstances under which they were produced.
_Avoid_: Update, edit

**Recommendation**:
The system's evidence-backed proposal for how a human should handle an Exposure: Urgent Remediation, Planned Remediation, Monitor, No Remediation Indicated, or More Evidence Required.
_Avoid_: Decision, disposition

**Disposition**:
A human-authored, append-only decision event to remediate, monitor, mark an Exposure not affected, accept its risk, or request more evidence. Risk acceptance requires a rationale and an expiration or review date.
_Avoid_: Recommendation, severity, status

## Evidence

**Source**:
An authority and location from which information relevant to an Investigation originates.
_Avoid_: Evidence, citation

**Evidence Record**:
An immutable capture of source content actually examined during an Investigation, including enough identity and timing information to distinguish it from later changes to the Source.
_Avoid_: Source, URL, citation

**Claim**:
One atomic extracted fact or labeled inference in an Investigation, related to Evidence Records that support, contradict, or contextualize it.
_Avoid_: Answer, output, statement

**Evidence Gap**:
Missing, insufficient, stale, or materially conflicting evidence that prevents an Investigation from safely supporting a conclusion.
_Avoid_: Error, model uncertainty

**Embedding Space**:
A versioned identity for a mutually comparable set of semantic representations. Representations from different Embedding Spaces are never compared or mixed.
_Avoid_: Embedding model, vector index

## Safety

**Assistance Class**:
A classification of how much harmful cyber capability a requested or produced form of assistance could enable, independent of whether the system can act on it.
_Avoid_: Severity, threat level

**Action Level**:
A classification of the authority and real-world effect involved in an agent action, ranging from explanation through external execution.
_Avoid_: Assistance Class, permission

**Policy Decision**:
An auditable determination that a requested operation is allowed, restricted, or blocked under a specific version of the project's cyber-safety standard.
_Avoid_: Disposition, model refusal
