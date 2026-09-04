# Exposure Ledger roadmap

## Four-week vertical slice

### Week 1 — trustworthy asset boundary

- Establish monorepo, local PostgreSQL, migrations, settings, health checks, and CI.
- Capture one public repository at an immutable commit without executing it.
- Support `uv.lock`, `poetry.lock`, and fully pinned `requirements.txt` with explicit limitations.
- Normalize PyPI names, Environment Profile, Dependency Paths, and package instances.
- Batch-match OSV records and create deterministically ranked package-specific Exposures.

**Exit:** a fixture repository produces a persisted Asset Snapshot, Assessment Run, and ranked Exposure queue through a tested public interface.

### Week 2 — evidence and retrieval

- Implement allowlisted OSV, CISA KEV, FIRST EPSS, and first-party advisory adapters.
- Capture immutable Evidence Records with timestamps, digests, attribution, and source boundaries.
- Build source-aware passages, PostgreSQL full-text retrieval, local embeddings, metadata filters, and reciprocal-rank fusion.
- Build the Evidence Trace read model.

**Exit:** a known query retrieves the expected evidence in the correct Embedding Space and exposes why every passage ranked.

### Week 3 — bounded investigation

- Implement the LangGraph workflow, durable job events, retries, budgets, and incomplete revisions.
- Add structured local-model output for Claims, Evidence Gaps, follow-up proposals, and Recommendations.
- Enforce citation validation and the Cyber Safety Standard at request, tool, retrieved-content, and output stages.
- Establish the 30-case evaluation corpus and release report.

**Exit:** one Exposure produces a complete or safely incomplete immutable revision, and adversarial retrieved instructions cannot expand tools or targets.

### Week 4 — workbench and portfolio proof

- Implement Assessment, Exposure, Investigation, Evidence Trace, and Evaluation views.
- Add accessible Claim ↔ Evidence navigation and the agent-stage timeline.
- Export sanitized, versioned demonstration bundles and deploy the clearly labeled read-only experience.
- Complete architecture diagrams, operational setup, walkthrough script, and five-minute demo video.

**Exit:** a reviewer can understand the problem, run the local slice, inspect retrieval, reproduce evaluation results, and see safety tradeoffs without a guided explanation.

## Release gates

- 100% parser accuracy on supported fixtures
- 100% valid provenance and material-Claim evidence coverage
- 100% pass rate on known prompt-injection and repository-no-execution tests
- at least 90% retrieval recall@10
- at least 80% human-reviewed Recommendation agreement
- at least 90% correct abstention on insufficient-evidence cases

Latency, local resource use, and future provider cost are reported initially but do not block the first release.

## Continuing lab increments

Each two-to-four-week increment begins with a hypothesis and ends with evaluation deltas plus a threat-model review.

1. Compare local inference with OpenAI and Claude; enable budgeted live hosted runs only after measured promotion.
2. Accept CycloneDX and SPDX SBOMs as alternate Asset Snapshot inputs.
3. Add JavaScript/npm while preserving ecosystem-specific package identity.
4. Experiment with deeper static usage and reachability signals without overstating proof.
5. Add human-approved A2 patch proposals in an isolated workspace.
6. Compare specialized agents with the single-agent baseline; keep them only if evaluation shows material benefit.

## Explicitly deferred

Private repositories, private advisories, repository execution, dynamic reachability, exploit generation, patch application, production writes, organization accounts, collaborative review, arbitrary document upload, and general-purpose chat are outside v1.
