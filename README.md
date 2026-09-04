# Exposure Ledger

Exposure Ledger is a local-first, evidence-led RAG workbench that helps AppSec engineers decide whether a public software vulnerability requires action. It combines transparent hybrid retrieval, bounded agentic investigation, immutable evidence, and vendor-neutral cyber-safety controls.

> **Project status:** architecture baseline and executable scaffold. The included investigation is synthetic UI data, not a security finding.

## Why this project exists

The project is both a portfolio artifact and a long-lived engineering lab. Its first vertical slice analyzes one Python project at an immutable public repository revision, discovers package exposures, gathers allowlisted public evidence, and produces auditable Investigation Revisions rather than disposable chat answers.

## First-release shape

- **Web:** Next.js investigation workbench with a visible Evidence Trace
- **API:** FastAPI HTTP contract and SSE progress boundary
- **Worker:** bounded LangGraph orchestration
- **Domain:** framework-independent Python package
- **Data:** PostgreSQL with JSONB, full-text search, and pgvector
- **Local models:** Ollama using `gpt-oss:20b` and `qwen3-embedding:0.6b`
- **Sources:** OSV, CISA KEV, FIRST EPSS, and first-party advisories
- **Safety:** C0-C3 Assistance Classes crossed with A0-A4 Action Levels; v1 permits only C0-C1/A0-A1

## Repository map

```text
apps/
  api/       FastAPI delivery module
  web/       Next.js workbench and static demonstration
  worker/    LangGraph execution module
packages/
  domain/    framework-independent domain policy
docs/
  adr/           durable architectural decisions
  architecture/  system, data, graph, and test seams
  design/        interface rationale and states
  roadmap/       four-week slice and continuing lab cadence
```

## Local prerequisites

- Apple Silicon macOS for the first supported local workflow
- Python 3.12 managed through `uv`
- Node.js 20.9 or newer and pnpm 11
- Docker for PostgreSQL
- Ollama for local generation and embeddings

Model downloads are always explicit. The application never silently falls back to a hosted provider.

## Bootstrap

Start Docker Desktop, then run:

```bash
make install
make dev
```

`make dev` validates the PostgreSQL configuration, waits for the database, applies ordered migrations, and starts the API, worker, and web application together. Open [http://localhost:3000](http://localhost:3000). Configuration can be overridden by copying `.env.example` to `.env`; invalid database and API URLs fail with an actionable message.

Local model downloads remain explicit and are not needed for the synthetic Assessment Run:

```bash
make models
```

Create and inspect the tracer Assessment Run through the versioned API:

```bash
curl -sS -X POST http://localhost:8000/api/v1/assessment-runs \
  -H 'content-type: application/json' \
  -d '{"mode":"synthetic"}'

curl -N http://localhost:8000/api/v1/assessment-runs/<assessment-run-id>/events
curl -sS http://localhost:8000/api/v1/assessment-runs/<assessment-run-id>
curl -sS http://localhost:8000/api/v1/policy-decisions
```

SSE clients can resume with `Last-Event-ID` or the `after` query parameter. Events and Assessment state are replayed from PostgreSQL, so API and worker restarts do not lose progress. The workbench lists the same live runs and always labels this path `SYNTHETIC`.

Every Assessment request is classified by application-owned rules before a run is queued. The
response and workbench show its versioned Policy Decision, including the Assistance Class, Action
Level, target and authorization scope, result, rule version, and reason. Restricted, blocked, or
unrecognized operations return HTTP 403, remain visible in the Policy Decision ledger, and never
create a worker task. For example, this safely records a restricted request:

```bash
curl -sS -X POST http://localhost:8000/api/v1/assessment-runs \
  -H 'content-type: application/json' \
  -d '{"mode":"synthetic","policyContext":{"operationChain":["draft_dependency_patch"]}}'
```

For the visible failure contract, synthetic runs may set `"scenario":"worker_failure"`. This produces a persisted `failed` state and `assessment.failed` event without invoking a real provider.

## Verification

```bash
make test
make check
```

`make test` starts PostgreSQL and creates an isolated database for the API integration test. The real-model evaluation is a separate release gate because hosted CI does not assume access to the pinned local models.

## Core documentation

- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Domain model](CONTEXT.md)
- [Data model](docs/architecture/DATA_MODEL.md)
- [Agent graph](docs/architecture/AGENT_GRAPH.md)
- [Module interfaces and test seams](docs/architecture/MODULE_INTERFACES.md)
- [Interface design](docs/design/INTERFACE_DESIGN.md)
- [Roadmap](docs/roadmap/ROADMAP.md)
- [Cyber Safety Standard](CYBER_SAFETY_STANDARD.md)
- [Threat Model](THREAT_MODEL.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
