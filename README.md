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

- Apple Silicon macOS supported by both Docker Desktop and Ollama. Ollama requires macOS 14 or
  newer; Docker Desktop supports the current and two previous major macOS releases.
- [uv](https://docs.astral.sh/uv/getting-started/installation/) to manage Python 3.12, as selected
  by `.python-version`.
- [Node.js 24](https://nodejs.org/en/download), matching `.nvmrc`, and **pnpm 11.19.0**, matching
  `package.json`. The [pnpm compatibility table](https://pnpm.io/installation#compatibility)
  supports Node 24 for pnpm 11; Node 20 is insufficient.
- [Docker Desktop for Apple Silicon](https://docs.docker.com/desktop/setup/install/mac-install/),
  including Docker Compose, for PostgreSQL 17 with pgvector.
- [Ollama for macOS](https://docs.ollama.com/macos), running locally for generation and embeddings.
  Allow storage and memory for `gpt-oss:20b` and `qwen3-embedding:0.6b` alongside PostgreSQL and
  the application. Readiness checks do not establish that this workload fits the machine's
  Investigation time budget; run the opt-in model check below to measure it.

Model downloads are always explicit. The application never silently falls back to a hosted provider.

## Bootstrap

Install the prerequisites above, then run these commands from the repository root in order.
If using an existing nvm installation, `nvm install` followed by `nvm use` selects `.nvmrc`.

```bash
uv python install 3.12
npm install --global pnpm@11.19.0
node --version
pnpm --version
make install
```

The versions should report Node `v24.x` and pnpm `11.19.0`. Defaults match `.env.example`; optionally
copy it to a new root `.env` before continuing and edit the values there. Docker Compose and the
Python processes read that file. For the web application, export overrides such as
`EXPOSURE_LEDGER_API_URL` in the shell or place them in `apps/web/.env.local`. Keep local API and
Ollama URLs on loopback.

Start the Docker Desktop and Ollama applications, complete their first-run setup, and verify their
services before downloading models:

```bash
open -a Docker
open -a Ollama
docker info
docker compose version
ollama --version
curl --fail --show-error http://127.0.0.1:11434/api/version
make models
ollama list
```

`make models` explicitly pulls `gpt-oss:20b` and `qwen3-embedding:0.6b`; it is never called by
`make install` or `make dev`. Wait for both pulls to finish and verify both artifacts appear in
`ollama list`. If deliberately overriding a model tag in configuration, pull that exact local tag
explicitly as well. Cloud artifacts are not supported.

Then start PostgreSQL, wait for its health check, apply migrations, and launch the application:

```bash
make infra-up
make migrate
pnpm dev
```

Open [http://localhost:3000](http://localhost:3000). For subsequent starts after prerequisite and
model setup, `make dev` runs the PostgreSQL startup, migrations, and application commands together.
The application launcher stops its other processes if the worker fails. A missing generation
artifact therefore prevents this combined startup even when only a synthetic Assessment Run is
intended; install the configured artifact and restart the application.

If Turbopack fails with `Operation not permitted` while binding an internal CSS-processing port,
the following Webpack production build and startup path was verified on Apple Silicon. With
PostgreSQL migrated and the configured models installed, build from the repository root:

```bash
pnpm --filter @exposure-ledger/web exec next build --webpack
```

Then run each command in a separate terminal, using the same configuration:

```bash
make api
make worker
pnpm --filter @exposure-ledger/web start
```

This serves the built application at the same loopback address without development hot reload.
Rebuild after changing web code. The default development and CI build commands remain unchanged.

To view only the bundled synthetic interface after installing web dependencies, leave the API and
worker stopped and run:

```bash
EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS=false make web
```

This read-only display needs neither PostgreSQL nor Ollama and shows API-unavailable states for
live data. It does not process Assessment Runs. A queued `mode: synthetic` Assessment Run exercises
the API, PostgreSQL, and worker; although its fixture does not invoke generation, the production
worker still enforces generation readiness at startup.

`GET /health` reports the worker's latest persisted local embedding and generation readiness
observations. The worker refreshes them every ten seconds and the API rejects observations older
than thirty seconds. If Ollama is stopped or either configured artifact is missing, health is
`degraded` and includes the exact local setup command; the application never calls Ollama's pull
endpoint and never substitutes a hosted provider. `OLLAMA_BASE_URL` must be an HTTP loopback URL.
Cloud-tagged artifacts and model inventory entries that resolve to a remote model are rejected.
The production worker records the failed readiness observation and exits at startup when the pinned
generation artifact is unavailable. Because the combined launcher also stops the API in that case,
run `make api` separately to inspect the persisted health diagnostic, then complete the reported
setup step and restart `make dev`.

Generation uses Ollama's `/api/chat` structured-output contract with the application's JSON Schema,
`stream: false`, `think: "low"`, temperature `0`, and seed `0`. The complete request contract is
identified by the pinned prompt version `claims-recommendation-follow-up-v4-gptoss-low`. Ollama's
[thinking documentation](https://docs.ollama.com/capabilities/thinking) specifies `low`, `medium`, or
`high` for GPT-OSS; boolean values do not disable its reasoning. `low` is the initial setting to
measure, not a latency guarantee. [Structured output](https://docs.ollama.com/capabilities/structured-outputs)
still passes through application schema, evidence, and policy validation, and the local artifact
digest is checked before and after generation. Each call remains subject to the Investigation's
remaining absolute budget, including those checks.

Create and inspect the tracer Assessment Run through the versioned API:

```bash
curl -sS -X POST http://localhost:8000/api/v1/assessment-runs \
  -H 'content-type: application/json' \
  -d '{"mode":"synthetic"}'

curl -N http://localhost:8000/api/v1/assessment-runs/<assessment-run-id>/events
curl -sS http://localhost:8000/api/v1/assessment-runs/<assessment-run-id>
curl -sS http://localhost:8000/api/v1/policy-decisions
```

Capture a live public repository as an immutable Asset Snapshot from `uv.lock`, `poetry.lock`, or
fully pinned `requirements.txt` data by creating a repository Assessment Run with a complete commit
ID and explicit Environment Profile:

```bash
curl -sS -X POST http://localhost:8000/api/v1/assessment-runs \
  -H 'content-type: application/json' \
  -d '{
    "mode": "repository",
    "repository": "https://github.com/OWNER/REPOSITORY",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "projectRoot": ".",
    "lockfilePath": "uv.lock",
    "environmentProfile": {
      "pythonVersion": "3.12.2",
      "operatingSystem": "macos",
      "architecture": "arm64",
      "selectedExtras": []
    }
  }'
```

The API policy-gates and durably queues the request. The worker records a second Policy Decision at
the repository-fetch boundary, constrains egress to public GitHub codeload addresses, and reads the
archive and dependency data as untrusted text in memory. It never installs dependencies, imports
modules, runs builds or hooks, or executes repository content. Poetry capture also reads and retains
the selected project's `pyproject.toml` so direct and transitive Dependency Paths are derived from
declared project dependencies rather than guessed from graph shape. Fully pinned requirements data
does not carry trustworthy relationship provenance, so its API records return `null` for `direct`
and `dependencyPaths`; the workbench labels both as unknown. Unsupported markers, unpinned entries,
and other format limitations fail with typed Assessment errors. The bounded repository archive is
explicitly discarded after either successful capture or rejection and is never retained on disk.
`GET /api/v1/asset-snapshots`
exposes the pinned scope, digest, Environment Profile, normalized packages, and known or explicitly
unknown Dependency Paths shown in the workbench.

Repository requests must explicitly select one project root and one supported dependency file
(`uv.lock`, `poetry.lock`, `requirements.txt`, or `requirements-*.txt`). Unsafe targets,
ambiguous selections, archive traversal or links, corrupt content, and configured size, file-count,
compression-ratio, lockfile, or Dependency Path ceilings fail with a stable rejection code. A
request rejected before queueing returns that code in HTTP 422; a capture rejected by the worker
records it in the Assessment Run's `errorCode`. Rejected captures never create a partial Asset
Snapshot, and the workbench shows guidance for correcting the request.

After capture, the worker records a separate OSV-read Policy Decision, submits one normalized PyPI
version batch to the fixed public OSV origin, hydrates the returned identifiers into full retrieved
records, and re-evaluates affected versions locally with PEP 440 ordering. Aliases are coalesced into
one Vulnerability Record while Exposures remain unique by Asset Snapshot, Vulnerability Record, and
package. `GET /api/v1/assessment-runs/<assessment-run-id>/exposures` returns their deterministic
ordering and top-five Investigation selection. The workbench explains the score inputs: OSV severity
(0/10/20/30/40), direct dependency (20), published fix (10), and dependency proximity (up to 10),
with unknown dependency provenance contributing no directness or proximity points and remaining
visible in the response. Stable vulnerability aliases and package identity are used as tie-breakers.
No generation model participates in matching, identity, ranking, or selection.

The bounded Investigation runner then loads each selected Exposure, acquires its immutable evidence,
runs the pinned hybrid retrieval query, requests schema-constrained local generation, validates
Claim provenance, Recommendation evidence sufficiency, and output cyber policy, and atomically
seals an immutable Revision. Evidence captures carry their actual Source adapter version; each
Revision must pin the exact Source-to-adapter-version mapping before persistence accepts it.
To keep the wall-time limit absolute during PostgreSQL connection establishment, bounded
Investigation access accepts `localhost`, one numeric host/hostaddr, or an explicit Unix socket;
libpq service definitions, multi-host URLs, and DNS hostnames are rejected instead of multiplying
the per-address connection timeout.

Review all immutable Revisions and human Dispositions for one Exposure with
`GET /api/v1/exposures/<exposure-id>/investigation`. The workbench shows Revision identity,
creation time and Assessment Run, stopping condition, Recommendation changes, and changes to pinned
application, graph, prompt, policy, parser, retrieval, Source adapter, generation, and Embedding
Space versions. A local AppSec engineer can append a separate human Disposition with
`POST /api/v1/investigations/<investigation-id>/dispositions`. Supported decisions are remediate,
monitor, not affected, accept risk, and request more evidence. Risk acceptance requires a rationale
and an expiration or review date. Dispositions are database-enforced append-only events pinned to
the reviewed Revision and Asset Snapshot; they never replace a Recommendation or carry to a new
Asset Snapshot or Environment Profile.

Disposition writes are an OS-local operator capability, not a hosted-demo capability. The checked-in
development commands bind both Next.js and FastAPI to `127.0.0.1`, derive the author label from
`EXPOSURE_LEDGER_LOCAL_OPERATOR`, and enable writes explicitly with
`EXPOSURE_LEDGER_ENABLE_LOCAL_DISPOSITIONS=true`. Production mode defaults to read-only, and the
server action refuses to proxy mutations to a non-loopback API URL. The API independently rejects
Disposition writes whose client address is not loopback, and the checked-in API command disables
proxy-header interpretation so forwarded addresses cannot weaken that boundary.

After evidence capture, the worker records a retrieved-content Policy Decision, then records passage
representations in PostgreSQL under an immutable Embedding Space. Its identity covers the local
provider, model artifact and immutable digest, dimensions, retrieval instruction, normalizer, and
passage-construction version. The provider verifies the digest again after generation and discards
the result if the mutable Ollama tag changed. A changed input creates a different space and requires
re-embedding; representations are never compared across spaces. Recovered worker runs finish any
missing representations before they can complete.

Evidence retrieval defaults to `postgres-hybrid-rrf-v1`: metadata filters are applied before both
PostgreSQL full-text and pgvector ranking, then the two candidate lists are combined with
deterministic reciprocal-rank fusion (`k=60`). Each result exposes nullable `fullTextRank` and
`vectorRank`, its `fusedRank`, component scores, and the complete Embedding Space identity. An
optional repeated `expectedPassageIdentity` query parameter adds a recall@limit report for
known-answer evaluation without affecting ranking. The legacy `postgres-lexical-v1` configuration
remains explicitly queryable for comparison. Each Exposure response publishes its
worker-generated `retrievalQuery`; hybrid callers submit that query with an explicit
`embeddingSpaceIdentity`. Its immutable query representation is loaded from the same space in
PostgreSQL, so the public API never accepts untrusted vectors or invokes Ollama directly.

SSE clients can resume with `Last-Event-ID` or the `after` query parameter. Assessment state and
idempotent Investigation-stage events are replayed from PostgreSQL, so reconnecting clients receive
an ordered, gap-free view after API or worker restarts. The worker also records a stable operation
identity and synchronous PostgreSQL graph checkpoints for each selected Exposure. Reclaimed work
reuses the captured Asset Snapshot, resumes the same incomplete Revision, and does not repeat already
committed source reads, model stages, Policy Decisions, Evidence Records, or progress events. The
workbench distinguishes `REPOSITORY` and `SYNTHETIC` runs.

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

`make test` starts PostgreSQL and creates isolated databases for API integration tests. Deterministic
known-answer providers verify fusion, isolation, outage behavior, and recall reporting. A real-model
evaluation remains a separate release gate because CI does not download or assume access to the
pinned local artifact. After explicitly installing the models with `make models`, stop application
workers that could load the generation model, then run the local gate. For the default configuration:

```bash
ollama --version
ollama stop gpt-oss:20b
make check-real-model
```

The explicit stop prepares an unloaded first call without deleting or downloading the artifact.
If configuration overrides the model or endpoint, use that exact model tag and corresponding
`OLLAMA_HOST` for the stop command. The gate reads the worker's root `.env` settings and never
downloads, unloads, or substitutes a model itself.

Record the Ollama version alongside the gate's JSON observations for artifact digest,
request-contract version, readiness timing, and two consecutive structured generation calls.
It checks `/api/ps` before each call so the observed loaded, unloaded, or unknown state accompanies
the cold and warm candidates; the labels alone do not prove model residency. Each call retains
the default 120-second absolute
Investigation ceiling, including artifact checks. Validation verifies structured Claims and their
evidence provenance. This small fixture is a contract and timing check; it does not establish
full Assessment throughput or the quality of real vulnerability Recommendations. Record both
observations on the target machine before claiming a latency improvement. Without a running local
Ollama service and the configured artifact, this gate cannot produce real-model measurements.

See the [issue #34 validation record](docs/validation/issue-34-local-runtime.md) for commands
actually performed, observed prerequisites, and remaining real-runtime validation.

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
