# Issue #34 local runtime validation

Date: 2026-09-07. Scope: the current Apple Silicon workstation and this isolated worktree.
The initial observations below record the prerequisite blocker. The 2026-09-08 follow-up at the
end records completed setup, live synthetic processing, and the real-model contract check.
This does not establish the quality of a full real-repository Investigation.

## Prerequisite observations

The initial audit reported Docker unavailable. A sandboxed `docker info` still returned socket
permission errors, so the following service checks were repeated with approved read-only access
outside the sandbox. Docker was available at the time of this validation. No service was installed
or started, and no model was downloaded or unloaded during these readiness checks.

| Command or check actually performed | Result |
| --- | --- |
| Python `platform.platform()` and `platform.machine()` | `macOS-26.6.2-arm64-arm-64bit`; `arm64` |
| `node --version` | Exit 0; `v25.4.0` from `/opt/homebrew/bin/node`, which differs from the documented `.nvmrc` Node 24 workflow |
| `pnpm --version` | Exit 0; `11.19.0` |
| `uv --version` | Exit 0; `uv 0.9.26 (Homebrew 2026-01-15)` |
| `docker --version` | Exit 0; `Docker version 20.10.12, build e91ed57` |
| `docker compose version` | Exit 0; `Docker Compose version v5.5.0` |
| `docker compose config --quiet` | Exit 0; checked-in Compose configuration accepted |
| `docker info`, outside the sandbox | Exit 0; Docker Desktop server `20.10.12`, architecture `aarch64`, 19 running containers |
| Python `socket.create_connection(('127.0.0.1', 5432), timeout=2)`, outside the sandbox | TCP connection accepted; this alone does not establish database credentials, migrations, or pgvector readiness |
| Python `shutil.which('ollama')` | `None`; the `ollama --version` and `ollama list` checks could not execute |
| Python `Path('/Applications/Ollama.app').exists()` | `False` |
| `curl --noproxy '*' --connect-timeout 2 --max-time 4 -fsS http://127.0.0.1:11434/api/version`, outside the sandbox | Exit 7; connection refused |
| `curl --noproxy '*' --connect-timeout 2 --max-time 4 -fsS http://127.0.0.1:11434/api/tags`, outside the sandbox | Exit 7; connection refused; artifact inventory unavailable |
| `curl --noproxy '*' --connect-timeout 2 --max-time 4 -fsS http://127.0.0.1:8000/health`, outside the sandbox | Exit 7; connection refused; application health was not measured |

## Documentation and command checks

- Read issue #34 with `gh issue view 34 --repo jtabalon/exposure-ledger --json number,title,body,comments,labels,state`;
  its comments array was empty. The initial `--comments` command returned empty successful output.
- `make -n dev` prints PostgreSQL startup with `--wait`, database migration, then `pnpm dev`.
- `make -n web` prints the existing web development command; this is a dry run, not proof that
  the page started or rendered. Web dependencies were absent during this check.
- `make -n check-real-model` prints the opt-in generation check with `--capture=tee-sys`, which
  retains JSON timing observations in successful test output.
- `git diff --check` passed after the README and Makefile changes.

The documented Node 24 choice matches `.nvmrc` and the [pnpm compatibility
table](https://pnpm.io/installation#compatibility), which does not support Node 20 with pnpm 11.
The macOS prerequisites were checked against [Docker's installation
documentation](https://docs.docker.com/desktop/setup/install/mac-install/) and [Ollama's macOS
documentation](https://docs.ollama.com/macos). The generation contract follows [Ollama's GPT-OSS
thinking settings](https://docs.ollama.com/capabilities/thinking) and [structured-output
contract](https://docs.ollama.com/capabilities/structured-outputs).

## Controlled validation

The implementation checks used the worktree's installed Python environment. The database tests
used the existing local PostgreSQL service outside the socket-restricted sandbox.

```bash
.venv/bin/python -m pytest apps/worker/tests/test_worker_readiness.py apps/worker/tests/test_investigation_runner.py
# 28 passed in 4.48s

.venv/bin/python -m pytest apps/api/tests/test_local_generation.py apps/worker/tests/test_real_generation_model.py
# 25 passed, 1 skipped in 0.87s (the real-model gate is opt-in)

.venv/bin/python -m pytest apps/api/tests/test_investigation_persistence.py apps/api/tests/test_health.py
# 26 passed in 86.05s; one existing Starlette/AnyIO deprecation warning
```

Ruff checks passed across the Python source and tests; Ruff formatting accepted 58 files, and mypy
accepted 32 source files. These controlled tests exercise readiness failure, request settings,
schema and digest enforcement, budgets, and persistence without real generation.

A separate in-memory harness exercised the opt-in gate with the real adapter and a mocked HTTP
transport: two successful requests, an invalid citation, invalid structured output, and a timeout.
All four cases passed their assertions. It verified `.env` overrides, identical request settings,
120-second budgets, matching reported outcomes, and omission of rejected content and reasoning
from output. These are controlled checks, not real-model timing observations.

The opt-in gate was also explicitly attempted:

```bash
EXPOSURE_LEDGER_RUN_REAL_MODEL_CHECK=1 .venv/bin/python -m pytest -m real_model --capture=tee-sys apps/worker/tests/test_real_generation_model.py
# readiness: generation_runtime_unavailable, wall_seconds: 0.027
# 1 failed in 1.01s because the local Ollama prerequisite was unavailable
```

The 0.027-second observation measures a failed readiness check, not generation latency. No chat
request or cold/warm generation measurement followed it. This expected prerequisite failure is
not counted as a successful real-model contract validation.

## Prerequisites remaining after the initial audit

Ollama was neither available on `PATH` nor responding on the configured default loopback port.
No real structured generation, citation validation, cold or warm generation timing, or latency
improvement was measured. The supported Node 24 installation path and complete combined startup
were also not exercised on this workstation.

Follow the [README bootstrap sequence](../../README.md#bootstrap) to install and start Ollama,
explicitly pull the configured model artifacts, prepare PostgreSQL and migrations, and start the
application. For a real generation check, stop application workers, record `ollama --version`,
explicitly run `ollama stop gpt-oss:20b` for the default configuration, then run
`make check-real-model`. Record both calls' actual residency, typed outcome, artifact digest,
request-contract version, and wall time. Use the configured local artifact and endpoint if they
differ from the defaults. The gate does not install models or raise Investigation budgets, and
passing this single fixture does not satisfy issue #17's broader quality gates.


## Follow-up: installed runtime and live validation (2026-09-08)

The user authorized installation, explicit downloads, isolated database setup, and live checks.
Ollama 0.33.2 was installed with `HOMEBREW_NO_AUTO_UPDATE=1 brew install --cask ollama-app`.
The native app was configured for local-only onboarding; `~/.ollama/server.json` has
`disable_ollama_cloud: true`. The server responds with version 0.33.2 and listens on
`127.0.0.1:11434`. `make models` completed successfully, explicitly downloading both artifacts:

| Artifact | Bytes | SHA-256 digest |
| --- | ---: | --- |
| gpt-oss:20b | 13793441244 | 17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7 |
| qwen3-embedding:0.6b | 639150858 | ac6da0dfba84a81fdbfbaf330198c33cd77c4cdfc53e8bc50eb581914a15621d |

The existing healthy PostgreSQL container was reused. Its existing application database was left
unchanged. A separate database was created with:

```bash
docker compose exec -T postgres createdb -U exposure_ledger -O exposure_ledger exposure_ledger_issue34_7e5a
DATABASE_URL='postgresql://exposure_ledger:local-development-only@localhost:5432/exposure_ledger_issue34_7e5a' make migrate
```

Migrations completed successfully. The ignored worktree `.env` now selects this isolated database
for subsequent API and worker starts. No repository credentials or model weights were committed.

### Real-model contract and timing

The initial v3 request completed from an unloaded state in 10.834 seconds but failed the operation
check. A focused diagnostic confirmed `exposure_recommendation` instead of the required
`produce_exposure_recommendation`. The schema had allowed an arbitrary operation string.
The adapter now constrains that field to the single authorized operation and versions this schema
change as `claims-recommendation-follow-up-v4-gptoss-low`. It retains low reasoning, temperature 0,
seed 0, digest checks, citation validation, and the same absolute budgets. Regression tests reject
the observed invalid operation and both obsolete v2/v3 configurations.

After this correction, `ollama stop gpt-oss:20b && make check-real-model` passed:

| Phase | Residency before request | Wall seconds | Outcome |
| --- | --- | ---: | --- |
| Readiness | Not applicable | 0.016 | ready |
| Cold candidate | unloaded | 7.258 | contract_passed |
| Warm candidate | loaded | 3.909 | contract_passed |

Pytest: **1 passed in 11.38s**. Both calls used the GPT-OSS digest above and independent unchanged
120-second absolute limits, including artifact checks. Structured assistant content and evidence
citations passed deterministic validation. No reasoning traces or generated prose were recorded
in this report. These two observations are not a statistically established speedup or issue #17's
broader quality evaluation.

### Application startup and checks

The existing bundled Node 24.19.0 and pnpm 11.19.0 were used. The preceding setup completed
`pnpm install --frozen-lockfile`; web lint, typecheck, and 21 tests passed. The default Turbopack
production build failed when an internal CSS-processing subprocess attempted to bind a port
(`Operation not permitted`). The supported Webpack production build completed successfully:

```bash
export PATH="/Users/jtabalonjr/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$PATH"
pnpm --filter @exposure-ledger/web exec next build --webpack
```

The running local application uses these commands in separate terminals:

```bash
make api
make worker
pnpm --filter @exposure-ledger/web start
```

The web app listens on `127.0.0.1:3000`, and the API on `127.0.0.1:8000`. The worker reported ready.
`GET /health` returned `status: ok`, local inference, and both generation and embedding readiness
as `ready` (embedding dimensions: 1024). The browser rendered the workbench successfully.

A live `POST /api/v1/assessment-runs` with `{"mode":"synthetic"}` created
`94099207-2b4c-43b5-93d9-cd704f78e129`. It moved from queued to completed, with no error, and the
browser displayed COMPLETED and its allowed C1/A1 Policy Decision. The existing synthetic
Investigation display remains precomputed; this does not claim a real repository Assessment ran.

After the schema correction, adapter, worker readiness, and bounded runner tests passed:
**55 passed in 0.66s**. Ruff checks passed for the changed Python files, formatting accepted all
58 Python files, and mypy accepted all 32 source files. The earlier 26 database integration tests
remain recorded above. The default Turbopack path is still limited by the local OS restriction;
the validated running web app uses the successful Webpack build. No merge or deployment occurred.
