.PHONY: install models infra-up infra-down migrate api worker web dev test check check-real-model

APP_PYTHONPATH := apps/api/src:apps/worker/src:packages/domain/src:packages/storage/src

install:
	uv sync --all-packages
	pnpm install

models:
	@command -v ollama >/dev/null || (echo "Ollama is required: https://ollama.com/download" && exit 1)
	ollama pull gpt-oss:20b
	ollama pull qwen3-embedding:0.6b

infra-up:
	docker compose up -d --wait postgres

infra-down:
	docker compose down

migrate:
	PYTHONPATH="$(APP_PYTHONPATH)" uv run python -m exposure_ledger_storage.migrate

api:
	PYTHONPATH="$(APP_PYTHONPATH)" uv run uvicorn exposure_ledger_api.main:app --reload --port 8000

worker:
	PYTHONPATH="$(APP_PYTHONPATH)" uv run python -m exposure_ledger_worker.main

web:
	pnpm --filter @exposure-ledger/web dev

dev: infra-up migrate
	pnpm dev

test: infra-up
	PYTHONPATH="$(APP_PYTHONPATH)" uv run pytest
	pnpm --filter @exposure-ledger/web test

check:
	uv run ruff check packages apps/api apps/worker
	uv run ruff format --check packages apps/api apps/worker
	uv run mypy packages/domain/src packages/storage/src apps/api/src apps/worker/src
	pnpm --filter @exposure-ledger/web lint
	pnpm --filter @exposure-ledger/web typecheck
	pnpm --filter @exposure-ledger/web build

check-real-model:
	EXPOSURE_LEDGER_RUN_REAL_MODEL_CHECK=1 PYTHONPATH="$(APP_PYTHONPATH)" \
		uv run pytest -m real_model apps/worker/tests/test_real_generation_model.py
