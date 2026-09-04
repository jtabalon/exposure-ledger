import pytest
from exposure_ledger import GenerationReadiness
from exposure_ledger_worker.main import _require_generation_startup_ready


def test_worker_startup_fails_with_the_explicit_missing_generation_setup_step() -> None:
    readiness = GenerationReadiness(
        status="unavailable",
        code="generation_model_not_installed",
        message="Local generation artifact gpt-oss:20b is not installed.",
        setup="Run `ollama pull gpt-oss:20b`, then retry.",
        model=None,
    )

    with pytest.raises(RuntimeError, match="ollama pull gpt-oss:20b"):
        _require_generation_startup_ready(readiness)
