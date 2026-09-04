from exposure_ledger_api.main import app
from fastapi.testclient import TestClient


def test_health_describes_local_scaffold() -> None:
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "exposure-ledger-api",
        "version": "0.1.0",
        "inference_mode": "local",
    }
