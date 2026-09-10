from fastapi.testclient import TestClient

from src.api.app import app


client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze():
    payload = {
        "events": [
            {
                "type": "port_scan",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:00",
            },
            {
                "type": "failed_login",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:30",
            },
            {
                "type": "successful_login",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:45",
            },
        ]
    }

    response = client.post("/analyze", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert data["prediction"] == "high"
    assert data["threat_level"] == "high"
    assert data["attack_type"] == "multi_stage_attack"
    assert data["agreement"] is True
    assert data["confidence"] == 1.0
    assert "explanation" in data
    assert "severity" in data
    assert "features" in data


def test_analyze_rejects_empty_events():
    response = client.post(
        "/analyze",
        json={"events": []},
    )

    assert response.status_code == 422
