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

def test_create_job():
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

    response = client.post("/jobs", json=payload)

    assert response.status_code == 200

    data = response.json()

    assert "job_id" in data
    assert data["status"] == "pending"
    assert data["result"] is None
    assert data["error"] is None


def test_get_job():
    payload = {
        "events": [
            {
                "type": "failed_login",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:00",
            }
        ]
    }

    create_response = client.post("/jobs", json=payload)

    assert create_response.status_code == 200

    job_id = create_response.json()["job_id"]

    response = client.get(f"/jobs/{job_id}")

    assert response.status_code == 200

    data = response.json()

    assert data["job_id"] == job_id
    assert data["status"] == "pending"
    assert data["result"] is None
    assert data["error"] is None


def test_get_unknown_job():
    response = client.get("/jobs/unknown-job-id")

    assert response.status_code == 404
    assert response.json()["detail"] == "Job not found"
