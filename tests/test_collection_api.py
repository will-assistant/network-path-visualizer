import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

import main


class DummyProc:
    def __init__(self, returncode=0):
        self.returncode = returncode

    def communicate(self):
        return ("ok", "")


def test_collect_endpoints(monkeypatch):
    monkeypatch.setattr(main.subprocess, "Popen", lambda *args, **kwargs: DummyProc(returncode=0))

    client = TestClient(main.app)
    resp = client.post("/api/collect", json={"hosts": ["pe-nyc-1"], "types": ["bgp"]})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    status = client.get(f"/api/collect/{job_id}")
    assert status.status_code == 200
    assert status.json()["status"] in {"running", "completed"}


def test_collected_listing():
    client = TestClient(main.app)
    resp = client.get("/api/collected")
    assert resp.status_code == 200
    assert "files" in resp.json()
