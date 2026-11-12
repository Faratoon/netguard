"""API level tests using the mock router."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

os.environ["NETGUARD_CONFIG"] = os.path.join(tempfile.mkdtemp(), "config.yaml")
os.environ["NETGUARD_DATA_DIR"] = tempfile.mkdtemp()
os.environ["NETGUARD_DEMO"] = "1"

from netguard.config import AppConfig, RouterConfig  # noqa: E402
from netguard.main import app  # noqa: E402
from netguard.state import STATE  # noqa: E402


@pytest.fixture(scope="module")
def client():
    STATE.boot()
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200


def test_devices_are_discovered(client):
    res = client.get("/api/devices")
    assert res.status_code == 200
    assert res.json()["count"] >= 1


def test_admin_info(client):
    res = client.get("/api/admin/info")
    assert res.status_code == 200
    body = res.json()
    assert "router" in body and "counts" in body


def test_blocklist_and_check(client):
    res = client.post("/api/controls/blocklist", json={"domain": "example.org", "category": "adult"})
    assert res.status_code == 201

    check = client.post("/api/controls/check", json={"domain": "www.example.org"})
    assert check.status_code == 200
    assert check.json()["blocked"] is True

    allowed = client.post("/api/controls/check", json={"domain": "wikipedia.org"})
    assert allowed.json()["blocked"] is False


def test_policy_allow_overrides_blocklist(client):
    client.post("/api/controls/blocklist", json={"domain": "allowed-site.test", "category": "adult"})
    client.post("/api/controls/policies", json={"kind": "domain", "value": "allowed-site.test", "action": "allow"})
    res = client.post("/api/controls/check", json={"domain": "allowed-site.test"})
    assert res.json()["blocked"] is False


def test_apply_is_dry_run_by_default(client):
    res = client.post("/api/controls/apply", json={"apply": False})
    assert res.status_code == 200
    body = res.json()
    assert body["dry_run"] is True
    assert isinstance(body["commands"], list)


def test_topology_svg(client):
    res = client.get("/api/media/topology.svg")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("image/svg+xml")
    assert b"<svg" in res.content
