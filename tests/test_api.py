import pytest
from fastapi.testclient import TestClient

from pbca.caep import SESSION_REVOKED, CaepTransmitter, sign_set
from pbca.web.app import create_app


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(seed=5, n_users=60))


def frequent_user(client):
    return next(e for e in client.get("/api/employees?limit=60").json()
                if e["prior_logins"] >= 20 and e["role"] != "it_admin")["user_id"]


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "PBCA" in r.text


def test_login_access_activity_flow(client):
    uid = frequent_user(client)
    r = client.post("/api/login", json={"user_id": uid, "profile": "office", "mfa": "passkey"}).json()
    assert r["enforced"] == "ALLOW"
    sid = r["session"]["session_id"]
    a = client.post(f"/api/sessions/{sid}/access", json={"resource": "customer-records"}).json()
    assert a["enforced"] == "ALLOW" and a["sensitivity"] == "HIGH"
    w = client.post(f"/api/sessions/{sid}/activity", json={"kind": "bulk"}).json()
    assert w["enforced"] in ("RESTRICT", "DENY") and w["caep_events"]
    caep = client.get("/api/caep").json()
    assert caep["bank_sessions"][sid] in ("RESTRICT", "REVOKED")
    audit = client.get("/api/audit").json()
    assert audit["chain_ok"] and audit["count"] >= 3


def test_attacker_login_denied(client):
    uid = frequent_user(client)
    r = client.post("/api/login", json={"user_id": uid, "profile": "attacker_foreign", "mfa": "totp"}).json()
    assert r["enforced"] in ("RESTRICT", "DENY")


def test_revoked_session_returns_403(client):
    uid = frequent_user(client)
    sid = client.post("/api/login", json={"user_id": uid}).json()["session"]["session_id"]
    client.post(f"/api/sessions/{sid}/threat", json={"bad_ip": True})
    assert client.post(f"/api/sessions/{sid}/access", json={}).status_code == 403


def test_unknown_things_404(client):
    assert client.post("/api/login", json={"user_id": "nobody"}).status_code == 404
    assert client.post("/api/sessions/nope/access", json={}).status_code == 404


def test_playground_shows_bounding(client):
    d = client.post("/api/pdp/playground", json={"risk": 0.0, "managed": False,
                                                  "resource": "customer-records"}).json()
    assert d["d_policy"] == "DENY" and d["pbca"] == "DENY"
    assert d["b2_unbounded"] == "ALLOW" and d["b2_violates_policy"]


def test_caep_push_receiver(client):
    tx = CaepTransmitter()
    token = sign_set(tx.build(SESSION_REVOKED, "ext-1", "u", "demo-bank", "push test"), tx.secret)
    r = client.post("/api/caep/receiver", content=token, headers={"Content-Type": "application/secevent+jwt"})
    assert r.status_code == 202
    assert client.get("/api/caep").json()["bank_sessions"]["ext-1"] == "REVOKED"
    assert client.post("/api/caep/receiver", content=token + "x").status_code == 400
