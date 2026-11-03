"""The verification API: settings, auth, limits, headers, metrics, health, the log and migrations."""
import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_verify import AUDIT, DID, PATH, REAL_ABSENT, REAL_POST, plc, scenario

from atproof import db, ops

KEY = "atproof_" + "x" * 40
HASHED = {f"sha256:{hashlib.sha256(KEY.encode()).hexdigest()}": {"user": "examiner-1", "role": "examiner"}}
REAL_URI = "at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3mxhdhodv222n"
B64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
REAL = {"car": B64(REAL_POST), "identity": AUDIT, "uri": REAL_URI, "label": "case 9 exhibit 1"}


def boot(monkeypatch, **env):
    for k in [k for k in os.environ if k.startswith("ATPROOF_")]:
        monkeypatch.delenv(k)
    for k, v in env.items():
        monkeypatch.setenv(f"ATPROOF_{k}", v)
    import atproof.api as api

    return importlib.reload(api)


@pytest.mark.parametrize("change, message", [
    ({"ATPROOF_API_KEYS": None}, "API keys"),
    ({"ATPROOF_DATABASE_URL": None}, "DATABASE_URL"),
    ({"ATPROOF_API_KEYS": json.dumps({KEY: {"user": "x", "role": "examiner"}})}, "sha256"),
    ({"ATPROOF_API_KEYS": json.dumps({"sha256:" + "0" * 64: {"user": "x", "role": "root"}})}, "roles"),
    ({"ATPROOF_CORS_ORIGINS": "*"}, "CORS"),
])
def test_production_settings_refused(change, message):
    env = {"ATPROOF_ENV": "production", "ATPROOF_API_KEYS": json.dumps(HASHED), "ATPROOF_DATABASE_URL": "sqlite://"}
    assert ops.load_settings(env).production
    env.update(change)
    with pytest.raises(ops.ConfigError, match=message):
        ops.load_settings({k: v for k, v in env.items() if v is not None})


def test_no_public_bind_and_readable_exit():
    with pytest.raises(ops.ConfigError, match="without API keys"):
        ops.load_settings({"ATPROOF_HOST": "0.0.0.0"})
    env = {k: v for k, v in os.environ.items() if not k.startswith("ATPROOF_")}
    r = subprocess.run([sys.executable, "-m", "atproof", "serve", "--host", "0.0.0.0"], env=env,
                       capture_output=True, text=True, timeout=120, check=False)
    assert r.returncode != 0 and "without API keys" in r.stderr


def test_real_proof_and_deletion_are_logged_across_a_restart(monkeypatch, tmp_path):
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'v.db'}"
    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)
    r = c.post("/v1/verify", json=REAL).json()
    assert r["verdict"] == "present" and r["record"]["value"]["text"] == "a masterclass in alt text"
    assert r["inputs"]["car"] == hashlib.sha256(REAL_POST).hexdigest() and r["limits"]
    absent = c.post("/v1/verify", json={**REAL, "car": B64(REAL_ABSENT),
                                        "uri": "at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3zzzzzzzzzzzz"})
    assert absent.json()["verdict"] == "absent"
    _, mk, inc, ab = scenario()
    ident = plc(DID, ("2025-01-01T00:00:00.000Z", mk))
    body = {"inclusion": B64(inc), "absence": B64(ab), "identity": ident, "uri": f"at://{DID}/{PATH}"}
    d = c.post("/v1/deleted", json=body).json()
    assert d["verdict"] == "proven", d["reasons"]
    swapped = c.post("/v1/deleted", json={**body, "inclusion": body["absence"], "absence": body["inclusion"]}).json()
    assert swapped["verdict"] == "not proven"

    c = TestClient(boot(monkeypatch, DATABASE_URL=url).app)  # restart
    got = c.get(f"/v1/verifications/{r['verification_id']}").json()
    assert got["verdict"] == "present" and got["uri"] == REAL_URI and got["label"] == "case 9 exhibit 1"
    assert "masterclass" not in json.dumps(got)  # the record's content is returned, not stored
    log = c.get("/v1/verifications").json()["verifications"]
    assert [v["verdict"] for v in log] == ["not proven", "proven", "absent", "present"]
    assert c.get("/v1/verifications/nope").status_code == 404


def test_hostile_inputs_fail_cleanly(monkeypatch):
    c = TestClient(boot(monkeypatch).app)
    assert c.post("/v1/verify", json={**REAL, "car": "not base64!"}).status_code == 422
    assert c.post("/v1/verify", json={**REAL, "uri": "https://bsky.app/profile/x"}).status_code == 422
    junk = c.post("/v1/verify", json={**REAL, "car": B64(b"\xff" * 300)}).json()
    assert junk["verdict"] == "failed" and junk["failures"]
    tampered = bytearray(REAL_POST)
    tampered[-5] ^= 1
    assert c.post("/v1/verify", json={**REAL, "car": B64(bytes(tampered))}).json()["verdict"] == "failed"


def test_roles_and_metrics(monkeypatch):
    keys = {"k-ex": {"user": "asha", "role": "examiner"}, "k-view": {"user": "vic", "role": "viewer"},
            "k-mon": {"user": "prom", "role": "monitor"}}
    c = TestClient(boot(monkeypatch, API_KEYS=json.dumps(keys)).app)
    assert c.post("/v1/verify", json=REAL).status_code == 401
    assert c.post("/v1/verify", json=REAL, headers={"x-api-key": "wrong"}).status_code == 401
    assert c.post("/v1/verify", json=REAL, headers={"x-api-key": "k-view"}).status_code == 403
    assert c.post("/v1/verify", json=REAL, headers={"x-api-key": "k-ex"}).status_code == 200
    log = c.get("/v1/verifications", headers={"authorization": "Bearer k-view"}).json()["verifications"]
    assert log[0]["requested_by"] == "asha"
    assert c.get("/metrics", headers={"x-api-key": "k-ex"}).status_code == 403
    m = c.get("/metrics", headers={"x-api-key": "k-mon"})
    assert m.status_code == 200 and 'atproof_decisions_total{decision="present"}' in m.text


def test_limits_headers_errors_and_health(monkeypatch):
    c = TestClient(boot(monkeypatch, RATE_LIMIT="3").app)
    codes = [c.get("/v1/verifications").status_code for _ in range(5)]
    assert codes[:3] == [200] * 3 and codes[3:] == [429, 429]
    api = boot(monkeypatch, MAX_BODY_BYTES="500")

    @api.app.get("/boom")
    def boom():
        raise RuntimeError("secret detail: did:plc:victim")

    c = TestClient(api.app)
    assert c.post("/v1/verify", json={**REAL, "car": "A" * 600}).status_code == 413

    def chunks():
        for _ in range(10):
            yield b"a" * 100

    assert c.post("/v1/verify", content=chunks(), headers={"content-type": "application/json"}).status_code == 413
    crash = c.get("/boom")
    assert crash.status_code == 500 and "victim" not in crash.text and crash.json()["request_id"]
    bad = c.post("/v1/verify", json={"car": ["SECRETDID"], "identity": {}, "uri": "x"})
    assert bad.status_code == 422 and "SECRETDID" not in bad.text
    r = c.get("/v1/verifications", headers={"x-request-id": "abc-123"})
    assert r.headers["x-request-id"] == "abc-123" and r.headers["content-security-policy"] == ops.API_CSP
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/readyz").json()["checks"] == {"database": True}
    monkeypatch.setattr(api.engine, "connect", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    assert c.get("/readyz").status_code == 503


def test_json_logs_carry_request_ids(capsys):
    ops.setup_logging("INFO")
    token = ops.request_id.set("rid-1")
    ops.log.info("hello")
    ops.request_id.reset(token)
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["request_id"] == "rid-1"


def test_migrations_apply_once(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    eng = db.engine(url)
    assert db.migrate(eng) == ["001_init.sql"] and db.migrate(eng) == []
    with eng.connect() as c:
        tables = {r[0] for r in c.execute(text("SELECT name FROM sqlite_master WHERE type = 'table'"))}
    assert {"verifications", "schema_migrations"} <= tables
    env = {**{k: v for k, v in os.environ.items() if not k.startswith("ATPROOF_")}, "ATPROOF_DATABASE_URL": url}
    out = subprocess.run([sys.executable, "-m", "atproof", "migrate"], env=env, capture_output=True, text=True,
                         timeout=120, check=False)
    assert out.returncode == 0 and "up to date" in out.stdout
