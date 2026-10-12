"""Test harness: an isolated SQLite database + storage directory per test run, scan jobs run inline."""
import json
import os
import shutil
import tempfile

_TMP = tempfile.mkdtemp(prefix="retrace-tests-")
os.environ["DATABASE_URL"] = os.environ.get("RETRACE_TEST_DATABASE_URL") or f"sqlite:///{_TMP}/test.db"
os.environ["RETRACE_STORAGE_DIR"] = f"{_TMP}/storage"
os.environ["RETRACE_JOBS_INLINE"] = "1"
os.environ["RETRACE_SECRET_KEY"] = "t" * 40
os.environ["RETRACE_AI_PROVIDER"] = "none"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.adapters.base import AdapterResult  # noqa: E402
from app.db import Base, get_engine  # noqa: E402
from app.main import app  # noqa: E402
from app.security import limiter  # noqa: E402
from app.services import decompiler_service, mythril_service  # noqa: E402
from app import models  # noqa: F401,E402

VULNERABLE = "6000" * 5 + "33" + "5a" + "f1" + "50" + "6001" + "6000" + "55" + "00"
SAFE = "6001" + "6000" + "55" + "6000" * 5 + "33" + "5a" + "f1" + "50" + "00"
PW = "Str0ng-Passw0rd!"


def mythril_json(issues):
    return json.dumps({"success": True, "error": None, "issues": issues})


@pytest.fixture(autouse=True)
def fresh_db():
    engine = get_engine()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    limiter.reset()
    shutil.rmtree(os.environ["RETRACE_STORAGE_DIR"], ignore_errors=True)   # no files leak between tests
    yield


class Session:
    """A TestClient that remembers the CSRF token like the browser UI does."""

    def __init__(self):
        self.c = TestClient(app, base_url="http://localhost")
        self.csrf = None

    def _h(self, extra=None):
        h = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        h.update(extra or {})
        return h

    def request(self, method, url, **kw):
        kw["headers"] = self._h(kw.get("headers"))
        return self.c.request(method, url, **kw)

    get = lambda self, url, **kw: self.request("GET", url, **kw)
    post = lambda self, url, **kw: self.request("POST", url, **kw)
    patch = lambda self, url, **kw: self.request("PATCH", url, **kw)
    delete = lambda self, url, **kw: self.request("DELETE", url, **kw)

    def register(self, email="alice@example.com", name="Alice", password=PW):
        r = self.post("/api/auth/register", json={"name": name, "email": email, "password": password})
        if r.status_code == 201:
            self.csrf = r.json()["csrf_token"]
        return r

    def login(self, email, password=PW):
        r = self.post("/api/auth/login", json={"email": email, "password": password})
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
        return r


@pytest.fixture
def make_session():
    return Session


@pytest.fixture
def alice(make_session):
    s = make_session()
    assert s.register("alice@example.com", "Alice").status_code == 201
    return s


@pytest.fixture
def bob(make_session):
    s = make_session()
    assert s.register("bob@example.com", "Bob").status_code == 201
    return s


@pytest.fixture
def fake_tools(monkeypatch):
    state = {
        "heimdall": AdapterResult("ok", output="function withdraw() { /* ... */ }", duration_s=0.1),
        "mythril": AdapterResult("ok", output=mythril_json([]), duration_s=0.2),
    }
    monkeypatch.setattr(decompiler_service.heimdall_adapter, "run_heimdall", lambda code, settings: state["heimdall"])
    monkeypatch.setattr(mythril_service.mythril_adapter, "run_mythril", lambda code, settings: state["mythril"])
    return state


def run_scan(session, code, **kw):
    """Create a scan from pasted bytecode (jobs run inline) and return its final JSON."""
    r = session.post("/api/scans", json={"bytecode": code, **kw})
    assert r.status_code == 202, r.text
    return session.get(f"/api/scans/{r.json()['id']}").json()
