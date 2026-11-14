"""Shared pytest fixtures for the AutoPentest AI API tests.

Isolation guarantees
--------------------
1. DATABASE_URL is forced to an in-memory SQLite URL *before* the app is
   imported, so the application's own engine can never point at
   ``autopentest.db`` (environment variables take precedence over ``.env``).
2. Every test gets a brand-new in-memory database (StaticPool keeps the single
   in-memory connection alive for the duration of that test only).
3. ``get_db`` is overridden so every request uses the per-test database.
4. ``TestClient`` is created WITHOUT a ``with`` block, so the app lifespan
   (``create_all`` / ``ALTER TABLE`` on the app engine) is never run.
5. A session-wide guard fingerprints ``autopentest.db`` before and after the
   run and fails loudly if it changed.
"""

import hashlib
import os
import uuid
from pathlib import Path

# Must happen before any `app` import (see guarantee 1). Environment variables
# override .env, so local dev settings (e.g. ALLOW_PRIVATE_TARGETS=true) cannot
# leak into tests; tests that need a setting monkeypatch it explicitly.
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["ALLOW_PRIVATE_TARGETS"] = "false"
os.environ["CORS_ORIGINS"] = ""
os.environ["NMAP_PATH"] = ""
os.environ["NUCLEI_PATH"] = ""
os.environ["FFUF_PATH"] = ""
os.environ["ZAP_DOCKER_PATH"] = ""
os.environ["ZAP_DOCKER_NETWORK"] = ""
# Keep the real API key (from .env) out of the test process entirely; blank
# means "not configured". Tests that need a key monkeypatch a fake one.
os.environ["ANTHROPIC_API_KEY"] = ""

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, event  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.database import database as app_database  # noqa: E402
from app.database.base import Base  # noqa: E402
from app.database.database import get_db  # noqa: E402
from app.main import app  # noqa: E402

DEV_DB_PATH = Path(__file__).resolve().parent.parent / "autopentest.db"


def _fingerprint(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="session", autouse=True)
def guard_dev_database():
    """Fail the run if the development database is touched in any way."""
    assert app_database.engine.url.database in (None, "", ":memory:"), (
        "App engine is not in-memory; refusing to run tests against "
        f"{app_database.engine.url!r}"
    )
    before = _fingerprint(DEV_DB_PATH)
    yield
    after = _fingerprint(DEV_DB_PATH)
    assert before == after, "autopentest.db was modified during the test run!"


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@pytest.fixture
def engine():
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    event.listen(test_engine, "connect", _enable_sqlite_foreign_keys)
    Base.metadata.create_all(bind=test_engine)
    yield test_engine
    test_engine.dispose()  # discards the in-memory database entirely


@pytest.fixture
def session_factory(engine):
    return sessionmaker(bind=engine, autoflush=False, autocommit=False)


@pytest.fixture
def db_session(session_factory):
    """Direct ORM session on the per-test database, for DB-level assertions."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def _make_client(session_factory, raise_server_exceptions: bool):
    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    # No `with` block: the lifespan must not run (see module docstring).
    return TestClient(app, raise_server_exceptions=raise_server_exceptions)


@pytest.fixture
def client(session_factory):
    yield _make_client(session_factory, raise_server_exceptions=True)
    app.dependency_overrides.clear()


@pytest.fixture
def client_no_raise(session_factory):
    """Client that turns unhandled server errors into HTTP 500 responses
    (instead of re-raising them), so we can observe what a real caller sees."""
    yield _make_client(session_factory, raise_server_exceptions=False)
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Factory fixtures: create records through the public API.
# ---------------------------------------------------------------------------

API = "/api/v1"


@pytest.fixture
def make_project(client):
    def _make(**overrides):
        body = {"name": "Acme Assessment", "description": "Q4 web assessment"}
        body.update(overrides)
        resp = client.post(f"{API}/projects", json=body)
        assert resp.status_code == 201, resp.text
        return resp.json()

    return _make


@pytest.fixture
def make_target(client, make_project):
    def _make(project_id=None, **overrides):
        if project_id is None:
            project_id = make_project()["id"]
        body = {
            "name": "Main site",
            "host": "example.com",
            "base_url": "https://example.com",
            "is_authorized": True,
        }
        body.update(overrides)
        resp = client.post(f"{API}/projects/{project_id}/targets", json=body)
        assert resp.status_code == 201, resp.text
        return resp.json()

    return _make


@pytest.fixture
def make_scan(client, make_target):
    def _make(target=None):
        if target is None:
            target = make_target()
        resp = client.post(
            f"{API}/projects/{target['project_id']}/scans",
            json={"target_id": target["id"]},
        )
        assert resp.status_code == 201, resp.text
        return resp.json()

    return _make


@pytest.fixture
def make_finding(client, make_scan):
    def _make(scan_id=None, **overrides):
        if scan_id is None:
            scan_id = make_scan()["id"]
        body = {"title": "Missing security headers", "severity": "medium"}
        body.update(overrides)
        resp = client.post(f"{API}/scans/{scan_id}/findings", json=body)
        assert resp.status_code == 201, resp.text
        return resp.json()

    return _make


@pytest.fixture
def missing_id():
    """A syntactically valid UUID that does not exist in the database."""
    return str(uuid.uuid4())


@pytest.fixture(autouse=True)
def block_real_anthropic_api(monkeypatch):
    """No test may reach the real Claude API (cost, credentials, flakiness).
    Tests that exercise the analyst install a fake client explicitly."""
    from app.services import ai_analyst

    def _blocked():
        raise RuntimeError("Real Anthropic API calls are disabled in tests")

    monkeypatch.setattr(ai_analyst, "get_client", _blocked)
