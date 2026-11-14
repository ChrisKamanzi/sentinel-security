"""Additive SQLite schema upgrade, tested on a temporary file (never autopentest.db)."""

from sqlalchemy import create_engine, text

from app.database.base import Base
from app.database.migrations import upgrade_sqlite_schema

# The schema of the pre-scanner development database (copied from autopentest.db).
LEGACY_SCHEMA = [
    """CREATE TABLE projects (id CHAR(32) NOT NULL, name VARCHAR(120) NOT NULL,
       description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
       PRIMARY KEY (id))""",
    """CREATE TABLE scans (id CHAR(32) NOT NULL, project_id CHAR(32) NOT NULL,
       target_url VARCHAR(2048) NOT NULL, scanner VARCHAR(40) NOT NULL,
       status VARCHAR(9) NOT NULL, error_message TEXT,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL, started_at DATETIME,
       completed_at DATETIME, PRIMARY KEY (id),
       FOREIGN KEY(project_id) REFERENCES projects (id) ON DELETE CASCADE)""",
    """CREATE TABLE findings (id CHAR(32) NOT NULL, scan_id CHAR(32) NOT NULL,
       title VARCHAR(255) NOT NULL, severity VARCHAR(8) NOT NULL, description TEXT,
       recommendation TEXT, location VARCHAR(2048), evidence TEXT,
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL, PRIMARY KEY (id),
       FOREIGN KEY(scan_id) REFERENCES scans (id) ON DELETE CASCADE)""",
]


def _columns(conn, table):
    return {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}


def test_upgrade_legacy_database_preserves_rows(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as conn:
        for ddl in LEGACY_SCHEMA:
            conn.execute(text(ddl))
        conn.execute(text("INSERT INTO projects (id, name) VALUES ('a'*1, 'Existing')"))
        conn.execute(text(
            "INSERT INTO scans (id, project_id, target_url, scanner, status) "
            "VALUES ('s', 'a', 'https://example.com', 'pending', 'queued')"
        ))

    Base.metadata.create_all(engine)  # what app startup does first
    executed = upgrade_sqlite_schema(engine)
    assert executed  # columns were added
    assert upgrade_sqlite_schema(engine) == []  # idempotent

    with engine.connect() as conn:
        assert {"target_id", "options"} <= _columns(conn, "scans")
        assert {"scanner", "scanner_run_id", "detected_by", "source_id",
                "original_severity", "confidence", "cwe", "references",
                "fingerprint"} <= _columns(conn, "findings")
        tables = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        assert {"targets", "scanner_runs"} <= tables
        # existing data untouched
        assert conn.execute(text("SELECT name FROM projects")).scalar() == "Existing"
        assert conn.execute(text("SELECT target_url FROM scans")).scalar() == "https://example.com"
        indexes = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='index'"))}
        assert "uq_findings_scan_fingerprint" in indexes


def test_upgrade_fresh_database_is_noop(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    Base.metadata.create_all(engine)
    assert upgrade_sqlite_schema(engine) == []
