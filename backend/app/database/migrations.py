"""Additive, idempotent schema upgrades for existing SQLite databases.

``Base.metadata.create_all()`` creates missing tables but never alters existing
ones. This module adds any missing *nullable* columns and indexes in place,
preserving the database file and every existing row. It never drops, renames
or rewrites anything. Use Alembic before production.
"""

from sqlalchemy import Engine, text

# table -> {column: SQLite column DDL}. Columns are nullable or have a default.
ADDITIVE_COLUMNS: dict[str, dict[str, str]] = {
    "scans": {
        "target_id": "CHAR(32) REFERENCES targets(id)",
        "options": "JSON",
    },
    "scanner_runs": {
        "attempt": "INTEGER NOT NULL DEFAULT 1",
    },
    "findings": {
        "scanner": "VARCHAR(40)",
        "scanner_run_id": "CHAR(32) REFERENCES scanner_runs(id) ON DELETE SET NULL",
        "detected_by": "JSON",
        "source_id": "VARCHAR(255)",
        "original_severity": "VARCHAR(40)",
        "confidence": "VARCHAR(20)",
        "cwe": "VARCHAR(40)",
        "references": "JSON",
        "fingerprint": "VARCHAR(64)",
    },
}

# Names match what create_all() generates for a fresh database.
ADDITIVE_INDEXES: dict[str, list[str]] = {
    "scans": [
        "CREATE INDEX IF NOT EXISTS ix_scans_target_id ON scans (target_id)",
    ],
    "findings": [
        "CREATE INDEX IF NOT EXISTS ix_findings_scanner ON findings (scanner)",
        "CREATE INDEX IF NOT EXISTS ix_findings_scanner_run_id ON findings (scanner_run_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_scan_fingerprint "
        "ON findings (scan_id, fingerprint)",
    ],
}


def upgrade_sqlite_schema(engine: Engine) -> list[str]:
    """Apply missing columns/indexes. Returns the statements executed."""
    executed: list[str] = []
    with engine.begin() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
        }
        for table, columns in ADDITIVE_COLUMNS.items():
            if table not in tables:
                continue  # create_all() builds it with every column
            existing = {
                row[1] for row in conn.execute(text(f'PRAGMA table_info("{table}")'))
            }
            for name, ddl in columns.items():
                if name not in existing:
                    stmt = f'ALTER TABLE "{table}" ADD COLUMN "{name}" {ddl}'
                    conn.execute(text(stmt))
                    executed.append(stmt)
        for table, statements in ADDITIVE_INDEXES.items():
            if table in tables:
                for stmt in statements:
                    conn.execute(text(stmt))
    return executed
