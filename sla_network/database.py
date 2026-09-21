from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_metadata(key, value) VALUES ('schema_version', '1');
CREATE TABLE IF NOT EXISTS machines (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capabilities (
    machine_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    region TEXT NOT NULL,
    unit TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    FOREIGN KEY (machine_id) REFERENCES machines(id)
);
CREATE TABLE IF NOT EXISTS idempotency_records (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capability_idempotency_records (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    expected_version INTEGER NOT NULL,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    region TEXT NOT NULL,
    unit TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    status_code INTEGER NOT NULL,
    response_body BLOB NOT NULL
);
"""


def connect(path: str) -> sqlite3.Connection:
    database = Path(path)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection

