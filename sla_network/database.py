from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_metadata(key, value) VALUES ('schema_version', '1');
CREATE TABLE IF NOT EXISTS schema_migrations (
    id INTEGER PRIMARY KEY,
    applied_at_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS machines (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency_records (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    public_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS machine_capabilities (
    machine_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    region TEXT NOT NULL,
    unit TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS capability_idempotency_records (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sla_templates (
    id TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    capability_version INTEGER NOT NULL,
    price_micros INTEGER NOT NULL,
    max_latency_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sla_template_idempotency_records (
    key TEXT PRIMARY KEY,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS slas (
    id TEXT PRIMARY KEY,
    template_id TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    consumer_id TEXT NOT NULL,
    capability_version INTEGER NOT NULL,
    price_micros INTEGER NOT NULL,
    max_latency_ms INTEGER NOT NULL,
    start_unix INTEGER NOT NULL,
    end_unix INTEGER NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sla_idempotency_records (
    key TEXT PRIMARY KEY,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sla_confirmations (
    sla_id TEXT NOT NULL,
    party TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    PRIMARY KEY (sla_id, party)
);
CREATE TABLE IF NOT EXISTS sla_confirmation_idempotency_records (
    key TEXT PRIMARY KEY,
    sla_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sla_telemetry_events (
    sla_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    digest TEXT NOT NULL,
    commit_seq INTEGER NOT NULL UNIQUE,
    PRIMARY KEY (sla_id, event_id)
);
CREATE TABLE IF NOT EXISTS sla_telemetry_idempotency_records (
    key TEXT PRIMARY KEY,
    sla_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
"""


def _migrate_telemetry_commit_seq(connection: sqlite3.Connection) -> None:
    # 旧库的事件按全库 rowid 升序一次性重编号为 1..N；标记写入同一事务，
    # 重启后不再重编号。事件内容与幂等记录保持不变。
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(sla_telemetry_events)")
    }
    if "commit_seq" not in columns:
        connection.execute(
            "ALTER TABLE sla_telemetry_events ADD COLUMN commit_seq INTEGER"
        )
    applied = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE id = 1"
    ).fetchone()
    if applied is not None:
        return
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE sla_telemetry_events SET commit_seq = ("
            " SELECT COUNT(*) FROM sla_telemetry_events AS earlier"
            " WHERE earlier.rowid <= sla_telemetry_events.rowid)"
        )
        connection.execute(
            "INSERT INTO schema_migrations(id, applied_at_unix) VALUES (1, 0)"
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def connect(path: str) -> sqlite3.Connection:
    database = Path(path)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    _migrate_telemetry_commit_seq(connection)
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_sla_telemetry_commit_seq_unique"
        " ON sla_telemetry_events(commit_seq)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_sla_telemetry_commit"
        " ON sla_telemetry_events(sla_id, commit_seq, timestamp_ms, event_id)"
    )
    return connection
