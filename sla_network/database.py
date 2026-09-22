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


def connect(path: str) -> sqlite3.Connection:
    database = Path(path)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection

