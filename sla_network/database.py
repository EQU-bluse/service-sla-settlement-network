from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_metadata(key, value) VALUES ('schema_version', '1');
CREATE TABLE IF NOT EXISTS machines (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL REFERENCES machines(id)
);
"""


def connect(path: str) -> sqlite3.Connection:
    database = Path(path)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.executescript(SCHEMA)
    return connection


# 登记结果：created 首次提交，replayed 幂等重放，
# idempotency_conflict 同键异请求，machine_exists 异键同机器。
def register_machine(
    path: str, idempotency_key: str, machine_id: str, public_key: str
) -> tuple[str, str | None]:
    with closing(connect(path)) as database:
        try:
            database.execute("BEGIN IMMEDIATE")
            record = database.execute(
                "SELECT machine_id FROM idempotency_keys WHERE key = ?",
                (idempotency_key,),
            ).fetchone()
            if record is not None:
                if record["machine_id"] != machine_id:
                    database.rollback()
                    return "idempotency_conflict", None
                machine = database.execute(
                    "SELECT public_key FROM machines WHERE id = ?", (machine_id,)
                ).fetchone()
                database.commit()
                return "replayed", machine["public_key"]
            existing = database.execute(
                "SELECT 1 FROM machines WHERE id = ?", (machine_id,)
            ).fetchone()
            if existing is not None:
                database.rollback()
                return "machine_exists", None
            database.execute(
                "INSERT INTO machines(id, public_key) VALUES (?, ?)",
                (machine_id, public_key),
            )
            database.execute(
                "INSERT INTO idempotency_keys(key, machine_id) VALUES (?, ?)",
                (idempotency_key, machine_id),
            )
            database.commit()
            return "created", None
        except Exception:
            database.rollback()
            raise

