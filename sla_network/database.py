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
    commit_seq INTEGER NOT NULL,
    PRIMARY KEY (sla_id, event_id)
);
CREATE TABLE IF NOT EXISTS sla_telemetry_idempotency_records (
    key TEXT PRIMARY KEY,
    sla_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sla_evaluation_idempotency_records (
    key TEXT PRIMARY KEY,
    sla_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    evaluation_seq INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ledger_accounts (
    account_id TEXT PRIMARY KEY,
    balance_micros INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_entries (
    entry_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    reference_seq INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    delta_micros INTEGER NOT NULL,
    balance_after_micros INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fund_deposits (
    deposit_seq INTEGER PRIMARY KEY,
    machine_id TEXT NOT NULL,
    amount_micros INTEGER NOT NULL,
    reference TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fund_idempotency_records (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settlements (
    settlement_seq INTEGER PRIMARY KEY,
    sla_id TEXT NOT NULL,
    evaluation_seq INTEGER NOT NULL UNIQUE,
    result TEXT NOT NULL,
    amount_micros INTEGER NOT NULL,
    payer_id TEXT,
    payee_id TEXT,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS settlement_idempotency_records (
    key TEXT PRIMARY KEY,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS disputes (
    id TEXT PRIMARY KEY,
    settlement_seq INTEGER NOT NULL UNIQUE,
    claimant_id TEXT NOT NULL,
    payer_id TEXT NOT NULL,
    payee_id TEXT NOT NULL,
    amount_micros INTEGER NOT NULL,
    state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dispute_idempotency_records (
    key TEXT PRIMARY KEY,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dispute_resolution_idempotency_records (
    key TEXT PRIMARY KEY,
    dispute_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dispute_events (
    event_seq INTEGER PRIMARY KEY,
    dispute_id TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS dispute_evidences (
    evidence_seq INTEGER PRIMARY KEY,
    dispute_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    digest TEXT NOT NULL,
    UNIQUE (dispute_id, evidence_id),
    UNIQUE (dispute_id, digest)
);
CREATE TABLE IF NOT EXISTS dispute_evidence_idempotency_records (
    key TEXT PRIMARY KEY,
    dispute_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    evidence_seq INTEGER NOT NULL UNIQUE
);
"""

TELEMETRY_SEQ_MARKER = "telemetry_commit_seq_renumbered"
TELEMETRY_SEQ_INDEX = "idx_sla_telemetry_commit_seq_unique"
EVALUATION_SEQ_MARKER = "evaluation_seq_renumbered"
EVALUATION_SEQ_INDEX = "idx_sla_evaluation_seq_unique"
DISPUTE_EVENT_MARKER = "dispute_events_backfilled"
DISPUTE_EVENT_INDEX = "idx_dispute_events_dispute_seq"


def _renumber_commit_seq(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (TELEMETRY_SEQ_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁，不再重编号。
            connection.execute("COMMIT")
            return
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(sla_telemetry_events)")
        }
        if "commit_seq" not in columns:
            connection.execute(
                "ALTER TABLE sla_telemetry_events ADD COLUMN commit_seq INTEGER"
            )
        # 单事务按全局 rowid 升序稠密重编号 1..N；事件内容与幂等记录不变。
        rows = connection.execute(
            "SELECT rowid AS rid FROM sla_telemetry_events ORDER BY rowid ASC"
        ).fetchall()
        for commit_seq, row in enumerate(rows, start=1):
            connection.execute(
                "UPDATE sla_telemetry_events SET commit_seq = ? WHERE rowid = ?",
                (commit_seq, row["rid"]),
            )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (TELEMETRY_SEQ_MARKER,),
        )
        # 唯一索引必须在重编号之后建立：旧库迁移前存在跨 SLA 的重复序号。
        connection.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {TELEMETRY_SEQ_INDEX}"
            " ON sla_telemetry_events(commit_seq)"
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _renumber_evaluation_seq(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (EVALUATION_SEQ_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁，不再重编号。
            connection.execute("COMMIT")
            return
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(sla_evaluation_idempotency_records)"
            )
        }
        if "evaluation_seq" not in columns:
            connection.execute(
                "ALTER TABLE sla_evaluation_idempotency_records"
                " ADD COLUMN evaluation_seq INTEGER NOT NULL DEFAULT 0"
            )
        if "created_at_ms" not in columns:
            connection.execute(
                "ALTER TABLE sla_evaluation_idempotency_records"
                " ADD COLUMN created_at_ms INTEGER NOT NULL DEFAULT 0"
            )
        # 单事务按评估幂等表全局 rowid 升序稠密赋 1..N，createdAt=0；
        # request_json/response_json 等既有字节一律不改。
        rows = connection.execute(
            "SELECT rowid AS rid FROM sla_evaluation_idempotency_records"
            " ORDER BY rowid ASC"
        ).fetchall()
        for evaluation_seq, row in enumerate(rows, start=1):
            connection.execute(
                "UPDATE sla_evaluation_idempotency_records"
                " SET evaluation_seq = ?, created_at_ms = 0 WHERE rowid = ?",
                (evaluation_seq, row["rid"]),
            )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (EVALUATION_SEQ_MARKER,),
        )
        # 唯一索引必须在赋值之后建立：旧库迁移前 evaluation_seq 全为 0。
        connection.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {EVALUATION_SEQ_INDEX}"
            " ON sla_evaluation_idempotency_records(evaluation_seq)"
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _backfill_dispute_events(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (DISPUTE_EVENT_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁，不再补事件。
            connection.execute("COMMIT")
            return
        # 旧库没有 dispute_events 表（新库由 SCHEMA 创建），单事务内补齐：
        # 按争议 rowid 升序每个争议补 opened；已裁决项紧随补结果。时间记零，
        # 不虚构旧失败，不改争议与幂等等既有数据。
        rows = connection.execute(
            "SELECT rowid AS rid, id, state FROM disputes ORDER BY rowid ASC"
        ).fetchall()
        event_seq = 0
        for row in rows:
            event_seq += 1
            connection.execute(
                "INSERT INTO dispute_events(event_seq, dispute_id, type, created_at_ms)"
                " VALUES (?, ?, 'opened', 0)",
                (event_seq, row["id"]),
            )
            if row["state"] in ("released", "refunded"):
                event_seq += 1
                connection.execute(
                    "INSERT INTO dispute_events"
                    "(event_seq, dispute_id, type, created_at_ms)"
                    " VALUES (?, ?, ?, 0)",
                    (event_seq, row["id"], row["state"]),
                )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (DISPUTE_EVENT_MARKER,),
        )
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS {DISPUTE_EVENT_INDEX}"
            " ON dispute_events(dispute_id, event_seq)"
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
    # 快速路径：一次性标记已存在则纯读，避免给普通读请求加写锁；
    # 标记与唯一索引在同一事务写入，故标记存在即索引已就绪。
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (TELEMETRY_SEQ_MARKER,),
        ).fetchone()
        is None
    ):
        _renumber_commit_seq(connection)
    # 此处 commit_seq 必然存在：新库由 SCHEMA 建列，旧库由迁移补列。
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_sla_telemetry_commit"
        " ON sla_telemetry_events(sla_id, commit_seq, timestamp_ms, event_id)"
    )
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (EVALUATION_SEQ_MARKER,),
        ).fetchone()
        is None
    ):
        _renumber_evaluation_seq(connection)
    # 此处 evaluation_seq 必然存在：新库由 SCHEMA 建列，旧库由迁移补列。
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_sla_evaluation_seq"
        " ON sla_evaluation_idempotency_records(sla_id, evaluation_seq)"
    )
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (DISPUTE_EVENT_MARKER,),
        ).fetchone()
        is None
    ):
        _backfill_dispute_events(connection)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_settlements_sla_seq"
        " ON settlements(sla_id, settlement_seq)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_ledger_entries_account_seq"
        " ON ledger_entries(account_id, entry_seq)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_disputes_payee_state"
        " ON disputes(payee_id, state)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_dispute_evidences_dispute_seq"
        " ON dispute_evidences(dispute_id, evidence_seq)"
    )
    return connection

