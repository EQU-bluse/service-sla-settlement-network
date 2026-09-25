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
CREATE TABLE IF NOT EXISTS machine_keys (
    machine_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    public_key TEXT NOT NULL,
    activated_at_ms INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (machine_id, version)
);
CREATE TABLE IF NOT EXISTS machine_key_rotation_idempotency_records (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS machine_key_revocation_idempotency_records (
    key TEXT PRIMARY KEY,
    machine_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_machine_keys_key_unique
ON machine_keys(machine_id, public_key);
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
    response_json TEXT NOT NULL,
    auth_machine_id TEXT,
    auth_key_version INTEGER,
    auth_request_time_ms INTEGER,
    auth_nonce TEXT,
    auth_signature TEXT
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
    response_json TEXT NOT NULL,
    auth_machine_id TEXT,
    auth_key_version INTEGER,
    auth_request_time_ms INTEGER,
    auth_nonce TEXT,
    auth_signature TEXT
);
CREATE TABLE IF NOT EXISTS sla_telemetry_events (
    sla_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    timestamp_ms INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    digest TEXT NOT NULL,
    commit_seq INTEGER NOT NULL,
    signature TEXT,
    key_version INTEGER,
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
    observed_at_ms INTEGER NOT NULL,
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
    auth_machine_id TEXT,
    auth_key_version INTEGER,
    auth_request_time_ms INTEGER,
    auth_nonce TEXT,
    auth_signature TEXT
);
CREATE TABLE IF NOT EXISTS dispute_evidence_proofs (
    proof_seq INTEGER PRIMARY KEY,
    evidence_seq INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    verified INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE (evidence_seq, actor_id)
);
CREATE TABLE IF NOT EXISTS dispute_evidence_proof_idempotency_records (
    key TEXT PRIMARY KEY,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    auth_machine_id TEXT,
    auth_key_version INTEGER,
    auth_request_time_ms INTEGER,
    auth_nonce TEXT,
    auth_signature TEXT
);
CREATE TABLE IF NOT EXISTS machine_delegations (
    id TEXT PRIMARY KEY,
    issuer_machine_id TEXT NOT NULL,
    delegate_public_key TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    issued_key_version INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    operation TEXT,
    capability_version INTEGER,
    dispute_id TEXT,
    evidence_seq INTEGER
);
CREATE TABLE IF NOT EXISTS delegation_idempotency_records (
    key TEXT PRIMARY KEY,
    delegation_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    auth_machine_id TEXT,
    auth_key_version INTEGER,
    auth_request_time_ms INTEGER,
    auth_nonce TEXT,
    auth_signature TEXT
);
CREATE TABLE IF NOT EXISTS delegation_revocation_idempotency_records (
    key TEXT PRIMARY KEY,
    delegation_id TEXT NOT NULL,
    request_json TEXT NOT NULL,
    status INTEGER NOT NULL,
    response_json TEXT NOT NULL,
    auth_machine_id TEXT,
    auth_key_version INTEGER,
    auth_request_time_ms INTEGER,
    auth_nonce TEXT,
    auth_signature TEXT
);
CREATE TABLE IF NOT EXISTS delegation_events (
    event_seq INTEGER PRIMARY KEY,
    delegation_id TEXT NOT NULL,
    type TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    resource TEXT,
    request_digest TEXT
);
CREATE TABLE IF NOT EXISTS auth_nonce_records (
    machine_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    request_time_ms INTEGER NOT NULL,
    PRIMARY KEY (machine_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_dispute_evidences_dispute_seq
ON dispute_evidences(dispute_id, evidence_seq);
CREATE INDEX IF NOT EXISTS idx_dispute_evidence_proofs_evidence_seq
ON dispute_evidence_proofs(evidence_seq, proof_seq);
CREATE INDEX IF NOT EXISTS idx_auth_nonce_records_machine_time
ON auth_nonce_records(machine_id, request_time_ms);
"""

TELEMETRY_SEQ_MARKER = "telemetry_commit_seq_renumbered"
TELEMETRY_SEQ_INDEX = "idx_sla_telemetry_commit_seq_unique"
TELEMETRY_SIGNATURE_MARKER = "telemetry_signature_added"
TELEMETRY_KEY_VERSION_MARKER = "telemetry_key_version_added"
EVALUATION_SEQ_MARKER = "evaluation_seq_renumbered"
EVALUATION_SEQ_INDEX = "idx_sla_evaluation_seq_unique"
DISPUTE_EVENT_MARKER = "dispute_events_backfilled"
DISPUTE_EVENT_INDEX = "idx_dispute_events_dispute_seq"
MACHINE_KEYS_MARKER = "machine_keys_backfilled"
SLA_AUTH_MARKER = "sla_auth_added"
DELEGATION_EVENT_MARKER = "delegation_events_backfilled"
DELEGATION_EVENT_INDEX = "idx_delegation_events_delegation_seq"
DELEGATION_SCOPE_MARKER = "delegation_scope_added"
DELEGATION_DISPUTE_MARKER = "delegation_dispute_added"
DELEGATION_PROOF_MARKER = "delegation_proof_added"

AUTH_IDEMPOTENCY_TABLES = (
    "capability_idempotency_records",
    "sla_confirmation_idempotency_records",
    "dispute_evidence_idempotency_records",
    "dispute_evidence_proof_idempotency_records",
)
AUTH_IDEMPOTENCY_COLUMNS = (
    "auth_machine_id TEXT",
    "auth_key_version INTEGER",
    "auth_request_time_ms INTEGER",
    "auth_nonce TEXT",
    "auth_signature TEXT",
)


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


def _add_telemetry_signature_column(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (TELEMETRY_SIGNATURE_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁。
            connection.execute("COMMIT")
            return
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(sla_telemetry_events)")
        }
        if "signature" not in columns:
            # 旧库补可空签名列：既有事件保持 NULL（无签名），不补造、不重排序号。
            connection.execute(
                "ALTER TABLE sla_telemetry_events ADD COLUMN signature TEXT"
            )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (TELEMETRY_SIGNATURE_MARKER,),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _add_telemetry_key_version_column(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (TELEMETRY_KEY_VERSION_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁。
            connection.execute("COMMIT")
            return
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(sla_telemetry_events)")
        }
        if "key_version" not in columns:
            # 旧事件（含签名 v1 事件）不回填密钥版本，保持 NULL：照常查询、评估、结算。
            connection.execute(
                "ALTER TABLE sla_telemetry_events ADD COLUMN key_version INTEGER"
            )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (TELEMETRY_KEY_VERSION_MARKER,),
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


def _backfill_machine_keys(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (MACHINE_KEYS_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁，不再补历史。
            connection.execute("COMMIT")
            return
        # 升级与新登记均建立版本一历史：旧库中每台已登记机器补一条 version=1、
        # activated_at_ms=0、未吊销的记录，公钥取 machines.public_key。新库首启时
        # machines 为空，此处不写入；机器登记在登记事务内自行建立版本一。
        connection.execute(
            "INSERT INTO machine_keys(machine_id, version, public_key,"
            " activated_at_ms, revoked)"
            " SELECT m.id, 1, m.public_key, 0, 0 FROM machines AS m"
            " WHERE NOT EXISTS ("
            " SELECT 1 FROM machine_keys AS k WHERE k.machine_id = m.id)"
        )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (MACHINE_KEYS_MARKER,),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _add_sla_auth(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (SLA_AUTH_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁。
            connection.execute("COMMIT")
            return
        # 升级前幂等记录的认证五段一律保持 NULL：作为唯一例外按原请求先行重放，
        # 不补认证数据；随机数表为空，旧记录重放不消费随机数。
        for table in AUTH_IDEMPOTENCY_TABLES:
            existing = {
                row["name"]
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            for name, declaration in (
                column.split(" ", 1) for column in AUTH_IDEMPOTENCY_COLUMNS
            ):
                if name not in existing:
                    connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN {name} {declaration}"
                    )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (SLA_AUTH_MARKER,),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _backfill_delegation_events(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (DELEGATION_EVENT_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁，不再补事件。
            connection.execute("COMMIT")
            return
        # 旧库没有 delegation_events 表（新库由 SCHEMA 创建），单事务内补齐：
        # 先按委托 rowid 升序为每张委托补一条 issued，再依现有 consumed/revoked
        # 标记紧随补 consumed/revoked；时间一律记零，不改动委托与幂等等既有数据。
        event_seq = 0
        rows = connection.execute(
            "SELECT rowid AS rid, id, consumed, revoked FROM machine_delegations"
            " ORDER BY rowid ASC"
        ).fetchall()
        for row in rows:
            event_seq += 1
            connection.execute(
                "INSERT INTO delegation_events(event_seq, delegation_id, type,"
                " created_at_ms) VALUES (?, ?, 'issued', 0)",
                (event_seq, row["id"]),
            )
            if row["consumed"]:
                event_seq += 1
                connection.execute(
                    "INSERT INTO delegation_events(event_seq, delegation_id, type,"
                    " created_at_ms) VALUES (?, ?, 'consumed', 0)",
                    (event_seq, row["id"]),
                )
            if row["revoked"]:
                event_seq += 1
                connection.execute(
                    "INSERT INTO delegation_events(event_seq, delegation_id, type,"
                    " created_at_ms) VALUES (?, ?, 'revoked', 0)",
                    (event_seq, row["id"]),
                )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (DELEGATION_EVENT_MARKER,),
        )
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS {DELEGATION_EVENT_INDEX}"
            " ON delegation_events(delegation_id, event_seq)"
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _add_delegation_scope(connection: sqlite3.Connection) -> None:
    # 仅在一次性迁移（含空库首次连接）时取写锁；BEGIN IMMEDIATE 串行并发首启。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (DELEGATION_SCOPE_MARKER,),
            ).fetchone()
            is not None
        ):
            # 其他连接已完成迁移，直接释放写锁。
            connection.execute("COMMIT")
            return
        # 旧委托与旧 consumed 事件的最小权限范围与消费审计列保持 NULL：
        # 旧凭证按无范围语义消费，旧事件新增业务元数据均为 null，不补造。
        delegation_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(machine_delegations)")
        }
        if "operation" not in delegation_columns:
            connection.execute(
                "ALTER TABLE machine_delegations ADD COLUMN operation TEXT"
            )
        if "capability_version" not in delegation_columns:
            connection.execute(
                "ALTER TABLE machine_delegations ADD COLUMN capability_version INTEGER"
            )
        event_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(delegation_events)")
        }
        if "resource" not in event_columns:
            connection.execute(
                "ALTER TABLE delegation_events ADD COLUMN resource TEXT"
            )
        if "request_digest" not in event_columns:
            connection.execute(
                "ALTER TABLE delegation_events ADD COLUMN request_digest TEXT"
            )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (DELEGATION_SCOPE_MARKER,),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _add_delegation_dispute(connection: sqlite3.Connection) -> None:
    # 单笔争议证据授权：旧委托只补可空 dispute_id 列并保持 NULL。
    # 能力授权与升级前凭证对应 null；不改动旧委托、事件序号、幂等数据或历史响应。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (DELEGATION_DISPUTE_MARKER,),
            ).fetchone()
            is not None
        ):
            connection.execute("COMMIT")
            return
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(machine_delegations)")
        }
        if "dispute_id" not in columns:
            connection.execute(
                "ALTER TABLE machine_delegations ADD COLUMN dispute_id TEXT"
            )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (DELEGATION_DISPUTE_MARKER,),
        )
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise


def _add_delegation_proof(connection: sqlite3.Connection) -> None:
    # 单条证据证明授权：旧委托只补可空 evidence_seq 列并保持 NULL。
    # 能力授权、争议授权与升级前凭证对应 null；不改动旧委托、事件序号、
    # 幂等数据或历史响应字节。
    connection.execute("BEGIN IMMEDIATE")
    try:
        if (
            connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = ?",
                (DELEGATION_PROOF_MARKER,),
            ).fetchone()
            is not None
        ):
            connection.execute("COMMIT")
            return
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(machine_delegations)")
        }
        if "evidence_seq" not in columns:
            connection.execute(
                "ALTER TABLE machine_delegations ADD COLUMN evidence_seq INTEGER"
            )
        connection.execute(
            "INSERT INTO schema_metadata(key, value) VALUES (?, '1')",
            (DELEGATION_PROOF_MARKER,),
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
            (TELEMETRY_SIGNATURE_MARKER,),
        ).fetchone()
        is None
    ):
        _add_telemetry_signature_column(connection)
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (TELEMETRY_KEY_VERSION_MARKER,),
        ).fetchone()
        is None
    ):
        _add_telemetry_key_version_column(connection)
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
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (MACHINE_KEYS_MARKER,),
        ).fetchone()
        is None
    ):
        _backfill_machine_keys(connection)
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (SLA_AUTH_MARKER,),
        ).fetchone()
        is None
    ):
        _add_sla_auth(connection)
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (DELEGATION_EVENT_MARKER,),
        ).fetchone()
        is None
    ):
        _backfill_delegation_events(connection)
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (DELEGATION_SCOPE_MARKER,),
        ).fetchone()
        is None
    ):
        _add_delegation_scope(connection)
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (DELEGATION_DISPUTE_MARKER,),
        ).fetchone()
        is None
    ):
        _add_delegation_dispute(connection)
    if (
        connection.execute(
            "SELECT 1 FROM schema_metadata WHERE key = ?",
            (DELEGATION_PROOF_MARKER,),
        ).fetchone()
        is None
    ):
        _add_delegation_proof(connection)
    # 委托按签发事件序号分页：事件表 join 委托后需 (issuer, issued_seq) 索引。
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_delegation_events_delegation_seq"
        " ON delegation_events(delegation_id, event_seq)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_machine_delegations_issuer"
        " ON machine_delegations(issuer_machine_id, id)"
    )
    # 消费审计按全库事件序号升序扫描某签发机器的 consumed 事件：type+seq 索引。
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_delegation_events_consumed_seq"
        " ON delegation_events(type, event_seq)"
    )
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
    return connection

