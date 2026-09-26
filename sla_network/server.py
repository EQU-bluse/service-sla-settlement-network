from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable
from contextlib import closing
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, NamedTuple
from urllib.parse import parse_qsl, urlsplit

from .database import connect
from .ed25519 import verify as ed25519_verify

IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9-]{1,64}")
PUBLIC_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")
CAPABILITIES_PATH_PATTERN = re.compile(r"/v1/machines/([^/]+)/capabilities")
MACHINE_DELEGATIONS_PATH_PATTERN = re.compile(
    r"/v1/machines/([^/]+)/delegations"
)
MACHINE_DELEGATION_CONSUMPTIONS_PATH_PATTERN = re.compile(
    r"/v1/machines/([^/]+)/delegation-consumptions"
)
MACHINE_KEYS_PATH_PATTERN = re.compile(r"/v1/machines/([^/]+)/keys")
MACHINE_KEY_REVOCATION_PATH_PATTERN = re.compile(
    r"/v1/machines/([^/]+)/keys/([^/]+)/revocation"
)
CAPABILITY_NAME_PATTERN = re.compile(r"[a-z0-9-]{1,32}")
TEMPLATE_ID_PATTERN = re.compile(r"[a-z0-9-]{1,64}")
SLA_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)")
SLA_CONFIRMATIONS_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)/confirmations")
SLA_TELEMETRY_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)/telemetry")
SLA_EVALUATIONS_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)/evaluations")
SLA_SETTLEMENTS_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)/settlements")
ACCOUNT_LEDGER_PATH_PATTERN = re.compile(r"/v1/accounts/([^/]+)/ledger")
FUNDS_PATH_PATTERN = re.compile(r"/v1/funds/([^/]+)")
DISPUTE_PATH_PATTERN = re.compile(r"/v1/disputes/([^/]+)")
DISPUTE_EVENTS_PATH_PATTERN = re.compile(r"/v1/disputes/([^/]+)/events")
DISPUTE_EVIDENCE_PATH_PATTERN = re.compile(r"/v1/disputes/([^/]+)/evidence")
DISPUTE_EVIDENCE_SNAPSHOTS_PATH_PATTERN = re.compile(
    r"/v1/disputes/([^/]+)/evidence-snapshots"
)
DISPUTE_EVIDENCE_SNAPSHOT_ITEM_PATH_PATTERN = re.compile(
    r"/v1/disputes/([^/]+)/evidence-snapshots/([^/]+)"
)
DISPUTE_ADJUDICATION_PROPOSALS_PATH_PATTERN = re.compile(
    r"/v1/disputes/([^/]+)/adjudication-proposals"
)
DISPUTE_ESCALATIONS_PATH_PATTERN = re.compile(
    r"/v1/disputes/([^/]+)/escalations"
)
DISPUTE_ARBITRATIONS_PATH_PATTERN = re.compile(
    r"/v1/disputes/([^/]+)/arbitrations"
)
DISPUTE_RESOLUTION_PATH_PATTERN = re.compile(r"/v1/disputes/([^/]+)/resolution")
EVIDENCE_PROOFS_PATH_PATTERN = re.compile(r"/v1/evidence/([^/]+)/proofs")
AUDIT_CHECKPOINT_ITEM_PATH_PATTERN = re.compile(r"/v1/audit-checkpoints/([^/]+)")
CAPABILITY_FIELDS = {"expectedVersion", "name", "protocol", "region", "unit", "capacity"}
SLA_TEMPLATE_FIELDS = {
    "id",
    "machineId",
    "capabilityVersion",
    "priceMicros",
    "maxLatencyMs",
}
SLA_FIELDS = {"id", "templateId", "consumerId", "start", "end"}
CONFIRMATION_FIELDS = {"party", "actorId"}
CONFIRMATION_PARTIES = {"producer", "consumer"}
TELEMETRY_FIELDS = {"eventId", "timestamp", "latencyMs", "digest"}
TELEMETRY_V1_SIGNED_FIELDS = TELEMETRY_FIELDS | {"signature"}
TELEMETRY_SIGNED_FIELDS = TELEMETRY_FIELDS | {"keyVersion", "signature"}
SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{128}")
EVALUATION_FIELDS = {"from", "to"}
FUND_FIELDS = {"amountMicros", "reference"}
SETTLEMENT_FIELDS = {"slaId", "evaluationSeq"}
DISPUTE_FIELDS = {"id", "settlementSeq", "claimantId"}
RESOLUTION_FIELDS = {"decision"}
EVIDENCE_FIELDS = {"evidenceId", "actorId", "observedAt", "digest"}
EVIDENCE_SNAPSHOT_FIELDS = {"actorId"}
ADJUDICATION_PROPOSAL_FIELDS = {"actorId", "snapshotSeq", "decision", "reasonDigest"}
ESCALATION_FIELDS = {"actorId"}
ARBITRATION_FIELDS = {"decision"}
EVIDENCE_PROOF_FIELDS = {"evidenceSeq", "actorId", "signature"}
KEY_ROTATION_FIELDS = {
    "expectedVersion",
    "publicKey",
    "currentSignature",
    "newSignature",
}
KEY_REVOCATION_FIELDS = {"signature"}
DISPUTE_DECISIONS = {"release", "refund"}
DISPUTABLE_RESULTS = {"charged", "compensated"}
AMOUNT_CAP_MICROS = 9_000_000_000_000_000
INT64_MAX = 9_223_372_036_854_775_807
CLEARING_ACCOUNT_ID = "external:clearing"
TELEMETRY_QUERY_PARAMS = {"from", "to", "limit", "cursor"}
EVALUATION_QUERY_PARAMS = {"limit", "cursor"}
SETTLEMENT_QUERY_PARAMS = {"limit", "cursor"}
LEDGER_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_EVENTS_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_EVIDENCE_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_EVIDENCE_SNAPSHOTS_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_ADJUDICATION_PROPOSALS_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_ESCALATIONS_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_ARBITRATIONS_QUERY_PARAMS = {"limit", "cursor"}
DISPUTES_QUERY_PARAMS = {"accountId", "state", "limit", "cursor"}
MACHINE_DELEGATIONS_QUERY_PARAMS = {"limit", "cursor"}
DELEGATION_EVENTS_QUERY_PARAMS = {"limit", "cursor"}
DELEGATION_CONSUMPTIONS_QUERY_PARAMS = {"limit", "cursor"}
AUDIT_CHECKPOINTS_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_SNAPSHOT_STATES = {"open", "released", "refunded", "escalated"}
ESCALATION_DELAY_MS = 86_400_000
TELEMETRY_TIME_MAX = 2147483648000
TELEMETRY_DEFAULT_LIMIT = 50
TELEMETRY_MAX_LIMIT = 100
DECIMAL_PATTERN = re.compile(r"0|[1-9][0-9]*")
CAPABILITY_PROTOCOLS = {"http", "mqtt"}
CAPABILITY_REGIONS = {"cn", "eu", "us"}
CAPABILITY_UNITS = {"call", "byte", "ms"}
# SLA-Auth 认证：machineId;keyVersion;requestTimeMs;nonce;signature，五段以分号连接。
SLA_AUTH_HEADER = "SLA-Auth"
SLA_AUTH_CONTEXT = "request-auth-v1"
SLA_AUTH_MACHINE_PATTERN = re.compile(r"[0-9a-f]{64}")
SLA_AUTH_NONCE_PATTERN = re.compile(r"[A-Za-z0-9-]{16,64}")
SLA_AUTH_SIGNATURE_PATTERN = re.compile(r"[0-9a-f]{128}")
SLA_AUTH_SKEW_MS = 300_000
SLA_AUTH_NONCE_RETENTION_MS = 600_000
# SLA-Delegation 一次性代理头：复用 SLA-Auth 五段格式，首段为委托标识、
# 版本段固定为 0、签名域为 delegation-auth-v1，由代理公钥验签。
SLA_DELEGATION_HEADER = "SLA-Delegation"
SLA_DELEGATION_CONTEXT = "delegation-auth-v1"
DELEGATION_PATH_PATTERN = re.compile(r"/v1/delegations/([^/]+)/revocation")
DELEGATION_EVENTS_PATH_PATTERN = re.compile(r"/v1/delegations/([^/]+)/events")
DELEGATION_FIELDS = {
    "id",
    "delegatePublicKey",
    "expiresAt",
    "operation",
    "capabilityVersion",
}
DELEGATION_DISPUTE_FIELDS = {
    "id",
    "delegatePublicKey",
    "expiresAt",
    "operation",
    "disputeId",
}
DELEGATION_PROOF_FIELDS = {
    "id",
    "delegatePublicKey",
    "expiresAt",
    "operation",
    "evidenceSeq",
}
DELEGATION_MAX_TTL_MS = 86_400_000
# 最小权限：能力写入、单笔争议证据提交或单条证据证明；路径资源分别为
# 能力路径、争议证据路径与证明入口。
DELEGATION_OPERATION_CAPABILITY_WRITE = "capability.write"
DELEGATION_OPERATION_EVIDENCE_WRITE = "evidence.write"
DELEGATION_OPERATION_PROOF_WRITE = "evidence.proof.write"
DELEGATION_OPERATIONS = {
    DELEGATION_OPERATION_CAPABILITY_WRITE,
    DELEGATION_OPERATION_EVIDENCE_WRITE,
    DELEGATION_OPERATION_PROOF_WRITE,
}


class SlaAuth(NamedTuple):
    machine_id: str
    key_version: int
    request_time_ms: int
    nonce: str
    signature: str
    signature_bytes: bytes


class AuthRejected(Exception):
    """认证结构已解析但校验失败：携带对应 HTTP 状态与错误码。"""

    def __init__(self, status: HTTPStatus, error: str) -> None:
        super().__init__(error)
        self.status = status
        self.error = error


class ApiServer(ThreadingHTTPServer):
    database_path: str
    # 启动时 --arbitrator 配置的终局仲裁机器集合；缺省为空（仲裁写入口不可达）。
    arbitrators: frozenset = frozenset()
    # 启动时 --auditor 配置的审计机器集合；缺省为空（审计写入口一律 403）。
    auditors: frozenset = frozenset()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate object member")
    return dict(pairs)


def _bounded_int(value: Any, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


class Handler(BaseHTTPRequestHandler):
    server: ApiServer

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        target = urlsplit(self.path)
        if target.path == "/health":
            with closing(connect(self.server.database_path)) as database:
                version = database.execute(
                    "SELECT value FROM schema_metadata WHERE key = 'schema_version'"
                ).fetchone()[0]
            self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "service": "service-sla-settlement-network",
                    "schemaVersion": version,
                    "time": datetime.now(UTC).isoformat(),
                },
            )
            return
        telemetry_match = SLA_TELEMETRY_PATH_PATTERN.fullmatch(target.path)
        if telemetry_match is not None:
            self._get_telemetry(telemetry_match.group(1), target.query)
            return
        machine_delegations_match = MACHINE_DELEGATIONS_PATH_PATTERN.fullmatch(
            target.path
        )
        if machine_delegations_match is not None:
            self._get_machine_delegations(
                machine_delegations_match.group(1), target.query
            )
            return
        delegation_consumptions_match = (
            MACHINE_DELEGATION_CONSUMPTIONS_PATH_PATTERN.fullmatch(target.path)
        )
        if delegation_consumptions_match is not None:
            self._get_delegation_consumptions(
                delegation_consumptions_match.group(1), target.query
            )
            return
        delegation_events_match = DELEGATION_EVENTS_PATH_PATTERN.fullmatch(target.path)
        if delegation_events_match is not None:
            self._get_delegation_events(
                delegation_events_match.group(1), target.query
            )
            return
        evaluations_match = SLA_EVALUATIONS_PATH_PATTERN.fullmatch(target.path)
        if evaluations_match is not None:
            self._get_evaluations(evaluations_match.group(1), target.query)
            return
        settlements_match = SLA_SETTLEMENTS_PATH_PATTERN.fullmatch(target.path)
        if settlements_match is not None:
            self._get_settlements(settlements_match.group(1), target.query)
            return
        ledger_match = ACCOUNT_LEDGER_PATH_PATTERN.fullmatch(target.path)
        if ledger_match is not None:
            self._get_ledger(ledger_match.group(1), target.query)
            return
        if target.path == "/v1/disputes":
            self._get_disputes(target.query)
            return
        dispute_events_match = DISPUTE_EVENTS_PATH_PATTERN.fullmatch(target.path)
        if dispute_events_match is not None:
            self._get_dispute_events(
                dispute_events_match.group(1), target.query
            )
            return
        dispute_evidence_match = DISPUTE_EVIDENCE_PATH_PATTERN.fullmatch(target.path)
        if dispute_evidence_match is not None:
            self._get_dispute_evidence(
                dispute_evidence_match.group(1), target.query
            )
            return
        evidence_proofs_match = EVIDENCE_PROOFS_PATH_PATTERN.fullmatch(target.path)
        if evidence_proofs_match is not None:
            self._get_evidence_proofs(
                evidence_proofs_match.group(1), target.query
            )
            return
        snapshot_item_match = (
            DISPUTE_EVIDENCE_SNAPSHOT_ITEM_PATH_PATTERN.fullmatch(target.path)
        )
        if snapshot_item_match is not None:
            self._get_evidence_snapshot(
                snapshot_item_match.group(1),
                snapshot_item_match.group(2),
                target.query,
            )
            return
        snapshot_collection_match = (
            DISPUTE_EVIDENCE_SNAPSHOTS_PATH_PATTERN.fullmatch(target.path)
        )
        if snapshot_collection_match is not None:
            self._get_evidence_snapshots(
                snapshot_collection_match.group(1), target.query
            )
            return
        proposals_match = DISPUTE_ADJUDICATION_PROPOSALS_PATH_PATTERN.fullmatch(
            target.path
        )
        if proposals_match is not None:
            self._get_adjudication_proposals(
                proposals_match.group(1), target.query
            )
            return
        escalations_match = DISPUTE_ESCALATIONS_PATH_PATTERN.fullmatch(target.path)
        if escalations_match is not None:
            self._get_escalations(escalations_match.group(1), target.query)
            return
        arbitrations_match = DISPUTE_ARBITRATIONS_PATH_PATTERN.fullmatch(target.path)
        if arbitrations_match is not None:
            self._get_arbitrations(arbitrations_match.group(1), target.query)
            return
        dispute_match = DISPUTE_PATH_PATTERN.fullmatch(target.path)
        if dispute_match is not None:
            self._get_dispute(dispute_match.group(1), target.query)
            return
        checkpoint_item_match = AUDIT_CHECKPOINT_ITEM_PATH_PATTERN.fullmatch(
            target.path
        )
        if checkpoint_item_match is not None:
            self._get_audit_checkpoint(
                checkpoint_item_match.group(1), target.query
            )
            return
        if target.path == "/v1/audit-checkpoints":
            self._get_audit_checkpoints(target.query)
            return
        sla_match = SLA_PATH_PATTERN.fullmatch(target.path)
        if sla_match is not None:
            self._get_sla(sla_match.group(1))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _get_sla(self, sla_id: str) -> None:
        with closing(connect(self.server.database_path)) as database:
            record = database.execute(
                "SELECT id, template_id, machine_id, consumer_id, capability_version,"
                " price_micros, max_latency_ms, start_unix, end_unix, state"
                " FROM slas WHERE id = ?",
                (sla_id,),
            ).fetchone()
        if record is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._json(
            HTTPStatus.OK,
            {
                "id": record["id"],
                "templateId": record["template_id"],
                "machineId": record["machine_id"],
                "consumerId": record["consumer_id"],
                "capabilityVersion": record["capability_version"],
                "priceMicros": record["price_micros"],
                "maxLatencyMs": record["max_latency_ms"],
                "start": record["start_unix"],
                "end": record["end_unix"],
                "state": record["state"],
            },
        )

    def _parse_telemetry_query(
        self, query: str
    ) -> tuple[int, int, int, tuple[int, int, str] | None] | None:
        parameters: dict[str, list[str]] = {}
        for key, value in parse_qsl(query, keep_blank_values=True):
            parameters.setdefault(key, []).append(value)
        if not set(parameters) <= TELEMETRY_QUERY_PARAMS:
            return None
        if any(len(values) != 1 for values in parameters.values()):
            return None

        def decimal(key: str) -> int | None:
            text = parameters[key][0]
            if DECIMAL_PATTERN.fullmatch(text) is None:
                return None
            return int(text)

        if "from" not in parameters or "to" not in parameters:
            return None
        start = decimal("from")
        end = decimal("to")
        if (
            start is None
            or end is None
            or not 0 <= start < end <= TELEMETRY_TIME_MAX
        ):
            return None
        if "limit" in parameters:
            limit = decimal("limit")
            if limit is None or not 1 <= limit <= TELEMETRY_MAX_LIMIT:
                return None
        else:
            limit = TELEMETRY_DEFAULT_LIMIT
        cursor: tuple[int, int, str] | None = None
        if "cursor" in parameters:
            parts = parameters["cursor"][0].split(":")
            if len(parts) != 3:
                return None
            cut_text, timestamp_text, event_id = parts
            if (
                DECIMAL_PATTERN.fullmatch(cut_text) is None
                or DECIMAL_PATTERN.fullmatch(timestamp_text) is None
                or TEMPLATE_ID_PATTERN.fullmatch(event_id) is None
            ):
                return None
            cursor = (int(cut_text), int(timestamp_text), event_id)
        return start, end, limit, cursor

    def _get_telemetry(self, sla_id: str, query: str) -> None:
        parsed = self._parse_telemetry_query(query)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        start, end, limit, cursor = parsed
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                record = database.execute(
                    "SELECT max_latency_ms FROM slas WHERE id = ?", (sla_id,)
                ).fetchone()
                if record is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                cut_record = database.execute(
                    "SELECT MAX(commit_seq) AS cut FROM sla_telemetry_events"
                ).fetchone()
                current_cut = cut_record["cut"]
                if current_cut is None:
                    current_cut = 0
                if cursor is None:
                    cut = current_cut
                else:
                    cut, cursor_timestamp, cursor_event_id = cursor
                    if cut > current_cut:
                        database.execute("ROLLBACK")
                        self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM sla_telemetry_events"
                        " WHERE sla_id = ? AND event_id = ? AND commit_seq <= ?"
                        " AND timestamp_ms = ? AND timestamp_ms >= ? AND timestamp_ms < ?",
                        (
                            sla_id,
                            cursor_event_id,
                            cut,
                            cursor_timestamp,
                            start,
                            end,
                        ),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
                        return
                summary = database.execute(
                    "SELECT COUNT(*) AS count, COALESCE(SUM(latency_ms), 0) AS latency_sum,"
                    " MAX(latency_ms) AS max_latency,"
                    " COALESCE(SUM(CASE WHEN latency_ms > ? THEN 1 ELSE 0 END), 0)"
                    " AS violations"
                    " FROM sla_telemetry_events"
                    " WHERE sla_id = ? AND commit_seq <= ?"
                    " AND timestamp_ms >= ? AND timestamp_ms < ?",
                    (
                        record["max_latency_ms"],
                        sla_id,
                        cut,
                        start,
                        end,
                    ),
                ).fetchone()
                if cursor is None:
                    rows = database.execute(
                        "SELECT event_id, timestamp_ms, latency_ms, digest"
                        " FROM sla_telemetry_events"
                        " WHERE sla_id = ? AND commit_seq <= ?"
                        " AND timestamp_ms >= ? AND timestamp_ms < ?"
                        " ORDER BY timestamp_ms ASC, event_id ASC"
                        " LIMIT ?",
                        (sla_id, cut, start, end, limit + 1),
                    ).fetchall()
                else:
                    _, cursor_timestamp, cursor_event_id = cursor
                    rows = database.execute(
                        "SELECT event_id, timestamp_ms, latency_ms, digest"
                        " FROM sla_telemetry_events"
                        " WHERE sla_id = ? AND commit_seq <= ?"
                        " AND timestamp_ms >= ? AND timestamp_ms < ?"
                        " AND (timestamp_ms > ?"
                        " OR (timestamp_ms = ? AND event_id > ?))"
                        " ORDER BY timestamp_ms ASC, event_id ASC"
                        " LIMIT ?",
                        (
                            sla_id,
                            cut,
                            start,
                            end,
                            cursor_timestamp,
                            cursor_timestamp,
                            cursor_event_id,
                            limit + 1,
                        ),
                    ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        events = [
            {
                "eventId": row["event_id"],
                "timestamp": row["timestamp_ms"],
                "latencyMs": row["latency_ms"],
                "digest": row["digest"],
            }
            for row in page
        ]
        if has_next:
            last = page[-1]
            next_cursor = f"{cut}:{last['timestamp_ms']}:{last['event_id']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {
                "events": events,
                "summary": {
                    "count": summary["count"],
                    "latencySum": summary["latency_sum"],
                    "maxLatency": summary["max_latency"],
                    "violations": summary["violations"],
                },
                "nextCursor": next_cursor,
            },
        )

    def _parse_evaluation_query(
        self, query: str, allowed_params: set[str] = EVALUATION_QUERY_PARAMS
    ) -> tuple[int, tuple[int, int] | None] | None:
        parameters: dict[str, list[str]] = {}
        for key, value in parse_qsl(query, keep_blank_values=True):
            parameters.setdefault(key, []).append(value)
        if not set(parameters) <= allowed_params:
            return None
        if any(len(values) != 1 for values in parameters.values()):
            return None

        def decimal(text: str) -> int | None:
            if DECIMAL_PATTERN.fullmatch(text) is None:
                return None
            return int(text)

        if "limit" in parameters:
            limit = decimal(parameters["limit"][0])
            if limit is None or not 1 <= limit <= TELEMETRY_MAX_LIMIT:
                return None
        else:
            limit = TELEMETRY_DEFAULT_LIMIT
        cursor: tuple[int, int] | None = None
        if "cursor" in parameters:
            parts = parameters["cursor"][0].split(":")
            if len(parts) != 2:
                return None
            cut = decimal(parts[0])
            last_seq = decimal(parts[1])
            if cut is None or last_seq is None:
                return None
            cursor = (cut, last_seq)
        return limit, cursor

    def _get_evaluations(self, sla_id: str, query: str) -> None:
        parsed = self._parse_evaluation_query(query)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                record = database.execute(
                    "SELECT 1 FROM slas WHERE id = ?", (sla_id,)
                ).fetchone()
                if record is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                max_record = database.execute(
                    "SELECT MAX(evaluation_seq) AS current_max"
                    " FROM sla_evaluation_idempotency_records"
                ).fetchone()
                current_max = max_record["current_max"]
                if current_max is None:
                    current_max = 0
                if cursor is None:
                    cut = current_max
                    last_seq = 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM sla_evaluation_idempotency_records"
                        " WHERE sla_id = ? AND evaluation_seq = ? AND evaluation_seq <= ?",
                        (sla_id, last_seq, cut),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                rows = database.execute(
                    "SELECT evaluation_seq, created_at_ms, response_json"
                    " FROM sla_evaluation_idempotency_records"
                    " WHERE sla_id = ? AND evaluation_seq <= ? AND evaluation_seq > ?"
                    " ORDER BY evaluation_seq ASC"
                    " LIMIT ?",
                    (sla_id, cut, last_seq, limit + 1),
                ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        evaluations: list[dict[str, Any]] = []
        for row in page:
            snapshot = json.loads(row["response_json"])
            evaluations.append(
                {
                    "evaluationSeq": row["evaluation_seq"],
                    "from": snapshot["from"],
                    "to": snapshot["to"],
                    "cut": snapshot["cut"],
                    "count": snapshot["count"],
                    "latencySum": snapshot["latencySum"],
                    "maxLatency": snapshot["maxLatency"],
                    "violations": snapshot["violations"],
                    "outcome": snapshot["outcome"],
                    "createdAt": row["created_at_ms"],
                }
            )
        if has_next:
            next_cursor = f"{cut}:{page[-1]['evaluation_seq']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {"evaluations": evaluations, "nextCursor": next_cursor},
        )

    def _get_settlements(self, sla_id: str, query: str) -> None:
        parsed = self._parse_evaluation_query(query, SETTLEMENT_QUERY_PARAMS)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                record = database.execute(
                    "SELECT 1 FROM slas WHERE id = ?", (sla_id,)
                ).fetchone()
                if record is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                max_record = database.execute(
                    "SELECT MAX(settlement_seq) AS current_max FROM settlements"
                ).fetchone()
                current_max = max_record["current_max"]
                if current_max is None:
                    current_max = 0
                if cursor is None:
                    cut = current_max
                    last_seq = 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM settlements"
                        " WHERE sla_id = ? AND settlement_seq = ? AND settlement_seq <= ?",
                        (sla_id, last_seq, cut),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                rows = database.execute(
                    "SELECT settlement_seq, evaluation_seq, result, amount_micros,"
                    " payer_id, payee_id, created_at_ms"
                    " FROM settlements"
                    " WHERE sla_id = ? AND settlement_seq <= ? AND settlement_seq > ?"
                    " ORDER BY settlement_seq ASC"
                    " LIMIT ?",
                    (sla_id, cut, last_seq, limit + 1),
                ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        settlements = [
            {
                "settlementSeq": row["settlement_seq"],
                "evaluationSeq": row["evaluation_seq"],
                "result": row["result"],
                "amount": row["amount_micros"],
                "payerId": row["payer_id"],
                "payeeId": row["payee_id"],
                "createdAt": row["created_at_ms"],
            }
            for row in page
        ]
        if has_next:
            next_cursor = f"{cut}:{page[-1]['settlement_seq']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {"settlements": settlements, "nextCursor": next_cursor},
        )

    def _get_ledger(self, account_id: str, query: str) -> None:
        parsed = self._parse_evaluation_query(query, LEDGER_QUERY_PARAMS)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                if account_id == CLEARING_ACCOUNT_ID:
                    account_valid = True
                else:
                    account_valid = (
                        database.execute(
                            "SELECT 1 FROM machines WHERE id = ?", (account_id,)
                        ).fetchone()
                        is not None
                    )
                if not account_valid:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                max_record = database.execute(
                    "SELECT MAX(entry_seq) AS current_max FROM ledger_entries"
                ).fetchone()
                current_max = max_record["current_max"]
                if current_max is None:
                    current_max = 0
                if cursor is None:
                    cut = current_max
                    last_seq = 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM ledger_entries"
                        " WHERE account_id = ? AND entry_seq = ? AND entry_seq <= ?",
                        (account_id, last_seq, cut),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                rows = database.execute(
                    "SELECT e.entry_seq AS entry_seq, e.kind AS kind,"
                    " e.reference_seq AS reference_seq, e.delta_micros AS delta_micros,"
                    " e.balance_after_micros AS balance_after_micros,"
                    " e.created_at_ms AS created_at_ms,"
                    " d.reference AS deposit_reference,"
                    " s.sla_id AS sla_id,"
                    " s.evaluation_seq AS settlement_evaluation_seq"
                    " FROM ledger_entries AS e"
                    " LEFT JOIN fund_deposits AS d"
                    " ON e.kind = 'deposit' AND e.reference_seq = d.deposit_seq"
                    " LEFT JOIN dispute_escalations AS x"
                    " ON e.kind = 'dispute_escalation'"
                    " AND e.reference_seq = x.escalation_seq"
                    " LEFT JOIN disputes AS ed ON ed.id = x.dispute_id"
                    " LEFT JOIN dispute_arbitrations AS a"
                    " ON e.kind = 'dispute_arbitration'"
                    " AND e.reference_seq = a.arbitration_seq"
                    " LEFT JOIN disputes AS ad ON ad.id = a.dispute_id"
                    " LEFT JOIN settlements AS s"
                    " ON (e.kind IN ('settlement', 'dispute_refund')"
                    " AND e.reference_seq = s.settlement_seq)"
                    " OR (e.kind = 'dispute_escalation'"
                    " AND s.settlement_seq = ed.settlement_seq)"
                    " OR (e.kind = 'dispute_arbitration'"
                    " AND s.settlement_seq = ad.settlement_seq)"
                    " WHERE e.account_id = ? AND e.entry_seq <= ? AND e.entry_seq > ?"
                    " ORDER BY e.entry_seq ASC"
                    " LIMIT ?",
                    (account_id, cut, last_seq, limit + 1),
                ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        entries: list[dict[str, Any]] = []
        for row in page:
            if row["kind"] == "deposit":
                entry = {
                    "entrySeq": row["entry_seq"],
                    "kind": "deposit",
                    "referenceSeq": row["reference_seq"],
                    "reference": row["deposit_reference"],
                    "slaId": None,
                    "evaluationSeq": None,
                    "delta": row["delta_micros"],
                    "balanceAfter": row["balance_after_micros"],
                    "createdAt": row["created_at_ms"],
                }
            else:
                entry = {
                    "entrySeq": row["entry_seq"],
                    "kind": row["kind"],
                    "referenceSeq": row["reference_seq"],
                    "reference": None,
                    "slaId": row["sla_id"],
                    "evaluationSeq": row["settlement_evaluation_seq"],
                    "delta": row["delta_micros"],
                    "balanceAfter": row["balance_after_micros"],
                    "createdAt": row["created_at_ms"],
                }
            entries.append(entry)
        if has_next:
            next_cursor = f"{cut}:{page[-1]['entry_seq']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {"entries": entries, "nextCursor": next_cursor},
        )

    def _get_dispute(self, dispute_id: str, query: str) -> None:
        # 读取端点不接受任何查询参数：参数校验先于争议查询。
        if parse_qsl(query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        with closing(connect(self.server.database_path)) as database:
            record = database.execute(
                "SELECT d.id AS id, d.state AS state, d.amount_micros AS amount_micros,"
                " d.claimant_id AS claimant_id, d.payer_id AS payer_id,"
                " d.payee_id AS payee_id, d.settlement_seq AS settlement_seq,"
                " s.sla_id AS sla_id, s.evaluation_seq AS evaluation_seq,"
                " s.result AS result"
                " FROM disputes AS d"
                " JOIN settlements AS s ON s.settlement_seq = d.settlement_seq"
                " WHERE d.id = ?",
                (dispute_id,),
            ).fetchone()
        if record is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self._json(
            HTTPStatus.OK,
            {
                "id": record["id"],
                "state": record["state"],
                "amount": record["amount_micros"],
                "claimantId": record["claimant_id"],
                "payerId": record["payer_id"],
                "payeeId": record["payee_id"],
                "settlementSeq": record["settlement_seq"],
                "slaId": record["sla_id"],
                "evaluationSeq": record["evaluation_seq"],
                "result": record["result"],
            },
        )

    def _get_dispute_events(self, dispute_id: str, query: str) -> None:
        parsed = self._parse_evaluation_query(query, DISPUTE_EVENTS_QUERY_PARAMS)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                record = database.execute(
                    "SELECT 1 FROM disputes WHERE id = ?", (dispute_id,)
                ).fetchone()
                if record is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                # cut 为读事务起点的全库最大争议事件序号（空库为 0），跨争议全局。
                max_record = database.execute(
                    "SELECT MAX(event_seq) AS current_max FROM dispute_events"
                ).fetchone()
                current_max = max_record["current_max"]
                if current_max is None:
                    current_max = 0
                if cursor is None:
                    cut = current_max
                    last_seq = 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM dispute_events"
                        " WHERE dispute_id = ? AND event_seq = ? AND event_seq <= ?",
                        (dispute_id, last_seq, cut),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                rows = database.execute(
                    "SELECT event_seq, type, created_at_ms FROM dispute_events"
                    " WHERE dispute_id = ? AND event_seq <= ? AND event_seq > ?"
                    " ORDER BY event_seq ASC"
                    " LIMIT ?",
                    (dispute_id, cut, last_seq, limit + 1),
                ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        events = [
            {
                "eventSeq": row["event_seq"],
                "type": row["type"],
                "createdAt": row["created_at_ms"],
            }
            for row in page
        ]
        if has_next:
            next_cursor = f"{cut}:{page[-1]['event_seq']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {"events": events, "nextCursor": next_cursor},
        )

    def _get_dispute_evidence(self, dispute_id: str, query: str) -> None:
        # 查询参数、错误次序、cut:lastSeq 游标与并发快照语义均沿用评估历史查询。
        parsed = self._parse_evaluation_query(
            query, DISPUTE_EVIDENCE_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                record = database.execute(
                    "SELECT 1 FROM disputes WHERE id = ?", (dispute_id,)
                ).fetchone()
                if record is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                # cut 为读事务起点的全库最大证据序号（空库为 0），跨争议全局。
                max_record = database.execute(
                    "SELECT MAX(evidence_seq) AS current_max FROM dispute_evidences"
                ).fetchone()
                current_max = max_record["current_max"]
                if current_max is None:
                    current_max = 0
                if cursor is None:
                    cut = current_max
                    last_seq = 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM dispute_evidences"
                        " WHERE dispute_id = ? AND evidence_seq = ?"
                        " AND evidence_seq <= ?",
                        (dispute_id, last_seq, cut),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                rows = database.execute(
                    "SELECT evidence_seq, evidence_id, actor_id, observed_at_ms, digest"
                    " FROM dispute_evidences"
                    " WHERE dispute_id = ? AND evidence_seq <= ? AND evidence_seq > ?"
                    " ORDER BY evidence_seq ASC"
                    " LIMIT ?",
                    (dispute_id, cut, last_seq, limit + 1),
                ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        evidence = [
            {
                "evidenceSeq": row["evidence_seq"],
                "evidenceId": row["evidence_id"],
                "actorId": row["actor_id"],
                "observedAt": row["observed_at_ms"],
                "digest": row["digest"],
            }
            for row in page
        ]
        if has_next:
            next_cursor = f"{cut}:{page[-1]['evidence_seq']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {"evidence": evidence, "nextCursor": next_cursor},
        )

    def _parse_disputes_query(
        self, query: str
    ) -> tuple[str, str | None, int, tuple[int, int] | None] | None:
        parameters: dict[str, list[str]] = {}
        for key, value in parse_qsl(query, keep_blank_values=True):
            parameters.setdefault(key, []).append(value)
        if not set(parameters) <= DISPUTES_QUERY_PARAMS:
            return None
        if any(len(values) != 1 for values in parameters.values()):
            return None
        if "accountId" not in parameters:
            return None
        account_id = parameters["accountId"][0]
        if PUBLIC_KEY_PATTERN.fullmatch(account_id) is None:
            return None
        state: str | None = None
        if "state" in parameters:
            state = parameters["state"][0]
            if state not in DISPUTE_SNAPSHOT_STATES:
                return None

        def decimal(text: str) -> int | None:
            if DECIMAL_PATTERN.fullmatch(text) is None:
                return None
            return int(text)

        if "limit" in parameters:
            limit = decimal(parameters["limit"][0])
            if limit is None or not 1 <= limit <= TELEMETRY_MAX_LIMIT:
                return None
        else:
            limit = TELEMETRY_DEFAULT_LIMIT
        cursor: tuple[int, int] | None = None
        if "cursor" in parameters:
            parts = parameters["cursor"][0].split(":")
            if len(parts) != 2:
                return None
            cut = decimal(parts[0])
            last_seq = decimal(parts[1])
            if cut is None or last_seq is None:
                return None
            cursor = (cut, last_seq)
        return account_id, state, limit, cursor

    @staticmethod
    def _dispute_snapshot_query(
        select: str,
        cut: int,
        account_id: str,
        state: str | None,
        opened_condition: str,
        opened_seq: int,
    ) -> tuple[str, list[Any]]:
        # 快照状态由 cut 以内最后一项生命周期事件推导；opened 事件唯一且先于结果事件。
        sql = (
            select
            + " FROM disputes AS d"
            + " JOIN settlements AS s ON s.settlement_seq = d.settlement_seq"
            + " JOIN dispute_events AS o ON o.dispute_id = d.id AND o.type = 'opened'"
            + " JOIN dispute_events AS l ON l.dispute_id = d.id AND l.event_seq ="
            + " (SELECT MAX(event_seq) FROM dispute_events"
            + " WHERE dispute_id = d.id AND event_seq <= ?)"
            + " WHERE (d.payer_id = ? OR d.payee_id = ?) AND o.event_seq <= ?"
        )
        arguments: list[Any] = [cut, account_id, account_id, cut]
        if state is not None:
            sql += " AND l.type = ?"
            arguments.append("opened" if state == "open" else state)
        sql += f" AND o.event_seq {opened_condition} ?"
        arguments.append(opened_seq)
        return sql, arguments

    def _get_disputes(self, query: str) -> None:
        parsed = self._parse_disputes_query(query)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        account_id, state, limit, cursor = parsed
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                account = database.execute(
                    "SELECT 1 FROM machines WHERE id = ?", (account_id,)
                ).fetchone()
                if account is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                # cut 为读事务起点的全库最大争议事件序号（空库为 0），跨争议全局。
                max_record = database.execute(
                    "SELECT MAX(event_seq) AS current_max FROM dispute_events"
                ).fetchone()
                current_max = max_record["current_max"]
                if current_max is None:
                    current_max = 0
                if cursor is None:
                    cut = current_max
                    last_seq = 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor_sql, anchor_arguments = self._dispute_snapshot_query(
                        "SELECT 1", cut, account_id, state, "=", last_seq
                    )
                    anchor = database.execute(anchor_sql, anchor_arguments).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                select = (
                    "SELECT d.id AS id, d.amount_micros AS amount_micros,"
                    " d.claimant_id AS claimant_id, d.payer_id AS payer_id,"
                    " d.payee_id AS payee_id, d.settlement_seq AS settlement_seq,"
                    " s.sla_id AS sla_id, s.evaluation_seq AS evaluation_seq,"
                    " s.result AS result,"
                    " o.event_seq AS opened_seq, o.created_at_ms AS opened_at,"
                    " l.event_seq AS resolved_seq, l.type AS snapshot_state,"
                    " l.created_at_ms AS resolved_at"
                )
                page_sql, page_arguments = self._dispute_snapshot_query(
                    select, cut, account_id, state, ">", last_seq
                )
                page_sql += " ORDER BY o.event_seq ASC LIMIT ?"
                rows = database.execute(
                    page_sql, (*page_arguments, limit + 1)
                ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        disputes: list[dict[str, Any]] = []
        for row in page:
            snapshot_state = (
                "open" if row["snapshot_state"] == "opened" else row["snapshot_state"]
            )
            resolved = snapshot_state != "open"
            disputes.append(
                {
                    "id": row["id"],
                    "state": snapshot_state,
                    "amount": row["amount_micros"],
                    "claimantId": row["claimant_id"],
                    "payerId": row["payer_id"],
                    "payeeId": row["payee_id"],
                    "settlementSeq": row["settlement_seq"],
                    "slaId": row["sla_id"],
                    "evaluationSeq": row["evaluation_seq"],
                    "result": row["result"],
                    "openedEventSeq": row["opened_seq"],
                    "openedAt": row["opened_at"],
                    "resolvedEventSeq": row["resolved_seq"] if resolved else None,
                    "resolvedAt": row["resolved_at"] if resolved else None,
                }
            )
        if has_next:
            next_cursor = f"{cut}:{page[-1]['opened_seq']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {"disputes": disputes, "nextCursor": next_cursor},
        )

    def _authenticated_audit_transaction(
        self,
        path: str,
        auth: SlaAuth,
        resolve_resource: Any,
        build_snapshot: Any,
    ) -> tuple[HTTPStatus, str | None, dict[str, Any] | None]:
        # 两个审计入口共用判定：资源、签发身份、认证有效性、随机数、游标关联。
        # GET 无正文：正文摘要按空字节的 SHA-256 计算。只有全部判定通过、读取
        # 完成后才在同一写事务内消费随机数并提交；任何失败均回滚、不消费随机数。
        body_digest = hashlib.sha256(b"").hexdigest()
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                # 资源回调同时给出签发机器：资源不存在为 404，认证机器不属签发者为 403。
                resource, expected_machine = resolve_resource(database)
                if resource is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, "not_found", None
                try:
                    self._verify_request_auth(
                        database, auth, expected_machine, path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, rejected.error, None
                result = build_snapshot(database, resource)
                if result is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.BAD_REQUEST, "invalid_request", None
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        return HTTPStatus.OK, None, result

    def _get_machine_delegations(self, machine_id: str, query: str) -> None:
        # 查询参数、limit、cursor=cut:lastSeq 的格式与范围沿用评估历史查询。
        parsed = self._parse_evaluation_query(
            query, MACHINE_DELEGATIONS_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        # 认证结构先于资源检查；GET 无正文。
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        standard_path = urlsplit(self.path).path

        def resolve_resource(database: Any) -> tuple[Any, str]:
            # 路径机器不存在为 404；存在即返回行，签发身份随后判定为 403。
            return (
                database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone(),
                machine_id,
            )

        def build_snapshot(database: Any, resource: Any) -> dict[str, Any] | None:
            # 两类首页均以读事务起点的全库最大委托事件序号冻结快照。
            max_record = database.execute(
                "SELECT MAX(event_seq) AS current_max FROM delegation_events"
            ).fetchone()
            current_max = max_record["current_max"] or 0
            if cursor is None:
                cut = current_max
                last_seq = 0
            else:
                cut, last_seq = cursor
                if cut > current_max:
                    return None
                # 锚点须是目标机器签发事件、且在当前快照内；
                # 不属于目标机器或快照（含非 issued 事件）均为非法游标。
                anchor = database.execute(
                    "SELECT 1 FROM delegation_events AS e"
                    " JOIN machine_delegations AS d ON d.id = e.delegation_id"
                    " WHERE e.type = 'issued' AND d.issuer_machine_id = ?"
                    " AND e.event_seq = ? AND e.event_seq <= ?",
                    (machine_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            # 委托按签发事件序号升序分页；消费/撤销标记只计 cut 以内的对应事件。
            rows = database.execute(
                "SELECT d.id AS id, d.delegate_public_key AS delegate_public_key,"
                " d.expires_at_ms AS expires_at_ms,"
                " d.issued_key_version AS issued_key_version,"
                " d.operation AS operation,"
                " d.capability_version AS capability_version,"
                " d.dispute_id AS dispute_id,"
                " d.evidence_seq AS evidence_seq,"
                " e.event_seq AS issued_seq,"
                " EXISTS (SELECT 1 FROM delegation_events AS c"
                " WHERE c.delegation_id = d.id AND c.type = 'consumed'"
                " AND c.event_seq <= ?) AS consumed_in_cut,"
                " EXISTS (SELECT 1 FROM delegation_events AS r"
                " WHERE r.delegation_id = d.id AND r.type = 'revoked'"
                " AND r.event_seq <= ?) AS revoked_in_cut"
                " FROM machine_delegations AS d"
                " JOIN delegation_events AS e"
                " ON e.delegation_id = d.id AND e.type = 'issued'"
                " WHERE d.issuer_machine_id = ? AND e.event_seq <= ?"
                " AND e.event_seq > ?"
                " ORDER BY e.event_seq ASC"
                " LIMIT ?",
                (cut, cut, machine_id, cut, last_seq, limit + 1),
            ).fetchall()
            has_next = len(rows) > limit
            page = rows[:limit]
            delegations = [
                {
                    "id": row["id"],
                    "delegatePublicKey": row["delegate_public_key"],
                    "expiresAt": row["expires_at_ms"],
                    "issuedKeyVersion": row["issued_key_version"],
                    "consumed": bool(row["consumed_in_cut"]),
                    "revoked": bool(row["revoked_in_cut"]),
                    # 最小权限范围追加在项尾；升级前凭证四项均为 null。
                    "operation": row["operation"],
                    "capabilityVersion": row["capability_version"],
                    "disputeId": row["dispute_id"],
                    "evidenceSeq": row["evidence_seq"],
                }
                for row in page
            ]
            next_cursor = (
                f"{cut}:{page[-1]['issued_seq']}" if has_next else None
            )
            return {"delegations": delegations, "nextCursor": next_cursor}

        status, error, payload = self._authenticated_audit_transaction(
            standard_path, auth, resolve_resource, build_snapshot
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def _get_delegation_events(self, delegation_id: str, query: str) -> None:
        # 查询参数、limit、cursor=cut:lastSeq 的格式与范围沿用评估历史查询。
        parsed = self._parse_evaluation_query(query, DELEGATION_EVENTS_QUERY_PARAMS)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        # 认证结构先于资源检查；GET 无正文。
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        standard_path = urlsplit(self.path).path

        def resolve_resource(database: Any) -> tuple[Any, str]:
            # 委托不存在为 404；存在时以签发机器作为期望签名者，不符即为 403。
            delegation = database.execute(
                "SELECT issuer_machine_id FROM machine_delegations WHERE id = ?",
                (delegation_id,),
            ).fetchone()
            if delegation is None:
                return None, auth.machine_id
            return delegation, delegation["issuer_machine_id"]

        def build_snapshot(database: Any, resource: Any) -> dict[str, Any] | None:
            # 首页以读事务起点的全库最大委托事件序号冻结快照。
            max_record = database.execute(
                "SELECT MAX(event_seq) AS current_max FROM delegation_events"
            ).fetchone()
            current_max = max_record["current_max"] or 0
            if cursor is None:
                cut = current_max
                last_seq = 0
            else:
                cut, last_seq = cursor
                if cut > current_max:
                    return None
                # 锚点须属于目标凭证且在当前快照内；属于其他凭证或不存在均非法。
                anchor = database.execute(
                    "SELECT 1 FROM delegation_events"
                    " WHERE delegation_id = ? AND event_seq = ? AND event_seq <= ?",
                    (delegation_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            rows = database.execute(
                "SELECT event_seq, type, created_at_ms FROM delegation_events"
                " WHERE delegation_id = ? AND event_seq <= ? AND event_seq > ?"
                " ORDER BY event_seq ASC"
                " LIMIT ?",
                (delegation_id, cut, last_seq, limit + 1),
            ).fetchall()
            has_next = len(rows) > limit
            page = rows[:limit]
            events = [
                {
                    "eventSeq": row["event_seq"],
                    "type": row["type"],
                    "createdAt": row["created_at_ms"],
                }
                for row in page
            ]
            next_cursor = f"{cut}:{page[-1]['event_seq']}" if has_next else None
            return {"events": events, "nextCursor": next_cursor}

        status, error, payload = self._authenticated_audit_transaction(
            standard_path, auth, resolve_resource, build_snapshot
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def _get_delegation_consumptions(self, machine_id: str, query: str) -> None:
        # 分页参数、认证次序与成功后消费随机数的语义沿用委托集合查询。
        parsed = self._parse_evaluation_query(
            query, DELEGATION_CONSUMPTIONS_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        # 认证结构先于资源检查；GET 无正文。
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        standard_path = urlsplit(self.path).path

        def resolve_resource(database: Any) -> tuple[Any, str]:
            # 路径机器不存在为 404；存在即返回行，签发身份随后判定为 403。
            return (
                database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone(),
                machine_id,
            )

        def build_snapshot(database: Any, resource: Any) -> dict[str, Any] | None:
            # 首页以读事务起点的全库最大委托事件序号冻结快照。
            max_record = database.execute(
                "SELECT MAX(event_seq) AS current_max FROM delegation_events"
            ).fetchone()
            current_max = max_record["current_max"] or 0
            if cursor is None:
                cut = current_max
                last_seq = 0
            else:
                cut, last_seq = cursor
                if cut > current_max:
                    return None
                # 锚点须是目标机器凭证的 consumed 事件且在当前快照内；
                # 属于其他机器、非 consumed 事件或不存在均为非法游标。
                anchor = database.execute(
                    "SELECT 1 FROM delegation_events AS e"
                    " JOIN machine_delegations AS d ON d.id = e.delegation_id"
                    " WHERE e.type = 'consumed' AND d.issuer_machine_id = ?"
                    " AND e.event_seq = ? AND e.event_seq <= ?",
                    (machine_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            # 只按序号返回该机器凭证在 cut 以内的 consumed 事件；
            # 旧 consumed 事件保留原序号，范围与审计列均为 NULL。
            rows = database.execute(
                "SELECT e.event_seq AS event_seq,"
                " e.delegation_id AS delegation_id,"
                " d.operation AS operation,"
                " d.capability_version AS capability_version,"
                " e.resource AS resource,"
                " e.request_digest AS request_digest,"
                " e.created_at_ms AS created_at_ms,"
                " d.evidence_seq AS evidence_seq"
                " FROM delegation_events AS e"
                " JOIN machine_delegations AS d ON d.id = e.delegation_id"
                " WHERE e.type = 'consumed' AND d.issuer_machine_id = ?"
                " AND e.event_seq <= ? AND e.event_seq > ?"
                " ORDER BY e.event_seq ASC"
                " LIMIT ?",
                (machine_id, cut, last_seq, limit + 1),
            ).fetchall()
            has_next = len(rows) > limit
            page = rows[:limit]
            consumptions = [
                {
                    "eventSeq": row["event_seq"],
                    "delegationId": row["delegation_id"],
                    "operation": row["operation"],
                    "capabilityVersion": row["capability_version"],
                    "resource": row["resource"],
                    "requestDigest": row["request_digest"],
                    "createdAt": row["created_at_ms"],
                    # 证明授权的证据序号追加在项尾；旧消费事件为 null。
                    "evidenceSeq": row["evidence_seq"],
                }
                for row in page
            ]
            next_cursor = (
                f"{cut}:{page[-1]['event_seq']}" if has_next else None
            )
            return {"consumptions": consumptions, "nextCursor": next_cursor}

        status, error, payload = self._authenticated_audit_transaction(
            standard_path, auth, resolve_resource, build_snapshot
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/machines":
            self._register()
            return
        capabilities_match = CAPABILITIES_PATH_PATTERN.fullmatch(self.path)
        if capabilities_match is not None:
            self._declare_capability(capabilities_match.group(1))
            return
        revocation_match = MACHINE_KEY_REVOCATION_PATH_PATTERN.fullmatch(
            urlsplit(self.path).path
        )
        if revocation_match is not None:
            self._revoke_key(
                revocation_match.group(1), revocation_match.group(2)
            )
            return
        keys_match = MACHINE_KEYS_PATH_PATTERN.fullmatch(urlsplit(self.path).path)
        if keys_match is not None:
            self._rotate_key(keys_match.group(1))
            return
        if self.path == "/v1/sla-templates":
            self._create_sla_template()
            return
        if self.path == "/v1/slas":
            self._create_sla()
            return
        confirmations_match = SLA_CONFIRMATIONS_PATH_PATTERN.fullmatch(self.path)
        if confirmations_match is not None:
            self._confirm_sla(confirmations_match.group(1))
            return
        telemetry_match = SLA_TELEMETRY_PATH_PATTERN.fullmatch(self.path)
        if telemetry_match is not None:
            self._post_telemetry(telemetry_match.group(1))
            return
        evaluations_match = SLA_EVALUATIONS_PATH_PATTERN.fullmatch(self.path)
        if evaluations_match is not None:
            self._evaluate_sla(evaluations_match.group(1))
            return
        funds_match = FUNDS_PATH_PATTERN.fullmatch(self.path)
        if funds_match is not None:
            self._deposit_funds(funds_match.group(1))
            return
        if self.path == "/v1/settlements":
            self._create_settlement()
            return
        if self.path == "/v1/disputes":
            self._create_dispute()
            return
        evidence_match = DISPUTE_EVIDENCE_PATH_PATTERN.fullmatch(
            urlsplit(self.path).path
        )
        if evidence_match is not None:
            self._submit_evidence(evidence_match.group(1))
            return
        snapshot_match = DISPUTE_EVIDENCE_SNAPSHOTS_PATH_PATTERN.fullmatch(
            urlsplit(self.path).path
        )
        if snapshot_match is not None:
            self._create_evidence_snapshot(snapshot_match.group(1))
            return
        proposals_match = DISPUTE_ADJUDICATION_PROPOSALS_PATH_PATTERN.fullmatch(
            urlsplit(self.path).path
        )
        if proposals_match is not None:
            self._create_adjudication_proposal(proposals_match.group(1))
            return
        escalations_match = DISPUTE_ESCALATIONS_PATH_PATTERN.fullmatch(
            urlsplit(self.path).path
        )
        if escalations_match is not None:
            self._create_escalation(escalations_match.group(1))
            return
        arbitrations_match = DISPUTE_ARBITRATIONS_PATH_PATTERN.fullmatch(
            urlsplit(self.path).path
        )
        if arbitrations_match is not None:
            self._create_arbitration(arbitrations_match.group(1))
            return
        resolution_match = DISPUTE_RESOLUTION_PATH_PATTERN.fullmatch(self.path)
        if resolution_match is not None:
            self._resolve_dispute(resolution_match.group(1))
            return
        if urlsplit(self.path).path == "/v1/evidence-proofs":
            self._create_evidence_proof()
            return
        if urlsplit(self.path).path == "/v1/delegations":
            self._create_delegation()
            return
        if urlsplit(self.path).path == "/v1/audit-checkpoints":
            self._create_audit_checkpoint()
            return
        delegation_revocation_match = DELEGATION_PATH_PATTERN.fullmatch(
            urlsplit(self.path).path
        )
        if delegation_revocation_match is not None:
            self._revoke_delegation(delegation_revocation_match.group(1))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def _register(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_idempotency_key"})
            return
        request_object = self._read_request_object()
        if request_object is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        public_key = request_object["publicKey"]
        machine_id = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
        status, payload = self._register_machine(idempotency_key, public_key, machine_id)
        self._json(status, payload)

    def _read_raw_body(self) -> bytes | None:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            return None
        try:
            length = int(length_header)
        except ValueError:
            return None
        if length <= 0:
            return None
        return self.rfile.read(length)

    def _read_json_object(self, body: bytes | None = None) -> dict[str, Any] | None:
        if body is None:
            body = self._read_raw_body()
            if body is None:
                return None
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return None
        try:
            parsed = json.loads(text, object_pairs_hook=_unique_object)
        except ValueError:
            return None
        if not isinstance(parsed, dict):
            return None
        return parsed

    def _parse_sla_auth(self) -> SlaAuth | None:
        # 认证头必须存在、单值且五段结构合法；任何结构问题在资源与业务检查之前拒绝。
        values = self.headers.get_all(SLA_AUTH_HEADER)
        if values is None or len(values) != 1:
            return None
        parts = values[0].split(";")
        if len(parts) != 5:
            return None
        machine_id_text, version_text, request_time_text, nonce, signature = parts
        if SLA_AUTH_MACHINE_PATTERN.fullmatch(machine_id_text) is None:
            return None
        if DECIMAL_PATTERN.fullmatch(version_text) is None:
            return None
        key_version = int(version_text)
        if key_version < 1:
            return None
        if DECIMAL_PATTERN.fullmatch(request_time_text) is None:
            return None
        request_time_ms = int(request_time_text)
        if SLA_AUTH_NONCE_PATTERN.fullmatch(nonce) is None:
            return None
        if SLA_AUTH_SIGNATURE_PATTERN.fullmatch(signature) is None:
            return None
        return SlaAuth(
            machine_id_text,
            key_version,
            request_time_ms,
            nonce,
            signature,
            bytes.fromhex(signature),
        )

    def _request_auth_signing_bytes(
        self, auth: SlaAuth, path: str, body_digest: str
    ) -> bytes:
        # request-auth-v1\nMETHOD\nPATH\nBODY_SHA256\nTIME\nNONCE\nVERSION\nMACHINE
        return (
            f"{SLA_AUTH_CONTEXT}\n{self.command}\n{path}\n{body_digest}\n"
            f"{auth.request_time_ms}\n{auth.nonce}\n{auth.key_version}\n"
            f"{auth.machine_id}"
        ).encode("utf-8")

    def _verify_request_principal(
        self,
        database: Any,
        auth: SlaAuth,
        path: str,
        body_digest: str,
    ) -> None:
        # 时间窗口、密钥与严格 Ed25519 验签；签名者身份由各入口自行判定。
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        if abs(auth.request_time_ms - now_ms) > SLA_AUTH_SKEW_MS:
            raise AuthRejected(HTTPStatus.UNAUTHORIZED, "stale_request")
        latest = database.execute(
            "SELECT MAX(version) AS latest FROM machine_keys"
            " WHERE machine_id = ?",
            (auth.machine_id,),
        ).fetchone()
        key = database.execute(
            "SELECT public_key, revoked FROM machine_keys"
            " WHERE machine_id = ? AND version = ?",
            (auth.machine_id, auth.key_version),
        ).fetchone()
        signature_valid = False
        if (
            latest["latest"] is not None
            and latest["latest"] == auth.key_version
            and key is not None
            and not key["revoked"]
        ):
            message = self._request_auth_signing_bytes(auth, path, body_digest)
            signature_valid = ed25519_verify(
                bytes.fromhex(key["public_key"]),
                message,
                auth.signature_bytes,
            )
        if not signature_valid:
            raise AuthRejected(HTTPStatus.UNAUTHORIZED, "invalid_authentication")

    def _verify_request_auth(
        self,
        database: Any,
        auth: SlaAuth,
        expected_machine: str,
        path: str,
        body_digest: str,
    ) -> None:
        # 次序：签名者（机器标识一致）、时间窗口、密钥与严格 Ed25519 验签。
        if auth.machine_id != expected_machine:
            raise AuthRejected(HTTPStatus.FORBIDDEN, "forbidden")
        self._verify_request_principal(database, auth, path, body_digest)

    def _parse_sla_delegation(self) -> SlaAuth | None:
        # 代理头必须存在、单值且五段结构合法；首段为委托标识，版本段固定为 0。
        values = self.headers.get_all(SLA_DELEGATION_HEADER)
        if values is None or len(values) != 1:
            return None
        parts = values[0].split(";")
        if len(parts) != 5:
            return None
        delegation_id, version_text, request_time_text, nonce, signature = parts
        if TEMPLATE_ID_PATTERN.fullmatch(delegation_id) is None:
            return None
        if version_text != "0":
            return None
        if DECIMAL_PATTERN.fullmatch(request_time_text) is None:
            return None
        request_time_ms = int(request_time_text)
        if SLA_AUTH_NONCE_PATTERN.fullmatch(nonce) is None:
            return None
        if SLA_AUTH_SIGNATURE_PATTERN.fullmatch(signature) is None:
            return None
        return SlaAuth(
            delegation_id,
            0,
            request_time_ms,
            nonce,
            signature,
            bytes.fromhex(signature),
        )

    def _verify_delegation_auth(
        self,
        database: Any,
        auth: SlaAuth,
        expected_machine: str,
        path: str,
        body_digest: str,
        requested_operation: str,
        requested_scope: Any,
    ) -> None:
        # 次序：委托存在、范围（路径机器、操作、能力版本或争议标识），时间窗口，
        # 再判过期/已用/已撤销/签发版本失效与代理公钥严格验签。
        delegation = database.execute(
            "SELECT issuer_machine_id, delegate_public_key, expires_at_ms,"
            " issued_key_version, revoked, consumed, operation, capability_version,"
            " dispute_id, evidence_seq"
            " FROM machine_delegations WHERE id = ?",
            (auth.machine_id,),
        ).fetchone()
        if delegation is None:
            raise AuthRejected(HTTPStatus.UNAUTHORIZED, "invalid_authentication")
        if delegation["issuer_machine_id"] != expected_machine:
            raise AuthRejected(HTTPStatus.FORBIDDEN, "forbidden")
        # 最小权限范围：操作须与凭证一致；能力授权比对 capabilityVersion，
        # 单笔争议授权比对 disputeId，证明授权比对 evidenceSeq。任一不符为 403，
        # 且不消费凭证、随机数或事件序号。
        # 升级前凭证范围列为 NULL：仅保留原能力声明语义，不获得证据或证明权限。
        if requested_operation == DELEGATION_OPERATION_EVIDENCE_WRITE:
            if (
                delegation["operation"] != DELEGATION_OPERATION_EVIDENCE_WRITE
                or delegation["dispute_id"] != requested_scope
            ):
                raise AuthRejected(HTTPStatus.FORBIDDEN, "forbidden")
        elif requested_operation == DELEGATION_OPERATION_PROOF_WRITE:
            if (
                delegation["operation"] != DELEGATION_OPERATION_PROOF_WRITE
                or delegation["evidence_seq"] != requested_scope
            ):
                raise AuthRejected(HTTPStatus.FORBIDDEN, "forbidden")
        elif delegation["operation"] is not None:
            if delegation["operation"] != requested_operation:
                raise AuthRejected(HTTPStatus.FORBIDDEN, "forbidden")
            if delegation["capability_version"] != requested_scope:
                raise AuthRejected(HTTPStatus.FORBIDDEN, "forbidden")
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        if abs(auth.request_time_ms - now_ms) > SLA_AUTH_SKEW_MS:
            raise AuthRejected(HTTPStatus.UNAUTHORIZED, "stale_request")
        signature_valid = False
        if (
            not delegation["revoked"]
            and not delegation["consumed"]
            and now_ms < delegation["expires_at_ms"]
        ):
            # 签发时记录的密钥版本须仍为签发机器当前最新且未吊销的版本。
            issued_key = database.execute(
                "SELECT revoked FROM machine_keys"
                " WHERE machine_id = ? AND version = ?",
                (delegation["issuer_machine_id"], delegation["issued_key_version"]),
            ).fetchone()
            latest = database.execute(
                "SELECT MAX(version) AS latest FROM machine_keys"
                " WHERE machine_id = ?",
                (delegation["issuer_machine_id"],),
            ).fetchone()
            if (
                issued_key is not None
                and not issued_key["revoked"]
                and latest is not None
                and latest["latest"] == delegation["issued_key_version"]
            ):
                message = (
                    f"{SLA_DELEGATION_CONTEXT}\n{self.command}\n{path}\n{body_digest}\n"
                    f"{auth.request_time_ms}\n{auth.nonce}\n{auth.key_version}\n"
                    f"{auth.machine_id}"
                ).encode("utf-8")
                signature_valid = ed25519_verify(
                    bytes.fromhex(delegation["delegate_public_key"]),
                    message,
                    auth.signature_bytes,
                )
        if not signature_valid:
            raise AuthRejected(HTTPStatus.UNAUTHORIZED, "invalid_authentication")

    @staticmethod
    def _auth_record_matches(record: Any, auth: SlaAuth) -> bool:
        return (
            record["auth_machine_id"] == auth.machine_id
            and record["auth_key_version"] == auth.key_version
            and record["auth_request_time_ms"] == auth.request_time_ms
            and record["auth_nonce"] == auth.nonce
            and record["auth_signature"] == auth.signature
        )

    def _check_request_nonce(self, database: Any, auth: SlaAuth) -> None:
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        # 随机数至少保留到请求时间后十分钟；过期条目此后可清理，
        # 过期请求仍由时间窗口（±300000ms）先行拒绝。
        database.execute(
            "DELETE FROM auth_nonce_records"
            " WHERE request_time_ms < ?",
            (now_ms - SLA_AUTH_NONCE_RETENTION_MS,),
        )
        reused = database.execute(
            "SELECT 1 FROM auth_nonce_records"
            " WHERE machine_id = ? AND nonce = ?",
            (auth.machine_id, auth.nonce),
        ).fetchone()
        if reused is not None:
            raise AuthRejected(HTTPStatus.CONFLICT, "replay_detected")

    def _try_legacy_replay(
        self,
        table: str,
        key: str,
        request_json: str,
        extra_clause: str,
        extra_arguments: list[Any],
    ) -> tuple[HTTPStatus, dict[str, Any]] | None:
        # 升级前已有幂等记录是唯一例外：认证缺失/非法时仍可按原请求先行重放。
        # 这些记录认证五段列均为 NULL，重放不补认证数据、不消费随机数。
        with closing(connect(self.server.database_path)) as database:
            record = database.execute(
                f"SELECT status, response_json FROM {table}"
                f" WHERE key = ? AND auth_machine_id IS NULL"
                f" AND request_json = ?{extra_clause}",
                (key, request_json, *extra_arguments),
            ).fetchone()
        if record is None:
            return None
        return HTTPStatus(record["status"]), json.loads(record["response_json"])

    @staticmethod
    def _consume_request_nonce(database: Any, auth: SlaAuth) -> None:
        # 与业务变更、幂等结果在同一事务原子写入；失败路径不到达此处。
        database.execute(
            "INSERT INTO auth_nonce_records(machine_id, nonce, request_time_ms)"
            " VALUES (?, ?, ?)",
            (auth.machine_id, auth.nonce, auth.request_time_ms),
        )

    @staticmethod
    def _append_delegation_event(
        database: Any,
        delegation_id: str,
        event_type: str,
        created_at_ms: int,
        resource: str | None = None,
        request_digest: str | None = None,
    ) -> None:
        # 全库唯一递增事件序号：写事务均以 BEGIN IMMEDIATE 串行，取 MAX+1 安全。
        # 仅首次业务成功到达此处；失败、同键重放与并发败者均不写事件、不推进序号。
        # consumed 事件同事务保存标准资源路径与原始正文 SHA-256 摘要；
        # issued/revoked 与迁移补出的旧事件该两项为 NULL。
        max_record = database.execute(
            "SELECT MAX(event_seq) AS current_max FROM delegation_events"
        ).fetchone()
        event_seq = (max_record["current_max"] or 0) + 1
        database.execute(
            "INSERT INTO delegation_events"
            "(event_seq, delegation_id, type, created_at_ms, resource, request_digest)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (event_seq, delegation_id, event_type, created_at_ms, resource, request_digest),
        )

    def _read_request_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != {"publicKey"}:
            return None
        public_key = parsed["publicKey"]
        if not isinstance(public_key, str) or PUBLIC_KEY_PATTERN.fullmatch(public_key) is None:
            return None
        return parsed

    def _register_machine(
        self, idempotency_key: str, public_key: str, machine_id: str
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT machine_id, public_key FROM idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["public_key"] == public_key:
                        return HTTPStatus.OK, {"id": record["machine_id"], "publicKey": public_key}
                    return HTTPStatus.CONFLICT, {"error": "idempotency_conflict"}
                existing = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "machine_exists"}
                database.execute(
                    "INSERT INTO machines(id, public_key) VALUES (?, ?)",
                    (machine_id, public_key),
                )
                # 新登记即建立版本一历史：零时激活且未吊销。
                database.execute(
                    "INSERT INTO machine_keys"
                    "(machine_id, version, public_key, activated_at_ms, revoked)"
                    " VALUES (?, 1, ?, 0, 0)",
                    (machine_id, public_key),
                )
                database.execute(
                    "INSERT INTO idempotency_records(key, machine_id, public_key) VALUES (?, ?, ?)",
                    (idempotency_key, machine_id, public_key),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, {"id": machine_id, "publicKey": public_key}
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _declare_capability(self, machine_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 先读并校验正文：升级前既有幂等记录可在无认证头时按原请求先行重放。
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_capability_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        legacy = self._try_legacy_replay(
            "capability_idempotency_records",
            idempotency_key,
            request_json,
            " AND machine_id = ?",
            [machine_id],
        )
        if legacy is not None:
            self._json(legacy[0], legacy[1])
            return
        # 非旧记录重放：认证结构必须合法，且先于资源与业务检查。
        # 可用单值 SLA-Delegation 替代 SLA-Auth，两者并存即非法。
        sla_auth_values = self.headers.get_all(SLA_AUTH_HEADER)
        delegation_values = self.headers.get_all(SLA_DELEGATION_HEADER)
        if sla_auth_values and delegation_values:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        delegation = bool(delegation_values)
        auth = (
            self._parse_sla_delegation() if delegation else self._parse_sla_auth()
        )
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_capability(
            idempotency_key, machine_id, fields, auth, body_digest, delegation
        )
        self._json(status, payload)

    def _read_capability_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != CAPABILITY_FIELDS:
            return None
        if not _bounded_int(parsed["expectedVersion"], 0, 2147483646):
            return None
        name = parsed["name"]
        if not isinstance(name, str) or CAPABILITY_NAME_PATTERN.fullmatch(name) is None:
            return None
        protocol = parsed["protocol"]
        if not isinstance(protocol, str) or protocol not in CAPABILITY_PROTOCOLS:
            return None
        region = parsed["region"]
        if not isinstance(region, str) or region not in CAPABILITY_REGIONS:
            return None
        unit = parsed["unit"]
        if not isinstance(unit, str) or unit not in CAPABILITY_UNITS:
            return None
        if not _bounded_int(parsed["capacity"], 1, 2147483647):
            return None
        return parsed

    def _apply_capability(
        self,
        idempotency_key: str,
        machine_id: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
        delegation: bool,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT machine_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM capability_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["machine_id"] == machine_id and record["request_json"] == request_json:
                        # 既有幂等记录直接重放：旧记录（认证列为 NULL）不补认证数据，
                        # 新记录须认证五段完全一致，且不再次消费随机数。
                        if record["auth_machine_id"] is None or self._auth_record_matches(
                            record, auth
                        ):
                            return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                machine = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone()
                if machine is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                try:
                    # 资源存在后依次校验签名者、时间、密钥与签名、随机数；
                    # 代理凭证改按委托记录与代理公钥校验。
                    if delegation:
                        self._verify_delegation_auth(
                            database,
                            auth,
                            machine_id,
                            standard_path,
                            body_digest,
                            DELEGATION_OPERATION_CAPABILITY_WRITE,
                            fields["expectedVersion"],
                        )
                    else:
                        self._verify_request_auth(
                            database, auth, machine_id, standard_path, body_digest
                        )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                current = database.execute(
                    "SELECT version FROM machine_capabilities WHERE machine_id = ?",
                    (machine_id,),
                ).fetchone()
                current_version = current["version"] if current is not None else 0
                if fields["expectedVersion"] != current_version:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                new_version = current_version + 1
                status = HTTPStatus.CREATED if current is None else HTTPStatus.OK
                payload = {"version": new_version}
                database.execute(
                    "INSERT INTO machine_capabilities"
                    " (machine_id, name, protocol, region, unit, capacity, version)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(machine_id) DO UPDATE SET"
                    " name = excluded.name, protocol = excluded.protocol,"
                    " region = excluded.region, unit = excluded.unit,"
                    " capacity = excluded.capacity, version = excluded.version",
                    (
                        machine_id,
                        fields["name"],
                        fields["protocol"],
                        fields["region"],
                        fields["unit"],
                        fields["capacity"],
                        new_version,
                    ),
                )
                database.execute(
                    "INSERT INTO capability_idempotency_records"
                    "(key, machine_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        machine_id,
                        request_json,
                        int(status),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 只有首次业务成功才原子写入随机数；任何失败均不推进任何状态。
                if delegation:
                    # 代理凭证一次性：消费标记与业务变更、幂等结果、随机数同事务提交；
                    # 失败或同键重放均不消费凭证。
                    database.execute(
                        "UPDATE machine_delegations SET consumed = 1 WHERE id = ?",
                        (auth.machine_id,),
                    )
                    # 成功消费事件同事务追加并保存标准路径与原始正文 SHA-256 摘要；
                    # 版本竞争等失败路径不到达此处，不推进事件序号。
                    self._append_delegation_event(
                        database,
                        auth.machine_id,
                        "consumed",
                        int(datetime.now(UTC).timestamp() * 1000),
                        standard_path,
                        body_digest,
                    )
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return status, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_delegation(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 签发入口不接受任何查询参数：参数校验先于体校验。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_delegation_object(raw_body)
        )
        if fields is None:
            # 升级前签发请求只有三项：新五字段体校验不通过时，先尝试按旧请求
            # 逐字节重放既有签发幂等记录，再判非法正文。
            legacy = self._try_legacy_delegation_replay(
                idempotency_key, raw_body
            )
            if legacy is not None:
                self._json(legacy[0], legacy[1])
                return
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_delegation(
            idempotency_key, fields, auth, body_digest
        )
        self._json(status, payload)

    def _read_legacy_delegation_object(self, body: bytes) -> dict[str, Any] | None:
        # 仅用于识别升级前的三字段签发正文以逐字节重放；不做到期窗口等
        # 依赖服务当前时刻的校验，重放必须与首次结果一致。
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != {"id", "delegatePublicKey", "expiresAt"}:
            return None
        delegation_id = parsed["id"]
        if (
            not isinstance(delegation_id, str)
            or TEMPLATE_ID_PATTERN.fullmatch(delegation_id) is None
        ):
            return None
        delegate_public_key = parsed["delegatePublicKey"]
        if (
            not isinstance(delegate_public_key, str)
            or PUBLIC_KEY_PATTERN.fullmatch(delegate_public_key) is None
        ):
            return None
        expires_at = parsed["expiresAt"]
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            return None
        return parsed

    def _try_legacy_delegation_replay(
        self, idempotency_key: str, raw_body: bytes | None
    ) -> tuple[HTTPStatus, dict[str, Any]] | None:
        if raw_body is None:
            return None
        parsed = self._read_legacy_delegation_object(raw_body)
        if parsed is None:
            return None
        request_json = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            record = database.execute(
                "SELECT status, response_json, auth_machine_id, auth_key_version,"
                " auth_request_time_ms, auth_nonce, auth_signature"
                " FROM delegation_idempotency_records"
                " WHERE key = ? AND delegation_id = ? AND request_json = ?",
                (idempotency_key, parsed["id"], request_json),
            ).fetchone()
        if record is None:
            return None
        # 旧签发记录携带认证五段：重放须逐字节复用；认证列为 NULL 的更旧记录
        # （或重放请求未带可解析认证头）交由常规认证结构判定。
        auth = self._parse_sla_auth()
        if record["auth_machine_id"] is None:
            return HTTPStatus(record["status"]), json.loads(record["response_json"])
        if auth is not None and self._auth_record_matches(record, auth):
            return HTTPStatus(record["status"]), json.loads(record["response_json"])
        # 记录命中但认证五段缺失/不一致：与同键异认证的常规冲突语义一致。
        if auth is not None:
            return HTTPStatus.CONFLICT, {"error": "conflict"}
        return None

    def _read_delegation_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None:
            return None
        keys = set(parsed)
        capability_scope = keys == DELEGATION_FIELDS
        dispute_scope = keys == DELEGATION_DISPUTE_FIELDS
        proof_scope = keys == DELEGATION_PROOF_FIELDS
        # 五字段恰含一种范围标识：capabilityVersion、disputeId 与 evidenceSeq
        # 缺失、重复、混用或同时出现均为非法正文。
        if not capability_scope and not dispute_scope and not proof_scope:
            return None
        delegation_id = parsed["id"]
        if (
            not isinstance(delegation_id, str)
            or TEMPLATE_ID_PATTERN.fullmatch(delegation_id) is None
        ):
            return None
        delegate_public_key = parsed["delegatePublicKey"]
        if (
            not isinstance(delegate_public_key, str)
            or PUBLIC_KEY_PATTERN.fullmatch(delegate_public_key) is None
        ):
            return None
        expires_at = parsed["expiresAt"]
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            return None
        # 到期时刻须在服务当前 UTC 毫秒之后且不超过二十四小时。
        now_ms = int(datetime.now(UTC).timestamp() * 1000)
        if not now_ms < expires_at <= now_ms + DELEGATION_MAX_TTL_MS:
            return None
        # 最小权限范围：操作须与范围标识严格对应，不得混用。
        operation = parsed["operation"]
        if not isinstance(operation, str) or operation not in DELEGATION_OPERATIONS:
            return None
        if capability_scope:
            if operation != DELEGATION_OPERATION_CAPABILITY_WRITE:
                return None
            # 能力版本为 0..2147483646 的非布尔整数。
            if not _bounded_int(parsed["capabilityVersion"], 0, 2147483646):
                return None
        elif dispute_scope:
            if operation != DELEGATION_OPERATION_EVIDENCE_WRITE:
                return None
            # disputeId 沿用争议标识格式 [a-z0-9-]{1,64}。
            dispute_id = parsed["disputeId"]
            if (
                not isinstance(dispute_id, str)
                or TEMPLATE_ID_PATTERN.fullmatch(dispute_id) is None
            ):
                return None
        else:
            if operation != DELEGATION_OPERATION_PROOF_WRITE:
                return None
            # evidenceSeq 为非布尔正整数（不越过 SQLite 整数上界）。
            if not _bounded_int(parsed["evidenceSeq"], 1, INT64_MAX):
                return None
        return parsed

    def _apply_delegation(
        self,
        idempotency_key: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT delegation_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM delegation_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["delegation_id"] == fields["id"]
                        and record["request_json"] == request_json
                        and self._auth_record_matches(record, auth)
                    ):
                        return HTTPStatus(record["status"]), json.loads(
                            record["response_json"]
                        )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                try:
                    # 签发者即认证机器：依次校验时间、密钥与签名、随机数。
                    self._verify_request_auth(
                        database, auth, auth.machine_id, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                existing = database.execute(
                    "SELECT 1 FROM machine_delegations WHERE id = ?",
                    (fields["id"],),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                # 原子保存签发密钥版本与最小权限范围：代理使用时该版本须仍为最新
                # 有效版本，操作与能力版本/争议标识/证据序号须与凭证范围一致。
                database.execute(
                    "INSERT INTO machine_delegations"
                    "(id, issuer_machine_id, delegate_public_key, expires_at_ms,"
                    " issued_key_version, revoked, consumed, created_at_ms,"
                    " operation, capability_version, dispute_id, evidence_seq)"
                    " VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?)",
                    (
                        fields["id"],
                        auth.machine_id,
                        fields["delegatePublicKey"],
                        fields["expiresAt"],
                        auth.key_version,
                        created_at_ms,
                        fields["operation"],
                        fields.get("capabilityVersion"),
                        fields.get("disputeId"),
                        fields.get("evidenceSeq"),
                    ),
                )
                # 签发事件与委托、幂等结果、随机数同事务追加，序号全库唯一递增。
                self._append_delegation_event(
                    database, fields["id"], "issued", created_at_ms
                )
                payload = {"id": fields["id"], "expiresAt": fields["expiresAt"]}
                database.execute(
                    "INSERT INTO delegation_idempotency_records"
                    "(key, delegation_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        fields["id"],
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 只有首次成功才原子写入随机数、委托与幂等结果；失败无副作用。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _revoke_delegation(self, delegation_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 撤销入口不接受任何查询参数。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 请求体须为空对象。
        raw_body = self._read_raw_body()
        parsed = (
            None if raw_body is None else self._read_json_object(raw_body)
        )
        if parsed is None or parsed != {}:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_delegation_revocation(
            idempotency_key, delegation_id, auth, body_digest
        )
        self._json(status, payload)

    def _apply_delegation_revocation(
        self,
        idempotency_key: str,
        delegation_id: str,
        auth: SlaAuth,
        body_digest: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = "{}"
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT delegation_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM delegation_revocation_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["delegation_id"] == delegation_id
                        and record["request_json"] == request_json
                        and self._auth_record_matches(record, auth)
                    ):
                        return HTTPStatus(record["status"]), json.loads(
                            record["response_json"]
                        )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                delegation = database.execute(
                    "SELECT issuer_machine_id, revoked"
                    " FROM machine_delegations WHERE id = ?",
                    (delegation_id,),
                ).fetchone()
                if delegation is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                try:
                    # 仅签发者可撤销：签名者须等于签发机器，再验时间、密钥、签名、随机数。
                    self._verify_request_auth(
                        database,
                        auth,
                        delegation["issuer_machine_id"],
                        standard_path,
                        body_digest,
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                if delegation["revoked"]:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                database.execute(
                    "UPDATE machine_delegations SET revoked = 1 WHERE id = ?",
                    (delegation_id,),
                )
                # 首次撤销事件与撤销标记、幂等结果、随机数同事务追加。
                self._append_delegation_event(
                    database,
                    delegation_id,
                    "revoked",
                    int(datetime.now(UTC).timestamp() * 1000),
                )
                payload = {"id": delegation_id, "revoked": True}
                database.execute(
                    "INSERT INTO delegation_revocation_idempotency_records"
                    "(key, delegation_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        delegation_id,
                        request_json,
                        int(HTTPStatus.OK),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 撤销与幂等结果、随机数在同一事务原子提交；失败无副作用。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.OK, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _rotate_key(self, machine_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 轮换入口不接受任何查询参数：参数校验先于体校验与机器查询。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_key_rotation_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_key_rotation(idempotency_key, machine_id, fields)
        self._json(status, payload)

    def _read_key_rotation_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != KEY_ROTATION_FIELDS:
            return None
        if not _bounded_int(parsed["expectedVersion"], 1, 2147483646):
            return None
        public_key = parsed["publicKey"]
        if not isinstance(public_key, str) or PUBLIC_KEY_PATTERN.fullmatch(public_key) is None:
            return None
        current_signature = parsed["currentSignature"]
        if (
            not isinstance(current_signature, str)
            or SIGNATURE_PATTERN.fullmatch(current_signature) is None
        ):
            return None
        new_signature = parsed["newSignature"]
        if (
            not isinstance(new_signature, str)
            or SIGNATURE_PATTERN.fullmatch(new_signature) is None
        ):
            return None
        return parsed

    def _apply_key_rotation(
        self, idempotency_key: str, machine_id: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        expected_version = fields["expectedVersion"]
        new_public_key = fields["publicKey"]
        # key-rotate-v1 消息按 标识、机器id、期望版本、新公钥 逐行连接，末尾无换行；
        # 旧密钥与新密钥分别对同一消息签名。
        rotate_message = (
            f"key-rotate-v1\n{machine_id}\n{expected_version}\n{new_public_key}"
        ).encode("utf-8")
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT machine_id, request_json, status, response_json"
                    " FROM machine_key_rotation_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["machine_id"] == machine_id and record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                machine = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone()
                if machine is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                latest = database.execute(
                    "SELECT version, public_key FROM machine_keys"
                    " WHERE machine_id = ? ORDER BY version DESC LIMIT 1",
                    (machine_id,),
                ).fetchone()
                # 版本不符：期望版本必须等于当前最新版本（机器必有版本一历史）。
                if latest is None or latest["version"] != expected_version:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                # 历史公钥复用：新公钥不得等于该机器任一历史版本公钥（含当前）。
                reused = database.execute(
                    "SELECT 1 FROM machine_keys"
                    " WHERE machine_id = ? AND public_key = ?",
                    (machine_id, new_public_key),
                ).fetchone()
                if reused is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "key_exists"}
                current_valid = ed25519_verify(
                    bytes.fromhex(latest["public_key"]),
                    rotate_message,
                    bytes.fromhex(fields["currentSignature"]),
                )
                new_valid = ed25519_verify(
                    bytes.fromhex(new_public_key),
                    rotate_message,
                    bytes.fromhex(fields["newSignature"]),
                )
                if not current_valid or not new_valid:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "invalid_signature"}
                new_version = expected_version + 1
                activated_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                payload = {
                    "version": new_version,
                    "publicKey": new_public_key,
                    "activatedAt": activated_at_ms,
                    "revoked": False,
                }
                try:
                    database.execute(
                        "INSERT INTO machine_keys"
                        "(machine_id, version, public_key, activated_at_ms, revoked)"
                        " VALUES (?, ?, ?, ?, 0)",
                        (machine_id, new_version, new_public_key, activated_at_ms),
                    )
                except sqlite3.IntegrityError:
                    # 异键同版本/同公钥并发：仅一项成功。
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                database.execute(
                    "INSERT INTO machine_key_rotation_idempotency_records"
                    "(key, machine_id, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        machine_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _revoke_key(self, machine_id: str, version_text: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 吊销入口不接受任何查询参数。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_key_revocation_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_key_revocation(
            idempotency_key, machine_id, version_text, fields
        )
        self._json(status, payload)

    def _read_key_revocation_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != KEY_REVOCATION_FIELDS:
            return None
        signature = parsed["signature"]
        if not isinstance(signature, str) or SIGNATURE_PATTERN.fullmatch(signature) is None:
            return None
        return parsed

    def _apply_key_revocation(
        self,
        idempotency_key: str,
        machine_id: str,
        version_text: str,
        fields: dict[str, Any],
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        # 路径版本须为无前导零十进制正整数；非法按不存在处理（404）。
        version: int | None = None
        if DECIMAL_PATTERN.fullmatch(version_text) is not None:
            value = int(version_text)
            if 1 <= value <= INT64_MAX:
                version = value
        # key-revoke-v1 消息逐行绑定 机器id、版本，由最新密钥签署。
        revoke_message = (
            f"key-revoke-v1\n{machine_id}\n{version_text}"
        ).encode("utf-8")
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT machine_id, version, request_json, status, response_json"
                    " FROM machine_key_revocation_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["machine_id"] == machine_id
                        and record["version"] == (version if version is not None else -1)
                        and record["request_json"] == request_json
                    ):
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                machine = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone()
                if machine is None or version is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                key_record = database.execute(
                    "SELECT public_key, revoked FROM machine_keys"
                    " WHERE machine_id = ? AND version = ?",
                    (machine_id, version),
                ).fetchone()
                if key_record is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                latest = database.execute(
                    "SELECT MAX(version) AS latest FROM machine_keys"
                    " WHERE machine_id = ?",
                    (machine_id,),
                ).fetchone()
                if latest["latest"] == version:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                if key_record["revoked"]:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_revoked"}
                latest_record = database.execute(
                    "SELECT public_key FROM machine_keys"
                    " WHERE machine_id = ? AND version = ?",
                    (machine_id, latest["latest"]),
                ).fetchone()
                signature_valid = False
                if latest_record is not None:
                    signature_valid = ed25519_verify(
                        bytes.fromhex(latest_record["public_key"]),
                        revoke_message,
                        bytes.fromhex(fields["signature"]),
                    )
                if not signature_valid:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "invalid_signature"}
                database.execute(
                    "UPDATE machine_keys SET revoked = 1"
                    " WHERE machine_id = ? AND version = ?",
                    (machine_id, version),
                )
                payload = {"version": version, "revoked": True}
                database.execute(
                    "INSERT INTO machine_key_revocation_idempotency_records"
                    "(key, machine_id, version, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        machine_id,
                        version,
                        request_json,
                        int(HTTPStatus.OK),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.OK, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_sla_template(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_sla_template_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_sla_template(idempotency_key, fields)
        self._json(status, payload)

    def _read_sla_template_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != SLA_TEMPLATE_FIELDS:
            return None
        template_id = parsed["id"]
        if not isinstance(template_id, str) or TEMPLATE_ID_PATTERN.fullmatch(template_id) is None:
            return None
        machine_id = parsed["machineId"]
        if not isinstance(machine_id, str) or PUBLIC_KEY_PATTERN.fullmatch(machine_id) is None:
            return None
        if not _bounded_int(parsed["capabilityVersion"], 1, 2147483647):
            return None
        if not _bounded_int(parsed["priceMicros"], 0, 2147483647):
            return None
        if not _bounded_int(parsed["maxLatencyMs"], 1, 2147483647):
            return None
        return parsed

    def _apply_sla_template(
        self, idempotency_key: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT request_json, status, response_json"
                    " FROM sla_template_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                machine = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (fields["machineId"],)
                ).fetchone()
                if machine is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                capability = database.execute(
                    "SELECT version FROM machine_capabilities WHERE machine_id = ?",
                    (fields["machineId"],),
                ).fetchone()
                if capability is None or capability["version"] != fields["capabilityVersion"]:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                existing = database.execute(
                    "SELECT id FROM sla_templates WHERE id = ?", (fields["id"],)
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "template_exists"}
                payload = {"id": fields["id"]}
                database.execute(
                    "INSERT INTO sla_templates"
                    "(id, machine_id, capability_version, price_micros, max_latency_ms)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        fields["id"],
                        fields["machineId"],
                        fields["capabilityVersion"],
                        fields["priceMicros"],
                        fields["maxLatencyMs"],
                    ),
                )
                database.execute(
                    "INSERT INTO sla_template_idempotency_records"
                    "(key, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        idempotency_key,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_sla(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_sla_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_sla(idempotency_key, fields)
        self._json(status, payload)

    def _read_sla_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != SLA_FIELDS:
            return None
        sla_id = parsed["id"]
        if not isinstance(sla_id, str) or TEMPLATE_ID_PATTERN.fullmatch(sla_id) is None:
            return None
        template_id = parsed["templateId"]
        if not isinstance(template_id, str) or TEMPLATE_ID_PATTERN.fullmatch(template_id) is None:
            return None
        consumer_id = parsed["consumerId"]
        if not isinstance(consumer_id, str) or PUBLIC_KEY_PATTERN.fullmatch(consumer_id) is None:
            return None
        if not _bounded_int(parsed["start"], 0, 2147483647):
            return None
        if not _bounded_int(parsed["end"], 0, 2147483647):
            return None
        if parsed["start"] >= parsed["end"]:
            return None
        return parsed

    def _apply_sla(
        self, idempotency_key: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT request_json, status, response_json"
                    " FROM sla_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                template = database.execute(
                    "SELECT machine_id, capability_version, price_micros, max_latency_ms"
                    " FROM sla_templates WHERE id = ?",
                    (fields["templateId"],),
                ).fetchone()
                if template is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                capability = database.execute(
                    "SELECT version FROM machine_capabilities WHERE machine_id = ?",
                    (template["machine_id"],),
                ).fetchone()
                if capability is None or capability["version"] != template["capability_version"]:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                consumer = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (fields["consumerId"],)
                ).fetchone()
                if consumer is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                existing = database.execute(
                    "SELECT id FROM slas WHERE id = ?", (fields["id"],)
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "sla_exists"}
                payload = {"id": fields["id"]}
                database.execute(
                    "INSERT INTO slas"
                    "(id, template_id, machine_id, consumer_id, capability_version,"
                    " price_micros, max_latency_ms, start_unix, end_unix, state)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        fields["id"],
                        fields["templateId"],
                        template["machine_id"],
                        fields["consumerId"],
                        template["capability_version"],
                        template["price_micros"],
                        template["max_latency_ms"],
                        fields["start"],
                        fields["end"],
                        "pending",
                    ),
                )
                database.execute(
                    "INSERT INTO sla_idempotency_records"
                    "(key, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        idempotency_key,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _confirm_sla(self, sla_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 先读并校验正文：升级前既有幂等记录可在无认证头时按原请求先行重放。
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_confirmation_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        legacy = self._try_legacy_replay(
            "sla_confirmation_idempotency_records",
            idempotency_key,
            request_json,
            " AND sla_id = ?",
            [sla_id],
        )
        if legacy is not None:
            self._json(legacy[0], legacy[1])
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_confirmation(
            idempotency_key, sla_id, fields, auth, body_digest
        )
        self._json(status, payload)

    def _read_confirmation_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != CONFIRMATION_FIELDS:
            return None
        party = parsed["party"]
        if not isinstance(party, str) or party not in CONFIRMATION_PARTIES:
            return None
        actor_id = parsed["actorId"]
        if not isinstance(actor_id, str) or PUBLIC_KEY_PATTERN.fullmatch(actor_id) is None:
            return None
        return parsed

    def _apply_confirmation(
        self,
        idempotency_key: str,
        sla_id: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                now = int(datetime.now(UTC).timestamp())
                record = database.execute(
                    "SELECT sla_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM sla_confirmation_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["sla_id"] == sla_id and record["request_json"] == request_json:
                        if record["auth_machine_id"] is None or self._auth_record_matches(
                            record, auth
                        ):
                            return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                sla = database.execute(
                    "SELECT machine_id, consumer_id, capability_version,"
                    " start_unix, end_unix, state FROM slas WHERE id = ?",
                    (sla_id,),
                ).fetchone()
                if sla is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                expected_actor = (
                    sla["machine_id"] if fields["party"] == "producer" else sla["consumer_id"]
                )
                # 参与方身份即签名者：正文 actorId 须为应签方，认证机器标识须与之一致。
                if fields["actorId"] != expected_actor:
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    self._verify_request_auth(
                        database, auth, fields["actorId"], standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                # 认证全部通过后执行既有业务判定（重复方、时间窗与能力版本）。
                existing = database.execute(
                    "SELECT party FROM sla_confirmations WHERE sla_id = ? AND party = ?",
                    (sla_id, fields["party"]),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_confirmed"}
                capability = database.execute(
                    "SELECT version FROM machine_capabilities WHERE machine_id = ?",
                    (sla["machine_id"],),
                ).fetchone()
                if (
                    not (sla["start_unix"] <= now < sla["end_unix"])
                    or capability is None
                    or capability["version"] != sla["capability_version"]
                ):
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                database.execute(
                    "INSERT INTO sla_confirmations(sla_id, party, actor_id) VALUES (?, ?, ?)",
                    (sla_id, fields["party"], fields["actorId"]),
                )
                other_party = "consumer" if fields["party"] == "producer" else "producer"
                counterpart = database.execute(
                    "SELECT party FROM sla_confirmations WHERE sla_id = ? AND party = ?",
                    (sla_id, other_party),
                ).fetchone()
                new_state = "active" if counterpart is not None else "pending"
                if new_state == "active":
                    database.execute(
                        "UPDATE slas SET state = 'active' WHERE id = ? AND state = 'pending'",
                        (sla_id,),
                    )
                payload = {"state": new_state}
                database.execute(
                    "INSERT INTO sla_confirmation_idempotency_records"
                    "(key, sla_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        sla_id,
                        request_json,
                        int(HTTPStatus.OK),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.OK, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _post_telemetry(self, sla_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        parsed = self._read_telemetry_object()
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields, kind = parsed
        status, payload = self._apply_telemetry(idempotency_key, sla_id, fields, kind)
        self._json(status, payload)

    def _read_telemetry_object(self) -> tuple[dict[str, Any], str] | None:
        parsed = self._read_json_object()
        if parsed is None:
            return None
        keys = set(parsed)
        if keys == TELEMETRY_SIGNED_FIELDS:
            kind = "v2"
        elif keys == TELEMETRY_V1_SIGNED_FIELDS or keys == TELEMETRY_FIELDS:
            # 旧正文（签名五字段或无签名四字段）：仅用于精确重放旧幂等记录。
            kind = "legacy"
        else:
            return None
        event_id = parsed["eventId"]
        if not isinstance(event_id, str) or TEMPLATE_ID_PATTERN.fullmatch(event_id) is None:
            return None
        if not _bounded_int(parsed["timestamp"], 0, 2147483647999):
            return None
        if not _bounded_int(parsed["latencyMs"], 0, 2147483647):
            return None
        digest = parsed["digest"]
        if not isinstance(digest, str) or PUBLIC_KEY_PATTERN.fullmatch(digest) is None:
            return None
        if "signature" in parsed:
            signature = parsed["signature"]
            if not isinstance(signature, str) or SIGNATURE_PATTERN.fullmatch(signature) is None:
                return None
        if kind == "v2":
            # keyVersion 为非布尔正整数。
            if not _bounded_int(parsed["keyVersion"], 1, INT64_MAX):
                return None
        return parsed, kind

    def _apply_telemetry(
        self, idempotency_key: str, sla_id: str, fields: dict[str, Any], kind: str
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT sla_id, request_json, status, response_json"
                    " FROM sla_telemetry_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["sla_id"] == sla_id and record["request_json"] == request_json:
                        # 同键同请求（含旧四字段/五字段记录的精确匹配）重放首次响应。
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    if kind != "v2":
                        # 其他旧正文提交按非法正文处理。
                        return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                if kind != "v2":
                    # 旧正文仅允许精确重放：无匹配幂等记录时按非法正文处理。
                    database.execute("ROLLBACK")
                    return HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                sla = database.execute(
                    "SELECT machine_id, start_unix, end_unix, state FROM slas WHERE id = ?",
                    (sla_id,),
                ).fetchone()
                if sla is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                timestamp = fields["timestamp"]
                if (
                    sla["state"] != "active"
                    or not (sla["start_unix"] * 1000 <= timestamp < sla["end_unix"] * 1000)
                ):
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                message = (
                    f"{sla_id}\n{fields['eventId']}\n{timestamp}\n"
                    f"{fields['latencyMs']}\n{sla['machine_id']}"
                )
                if hashlib.sha256(message.encode("utf-8")).hexdigest() != fields["digest"]:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                key_version = fields["keyVersion"]
                key = database.execute(
                    "SELECT public_key, activated_at_ms, revoked FROM machine_keys"
                    " WHERE machine_id = ? AND version = ?",
                    (sla["machine_id"], key_version),
                ).fetchone()
                # 判定在摘要之后、事件重复之前：未知版本、窗外、吊销或验签失败
                # 均为 invalid_signature，不留数据或幂等结果，也不推进 commit_seq。
                signature_valid = False
                if key is not None and not key["revoked"]:
                    next_activation = database.execute(
                        "SELECT activated_at_ms FROM machine_keys"
                        " WHERE machine_id = ? AND version > ?"
                        " ORDER BY version ASC LIMIT 1",
                        (sla["machine_id"], key_version),
                    ).fetchone()
                    within_window = timestamp >= key["activated_at_ms"] and (
                        next_activation is None
                        or timestamp < next_activation["activated_at_ms"]
                    )
                    if within_window:
                        signed_message = (
                            f"telemetry-v2\n{sla_id}\n{fields['eventId']}\n{timestamp}\n"
                            f"{fields['latencyMs']}\n{fields['digest']}\n"
                            f"{key_version}\n{sla['machine_id']}"
                        ).encode("utf-8")
                        signature_valid = ed25519_verify(
                            bytes.fromhex(key["public_key"]),
                            signed_message,
                            bytes.fromhex(fields["signature"]),
                        )
                if not signature_valid:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "invalid_signature"}
                # 摘要、版本窗口与签名均有效后才判事件重复。
                existing = database.execute(
                    "SELECT event_id FROM sla_telemetry_events"
                    " WHERE sla_id = ? AND event_id = ?",
                    (sla_id, fields["eventId"]),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "event_exists"}
                next_record = database.execute(
                    "SELECT COALESCE(MAX(commit_seq), 0) + 1 AS next_seq"
                    " FROM sla_telemetry_events"
                ).fetchone()
                commit_seq = next_record["next_seq"]
                payload = {"eventId": fields["eventId"]}
                database.execute(
                    "INSERT INTO sla_telemetry_events"
                    "(sla_id, event_id, timestamp_ms, latency_ms, digest, commit_seq,"
                    " signature, key_version)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        sla_id,
                        fields["eventId"],
                        timestamp,
                        fields["latencyMs"],
                        fields["digest"],
                        commit_seq,
                        fields["signature"],
                        key_version,
                    ),
                )
                database.execute(
                    "INSERT INTO sla_telemetry_idempotency_records"
                    "(key, sla_id, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        sla_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _evaluate_sla(self, sla_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_evaluation_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_evaluation(idempotency_key, sla_id, fields)
        self._json(status, payload)

    def _read_evaluation_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != EVALUATION_FIELDS:
            return None
        start = parsed["from"]
        end = parsed["to"]
        if not isinstance(start, int) or isinstance(start, bool):
            return None
        if not isinstance(end, int) or isinstance(end, bool):
            return None
        return parsed

    def _apply_evaluation(
        self, idempotency_key: str, sla_id: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT sla_id, request_json, status, response_json"
                    " FROM sla_evaluation_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["sla_id"] == sla_id and record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                sla = database.execute(
                    "SELECT max_latency_ms, start_unix, end_unix, state"
                    " FROM slas WHERE id = ?",
                    (sla_id,),
                ).fetchone()
                if sla is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                start = fields["from"]
                end = fields["to"]
                if (
                    sla["state"] != "active"
                    or not (sla["start_unix"] * 1000 <= start < end <= sla["end_unix"] * 1000)
                ):
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                cut_record = database.execute(
                    "SELECT MAX(commit_seq) AS cut FROM sla_telemetry_events"
                ).fetchone()
                cut = cut_record["cut"]
                if cut is None:
                    cut = 0
                summary = database.execute(
                    "SELECT COUNT(*) AS count, COALESCE(SUM(latency_ms), 0) AS latency_sum,"
                    " MAX(latency_ms) AS max_latency,"
                    " COALESCE(SUM(CASE WHEN latency_ms > ? THEN 1 ELSE 0 END), 0)"
                    " AS violations"
                    " FROM sla_telemetry_events"
                    " WHERE sla_id = ? AND commit_seq <= ?"
                    " AND timestamp_ms >= ? AND timestamp_ms < ?",
                    (
                        sla["max_latency_ms"],
                        sla_id,
                        cut,
                        start,
                        end,
                    ),
                ).fetchone()
                count = summary["count"]
                violations = summary["violations"]
                if count == 0:
                    outcome = "insufficient"
                elif violations == 0:
                    outcome = "fulfilled"
                else:
                    outcome = "breached"
                # 全库共享一条持久化评估序号：取写锁后取全库最大序号 + 1（空表 1）。
                next_record = database.execute(
                    "SELECT COALESCE(MAX(evaluation_seq), 0) + 1 AS next_seq"
                    " FROM sla_evaluation_idempotency_records"
                ).fetchone()
                evaluation_seq = next_record["next_seq"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                payload = {
                    "evaluationSeq": evaluation_seq,
                    "from": start,
                    "to": end,
                    "cut": cut,
                    "count": count,
                    "latencySum": summary["latency_sum"],
                    "maxLatency": summary["max_latency"],
                    "violations": violations,
                    "outcome": outcome,
                    "createdAt": created_at_ms,
                }
                database.execute(
                    "INSERT INTO sla_evaluation_idempotency_records"
                    "(key, sla_id, request_json, status, response_json,"
                    " evaluation_seq, created_at_ms)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        sla_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                        evaluation_seq,
                        created_at_ms,
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _deposit_funds(self, machine_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_fund_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_deposit(idempotency_key, machine_id, fields)
        self._json(status, payload)

    def _read_fund_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != FUND_FIELDS:
            return None
        if not _bounded_int(parsed["amountMicros"], 1, AMOUNT_CAP_MICROS):
            return None
        reference = parsed["reference"]
        if not isinstance(reference, str) or TEMPLATE_ID_PATTERN.fullmatch(reference) is None:
            return None
        return parsed

    @staticmethod
    def _adjust_account(
        database: Any, account_id: str, delta_micros: int
    ) -> int:
        database.execute(
            "INSERT INTO ledger_accounts(account_id, balance_micros) VALUES (?, ?)"
            " ON CONFLICT(account_id) DO UPDATE SET"
            " balance_micros = balance_micros + excluded.balance_micros",
            (account_id, delta_micros),
        )
        return database.execute(
            "SELECT balance_micros FROM ledger_accounts WHERE account_id = ?",
            (account_id,),
        ).fetchone()["balance_micros"]

    @staticmethod
    def _record_entry(
        database: Any,
        kind: str,
        reference_seq: int,
        account_id: str,
        delta_micros: int,
        balance_after_micros: int,
        created_at_ms: int,
    ) -> None:
        database.execute(
            "INSERT INTO ledger_entries"
            "(kind, reference_seq, account_id, delta_micros,"
            " balance_after_micros, created_at_ms)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                kind,
                reference_seq,
                account_id,
                delta_micros,
                balance_after_micros,
                created_at_ms,
            ),
        )

    def _apply_deposit(
        self, idempotency_key: str, machine_id: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT machine_id, request_json, status, response_json"
                    " FROM fund_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["machine_id"] == machine_id and record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                machine = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone()
                if machine is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                amount = fields["amountMicros"]
                # 全库共享一条持久化入金序号：取写锁后取全库最大序号 + 1（空表 1）。
                next_record = database.execute(
                    "SELECT COALESCE(MAX(deposit_seq), 0) + 1 AS next_seq"
                    " FROM fund_deposits"
                ).fetchone()
                deposit_seq = next_record["next_seq"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                # 双重记账：机器账户与外部清算账户等额反向分录，同事务提交。
                balance = self._adjust_account(database, machine_id, amount)
                clearing_balance = self._adjust_account(
                    database, CLEARING_ACCOUNT_ID, -amount
                )
                self._record_entry(
                    database, "deposit", deposit_seq, machine_id,
                    amount, balance, created_at_ms,
                )
                self._record_entry(
                    database, "deposit", deposit_seq, CLEARING_ACCOUNT_ID,
                    -amount, clearing_balance, created_at_ms,
                )
                database.execute(
                    "INSERT INTO fund_deposits"
                    "(deposit_seq, machine_id, amount_micros, reference, created_at_ms)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (deposit_seq, machine_id, amount, fields["reference"], created_at_ms),
                )
                payload = {"depositSeq": deposit_seq, "balance": balance}
                database.execute(
                    "INSERT INTO fund_idempotency_records"
                    "(key, machine_id, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        machine_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_settlement(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_settlement_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_settlement(idempotency_key, fields)
        self._json(status, payload)

    def _read_settlement_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != SETTLEMENT_FIELDS:
            return None
        sla_id = parsed["slaId"]
        if not isinstance(sla_id, str) or TEMPLATE_ID_PATTERN.fullmatch(sla_id) is None:
            return None
        evaluation_seq = parsed["evaluationSeq"]
        if not isinstance(evaluation_seq, int) or isinstance(evaluation_seq, bool):
            return None
        if evaluation_seq < 1:
            return None
        return parsed

    def _apply_settlement(
        self, idempotency_key: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        sla_id = fields["slaId"]
        evaluation_seq = fields["evaluationSeq"]
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT request_json, status, response_json"
                    " FROM settlement_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                sla = database.execute(
                    "SELECT machine_id, consumer_id, price_micros, state"
                    " FROM slas WHERE id = ?",
                    (sla_id,),
                ).fetchone()
                if sla is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                if sla["state"] != "active":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                evaluation = None
                if evaluation_seq <= INT64_MAX:
                    evaluation = database.execute(
                        "SELECT sla_id, response_json"
                        " FROM sla_evaluation_idempotency_records"
                        " WHERE evaluation_seq = ?",
                        (evaluation_seq,),
                    ).fetchone()
                if evaluation is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                if evaluation["sla_id"] != sla_id:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                existing = database.execute(
                    "SELECT 1 FROM settlements WHERE evaluation_seq = ?",
                    (evaluation_seq,),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "settlement_exists"}
                snapshot = json.loads(evaluation["response_json"])
                outcome = snapshot["outcome"]
                if outcome == "fulfilled":
                    result = "charged"
                    amount = sla["price_micros"] * snapshot["count"]
                    payer_id = sla["consumer_id"]
                    payee_id = sla["machine_id"]
                elif outcome == "breached":
                    result = "compensated"
                    amount = sla["price_micros"] * snapshot["violations"]
                    payer_id = sla["machine_id"]
                    payee_id = sla["consumer_id"]
                else:
                    result = "pending"
                    amount = 0
                    payer_id = None
                    payee_id = None
                if amount > AMOUNT_CAP_MICROS:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "amount_overflow"}
                payer_balance = 0
                payee_balance = 0
                if payer_id is not None:
                    balances = {
                        row["account_id"]: row["balance_micros"]
                        for row in database.execute(
                            "SELECT account_id, balance_micros FROM ledger_accounts"
                            " WHERE account_id IN (?, ?)",
                            (payer_id, payee_id),
                        )
                    }
                    payer_balance = balances.get(payer_id, 0)
                    payee_balance = balances.get(payee_id, 0)
                    if payee_balance + amount > AMOUNT_CAP_MICROS:
                        database.execute("ROLLBACK")
                        return HTTPStatus.CONFLICT, {"error": "amount_overflow"}
                    # 可用余额为总余额扣除全部 open 争议冻结后与零的较大值；
                    # 旧库冻结可能超过总余额，此时按零处理。
                    frozen_record = database.execute(
                        "SELECT COALESCE(SUM(amount_micros), 0) AS frozen"
                        " FROM disputes WHERE payee_id = ? AND state = 'open'",
                        (payer_id,),
                    ).fetchone()
                    payer_available = max(0, payer_balance - frozen_record["frozen"])
                    if payer_available < amount:
                        database.execute("ROLLBACK")
                        return HTTPStatus.CONFLICT, {"error": "insufficient_funds"}
                # 全库共享一条持久化结算序号：取写锁后取全库最大序号 + 1（空表 1）。
                next_record = database.execute(
                    "SELECT COALESCE(MAX(settlement_seq), 0) + 1 AS next_seq"
                    " FROM settlements"
                ).fetchone()
                settlement_seq = next_record["next_seq"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                if payer_id is not None:
                    payer_after = self._adjust_account(database, payer_id, -amount)
                    payee_after = self._adjust_account(database, payee_id, amount)
                    self._record_entry(
                        database, "settlement", settlement_seq, payer_id,
                        -amount, payer_after, created_at_ms,
                    )
                    self._record_entry(
                        database, "settlement", settlement_seq, payee_id,
                        amount, payee_after, created_at_ms,
                    )
                database.execute(
                    "INSERT INTO settlements"
                    "(settlement_seq, sla_id, evaluation_seq, result, amount_micros,"
                    " payer_id, payee_id, created_at_ms)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        settlement_seq,
                        sla_id,
                        evaluation_seq,
                        result,
                        amount,
                        payer_id,
                        payee_id,
                        created_at_ms,
                    ),
                )
                payload = {
                    "settlementSeq": settlement_seq,
                    "evaluationSeq": evaluation_seq,
                    "result": result,
                    "amount": amount,
                    "createdAt": created_at_ms,
                }
                database.execute(
                    "INSERT INTO settlement_idempotency_records"
                    "(key, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        idempotency_key,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_dispute(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_dispute_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_dispute(idempotency_key, fields)
        self._json(status, payload)

    def _read_dispute_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != DISPUTE_FIELDS:
            return None
        dispute_id = parsed["id"]
        if not isinstance(dispute_id, str) or TEMPLATE_ID_PATTERN.fullmatch(dispute_id) is None:
            return None
        settlement_seq = parsed["settlementSeq"]
        if not isinstance(settlement_seq, int) or isinstance(settlement_seq, bool):
            return None
        if settlement_seq < 1:
            return None
        claimant_id = parsed["claimantId"]
        if not isinstance(claimant_id, str) or PUBLIC_KEY_PATTERN.fullmatch(claimant_id) is None:
            return None
        return parsed

    def _apply_dispute(
        self, idempotency_key: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT request_json, status, response_json"
                    " FROM dispute_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                settlement_seq = fields["settlementSeq"]
                settlement = None
                if settlement_seq <= INT64_MAX:
                    settlement = database.execute(
                        "SELECT result, amount_micros, payer_id, payee_id"
                        " FROM settlements WHERE settlement_seq = ?",
                        (settlement_seq,),
                    ).fetchone()
                if settlement is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                payer_id = settlement["payer_id"]
                if payer_id is not None and fields["claimantId"] != payer_id:
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                amount = settlement["amount_micros"]
                if settlement["result"] not in DISPUTABLE_RESULTS or amount <= 0:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                existing = database.execute(
                    "SELECT 1 FROM disputes WHERE id = ? OR settlement_seq = ?",
                    (fields["id"], settlement_seq),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "dispute_exists"}
                # 冻结仅登记 open 争议：可用余额按总余额扣除 open 冻结派生，不写账本。
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                database.execute(
                    "INSERT INTO disputes"
                    "(id, settlement_seq, claimant_id, payer_id, payee_id,"
                    " amount_micros, state)"
                    " VALUES (?, ?, ?, ?, ?, ?, 'open')",
                    (
                        fields["id"],
                        settlement_seq,
                        fields["claimantId"],
                        settlement["payer_id"],
                        settlement["payee_id"],
                        amount,
                    ),
                )
                # 生命周期事件：全库共享持久递增序号，与争议及幂等结果同事务提交。
                next_record = database.execute(
                    "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq"
                    " FROM dispute_events"
                ).fetchone()
                event_seq = next_record["next_seq"]
                database.execute(
                    "INSERT INTO dispute_events"
                    "(event_seq, dispute_id, type, created_at_ms)"
                    " VALUES (?, ?, 'opened', ?)",
                    (event_seq, fields["id"], created_at_ms),
                )
                payload = {"id": fields["id"], "open": True, "amount": amount}
                database.execute(
                    "INSERT INTO dispute_idempotency_records"
                    "(key, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?)",
                    (
                        idempotency_key,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _submit_evidence(self, dispute_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # POST 证据不接受任何查询参数：参数校验先于体校验与争议查询。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 先读并校验正文：升级前既有幂等记录可在无认证头时按原请求先行重放。
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_evidence_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        legacy = self._try_legacy_replay(
            "dispute_evidence_idempotency_records",
            idempotency_key,
            request_json,
            " AND dispute_id = ?",
            [dispute_id],
        )
        if legacy is not None:
            self._json(legacy[0], legacy[1])
            return
        # 非旧记录重放：认证结构必须合法，且先于资源与业务检查。
        # 可用单值 SLA-Delegation 替代 SLA-Auth，两者并存即非法。
        sla_auth_values = self.headers.get_all(SLA_AUTH_HEADER)
        delegation_values = self.headers.get_all(SLA_DELEGATION_HEADER)
        if sla_auth_values and delegation_values:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        delegation = bool(delegation_values)
        auth = (
            self._parse_sla_delegation() if delegation else self._parse_sla_auth()
        )
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_evidence(
            idempotency_key, dispute_id, fields, auth, body_digest, delegation
        )
        self._json(status, payload)

    def _read_evidence_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != EVIDENCE_FIELDS:
            return None
        evidence_id = parsed["evidenceId"]
        if (
            not isinstance(evidence_id, str)
            or TEMPLATE_ID_PATTERN.fullmatch(evidence_id) is None
        ):
            return None
        actor_id = parsed["actorId"]
        if (
            not isinstance(actor_id, str)
            or PUBLIC_KEY_PATTERN.fullmatch(actor_id) is None
        ):
            return None
        # observedAt 为非布尔整数，上界与遥测毫秒时间一致。
        if not _bounded_int(parsed["observedAt"], 0, 2147483647999):
            return None
        digest = parsed["digest"]
        if not isinstance(digest, str) or PUBLIC_KEY_PATTERN.fullmatch(digest) is None:
            return None
        return parsed

    def _apply_evidence(
        self,
        idempotency_key: str,
        dispute_id: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
        delegation: bool,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM dispute_evidence_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["dispute_id"] == dispute_id
                        and record["request_json"] == request_json
                    ):
                        if record["auth_machine_id"] is None or self._auth_record_matches(
                            record, auth
                        ):
                            return HTTPStatus(record["status"]), json.loads(
                                record["response_json"]
                            )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                dispute = database.execute(
                    "SELECT payer_id, payee_id, state FROM disputes WHERE id = ?",
                    (dispute_id,),
                ).fetchone()
                if dispute is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                if fields["actorId"] not in (
                    dispute["payer_id"],
                    dispute["payee_id"],
                ):
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    # 认证机器标识须等于正文 actorId（参与方身份），再验时间、密钥、签名、随机数；
                    # 代理凭证改按委托记录与代理公钥校验，并须绑定本争议。
                    if delegation:
                        self._verify_delegation_auth(
                            database,
                            auth,
                            fields["actorId"],
                            standard_path,
                            body_digest,
                            DELEGATION_OPERATION_EVIDENCE_WRITE,
                            dispute_id,
                        )
                    else:
                        self._verify_request_auth(
                            database, auth, fields["actorId"], standard_path, body_digest
                        )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                # 认证全部通过后执行既有业务判定（争议状态与证据唯一性）。
                if dispute["state"] != "open":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_resolved"}
                # 同一争议内 evidenceId 与 digest 均不可被异键占用；
                # 写事务内复查 + 唯一约束保证异键并发至多一项成功。
                existing = database.execute(
                    "SELECT 1 FROM dispute_evidences"
                    " WHERE dispute_id = ? AND (evidence_id = ? OR digest = ?)",
                    (dispute_id, fields["evidenceId"], fields["digest"]),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "evidence_exists"}
                next_record = database.execute(
                    "SELECT COALESCE(MAX(evidence_seq), 0) + 1 AS next_seq"
                    " FROM dispute_evidences"
                ).fetchone()
                evidence_seq = next_record["next_seq"]
                database.execute(
                    "INSERT INTO dispute_evidences"
                    "(evidence_seq, dispute_id, evidence_id, actor_id,"
                    " observed_at_ms, digest)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        evidence_seq,
                        dispute_id,
                        fields["evidenceId"],
                        fields["actorId"],
                        fields["observedAt"],
                        fields["digest"],
                    ),
                )
                payload = {"evidenceSeq": evidence_seq}
                database.execute(
                    "INSERT INTO dispute_evidence_idempotency_records"
                    "(key, dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        dispute_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 只有首次证据成功才原子写入随机数；任何失败均不推进证据或事件序号。
                if delegation:
                    # 代理凭证一次性：消费标记与证据序号、幂等结果、随机数同事务提交；
                    # 失败或同键重放均不消费凭证。
                    database.execute(
                        "UPDATE machine_delegations SET consumed = 1 WHERE id = ?",
                        (auth.machine_id,),
                    )
                    # 成功消费事件同事务追加并保存标准路径与原始正文 SHA-256 摘要；
                    # 已裁决、重复证据等失败路径不到达此处，不推进事件序号。
                    self._append_delegation_event(
                        database,
                        auth.machine_id,
                        "consumed",
                        int(datetime.now(UTC).timestamp() * 1000),
                        standard_path,
                        body_digest,
                    )
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_evidence_snapshot(self, dispute_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 创建快照不接受任何查询参数：参数校验先于体校验与争议查询。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_evidence_snapshot_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 仅支持单一 SLA-Auth：头缺失、重复、结构非法或携带代理头均为非法请求，
        # 且先于争议查询。
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_evidence_snapshot(
            idempotency_key, dispute_id, fields, auth, body_digest
        )
        self._json(status, payload)

    def _read_evidence_snapshot_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != EVIDENCE_SNAPSHOT_FIELDS:
            return None
        actor_id = parsed["actorId"]
        if (
            not isinstance(actor_id, str)
            or PUBLIC_KEY_PATTERN.fullmatch(actor_id) is None
        ):
            return None
        return parsed

    @staticmethod
    def _snapshot_evidence_array(
        database: Any,
        dispute_id: str,
        evidence_bound: int,
        proof_bound: int,
    ) -> list[dict[str, Any]]:
        # 仅收录该争议且不超过两个全库上界的证据与证明，一律按全局序号升序；
        # 证明经证据表归属到本争议，空数组同样附在每个证据项末尾。
        rows = database.execute(
            "SELECT evidence_seq, evidence_id, actor_id, observed_at_ms, digest"
            " FROM dispute_evidences"
            " WHERE dispute_id = ? AND evidence_seq <= ?"
            " ORDER BY evidence_seq ASC",
            (dispute_id, evidence_bound),
        ).fetchall()
        proof_rows = database.execute(
            "SELECT p.proof_seq AS proof_seq, p.evidence_seq AS evidence_seq,"
            " p.actor_id AS actor_id, p.signature AS signature,"
            " p.verified AS verified, p.created_at_ms AS created_at_ms"
            " FROM dispute_evidence_proofs AS p"
            " JOIN dispute_evidences AS e ON e.evidence_seq = p.evidence_seq"
            " WHERE e.dispute_id = ? AND p.proof_seq <= ?"
            " ORDER BY p.proof_seq ASC",
            (dispute_id, proof_bound),
        ).fetchall()
        proofs_by_evidence: dict[int, list[dict[str, Any]]] = {
            row["evidence_seq"]: [] for row in rows
        }
        for proof in proof_rows:
            proofs_by_evidence.setdefault(proof["evidence_seq"], []).append(
                {
                    "proofSeq": proof["proof_seq"],
                    "actorId": proof["actor_id"],
                    "signature": proof["signature"],
                    "verified": proof["verified"] == 1,
                    "createdAt": proof["created_at_ms"],
                }
            )
        return [
            {
                "evidenceSeq": row["evidence_seq"],
                "evidenceId": row["evidence_id"],
                "actorId": row["actor_id"],
                "observedAt": row["observed_at_ms"],
                "digest": row["digest"],
                "proofs": proofs_by_evidence.get(row["evidence_seq"], []),
            }
            for row in rows
        ]

    def _apply_evidence_snapshot(
        self,
        idempotency_key: str,
        dispute_id: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                # 幂等判定先于资源查询：同键更换路径、正文或认证五段均冲突。
                record = database.execute(
                    "SELECT dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM dispute_evidence_snapshot_idempotency_records"
                    " WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["dispute_id"] == dispute_id
                        and record["request_json"] == request_json
                        and self._auth_record_matches(record, auth)
                    ):
                        return HTTPStatus(record["status"]), json.loads(
                            record["response_json"]
                        )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                dispute = database.execute(
                    "SELECT payer_id, payee_id, state FROM disputes WHERE id = ?",
                    (dispute_id,),
                ).fetchone()
                if dispute is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                actor_id = fields["actorId"]
                if actor_id not in (dispute["payer_id"], dispute["payee_id"]):
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    # 认证机器标识须等于正文 actorId（争议参与方），
                    # 再依次校验时间、密钥、签名、随机数。
                    self._verify_request_auth(
                        database, auth, actor_id, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                if dispute["state"] != "open":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_resolved"}
                # 事务内冻结全库证据、证明序号上界；空库取零。
                evidence_bound = database.execute(
                    "SELECT COALESCE(MAX(evidence_seq), 0) AS bound"
                    " FROM dispute_evidences"
                ).fetchone()["bound"]
                proof_bound = database.execute(
                    "SELECT COALESCE(MAX(proof_seq), 0) AS bound"
                    " FROM dispute_evidence_proofs"
                ).fetchone()["bound"]
                evidence = self._snapshot_evidence_array(
                    database, dispute_id, evidence_bound, proof_bound
                )
                # 摘要文档：争议标识、两个上界、证据数组，紧凑 UTF-8 JSON、无尾换行。
                document = {
                    "disputeId": dispute_id,
                    "evidenceSeqBound": evidence_bound,
                    "proofSeqBound": proof_bound,
                    "evidence": evidence,
                }
                document_bytes = json.dumps(
                    document, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
                digest = hashlib.sha256(document_bytes).hexdigest()
                # 全库唯一持久递增快照序号：取写锁后取最大序号 + 1（空表 1）。
                snapshot_seq = database.execute(
                    "SELECT COALESCE(MAX(snapshot_seq), 0) + 1 AS next_seq"
                    " FROM dispute_evidence_snapshots"
                ).fetchone()["next_seq"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                payload = {
                    "snapshotSeq": snapshot_seq,
                    "evidenceSeqBound": evidence_bound,
                    "proofSeqBound": proof_bound,
                    "digest": digest,
                    "createdBy": actor_id,
                    "createdAt": created_at_ms,
                    "evidence": evidence,
                }
                response_json = json.dumps(payload, separators=(",", ":"))
                database.execute(
                    "INSERT INTO dispute_evidence_snapshots"
                    "(snapshot_seq, dispute_id, evidence_seq_bound,"
                    " proof_seq_bound, digest, created_by, created_at_ms,"
                    " document_json, response_json)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        snapshot_seq,
                        dispute_id,
                        evidence_bound,
                        proof_bound,
                        digest,
                        actor_id,
                        created_at_ms,
                        document_bytes.decode("utf-8"),
                        response_json,
                    ),
                )
                database.execute(
                    "INSERT INTO dispute_evidence_snapshot_idempotency_records"
                    "(key, dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        dispute_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        response_json,
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 快照字节、序号、幂等结果与随机数同一事务原子持久化；
                # 任何失败路径都不到达此处，不消费随机数、不推进序号。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_adjudication_proposal(self, dispute_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 提交提案不接受任何查询参数：参数校验先于体校验与争议查询。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_adjudication_proposal_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 仅支持单一 SLA-Auth：头缺失、重复、结构非法或携带代理头均为非法请求，
        # 且先于争议查询。
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_adjudication_proposal(
            idempotency_key, dispute_id, fields, auth, body_digest
        )
        self._json(status, payload)

    def _read_adjudication_proposal_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != ADJUDICATION_PROPOSAL_FIELDS:
            return None
        actor_id = parsed["actorId"]
        if (
            not isinstance(actor_id, str)
            or PUBLIC_KEY_PATTERN.fullmatch(actor_id) is None
        ):
            return None
        # snapshotSeq 为任意非布尔正整数（无上界）；超出存储范围的值进入关联
        # 检查，与缺失或跨争议快照一样按 404 处理。
        snapshot_seq = parsed["snapshotSeq"]
        if (
            not isinstance(snapshot_seq, int)
            or isinstance(snapshot_seq, bool)
            or snapshot_seq < 1
        ):
            return None
        decision = parsed["decision"]
        if not isinstance(decision, str) or decision not in DISPUTE_DECISIONS:
            return None
        reason_digest = parsed["reasonDigest"]
        if (
            not isinstance(reason_digest, str)
            or PUBLIC_KEY_PATTERN.fullmatch(reason_digest) is None
        ):
            return None
        return parsed

    def _apply_adjudication_proposal(
        self,
        idempotency_key: str,
        dispute_id: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                # 幂等判定先于资源查询：同键更换路径、正文或认证五段均冲突。
                record = database.execute(
                    "SELECT dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM dispute_adjudication_proposal_idempotency_records"
                    " WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["dispute_id"] == dispute_id
                        and record["request_json"] == request_json
                        and self._auth_record_matches(record, auth)
                    ):
                        return HTTPStatus(record["status"]), json.loads(
                            record["response_json"]
                        )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                dispute = database.execute(
                    "SELECT settlement_seq, payer_id, payee_id,"
                    " amount_micros, state"
                    " FROM disputes WHERE id = ?",
                    (dispute_id,),
                ).fetchone()
                if dispute is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                actor_id = fields["actorId"]
                if actor_id not in (dispute["payer_id"], dispute["payee_id"]):
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    # 认证机器标识须等于正文 actorId（争议参与方），
                    # 再依次校验时间、密钥、签名、随机数。
                    self._verify_request_auth(
                        database, auth, actor_id, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                # 仅 open 争议可提交提案；状态判定先于快照关联与唯一性。
                if dispute["state"] != "open":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_resolved"}
                # 快照须存在且属于本争议；缺失或跨争议引用均为 404。
                # 超出 SQLite 整数范围的序号必然不存在，直接按缺失处理。
                snapshot = None
                if fields["snapshotSeq"] <= INT64_MAX:
                    snapshot = database.execute(
                        "SELECT digest FROM dispute_evidence_snapshots"
                        " WHERE dispute_id = ? AND snapshot_seq = ?",
                        (dispute_id, fields["snapshotSeq"]),
                    ).fetchone()
                if snapshot is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                # 同一参与方仅留一份提案：写事务内复查 + 唯一约束双保险。
                mine = database.execute(
                    "SELECT 1 FROM dispute_adjudication_proposals"
                    " WHERE dispute_id = ? AND actor_id = ?",
                    (dispute_id, actor_id),
                ).fetchone()
                if mine is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "proposal_exists"}
                other = database.execute(
                    "SELECT snapshot_seq, decision"
                    " FROM dispute_adjudication_proposals"
                    " WHERE dispute_id = ? AND actor_id != ?",
                    (dispute_id, actor_id),
                ).fetchone()
                amount = dispute["amount_micros"]
                decision = fields["decision"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                new_state: str | None = None
                if (
                    other is not None
                    and other["snapshot_seq"] == fields["snapshotSeq"]
                    and other["decision"] == decision
                ):
                    # 双方引用同一快照且决定一致：原子执行既有 release/refund 裁决。
                    result = "resolved"
                    response_amount: int | None = amount
                    if decision == "refund":
                        balance_record = database.execute(
                            "SELECT balance_micros FROM ledger_accounts"
                            " WHERE account_id = ?",
                            (dispute["payee_id"],),
                        ).fetchone()
                        payee_balance = (
                            balance_record["balance_micros"]
                            if balance_record is not None
                            else 0
                        )
                        # 余额不足：第二份提案、账本、事件、幂等结果与随机数均不保存。
                        if payee_balance < amount:
                            database.execute("ROLLBACK")
                            return HTTPStatus.CONFLICT, {
                                "error": "insufficient_funds"
                            }
                        payee_after = self._adjust_account(
                            database, dispute["payee_id"], -amount
                        )
                        payer_after = self._adjust_account(
                            database, dispute["payer_id"], amount
                        )
                        self._record_entry(
                            database, "dispute_refund",
                            dispute["settlement_seq"],
                            dispute["payee_id"], -amount, payee_after,
                            created_at_ms,
                        )
                        self._record_entry(
                            database, "dispute_refund",
                            dispute["settlement_seq"],
                            dispute["payer_id"], amount, payer_after,
                            created_at_ms,
                        )
                        new_state = "refunded"
                    else:
                        new_state = "released"
                elif other is None:
                    # 首方提案：冻结快照摘要，等待另一方。
                    result = "pending"
                    response_amount = None
                else:
                    # 快照或决定不同：保存第二份提案，争议保持 open 与资金冻结。
                    result = "disagreement"
                    response_amount = None
                # 每份成功提案分配全库唯一、持久递增序号（空表为 1，跨争议唯一）。
                proposal_seq = database.execute(
                    "SELECT COALESCE(MAX(proposal_seq), 0) + 1 AS next_seq"
                    " FROM dispute_adjudication_proposals"
                ).fetchone()["next_seq"]
                payload = {
                    "proposalSeq": proposal_seq,
                    "result": result,
                    "decision": decision,
                    "amount": response_amount,
                    "createdAt": created_at_ms,
                }
                response_json = json.dumps(payload, separators=(",", ":"))
                try:
                    database.execute(
                        "INSERT INTO dispute_adjudication_proposals"
                        "(proposal_seq, dispute_id, actor_id, snapshot_seq,"
                        " snapshot_digest, decision, reason_digest, result,"
                        " amount_micros, created_at_ms, response_json)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            proposal_seq,
                            dispute_id,
                            actor_id,
                            fields["snapshotSeq"],
                            snapshot["digest"],
                            decision,
                            fields["reasonDigest"],
                            result,
                            response_amount,
                            created_at_ms,
                            response_json,
                        ),
                    )
                except sqlite3.IntegrityError:
                    # 同方异键并发：唯一约束兜底，至多保留一份。
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "proposal_exists"}
                if new_state is not None:
                    # 裁决结果、余额、分录与生命周期事件同事务原子提交。
                    database.execute(
                        "UPDATE disputes SET state = ? WHERE id = ?",
                        (new_state, dispute_id),
                    )
                    next_event = database.execute(
                        "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq"
                        " FROM dispute_events"
                    ).fetchone()
                    database.execute(
                        "INSERT INTO dispute_events"
                        "(event_seq, dispute_id, type, created_at_ms)"
                        " VALUES (?, ?, ?, ?)",
                        (next_event["next_seq"], dispute_id, new_state, created_at_ms),
                    )
                database.execute(
                    "INSERT INTO dispute_adjudication_proposal_idempotency_records"
                    "(key, dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        dispute_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        response_json,
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 提案、冻结摘要、幂等结果、随机数及资金与生命周期事件同事务提交；
                # 任何失败路径都不到达此处，不消费随机数、不推进序号。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _create_escalation(self, dispute_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 升级不接受任何查询参数：参数校验先于体校验与争议查询。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_escalation_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 仅支持单一 SLA-Auth：头缺失、重复、结构非法或携带代理头均为非法请求，
        # 且先于争议查询。
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_escalation(
            idempotency_key, dispute_id, fields, auth, body_digest
        )
        self._json(status, payload)

    def _read_escalation_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != ESCALATION_FIELDS:
            return None
        actor_id = parsed["actorId"]
        if (
            not isinstance(actor_id, str)
            or PUBLIC_KEY_PATTERN.fullmatch(actor_id) is None
        ):
            return None
        return parsed

    def _apply_escalation(
        self,
        idempotency_key: str,
        dispute_id: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                # 幂等判定先于资源查询：同键更换路径、正文或认证五段均冲突。
                record = database.execute(
                    "SELECT dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM dispute_escalation_idempotency_records"
                    " WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["dispute_id"] == dispute_id
                        and record["request_json"] == request_json
                        and self._auth_record_matches(record, auth)
                    ):
                        return HTTPStatus(record["status"]), json.loads(
                            record["response_json"]
                        )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                dispute = database.execute(
                    "SELECT settlement_seq, payer_id, payee_id,"
                    " amount_micros, state"
                    " FROM disputes WHERE id = ?",
                    (dispute_id,),
                ).fetchone()
                if dispute is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                actor_id = fields["actorId"]
                if actor_id not in (dispute["payer_id"], dispute["payee_id"]):
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    # 认证机器标识须等于正文 actorId（争议参与方），
                    # 再依次校验时间、密钥、签名、随机数。
                    self._verify_request_auth(
                        database, auth, actor_id, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                # 已有升级记录（异键重复升级）：成功升级与状态变更原子提交，
                # 故记录存在即已升级；与直接 resolution 并发时仅先提交者生效。
                existing = database.execute(
                    "SELECT 1 FROM dispute_escalations WHERE dispute_id = ?",
                    (dispute_id,),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "escalation_exists"}
                # 仅 open 争议可升级；已裁决（含被直接 resolution）为已解决。
                if dispute["state"] != "open":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_resolved"}
                # 须恰有两份提案且结果为分歧（第二份为 disagreement）；
                # 分歧提案不完整为冲突。
                proposals = database.execute(
                    "SELECT proposal_seq, snapshot_digest, result, created_at_ms"
                    " FROM dispute_adjudication_proposals"
                    " WHERE dispute_id = ? ORDER BY proposal_seq ASC",
                    (dispute_id,),
                ).fetchall()
                if (
                    len(proposals) != 2
                    or proposals[1]["result"] != "disagreement"
                ):
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                # 截止时间固定为第二份提案创建后二十四小时；提前请求为 not_due。
                deadline_ms = proposals[1]["created_at_ms"] + ESCALATION_DELAY_MS
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                if created_at_ms < deadline_ms:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "not_due"}
                amount = dispute["amount_micros"]
                balance_record = database.execute(
                    "SELECT balance_micros FROM ledger_accounts"
                    " WHERE account_id = ?",
                    (dispute["payee_id"],),
                ).fetchone()
                payee_balance = (
                    balance_record["balance_micros"]
                    if balance_record is not None
                    else 0
                )
                # 收款方总余额不足：升级、账本、事件、幂等结果与随机数均不保存。
                if payee_balance < amount:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "insufficient_funds"}
                # 全库唯一持久递增升级序号：取写锁后取最大序号 + 1（空表 1）。
                escalation_seq = database.execute(
                    "SELECT COALESCE(MAX(escalation_seq), 0) + 1 AS next_seq"
                    " FROM dispute_escalations"
                ).fetchone()["next_seq"]
                # 冻结额自收款方划入外部清算账户：双方各写一笔
                # dispute_escalation 分录，referenceSeq 取升级序号。
                payee_after = self._adjust_account(
                    database, dispute["payee_id"], -amount
                )
                clearing_after = self._adjust_account(
                    database, CLEARING_ACCOUNT_ID, amount
                )
                self._record_entry(
                    database, "dispute_escalation", escalation_seq,
                    dispute["payee_id"], -amount, payee_after, created_at_ms,
                )
                self._record_entry(
                    database, "dispute_escalation", escalation_seq,
                    CLEARING_ACCOUNT_ID, amount, clearing_after, created_at_ms,
                )
                database.execute(
                    "UPDATE disputes SET state = 'escalated' WHERE id = ?",
                    (dispute_id,),
                )
                # 生命周期事件与升级、余额、分录及幂等结果同事务原子提交。
                next_event = database.execute(
                    "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq"
                    " FROM dispute_events"
                ).fetchone()
                database.execute(
                    "INSERT INTO dispute_events"
                    "(event_seq, dispute_id, type, created_at_ms)"
                    " VALUES (?, ?, 'escalated', ?)",
                    (next_event["next_seq"], dispute_id, created_at_ms),
                )
                # 记录冻结两份提案序号及对应快照摘要。
                database.execute(
                    "INSERT INTO dispute_escalations"
                    "(escalation_seq, dispute_id, first_proposal_seq,"
                    " second_proposal_seq, first_snapshot_digest,"
                    " second_snapshot_digest, deadline_ms, amount_micros,"
                    " created_at_ms)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        escalation_seq,
                        dispute_id,
                        proposals[0]["proposal_seq"],
                        proposals[1]["proposal_seq"],
                        proposals[0]["snapshot_digest"],
                        proposals[1]["snapshot_digest"],
                        deadline_ms,
                        amount,
                        created_at_ms,
                    ),
                )
                payload = {
                    "escalationSeq": escalation_seq,
                    "deadline": deadline_ms,
                    "amount": amount,
                    "createdAt": created_at_ms,
                }
                database.execute(
                    "INSERT INTO dispute_escalation_idempotency_records"
                    "(key, dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        dispute_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 升级、资金、事件、幂等结果与随机数同一事务原子提交；
                # 任何失败路径都不到达此处，不消费随机数、不推进序号。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except sqlite3.IntegrityError:
                # 异键并发升级同一争议：唯一约束兜底，至多一项成功。
                database.execute("ROLLBACK")
                return HTTPStatus.CONFLICT, {"error": "escalation_exists"}
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _get_escalations(self, dispute_id: str, query: str) -> None:
        # limit、cursor=cut:lastSeq 的格式、缺省值、认证、错误次序与随机数消费
        # 均沿用裁决提案集合读取，仅序号改为 escalationSeq。
        parsed = self._parse_evaluation_query(
            query, DISPUTE_ESCALATIONS_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return

        def build(database: Any) -> dict[str, Any] | None:
            # 首页以读事务起点的全库最大升级序号冻结 cut；空库为 0。
            max_record = database.execute(
                "SELECT MAX(escalation_seq) AS current_max"
                " FROM dispute_escalations"
            ).fetchone()
            current_max = max_record["current_max"] or 0
            if cursor is None:
                cut = current_max
                last_seq = 0
            else:
                cut, last_seq = cursor
                if cut > current_max:
                    return None
                # 锚点须属于目标争议且在当前快照内；属于其他争议或不存在均非法。
                anchor = database.execute(
                    "SELECT 1 FROM dispute_escalations"
                    " WHERE dispute_id = ? AND escalation_seq = ?"
                    " AND escalation_seq <= ?",
                    (dispute_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            rows = database.execute(
                "SELECT escalation_seq, first_proposal_seq, second_proposal_seq,"
                " first_snapshot_digest, second_snapshot_digest, deadline_ms,"
                " amount_micros, created_at_ms"
                " FROM dispute_escalations"
                " WHERE dispute_id = ? AND escalation_seq <= ?"
                " AND escalation_seq > ?"
                " ORDER BY escalation_seq ASC"
                " LIMIT ?",
                (dispute_id, cut, last_seq, limit + 1),
            ).fetchall()
            has_next = len(rows) > limit
            page = rows[:limit]
            escalations = [
                {
                    "escalationSeq": row["escalation_seq"],
                    "firstProposalSeq": row["first_proposal_seq"],
                    "firstSnapshotDigest": row["first_snapshot_digest"],
                    "secondProposalSeq": row["second_proposal_seq"],
                    "secondSnapshotDigest": row["second_snapshot_digest"],
                    "deadline": row["deadline_ms"],
                    "amount": row["amount_micros"],
                    "createdAt": row["created_at_ms"],
                }
                for row in page
            ]
            next_cursor = (
                f"{cut}:{page[-1]['escalation_seq']}" if has_next else None
            )
            return {"escalations": escalations, "nextCursor": next_cursor}

        status, error, payload = self._read_snapshot_get(
            dispute_id, auth, build, HTTPStatus.BAD_REQUEST
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def _create_arbitration(self, dispute_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 仲裁不接受任何查询参数：参数校验先于体校验与争议查询。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_arbitration_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 仅支持单一 SLA-Auth：头缺失、重复、结构非法或携带代理头均为非法请求，
        # 且先于争议查询。
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_arbitration(
            idempotency_key, dispute_id, fields, auth, body_digest
        )
        self._json(status, payload)

    def _read_arbitration_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != ARBITRATION_FIELDS:
            return None
        decision = parsed["decision"]
        if not isinstance(decision, str) or decision not in DISPUTE_DECISIONS:
            return None
        return parsed

    def _apply_arbitration(
        self,
        idempotency_key: str,
        dispute_id: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                # 幂等判定先于资源查询：同键更换路径、正文或认证五段均冲突。
                record = database.execute(
                    "SELECT dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM dispute_arbitration_idempotency_records"
                    " WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["dispute_id"] == dispute_id
                        and record["request_json"] == request_json
                        and self._auth_record_matches(record, auth)
                    ):
                        return HTTPStatus(record["status"]), json.loads(
                            record["response_json"]
                        )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                dispute = database.execute(
                    "SELECT settlement_seq, payer_id, payee_id,"
                    " amount_micros, state"
                    " FROM disputes WHERE id = ?",
                    (dispute_id,),
                ).fetchone()
                if dispute is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                # 认证机器须为启动时配置的仲裁机器；未配置或身份不符均为 403。
                if auth.machine_id not in self.server.arbitrators:
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    # 仲裁机器身份已判定，再依次校验时间、密钥、签名、随机数。
                    self._verify_request_principal(
                        database, auth, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                # 已有仲裁记录（异键重复仲裁）：成功仲裁与状态变更原子提交，
                # 故记录存在即已终局；与其他终局入口并发时仅先提交者生效。
                existing = database.execute(
                    "SELECT 1 FROM dispute_arbitrations WHERE dispute_id = ?",
                    (dispute_id,),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "arbitration_exists"}
                # 仅 escalated 争议可仲裁；其余状态（含已裁决）为已解决。
                if dispute["state"] != "escalated":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_resolved"}
                # 升级记录须存在且属于本争议；缺失或错属为冲突。
                escalation = database.execute(
                    "SELECT escalation_seq, first_proposal_seq,"
                    " second_proposal_seq, first_snapshot_digest,"
                    " second_snapshot_digest"
                    " FROM dispute_escalations WHERE dispute_id = ?",
                    (dispute_id,),
                ).fetchone()
                if escalation is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                amount = dispute["amount_micros"]
                balance_record = database.execute(
                    "SELECT balance_micros FROM ledger_accounts"
                    " WHERE account_id = ?",
                    (CLEARING_ACCOUNT_ID,),
                ).fetchone()
                clearing_balance = (
                    balance_record["balance_micros"]
                    if balance_record is not None
                    else 0
                )
                # 清算账户以负余额持有系统内资金：持有额不足以覆盖款项时
                # 仲裁、账本、事件、幂等结果与随机数均不保存。
                if clearing_balance + amount > 0:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "insufficient_funds"}
                # 全库唯一持久递增仲裁序号：取写锁后取最大序号 + 1（空表 1）。
                arbitration_seq = database.execute(
                    "SELECT COALESCE(MAX(arbitration_seq), 0) + 1 AS next_seq"
                    " FROM dispute_arbitrations"
                ).fetchone()["next_seq"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                decision = fields["decision"]
                # release 整笔交还原收款方，refund 整笔退还原付款方；
                # 款项自外部清算账户划出，双方各写一笔 dispute_arbitration
                # 分录，referenceSeq 取仲裁序号。
                recipient_id = (
                    dispute["payee_id"]
                    if decision == "release"
                    else dispute["payer_id"]
                )
                new_state = "released" if decision == "release" else "refunded"
                clearing_after = self._adjust_account(
                    database, CLEARING_ACCOUNT_ID, -amount
                )
                recipient_after = self._adjust_account(
                    database, recipient_id, amount
                )
                self._record_entry(
                    database, "dispute_arbitration", arbitration_seq,
                    CLEARING_ACCOUNT_ID, -amount, clearing_after, created_at_ms,
                )
                self._record_entry(
                    database, "dispute_arbitration", arbitration_seq,
                    recipient_id, amount, recipient_after, created_at_ms,
                )
                database.execute(
                    "UPDATE disputes SET state = ? WHERE id = ?",
                    (new_state, dispute_id),
                )
                # 生命周期事件与仲裁、余额、分录及幂等结果同事务原子提交。
                next_event = database.execute(
                    "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq"
                    " FROM dispute_events"
                ).fetchone()
                database.execute(
                    "INSERT INTO dispute_events"
                    "(event_seq, dispute_id, type, created_at_ms)"
                    " VALUES (?, ?, ?, ?)",
                    (next_event["next_seq"], dispute_id, new_state, created_at_ms),
                )
                # 冻结升级关联的两份提案序号及对应快照摘要。
                database.execute(
                    "INSERT INTO dispute_arbitrations"
                    "(arbitration_seq, dispute_id, escalation_seq, arbitrator_id,"
                    " decision, amount_micros, first_proposal_seq,"
                    " second_proposal_seq, first_snapshot_digest,"
                    " second_snapshot_digest, created_at_ms)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        arbitration_seq,
                        dispute_id,
                        escalation["escalation_seq"],
                        auth.machine_id,
                        decision,
                        amount,
                        escalation["first_proposal_seq"],
                        escalation["second_proposal_seq"],
                        escalation["first_snapshot_digest"],
                        escalation["second_snapshot_digest"],
                        created_at_ms,
                    ),
                )
                payload = {
                    "arbitrationSeq": arbitration_seq,
                    "decision": decision,
                    "amount": amount,
                    "arbitratorId": auth.machine_id,
                    "createdAt": created_at_ms,
                }
                database.execute(
                    "INSERT INTO dispute_arbitration_idempotency_records"
                    "(key, dispute_id, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        dispute_id,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 仲裁、资金、事件、幂等结果与随机数同一事务原子提交；
                # 任何失败路径都不到达此处，不消费随机数、不推进序号。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except sqlite3.IntegrityError:
                # 异键并发仲裁同一争议：唯一约束兜底，至多一项成功。
                database.execute("ROLLBACK")
                return HTTPStatus.CONFLICT, {"error": "arbitration_exists"}
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _get_arbitrations(self, dispute_id: str, query: str) -> None:
        # limit、cursor=cut:lastSeq 的格式、缺省值、认证、错误次序与随机数消费
        # 均沿用升级记录集合读取，仅序号改为 arbitrationSeq。
        parsed = self._parse_evaluation_query(
            query, DISPUTE_ARBITRATIONS_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return

        def build(database: Any) -> dict[str, Any] | None:
            # 首页以读事务起点的全库最大仲裁序号冻结 cut；空库为 0。
            max_record = database.execute(
                "SELECT MAX(arbitration_seq) AS current_max"
                " FROM dispute_arbitrations"
            ).fetchone()
            current_max = max_record["current_max"] or 0
            if cursor is None:
                cut = current_max
                last_seq = 0
            else:
                cut, last_seq = cursor
                if cut > current_max:
                    return None
                # 锚点须属于目标争议且在当前快照内；属于其他争议或不存在均非法。
                anchor = database.execute(
                    "SELECT 1 FROM dispute_arbitrations"
                    " WHERE dispute_id = ? AND arbitration_seq = ?"
                    " AND arbitration_seq <= ?",
                    (dispute_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            rows = database.execute(
                "SELECT arbitration_seq, escalation_seq, arbitrator_id, decision,"
                " amount_micros, created_at_ms"
                " FROM dispute_arbitrations"
                " WHERE dispute_id = ? AND arbitration_seq <= ?"
                " AND arbitration_seq > ?"
                " ORDER BY arbitration_seq ASC"
                " LIMIT ?",
                (dispute_id, cut, last_seq, limit + 1),
            ).fetchall()
            has_next = len(rows) > limit
            page = rows[:limit]
            arbitrations = [
                {
                    "arbitrationSeq": row["arbitration_seq"],
                    "escalationSeq": row["escalation_seq"],
                    "arbitratorId": row["arbitrator_id"],
                    "decision": row["decision"],
                    "amount": row["amount_micros"],
                    "createdAt": row["created_at_ms"],
                }
                for row in page
            ]
            next_cursor = (
                f"{cut}:{page[-1]['arbitration_seq']}" if has_next else None
            )
            return {"arbitrations": arbitrations, "nextCursor": next_cursor}

        status, error, payload = self._read_snapshot_get(
            dispute_id, auth, build, HTTPStatus.BAD_REQUEST
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def _create_evidence_proof(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # POST 证明不接受任何查询参数：参数校验先于体校验与资源查询。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 先读并校验正文：升级前既有幂等记录可在无认证头时按原请求先行重放。
        raw_body = self._read_raw_body()
        fields = (
            None
            if raw_body is None
            else self._read_evidence_proof_object(raw_body)
        )
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        legacy = self._try_legacy_replay(
            "dispute_evidence_proof_idempotency_records",
            idempotency_key,
            request_json,
            "",
            [],
        )
        if legacy is not None:
            self._json(legacy[0], legacy[1])
            return
        # 非旧记录重放：认证结构必须合法，且先于查证据等资源与业务检查。
        # 可用单值 SLA-Delegation 替代 SLA-Auth，两者并存即非法。
        sla_auth_values = self.headers.get_all(SLA_AUTH_HEADER)
        delegation_values = self.headers.get_all(SLA_DELEGATION_HEADER)
        if sla_auth_values and delegation_values:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        delegation = bool(delegation_values)
        auth = (
            self._parse_sla_delegation() if delegation else self._parse_sla_auth()
        )
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_evidence_proof(
            idempotency_key, fields, auth, body_digest, delegation
        )
        self._json(status, payload)

    def _read_evidence_proof_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != EVIDENCE_PROOF_FIELDS:
            return None
        evidence_seq = parsed["evidenceSeq"]
        if not isinstance(evidence_seq, int) or isinstance(evidence_seq, bool):
            return None
        if evidence_seq < 1:
            return None
        actor_id = parsed["actorId"]
        if (
            not isinstance(actor_id, str)
            or PUBLIC_KEY_PATTERN.fullmatch(actor_id) is None
        ):
            return None
        # 128 位小写十六进制签名，长度恰为 128 个字符。
        signature = parsed["signature"]
        if not isinstance(signature, str) or len(signature) != 128:
            return None
        if not all(char in "0123456789abcdef" for char in signature):
            return None
        return parsed

    def _apply_evidence_proof(
        self,
        idempotency_key: str,
        fields: dict[str, Any],
        auth: SlaAuth,
        body_digest: str,
        delegation: bool,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        evidence_seq = fields["evidenceSeq"]
        standard_path = "/v1/evidence-proofs"
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                # 幂等判定先于一切资源查询：同键异证据、签名者或签名均冲突。
                record = database.execute(
                    "SELECT request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM dispute_evidence_proof_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["request_json"] == request_json:
                        # 旧记录（认证列为 NULL）直接重放且不补认证数据；新记录须五段一致。
                        if record["auth_machine_id"] is None or self._auth_record_matches(
                            record, auth
                        ):
                            return HTTPStatus(record["status"]), json.loads(
                                record["response_json"]
                            )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                evidence = None
                if evidence_seq <= INT64_MAX:
                    evidence = database.execute(
                        "SELECT e.dispute_id AS dispute_id, e.digest AS digest,"
                        " d.payer_id AS payer_id, d.payee_id AS payee_id,"
                        " d.state AS state"
                        " FROM dispute_evidences AS e"
                        " JOIN disputes AS d ON d.id = e.dispute_id"
                        " WHERE e.evidence_seq = ?",
                        (evidence_seq,),
                    ).fetchone()
                if evidence is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                actor_id = fields["actorId"]
                if actor_id not in (evidence["payer_id"], evidence["payee_id"]):
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    # 认证机器标识须等于正文 actorId，再依次校验时间、密钥、签名、随机数；
                    # 代理凭证改按委托记录与代理公钥校验，并须绑定本条证据。
                    if delegation:
                        self._verify_delegation_auth(
                            database,
                            auth,
                            actor_id,
                            standard_path,
                            body_digest,
                            DELEGATION_OPERATION_PROOF_WRITE,
                            evidence_seq,
                        )
                    else:
                        self._verify_request_auth(
                            database, auth, actor_id, standard_path, body_digest
                        )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                # 认证全部通过后执行既有业务判定（争议状态、证明验签与重复证明）。
                if evidence["state"] != "open":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_resolved"}
                # 用登记的 publicKey 按 RFC 8032 验证 Ed25519 签名；
                # 参与方必为已登记机器，查不到公钥等同验签失败。
                machine = database.execute(
                    "SELECT public_key FROM machines WHERE id = ?",
                    (actor_id,),
                ).fetchone()
                signature_valid = False
                if machine is not None:
                    message = (
                        f"proof-v1\n{evidence['dispute_id']}\n{evidence_seq}\n"
                        f"{evidence['digest']}\n{actor_id}"
                    ).encode("utf-8")
                    signature_valid = ed25519_verify(
                        bytes.fromhex(machine["public_key"]),
                        message,
                        bytes.fromhex(fields["signature"]),
                    )
                if not signature_valid:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "invalid_signature"}
                # 每条证据每个签名者至多一条证明：写事务串行下复查 + 唯一约束，
                # 判定位于验签之后，异键并发至多一项成功。
                existing = database.execute(
                    "SELECT 1 FROM dispute_evidence_proofs"
                    " WHERE evidence_seq = ? AND actor_id = ?",
                    (evidence_seq, actor_id),
                ).fetchone()
                if existing is not None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "proof_exists"}
                # 全库唯一持久递增证明序号：取写锁后取最大序号 + 1（空表 1）。
                next_record = database.execute(
                    "SELECT COALESCE(MAX(proof_seq), 0) + 1 AS next_seq"
                    " FROM dispute_evidence_proofs"
                ).fetchone()
                proof_seq = next_record["next_seq"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                database.execute(
                    "INSERT INTO dispute_evidence_proofs"
                    "(proof_seq, evidence_seq, actor_id, signature,"
                    " verified, created_at_ms)"
                    " VALUES (?, ?, ?, ?, 1, ?)",
                    (
                        proof_seq,
                        evidence_seq,
                        actor_id,
                        fields["signature"],
                        created_at_ms,
                    ),
                )
                payload = {
                    "proofSeq": proof_seq,
                    "verified": True,
                    "createdAt": created_at_ms,
                }
                database.execute(
                    "INSERT INTO dispute_evidence_proof_idempotency_records"
                    "(key, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        request_json,
                        int(HTTPStatus.CREATED),
                        json.dumps(payload, separators=(",", ":")),
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 只有首次证明成功才原子写入随机数；任何失败均不推进证明或事件序号。
                if delegation:
                    # 代理凭证一次性：消费标记与证明序号、幂等结果、随机数同事务提交；
                    # 失败或同键重放均不消费凭证。
                    database.execute(
                        "UPDATE machine_delegations SET consumed = 1 WHERE id = ?",
                        (auth.machine_id,),
                    )
                    # 成功消费事件同事务追加并保存标准路径与原始正文 SHA-256 摘要；
                    # 已裁决、验签失败、重复证明等失败路径不到达此处，不推进事件序号。
                    self._append_delegation_event(
                        database,
                        auth.machine_id,
                        "consumed",
                        created_at_ms,
                        standard_path,
                        body_digest,
                    )
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _get_evidence_proofs(self, evidence_seq_text: str, query: str) -> None:
        # 查询参数、错误次序、cut:lastSeq 游标与并发快照语义均沿用评估历史查询。
        parsed = self._parse_evaluation_query(query, DISPUTE_EVIDENCE_QUERY_PARAMS)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        # 证据序号非法（非无前导零十进制正整数）按不存在处理。
        evidence_seq: int | None = None
        if DECIMAL_PATTERN.fullmatch(evidence_seq_text) is not None:
            value = int(evidence_seq_text)
            if 1 <= value <= INT64_MAX:
                evidence_seq = value
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN")
            try:
                if evidence_seq is None or database.execute(
                    "SELECT 1 FROM dispute_evidences WHERE evidence_seq = ?",
                    (evidence_seq,),
                ).fetchone() is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                # cut 为读事务起点的全库最大证明序号（空库为 0），跨证据全局。
                max_record = database.execute(
                    "SELECT MAX(proof_seq) AS current_max"
                    " FROM dispute_evidence_proofs"
                ).fetchone()
                current_max = max_record["current_max"]
                if current_max is None:
                    current_max = 0
                if cursor is None:
                    cut = current_max
                    last_seq = 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM dispute_evidence_proofs"
                        " WHERE evidence_seq = ? AND proof_seq = ? AND proof_seq <= ?",
                        (evidence_seq, last_seq, cut),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                rows = database.execute(
                    "SELECT proof_seq, actor_id, signature, verified, created_at_ms"
                    " FROM dispute_evidence_proofs"
                    " WHERE evidence_seq = ? AND proof_seq <= ? AND proof_seq > ?"
                    " ORDER BY proof_seq ASC"
                    " LIMIT ?",
                    (evidence_seq, cut, last_seq, limit + 1),
                ).fetchall()
                database.execute("ROLLBACK")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        has_next = len(rows) > limit
        page = rows[:limit]
        proofs = [
            {
                "proofSeq": row["proof_seq"],
                "actorId": row["actor_id"],
                "signature": row["signature"],
                "verified": row["verified"] == 1,
                "createdAt": row["created_at_ms"],
            }
            for row in page
        ]
        if has_next:
            next_cursor = f"{cut}:{page[-1]['proof_seq']}"
        else:
            next_cursor = None
        self._json(
            HTTPStatus.OK,
            {"proofs": proofs, "nextCursor": next_cursor},
        )

    def _read_snapshot_get(
        self,
        dispute_id: str,
        auth: SlaAuth,
        build_snapshot: Any,
        missing_status: HTTPStatus,
    ) -> Any:
        # 快照审计读取共用判定：争议存在 404、参与方身份 403、认证有效性 401、
        # 随机数 409、游标关联 400。GET 无正文，摘要按空字节 SHA-256 计算；
        # 仅全部判定通过且读取完成后才消费随机数并提交，任何失败均回滚。
        body_digest = hashlib.sha256(b"").hexdigest()
        standard_path = urlsplit(self.path).path
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                dispute = database.execute(
                    "SELECT payer_id, payee_id FROM disputes WHERE id = ?",
                    (dispute_id,),
                ).fetchone()
                if dispute is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, "not_found", None
                if auth.machine_id not in (
                    dispute["payer_id"],
                    dispute["payee_id"],
                ):
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, "forbidden", None
                try:
                    self._verify_request_principal(
                        database, auth, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, rejected.error, None
                result = build_snapshot(database)
                if result is None:
                    database.execute("ROLLBACK")
                    # 单笔读取：快照缺失为 404；集合读取：cut/锚点非法为 400。
                    return (
                        missing_status,
                        "not_found"
                        if missing_status == HTTPStatus.NOT_FOUND
                        else "invalid_request",
                        None,
                    )
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        return HTTPStatus.OK, None, result

    def _get_evidence_snapshot(
        self, dispute_id: str, snapshot_seq_text: str, query: str
    ) -> None:
        # 单笔读取不接受任何查询参数：参数校验先于认证结构与争议查询。
        if parse_qsl(query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 序号须为无前导零十进制正整数；非法按不存在处理。
        snapshot_seq: int | None = None
        if DECIMAL_PATTERN.fullmatch(snapshot_seq_text) is not None:
            value = int(snapshot_seq_text)
            if 1 <= value <= INT64_MAX:
                snapshot_seq = value
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return

        def build(database: Any) -> dict[str, Any] | None:
            # 成功返回创建时的完整对象：直接回放首次响应字节对应的 JSON。
            record = database.execute(
                "SELECT response_json FROM dispute_evidence_snapshots"
                " WHERE dispute_id = ? AND snapshot_seq = ?",
                (dispute_id, snapshot_seq),
            ).fetchone()
            if record is None:
                return None
            return json.loads(record["response_json"])

        status, error, payload = self._read_snapshot_get(
            dispute_id, auth, build, HTTPStatus.NOT_FOUND
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def _get_evidence_snapshots(self, dispute_id: str, query: str) -> None:
        # limit、cursor=cut:lastSeq 的格式、缺省值与校验次序沿用评估历史查询。
        parsed = self._parse_evaluation_query(
            query, DISPUTE_EVIDENCE_SNAPSHOTS_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return

        def build(database: Any) -> dict[str, Any] | None:
            # 首页以读事务起点的全库最大快照序号冻结 cut；空库为 0。
            max_record = database.execute(
                "SELECT MAX(snapshot_seq) AS current_max"
                " FROM dispute_evidence_snapshots"
            ).fetchone()
            current_max = max_record["current_max"] or 0
            if cursor is None:
                cut = current_max
                last_seq = 0
            else:
                cut, last_seq = cursor
                if cut > current_max:
                    return None
                # 锚点须属于目标争议且在当前快照内；属于其他争议或不存在均非法。
                anchor = database.execute(
                    "SELECT 1 FROM dispute_evidence_snapshots"
                    " WHERE dispute_id = ? AND snapshot_seq = ? AND snapshot_seq <= ?",
                    (dispute_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            rows = database.execute(
                "SELECT snapshot_seq, response_json FROM dispute_evidence_snapshots"
                " WHERE dispute_id = ? AND snapshot_seq <= ? AND snapshot_seq > ?"
                " ORDER BY snapshot_seq ASC"
                " LIMIT ?",
                (dispute_id, cut, last_seq, limit + 1),
            ).fetchall()
            has_next = len(rows) > limit
            page = rows[:limit]
            snapshots = [json.loads(row["response_json"]) for row in page]
            next_cursor = (
                f"{cut}:{page[-1]['snapshot_seq']}" if has_next else None
            )
            return {"snapshots": snapshots, "nextCursor": next_cursor}

        status, error, payload = self._read_snapshot_get(
            dispute_id, auth, build, HTTPStatus.BAD_REQUEST
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def _get_adjudication_proposals(self, dispute_id: str, query: str) -> None:
        # limit、cursor=cut:lastSeq 的格式、缺省值、认证、错误次序与随机数消费
        # 均沿用证据快照集合读取，仅序号改为 proposalSeq。
        parsed = self._parse_evaluation_query(
            query, DISPUTE_ADJUDICATION_PROPOSALS_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return

        def build(database: Any) -> dict[str, Any] | None:
            # 首页以读事务起点的全库最大提案序号冻结 cut；空库为 0。
            max_record = database.execute(
                "SELECT MAX(proposal_seq) AS current_max"
                " FROM dispute_adjudication_proposals"
            ).fetchone()
            current_max = max_record["current_max"] or 0
            if cursor is None:
                cut = current_max
                last_seq = 0
            else:
                cut, last_seq = cursor
                if cut > current_max:
                    return None
                # 锚点须属于目标争议且在当前快照内；属于其他争议或不存在均非法。
                anchor = database.execute(
                    "SELECT 1 FROM dispute_adjudication_proposals"
                    " WHERE dispute_id = ? AND proposal_seq = ? AND proposal_seq <= ?",
                    (dispute_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            rows = database.execute(
                "SELECT proposal_seq, actor_id, snapshot_seq, snapshot_digest,"
                " decision, reason_digest, result, amount_micros, created_at_ms"
                " FROM dispute_adjudication_proposals"
                " WHERE dispute_id = ? AND proposal_seq <= ? AND proposal_seq > ?"
                " ORDER BY proposal_seq ASC"
                " LIMIT ?",
                (dispute_id, cut, last_seq, limit + 1),
            ).fetchall()
            has_next = len(rows) > limit
            page = rows[:limit]
            # 裁决后仍可查看提案、首方冻结的快照摘要与结果；未裁决金额为 null。
            proposals = [
                {
                    "proposalSeq": row["proposal_seq"],
                    "actorId": row["actor_id"],
                    "snapshotSeq": row["snapshot_seq"],
                    "snapshotDigest": row["snapshot_digest"],
                    "decision": row["decision"],
                    "reasonDigest": row["reason_digest"],
                    "result": row["result"],
                    "amount": row["amount_micros"],
                    "createdAt": row["created_at_ms"],
                }
                for row in page
            ]
            next_cursor = (
                f"{cut}:{page[-1]['proposal_seq']}" if has_next else None
            )
            return {"proposals": proposals, "nextCursor": next_cursor}

        status, error, payload = self._read_snapshot_get(
            dispute_id, auth, build, HTTPStatus.BAD_REQUEST
        )
        if payload is None:
            self._json(status, {"error": error})
            return
        self._json(status, payload)

    def _resolve_dispute(self, dispute_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_resolution_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_resolution(idempotency_key, dispute_id, fields)
        self._json(status, payload)

    def _read_resolution_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != RESOLUTION_FIELDS:
            return None
        decision = parsed["decision"]
        if not isinstance(decision, str) or decision not in DISPUTE_DECISIONS:
            return None
        return parsed

    def _apply_resolution(
        self, idempotency_key: str, dispute_id: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT dispute_id, request_json, status, response_json"
                    " FROM dispute_resolution_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["dispute_id"] == dispute_id and record["request_json"] == request_json:
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                dispute = database.execute(
                    "SELECT settlement_seq, payer_id, payee_id, amount_micros, state"
                    " FROM disputes WHERE id = ?",
                    (dispute_id,),
                ).fetchone()
                if dispute is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, {"error": "not_found"}
                if dispute["state"] != "open":
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, {"error": "already_resolved"}
                decision = fields["decision"]
                amount = dispute["amount_micros"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                if decision == "refund":
                    balance_record = database.execute(
                        "SELECT balance_micros FROM ledger_accounts WHERE account_id = ?",
                        (dispute["payee_id"],),
                    ).fetchone()
                    payee_balance = (
                        balance_record["balance_micros"]
                        if balance_record is not None
                        else 0
                    )
                    # 退款校验总余额；不足时争议维持 open 且冻结不变。
                    if payee_balance < amount:
                        database.execute("ROLLBACK")
                        return HTTPStatus.CONFLICT, {"error": "insufficient_funds"}
                    payee_after = self._adjust_account(
                        database, dispute["payee_id"], -amount
                    )
                    payer_after = self._adjust_account(
                        database, dispute["payer_id"], amount
                    )
                    self._record_entry(
                        database, "dispute_refund", dispute["settlement_seq"],
                        dispute["payee_id"], -amount, payee_after, created_at_ms,
                    )
                    self._record_entry(
                        database, "dispute_refund", dispute["settlement_seq"],
                        dispute["payer_id"], amount, payer_after, created_at_ms,
                    )
                    new_state = "refunded"
                    payload = {"id": dispute_id, "refunded": True, "amount": amount}
                else:
                    new_state = "released"
                    payload = {"id": dispute_id, "released": True, "amount": amount}
                database.execute(
                    "UPDATE disputes SET state = ? WHERE id = ?",
                    (new_state, dispute_id),
                )
                # 生命周期事件与裁决结果、余额、分录及幂等结果同事务原子提交；
                # 余额不足等失败路径在到达此处前已回滚，不写事件。
                next_record = database.execute(
                    "SELECT COALESCE(MAX(event_seq), 0) + 1 AS next_seq"
                    " FROM dispute_events"
                ).fetchone()
                event_seq = next_record["next_seq"]
                database.execute(
                    "INSERT INTO dispute_events"
                    "(event_seq, dispute_id, type, created_at_ms)"
                    " VALUES (?, ?, ?, ?)",
                    (event_seq, dispute_id, new_state, created_at_ms),
                )
                database.execute(
                    "INSERT INTO dispute_resolution_idempotency_records"
                    "(key, dispute_id, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        dispute_id,
                        request_json,
                        int(HTTPStatus.OK),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.OK, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    # ---- 只读全库审计检查点 ----

    def _create_audit_checkpoint(self) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if (
            idempotency_key is None
            or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None
        ):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 审计创建拒绝查询参数：参数校验先于体校验与认证结构。
        if parse_qsl(urlsplit(self.path).query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 正文必须恰为空对象（重复键等非法 JSON 同样拒绝）。
        raw_body = self._read_raw_body()
        parsed = None if raw_body is None else self._read_json_object(raw_body)
        if parsed is None or parsed:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 仅接受单一 SLA-Auth：代理头、缺失、重复或结构非法均为非法请求。
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_audit_checkpoint(auth, body_digest, idempotency_key)
        self._json(status, payload)

    @staticmethod
    def _audit_difference(
        account_id: str,
        difference_type: str,
        entry_seq: int | None,
        reference_seq: int | None,
        expected: Any = None,
        actual: Any = None,
    ) -> dict[str, Any]:
        return {
            "accountId": account_id,
            "type": difference_type,
            "entrySeq": entry_seq,
            "referenceSeq": reference_seq,
            "expected": expected,
            "actual": actual,
        }

    @staticmethod
    def _audit_settlement_attribution(
        differences: list[dict[str, Any]],
        anchor_account: str,
        reference_seq: int,
        settlement: Any,
        evaluations: dict[int, Any],
        sla_ids: set[str],
    ) -> None:
        # 结算须关联到存在的 SLA，且评估归属同一 SLA；每组业务只记一条稳定差异。
        evaluation = evaluations.get(settlement["evaluation_seq"])
        if (
            settlement["sla_id"] not in sla_ids
            or evaluation is None
            or evaluation["sla_id"] != settlement["sla_id"]
        ):
            differences.append(
                {
                    "accountId": anchor_account,
                    "type": "entry_attribution",
                    "entrySeq": None,
                    "referenceSeq": reference_seq,
                    "expected": settlement["sla_id"],
                    "actual": None if evaluation is None else evaluation["sla_id"],
                }
            )

    def _build_audit_document(
        self, database: Any, entry_seq_bound: int
    ) -> dict[str, Any]:
        # 在写事务内冻结账本上界、账户余额、争议冻结额、升级托管额与仲裁结果。
        differences: list[dict[str, Any]] = []

        deposits = {
            row["deposit_seq"]: row
            for row in database.execute(
                "SELECT deposit_seq, machine_id, amount_micros, reference"
                " FROM fund_deposits"
            ).fetchall()
        }
        settlements = {
            row["settlement_seq"]: row
            for row in database.execute(
                "SELECT settlement_seq, sla_id, evaluation_seq, result,"
                " amount_micros, payer_id, payee_id FROM settlements"
            ).fetchall()
        }
        evaluations = {
            row["evaluation_seq"]: row
            for row in database.execute(
                "SELECT evaluation_seq, sla_id FROM sla_evaluation_idempotency_records"
            ).fetchall()
        }
        sla_ids = {row["id"] for row in database.execute("SELECT id FROM slas")}
        disputes_by_id: dict[str, Any] = {}
        for row in database.execute(
            "SELECT id, settlement_seq, claimant_id, payer_id, payee_id,"
            " amount_micros, state FROM disputes"
        ).fetchall():
            disputes_by_id[row["id"]] = row
        escalations = {
            row["escalation_seq"]: row
            for row in database.execute(
                "SELECT escalation_seq, dispute_id, amount_micros"
                " FROM dispute_escalations"
            ).fetchall()
        }
        arbitrations = {
            row["arbitration_seq"]: row
            for row in database.execute(
                "SELECT arbitration_seq, escalation_seq, dispute_id,"
                " arbitrator_id, decision, amount_micros FROM dispute_arbitrations"
            ).fetchall()
        }

        entries = [
            dict(row)
            for row in database.execute(
                "SELECT entry_seq, kind, reference_seq, account_id, delta_micros,"
                " balance_after_micros FROM ledger_entries"
                " WHERE entry_seq <= ? ORDER BY entry_seq ASC",
                (entry_seq_bound,),
            ).fetchall()
        ]
        stored_balances = {
            row["account_id"]: row["balance_micros"]
            for row in database.execute(
                "SELECT account_id, balance_micros FROM ledger_accounts"
            ).fetchall()
        }

        # 每个 open 争议按收款账户计入冻结。
        frozen_by_account: dict[str, int] = {}
        for dispute in disputes_by_id.values():
            if dispute["state"] == "open":
                frozen_by_account[dispute["payee_id"]] = (
                    frozen_by_account.get(dispute["payee_id"], 0)
                    + dispute["amount_micros"]
                )

        account_ids = set(stored_balances) | {
            entry["account_id"] for entry in entries
        }
        # 外部清算账户即使尚无任何分录也参与核对（余额取零）。
        account_ids.add(CLEARING_ACCOUNT_ID)
        entries_by_account: dict[str, list[dict[str, Any]]] = {
            account_id: [] for account_id in account_ids
        }
        for entry in entries:
            entries_by_account.setdefault(entry["account_id"], []).append(entry)

        # 逐账户重放上界内分录：累计值、每步余额，并与存储余额核对。
        accounts: list[dict[str, Any]] = []
        for account_id in sorted(account_ids):
            account_entries = entries_by_account.get(account_id, [])
            running = 0
            for entry in account_entries:
                expected_balance = running + entry["delta_micros"]
                if entry["balance_after_micros"] != expected_balance:
                    differences.append(
                        self._audit_difference(
                            account_id,
                            "step_balance_mismatch",
                            entry["entry_seq"],
                            entry["reference_seq"],
                            expected_balance,
                            entry["balance_after_micros"],
                        )
                    )
                running = expected_balance
            stored = stored_balances.get(account_id, 0)
            if running != stored:
                differences.append(
                    self._audit_difference(
                        account_id, "balance_mismatch", None, None, running, stored
                    )
                )
            frozen = frozen_by_account.get(account_id, 0)
            accounts.append(
                {
                    "accountId": account_id,
                    "storedBalance": stored,
                    "replayedBalance": running,
                    "frozen": frozen,
                    "availableBalance": max(0, stored - frozen),
                }
            )

        # 业务驱动的完整性核对：从每笔已持久化资金业务反向推导其本应留下的
        # 两条方向相反、金额守恒的分录。即使两侧分录全部消失也会产生差异，
        # 而不是仅在账本自身成对守恒时才通过。
        claimed_group_keys: set[tuple[str, int]] = set()

        def reconcile_group(
            kind: str,
            reference_seq: int,
            expected_legs: list[tuple[str, int]],
            settlement: Any,
        ) -> None:
            claimed_group_keys.add((kind, reference_seq))
            group = [
                entry
                for entry in entries
                if entry["kind"] == kind
                and entry["reference_seq"] == reference_seq
            ]
            expected_accounts = {account for account, _ in expected_legs}
            # 以账户匹配应有分录：账户错属或额外副本均落为多余分录。
            matched: dict[str, dict[str, Any]] = {}
            for entry in group:
                if (
                    entry["account_id"] not in expected_accounts
                    or entry["account_id"] in matched
                ):
                    differences.append(
                        self._audit_difference(
                            entry["account_id"], "entry_extra",
                            entry["entry_seq"], reference_seq,
                        )
                    )
                    continue
                matched[entry["account_id"]] = entry
            # 逐侧反向推导：一侧或两侧缺失、借贷方向颠倒、金额不等分别判差异。
            for account_id, expected_delta in expected_legs:
                entry = matched.get(account_id)
                if entry is None:
                    differences.append(
                        self._audit_difference(
                            account_id, "entry_missing", None, reference_seq,
                            expected_delta, None,
                        )
                    )
                elif entry["delta_micros"] != expected_delta:
                    differences.append(
                        self._audit_difference(
                            account_id, "entry_direction",
                            entry["entry_seq"], reference_seq,
                            expected_delta, entry["delta_micros"],
                        )
                    )
            # 结算系分录还须核对 SLA 与评估归属，防止关联另一份协议或评估；
            # 归属差异锚定其结算序号，保证能定位到对应业务。
            if settlement is not None:
                self._audit_settlement_attribution(
                    differences, expected_legs[0][0],
                    settlement["settlement_seq"],
                    settlement, evaluations, sla_ids,
                )

        # 入金：机器账户正额、外部清算账户等额反向，锚定机器、金额与原始引用。
        for deposit_seq in sorted(deposits):
            deposit = deposits[deposit_seq]
            reconcile_group(
                "deposit",
                deposit_seq,
                [
                    (deposit["machine_id"], deposit["amount_micros"]),
                    (CLEARING_ACCOUNT_ID, -deposit["amount_micros"]),
                ],
                None,
            )

        # 正金额结算：付款方负、收款方正；零金额待处理结算不产生分录，
        # 若账本仍留同组分录，则由末尾的孤立分录核对发现。
        for settlement_seq in sorted(settlements):
            settlement = settlements[settlement_seq]
            if settlement["result"] == "pending" or settlement["amount_micros"] == 0:
                continue
            reconcile_group(
                "settlement",
                settlement_seq,
                [
                    (settlement["payer_id"], -settlement["amount_micros"]),
                    (settlement["payee_id"], settlement["amount_micros"]),
                ],
                settlement,
            )

        # 争议退款须回指原结算：收款方负、付款方正，金额取原结算金额。
        # 注意：经升级后由终局仲裁 refund 的争议状态也是 refunded，但其款项自
        # 清算划出、只写 dispute_arbitration 分录，不得在此重复要求退款分录。
        arbitrated_dispute_ids = {
            arbitration["dispute_id"] for arbitration in arbitrations.values()
        }
        for dispute_id in sorted(disputes_by_id):
            dispute = disputes_by_id[dispute_id]
            if dispute["state"] != "refunded":
                continue
            if dispute_id in arbitrated_dispute_ids:
                continue
            settlement = settlements.get(dispute["settlement_seq"])
            amount = (
                dispute["amount_micros"] if settlement is None
                else settlement["amount_micros"]
            )
            if settlement is None:
                differences.append(
                    self._audit_difference(
                        dispute["payee_id"], "entry_attribution", None,
                        dispute["settlement_seq"],
                    )
                )
            reconcile_group(
                "dispute_refund",
                dispute["settlement_seq"],
                [
                    (dispute["payee_id"], -amount),
                    (dispute["payer_id"], amount),
                ],
                settlement,
            )

        # 升级须回指原争议：冻结额自收款方划入外部清算。
        for escalation_seq in sorted(escalations):
            escalation = escalations[escalation_seq]
            dispute = disputes_by_id.get(escalation["dispute_id"])
            if dispute is None:
                # 升级孤立于争议：无法推导两侧账户，仅占用组键避免重复报告，
                # 错属升级由升级与争议的交叉核对差异捕获。
                claimed_group_keys.add(("dispute_escalation", escalation_seq))
                continue
            settlement = settlements.get(dispute["settlement_seq"])
            if settlement is None:
                differences.append(
                    self._audit_difference(
                        dispute["payee_id"], "entry_attribution", None,
                        dispute["settlement_seq"],
                    )
                )
            reconcile_group(
                "dispute_escalation",
                escalation_seq,
                [
                    (dispute["payee_id"], -escalation["amount_micros"]),
                    (CLEARING_ACCOUNT_ID, escalation["amount_micros"]),
                ],
                settlement,
            )

        # 仲裁须关联唯一升级、仲裁决定与最终收款账户，款项自清算划入收款方。
        for arbitration_seq in sorted(arbitrations):
            arbitration = arbitrations[arbitration_seq]
            dispute = disputes_by_id.get(arbitration["dispute_id"])
            if dispute is None:
                # 仲裁孤立于争议：仅占用组键，错属仲裁由仲裁与升级交叉核对捕获。
                claimed_group_keys.add(("dispute_arbitration", arbitration_seq))
                continue
            expected_state = (
                "released" if arbitration["decision"] == "release" else "refunded"
            )
            if dispute["state"] != expected_state:
                differences.append(
                    self._audit_difference(
                        CLEARING_ACCOUNT_ID, "arbitration_state_mismatch",
                        None, arbitration_seq, expected_state, dispute["state"],
                    )
                )
            recipient_id = (
                dispute["payee_id"] if arbitration["decision"] == "release"
                else dispute["payer_id"]
            )
            settlement = settlements.get(dispute["settlement_seq"])
            if settlement is None:
                differences.append(
                    self._audit_difference(
                        recipient_id, "entry_attribution", None,
                        dispute["settlement_seq"],
                    )
                )
            reconcile_group(
                "dispute_arbitration",
                arbitration_seq,
                [
                    (CLEARING_ACCOUNT_ID, -arbitration["amount_micros"]),
                    (recipient_id, arbitration["amount_micros"]),
                ],
                settlement,
            )

        # 孤立分录：(kind, referenceSeq) 不对应任何已持久化业务——含引用序号
        # 错误、分录种类错误、零金额待处理结算伪造的分录——不得因账本自身
        # 成对守恒而放过。
        for entry in entries:
            if (entry["kind"], entry["reference_seq"]) not in claimed_group_keys:
                differences.append(
                    self._audit_difference(
                        entry["account_id"], "entry_reference",
                        entry["entry_seq"], entry["reference_seq"],
                    )
                )

        disputes_document = [
            {
                "disputeId": row["id"],
                "state": row["state"],
                "amount": row["amount_micros"],
                "claimantId": row["claimant_id"],
                "payerId": row["payer_id"],
                "payeeId": row["payee_id"],
                "settlementSeq": row["settlement_seq"],
            }
            for row in (
                disputes_by_id[key] for key in sorted(disputes_by_id)
            )
        ]

        # 未仲裁 escalated 金额计为清算负债：与升级记录及争议状态交叉核对。
        escrow_liability = sum(
            dispute["amount_micros"]
            for dispute in disputes_by_id.values()
            if dispute["state"] == "escalated"
        )
        recorded_escrow = 0
        escalations_document = []
        for escalation_seq in sorted(escalations):
            escalation = escalations[escalation_seq]
            dispute = disputes_by_id.get(escalation["dispute_id"])
            if dispute is None:
                differences.append(
                    self._audit_difference(
                        CLEARING_ACCOUNT_ID, "escalation_dispute_missing",
                        None, escalation_seq,
                    )
                )
                continue
            if dispute["state"] == "escalated":
                recorded_escrow += escalation["amount_micros"]
                if escalation["amount_micros"] != dispute["amount_micros"]:
                    differences.append(
                        self._audit_difference(
                            CLEARING_ACCOUNT_ID, "escrow_amount_mismatch",
                            None, escalation_seq,
                            dispute["amount_micros"], escalation["amount_micros"],
                        )
                    )
            escalations_document.append(
                {
                    "escalationSeq": escalation_seq,
                    "disputeId": escalation["dispute_id"],
                    "amount": escalation["amount_micros"],
                    "arbitrated": escalation["dispute_id"]
                    in arbitrated_dispute_ids,
                }
            )
        if escrow_liability != recorded_escrow:
            differences.append(
                self._audit_difference(
                    CLEARING_ACCOUNT_ID, "escrow_record_mismatch",
                    None, None, escrow_liability, recorded_escrow,
                )
            )

        # 冻结仲裁结果，并核对仲裁与升级的归属。
        arbitrations_document = []
        for arbitration_seq in sorted(arbitrations):
            arbitration = arbitrations[arbitration_seq]
            escalation = escalations.get(arbitration["escalation_seq"])
            if (
                escalation is None
                or escalation["dispute_id"] != arbitration["dispute_id"]
            ):
                differences.append(
                    self._audit_difference(
                        CLEARING_ACCOUNT_ID, "arbitration_escalation_mismatch",
                        None, arbitration_seq,
                    )
                )
            arbitrations_document.append(
                {
                    "arbitrationSeq": arbitration_seq,
                    "escalationSeq": arbitration["escalation_seq"],
                    "disputeId": arbitration["dispute_id"],
                    "arbitratorId": arbitration["arbitrator_id"],
                    "decision": arbitration["decision"],
                    "amount": arbitration["amount_micros"],
                }
            )

        # 外部清算账户持有的是系统入金的反向镜像与升级托管：
        # 余额 = 未仲裁升级托管 − 累计入金；结算与退款只在机器账户间转移。
        deposit_total = sum(
            deposit["amount_micros"] for deposit in deposits.values()
        )
        clearing_balance = stored_balances.get(CLEARING_ACCOUNT_ID, 0)
        expected_clearing = recorded_escrow - deposit_total
        if clearing_balance != expected_clearing:
            differences.append(
                self._audit_difference(
                    CLEARING_ACCOUNT_ID, "clearing_balance_mismatch",
                    None, None, expected_clearing, clearing_balance,
                )
            )
        clearing_document = {
            "accountId": CLEARING_ACCOUNT_ID,
            "storedBalance": clearing_balance,
            "depositTotal": deposit_total,
            "escrowLiability": recorded_escrow,
            "expectedBalance": expected_clearing,
        }

        # 差异项按账户、类型、引用序号（再按分录序号）稳定排序。
        differences.sort(
            key=lambda item: (
                item["accountId"],
                item["type"],
                item["referenceSeq"] is None,
                item["referenceSeq"] if item["referenceSeq"] is not None else 0,
                item["entrySeq"] is None,
                item["entrySeq"] if item["entrySeq"] is not None else 0,
            )
        )

        return {
            "entrySeqBound": entry_seq_bound,
            "consistent": not differences,
            "accounts": accounts,
            "disputes": disputes_document,
            "escalations": escalations_document,
            "arbitrations": arbitrations_document,
            "clearing": clearing_document,
            "differences": differences,
        }

    def _apply_audit_checkpoint(
        self,
        auth: SlaAuth,
        body_digest: str,
        idempotency_key: str,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = "{}"
        standard_path = "/v1/audit-checkpoints"
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                # 幂等判定先于授权与认证：同键更换正文或认证五段均冲突。
                record = database.execute(
                    "SELECT request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature"
                    " FROM audit_checkpoint_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if (
                        record["request_json"] == request_json
                        and self._auth_record_matches(record, auth)
                    ):
                        return HTTPStatus(record["status"]), json.loads(
                            record["response_json"]
                        )
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
                # 认证机器须为启动时配置的审计机器；未获审计授权一律 403。
                if auth.machine_id not in self.server.auditors:
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
                try:
                    self._verify_request_principal(
                        database, auth, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    return rejected.status, {"error": rejected.error}
                # 冻结账本上界：取写锁后全库最大分录序号（空库为 0）；
                # 并发写入只能完整落在上界一侧。
                entry_seq_bound = database.execute(
                    "SELECT COALESCE(MAX(entry_seq), 0) AS bound"
                    " FROM ledger_entries"
                ).fetchone()["bound"]
                document = self._build_audit_document(database, entry_seq_bound)
                document_bytes = json.dumps(
                    document, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
                digest = hashlib.sha256(document_bytes).hexdigest()
                # 全库唯一持久递增检查点序号：取最大序号 + 1（空表 1）。
                checkpoint_seq = database.execute(
                    "SELECT COALESCE(MAX(checkpoint_seq), 0) + 1 AS next_seq"
                    " FROM audit_checkpoints"
                ).fetchone()["next_seq"]
                created_at_ms = int(datetime.now(UTC).timestamp() * 1000)
                # 即使存在差异也返回 201 并保存不一致结论；审计不修正业务数据。
                payload = {
                    "checkpointSeq": checkpoint_seq,
                    "entrySeqBound": entry_seq_bound,
                    "digest": digest,
                    "createdBy": auth.machine_id,
                    "createdAt": created_at_ms,
                    "consistent": document["consistent"],
                    "accounts": document["accounts"],
                    "disputes": document["disputes"],
                    "escalations": document["escalations"],
                    "arbitrations": document["arbitrations"],
                    "clearing": document["clearing"],
                    "differences": document["differences"],
                }
                response_json = json.dumps(payload, separators=(",", ":"))
                database.execute(
                    "INSERT INTO audit_checkpoints"
                    "(checkpoint_seq, entry_seq_bound, digest, created_by,"
                    " created_at_ms, document_json, response_json)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        checkpoint_seq,
                        entry_seq_bound,
                        digest,
                        auth.machine_id,
                        created_at_ms,
                        document_bytes.decode("utf-8"),
                        response_json,
                    ),
                )
                database.execute(
                    "INSERT INTO audit_checkpoint_idempotency_records"
                    "(key, request_json, status, response_json,"
                    " auth_machine_id, auth_key_version, auth_request_time_ms,"
                    " auth_nonce, auth_signature)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        request_json,
                        int(HTTPStatus.CREATED),
                        response_json,
                        auth.machine_id,
                        auth.key_version,
                        auth.request_time_ms,
                        auth.nonce,
                        auth.signature,
                    ),
                )
                # 检查点、幂等结果与随机数同一事务原子持久化；
                # 重放、失败或并发败者不推进序号。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _audit_collection_page(
        self, database: Any, cut: int, last_seq: int, limit: int
    ) -> tuple[list[dict[str, Any]], str | None]:
        rows = database.execute(
            "SELECT checkpoint_seq, entry_seq_bound, digest, created_by, created_at_ms"
            " FROM audit_checkpoints"
            " WHERE checkpoint_seq <= ? AND checkpoint_seq > ?"
            " ORDER BY checkpoint_seq ASC LIMIT ?",
            (cut, last_seq, limit + 1),
        ).fetchall()
        has_next = len(rows) > limit
        page = rows[:limit]
        checkpoints = [
            {
                "checkpointSeq": row["checkpoint_seq"],
                "entrySeqBound": row["entry_seq_bound"],
                "digest": row["digest"],
                "createdBy": row["created_by"],
                "createdAt": row["created_at_ms"],
            }
            for row in page
        ]
        next_cursor = f"{cut}:{page[-1]['checkpoint_seq']}" if has_next else None
        return checkpoints, next_cursor

    def _get_audit_checkpoints(self, query: str) -> None:
        # 集合分页沿用评估历史的 limit 与 cursor=cut:lastSeq。
        parsed = self._parse_evaluation_query(query, AUDIT_CHECKPOINTS_QUERY_PARAMS)
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(b"").hexdigest()
        standard_path = "/v1/audit-checkpoints"
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                if auth.machine_id not in self.server.auditors:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                    return
                try:
                    self._verify_request_principal(
                        database, auth, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    self._json(rejected.status, {"error": rejected.error})
                    return
                current_max = database.execute(
                    "SELECT COALESCE(MAX(checkpoint_seq), 0) AS current_max"
                    " FROM audit_checkpoints"
                ).fetchone()["current_max"]
                if cursor is None:
                    cut, last_seq = current_max, 0
                else:
                    cut, last_seq = cursor
                    if cut > current_max:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                    anchor = database.execute(
                        "SELECT 1 FROM audit_checkpoints"
                        " WHERE checkpoint_seq = ? AND checkpoint_seq <= ?",
                        (last_seq, cut),
                    ).fetchone()
                    if anchor is None:
                        database.execute("ROLLBACK")
                        self._json(
                            HTTPStatus.BAD_REQUEST, {"error": "invalid_request"}
                        )
                        return
                checkpoints, next_cursor = self._audit_collection_page(
                    database, cut, last_seq, limit
                )
                # 仅成功读取才消费随机数。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        self._json(
            HTTPStatus.OK,
            {"checkpoints": checkpoints, "nextCursor": next_cursor},
        )

    def _get_audit_checkpoint(self, seq_text: str, query: str) -> None:
        # 单笔读取不接受任何查询参数：参数校验先于认证结构。
        if parse_qsl(query, keep_blank_values=True):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        # 序号须为无前导零十进制正整数；非法按不存在处理。
        checkpoint_seq: int | None = None
        if DECIMAL_PATTERN.fullmatch(seq_text) is not None:
            value = int(seq_text)
            if 1 <= value <= INT64_MAX:
                checkpoint_seq = value
        if self.headers.get_all(SLA_DELEGATION_HEADER):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(b"").hexdigest()
        standard_path = f"/v1/audit-checkpoints/{seq_text}"
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                if auth.machine_id not in self.server.auditors:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                    return
                try:
                    self._verify_request_principal(
                        database, auth, standard_path, body_digest
                    )
                    self._check_request_nonce(database, auth)
                except AuthRejected as rejected:
                    database.execute("ROLLBACK")
                    self._json(rejected.status, {"error": rejected.error})
                    return
                record = None
                if checkpoint_seq is not None:
                    record = database.execute(
                        "SELECT response_json FROM audit_checkpoints"
                        " WHERE checkpoint_seq = ?",
                        (checkpoint_seq,),
                    ).fetchone()
                if record is None:
                    database.execute("ROLLBACK")
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                    return
                payload = json.loads(record["response_json"])
                # 仅成功读取才在同一事务消费随机数。
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
            except BaseException:
                database.execute("ROLLBACK")
                raise
        self._json(HTTPStatus.OK, payload)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(
    host: str,
    port: int,
    database_path: str,
    arbitrators: Iterable[str] = (),
    auditors: Iterable[str] = (),
) -> None:
    server = ApiServer((host, port), Handler)
    server.database_path = database_path
    server.arbitrators = frozenset(arbitrators)
    server.auditors = frozenset(auditors)
    server.serve_forever()
