from __future__ import annotations

import hashlib
import json
import re
import sqlite3
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
DISPUTE_RESOLUTION_PATH_PATTERN = re.compile(r"/v1/disputes/([^/]+)/resolution")
EVIDENCE_PROOFS_PATH_PATTERN = re.compile(r"/v1/evidence/([^/]+)/proofs")
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
DISPUTES_QUERY_PARAMS = {"accountId", "state", "limit", "cursor"}
MACHINE_DELEGATIONS_QUERY_PARAMS = {"limit", "cursor"}
DELEGATION_EVENTS_QUERY_PARAMS = {"limit", "cursor"}
DISPUTE_SNAPSHOT_STATES = {"open", "released", "refunded"}
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
MACHINE_DELEGATION_CONSUMPTIONS_PATH_PATTERN = re.compile(
    r"/v1/machines/([^/]+)/delegation-consumptions"
)
DELEGATION_FIELDS = {
    "id",
    "delegatePublicKey",
    "expiresAt",
    "operation",
    "capabilityVersion",
}
DELEGATION_MAX_TTL_MS = 86_400_000
# 最小权限：委托只允许代理能力写入这一个目标操作；
# 资源（路径机器）与能力版本在使用凭证时再与凭证范围逐字比对。
DELEGATION_OPERATION = "capability.write"
DELEGATION_CONSUMPTIONS_QUERY_PARAMS = {"limit", "cursor"}


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
            self._get_machine_delegation_consumptions(
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
        dispute_match = DISPUTE_PATH_PATTERN.fullmatch(target.path)
        if dispute_match is not None:
            self._get_dispute(dispute_match.group(1), target.query)
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
                    " LEFT JOIN settlements AS s"
                    " ON e.kind IN ('settlement', 'dispute_refund')"
                    " AND e.reference_seq = s.settlement_seq"
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
                    "operation": row["operation"],
                    "capabilityVersion": row["capability_version"],
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

    def _get_machine_delegation_consumptions(
        self, machine_id: str, query: str
    ) -> None:
        # 查询参数、认证次序、随机数消费与快照语义均沿用委托集合查询。
        parsed = self._parse_evaluation_query(
            query, DELEGATION_CONSUMPTIONS_QUERY_PARAMS
        )
        if parsed is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        limit, cursor = parsed
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
            # 首页以同一读事务起点的全库委托事件最大序号冻结快照；
            # 只按序号返回该机器凭证的 consumed 事件。
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
                # 锚点须是该机器凭证在 cut 内的消费事件；
                # 属于其他机器、非 consumed 事件或不存在均为非法游标。
                anchor = database.execute(
                    "SELECT 1 FROM delegation_events AS c"
                    " JOIN machine_delegations AS d ON d.id = c.delegation_id"
                    " WHERE c.type = 'consumed' AND d.issuer_machine_id = ?"
                    " AND c.event_seq = ? AND c.event_seq <= ?",
                    (machine_id, last_seq, cut),
                ).fetchone()
                if anchor is None:
                    return None
            rows = database.execute(
                "SELECT c.event_seq AS event_seq,"
                " c.delegation_id AS delegation_id,"
                " d.operation AS operation,"
                " d.capability_version AS capability_version,"
                " c.standard_path AS resource,"
                " c.request_digest AS request_digest,"
                " c.created_at_ms AS created_at_ms"
                " FROM delegation_events AS c"
                " JOIN machine_delegations AS d ON d.id = c.delegation_id"
                " WHERE c.type = 'consumed' AND d.issuer_machine_id = ?"
                " AND c.event_seq <= ? AND c.event_seq > ?"
                " ORDER BY c.event_seq ASC"
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
        expected_operation: str,
        expected_version: int,
    ) -> None:
        # 次序：委托存在、签发机器与路径机器一致、凭证范围与本次目标一致、
        # 时间窗口，再判过期/已用/已撤销/签发版本失效与代理公钥严格验签。
        # 升级前旧凭证的范围两列为 NULL：沿用无范围语义，跳过范围比对。
        delegation = database.execute(
            "SELECT issuer_machine_id, delegate_public_key, expires_at_ms,"
            " issued_key_version, revoked, consumed, operation,"
            " capability_version"
            " FROM machine_delegations WHERE id = ?",
            (auth.machine_id,),
        ).fetchone()
        if delegation is None:
            raise AuthRejected(HTTPStatus.UNAUTHORIZED, "invalid_authentication")
        if delegation["issuer_machine_id"] != expected_machine:
            raise AuthRejected(HTTPStatus.FORBIDDEN, "forbidden")
        if delegation["operation"] is not None and (
            delegation["operation"] != expected_operation
            or delegation["capability_version"] != expected_version
        ):
            # 最小权限不符：操作或能力版本越界均为 403，且不消费凭证/随机数/序号。
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
        standard_path: str | None = None,
        request_digest: str | None = None,
    ) -> None:
        # 全库唯一递增事件序号：写事务均以 BEGIN IMMEDIATE 串行，取 MAX+1 安全。
        # 仅首次业务成功到达此处；失败、同键重放与并发败者均不写事件、不推进序号。
        # consumed 事件额外固化标准路径与原始正文 SHA-256；issued/revoked 为 NULL。
        max_record = database.execute(
            "SELECT MAX(event_seq) AS current_max FROM delegation_events"
        ).fetchone()
        event_seq = (max_record["current_max"] or 0) + 1
        database.execute(
            "INSERT INTO delegation_events"
            "(event_seq, delegation_id, type, created_at_ms, standard_path,"
            " request_digest) VALUES (?, ?, ?, ?, ?, ?)",
            (
                event_seq,
                delegation_id,
                event_type,
                created_at_ms,
                standard_path,
                request_digest,
            ),
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
                    # 代理凭证改按委托记录与代理公钥校验，并先比对凭证最小权限
                    # 范围（路径机器、操作、能力版本）与本次目标是否完全一致。
                    if delegation:
                        self._verify_delegation_auth(
                            database,
                            auth,
                            machine_id,
                            standard_path,
                            body_digest,
                            DELEGATION_OPERATION,
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
                    # 成功消费事件同事务追加；版本竞争等失败路径不到达此处。
                    # 固化标准路径与服务收到的原始正文 SHA-256，供签发机器审计。
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

    def _read_delegation_object(self, body: bytes) -> dict[str, Any] | None:
        parsed = self._read_json_object(body)
        if parsed is None or set(parsed) != DELEGATION_FIELDS:
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
        # 最小权限范围：操作仅接受 capability.write（非字符串不断连），
        # 能力版本为 0..2147483646 的非布尔整数。
        operation = parsed["operation"]
        if not isinstance(operation, str) or operation != DELEGATION_OPERATION:
            return None
        capability_version = parsed["capabilityVersion"]
        if not _bounded_int(capability_version, 0, 2147483646):
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
                # 原子保存签发密钥版本：代理使用时该版本须仍为最新有效版本。
                # 同时固化最小权限范围（操作与能力版本），消费时逐字比对。
                database.execute(
                    "INSERT INTO machine_delegations"
                    "(id, issuer_machine_id, delegate_public_key, expires_at_ms,"
                    " issued_key_version, revoked, consumed, created_at_ms,"
                    " operation, capability_version)"
                    " VALUES (?, ?, ?, ?, ?, 0, 0, ?, ?, ?)",
                    (
                        fields["id"],
                        auth.machine_id,
                        fields["delegatePublicKey"],
                        fields["expiresAt"],
                        auth.key_version,
                        created_at_ms,
                        fields["operation"],
                        fields["capabilityVersion"],
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
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_evidence(
            idempotency_key, dispute_id, fields, auth, body_digest
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
                    # 认证机器标识须等于正文 actorId（参与方身份），再验时间、密钥、签名、随机数。
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
                self._consume_request_nonce(database, auth)
                database.execute("COMMIT")
                return HTTPStatus.CREATED, payload
            except BaseException:
                database.execute("ROLLBACK")
                raise

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
        auth = self._parse_sla_auth()
        if auth is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        body_digest = hashlib.sha256(raw_body).hexdigest()
        status, payload = self._apply_evidence_proof(
            idempotency_key, fields, auth, body_digest
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
                    # 认证机器标识须等于正文 actorId，再依次校验时间、密钥、签名、随机数。
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

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str, port: int, database_path: str) -> None:
    server = ApiServer((host, port), Handler)
    server.database_path = database_path
    server.serve_forever()
