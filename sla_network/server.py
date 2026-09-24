from __future__ import annotations

import hashlib
import json
import re
from contextlib import closing
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .database import connect

IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9-]{1,64}")
PUBLIC_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")
CAPABILITIES_PATH_PATTERN = re.compile(r"/v1/machines/([^/]+)/capabilities")
CAPABILITY_NAME_PATTERN = re.compile(r"[a-z0-9-]{1,32}")
TEMPLATE_ID_PATTERN = re.compile(r"[a-z0-9-]{1,64}")
SLA_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)")
SLA_CONFIRMATIONS_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)/confirmations")
SLA_TELEMETRY_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)/telemetry")
SLA_EVALUATIONS_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)/evaluations")
FUNDS_PATH_PATTERN = re.compile(r"/v1/funds/([^/]+)")
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
EVALUATION_FIELDS = {"from", "to"}
FUND_FIELDS = {"amountMicros", "reference"}
SETTLEMENT_FIELDS = {"slaId", "evaluationSeq"}
AMOUNT_CAP_MICROS = 9_000_000_000_000_000
INT64_MAX = 9_223_372_036_854_775_807
CLEARING_ACCOUNT_ID = "external:clearing"
TELEMETRY_QUERY_PARAMS = {"from", "to", "limit", "cursor"}
EVALUATION_QUERY_PARAMS = {"limit", "cursor"}
TELEMETRY_TIME_MAX = 2147483648000
TELEMETRY_DEFAULT_LIMIT = 50
TELEMETRY_MAX_LIMIT = 100
DECIMAL_PATTERN = re.compile(r"0|[1-9][0-9]*")
CAPABILITY_PROTOCOLS = {"http", "mqtt"}
CAPABILITY_REGIONS = {"cn", "eu", "us"}
CAPABILITY_UNITS = {"call", "byte", "ms"}


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
        evaluations_match = SLA_EVALUATIONS_PATH_PATTERN.fullmatch(target.path)
        if evaluations_match is not None:
            self._get_evaluations(evaluations_match.group(1), target.query)
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
        self, query: str
    ) -> tuple[int, tuple[int, int] | None] | None:
        parameters: dict[str, list[str]] = {}
        for key, value in parse_qsl(query, keep_blank_values=True):
            parameters.setdefault(key, []).append(value)
        if not set(parameters) <= EVALUATION_QUERY_PARAMS:
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

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/machines":
            self._register()
            return
        capabilities_match = CAPABILITIES_PATH_PATTERN.fullmatch(self.path)
        if capabilities_match is not None:
            self._declare_capability(capabilities_match.group(1))
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

    def _read_json_object(self) -> dict[str, Any] | None:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            return None
        try:
            length = int(length_header)
        except ValueError:
            return None
        if length <= 0:
            return None
        body = self.rfile.read(length)
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
        fields = self._read_capability_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_capability(idempotency_key, machine_id, fields)
        self._json(status, payload)

    def _read_capability_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
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
        self, idempotency_key: str, machine_id: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT machine_id, request_json, status, response_json"
                    " FROM capability_idempotency_records WHERE key = ?",
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
                    "(machine_id, name, protocol, region, unit, capacity, version)"
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
                    "(key, machine_id, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        machine_id,
                        request_json,
                        int(status),
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
                database.execute("COMMIT")
                return status, payload
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
        fields = self._read_confirmation_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_confirmation(idempotency_key, sla_id, fields)
        self._json(status, payload)

    def _read_confirmation_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
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
        self, idempotency_key: str, sla_id: str, fields: dict[str, Any]
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                now = int(datetime.now(UTC).timestamp())
                record = database.execute(
                    "SELECT sla_id, request_json, status, response_json"
                    " FROM sla_confirmation_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    if record["sla_id"] == sla_id and record["request_json"] == request_json:
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
                if fields["actorId"] != expected_actor:
                    database.execute("ROLLBACK")
                    return HTTPStatus.FORBIDDEN, {"error": "forbidden"}
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
                    "(key, sla_id, request_json, status, response_json)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        sla_id,
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

    def _post_telemetry(self, sla_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        fields = self._read_telemetry_object()
        if fields is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, payload = self._apply_telemetry(idempotency_key, sla_id, fields)
        self._json(status, payload)

    def _read_telemetry_object(self) -> dict[str, Any] | None:
        parsed = self._read_json_object()
        if parsed is None or set(parsed) != TELEMETRY_FIELDS:
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
        return parsed

    def _apply_telemetry(
        self, idempotency_key: str, sla_id: str, fields: dict[str, Any]
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
                        return HTTPStatus(record["status"]), json.loads(record["response_json"])
                    return HTTPStatus.CONFLICT, {"error": "conflict"}
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
                    "(sla_id, event_id, timestamp_ms, latency_ms, digest, commit_seq)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        sla_id,
                        fields["eventId"],
                        timestamp,
                        fields["latencyMs"],
                        fields["digest"],
                        commit_seq,
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
                    if payer_balance < amount:
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

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str, port: int, database_path: str) -> None:
    server = ApiServer((host, port), Handler)
    server.database_path = database_path
    server.serve_forever()
