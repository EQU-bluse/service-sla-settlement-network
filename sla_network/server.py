from __future__ import annotations

import hashlib
import json
import re
from contextlib import closing
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .database import connect

IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9-]{1,64}")
PUBLIC_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")
CAPABILITIES_PATH_PATTERN = re.compile(r"/v1/machines/([^/]+)/capabilities")
CAPABILITY_NAME_PATTERN = re.compile(r"[a-z0-9-]{1,32}")
TEMPLATE_ID_PATTERN = re.compile(r"[a-z0-9-]{1,64}")
SLA_PATH_PATTERN = re.compile(r"/v1/slas/([^/]+)")
CAPABILITY_FIELDS = {"expectedVersion", "name", "protocol", "region", "unit", "capacity"}
SLA_TEMPLATE_FIELDS = {
    "id",
    "machineId",
    "capabilityVersion",
    "priceMicros",
    "maxLatencyMs",
}
SLA_FIELDS = {"id", "templateId", "consumerId", "start", "end"}
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
        if self.path == "/health":
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
        sla_match = SLA_PATH_PATTERN.fullmatch(self.path)
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

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str, port: int, database_path: str) -> None:
    server = ApiServer((host, port), Handler)
    server.database_path = database_path
    server.serve_forever()
