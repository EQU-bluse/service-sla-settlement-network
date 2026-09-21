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
CAPABILITY_PATH_PATTERN = re.compile(r"^/v1/machines/([^/]+)/capabilities$")
CAPABILITY_NAME_PATTERN = re.compile(r"[a-z0-9-]{1,32}")
CAPABILITY_PROTOCOLS = {"http", "mqtt"}
CAPABILITY_REGIONS = {"cn", "eu", "us"}
CAPABILITY_UNITS = {"call", "byte", "ms"}
MAX_EXPECTED_VERSION = 2147483646
MAX_CAPACITY = 2147483647


class ApiServer(ThreadingHTTPServer):
    database_path: str


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate object member")
    return dict(pairs)


class Handler(BaseHTTPRequestHandler):
    server: ApiServer

    def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._raw(status, body)

    def _raw(self, status: HTTPStatus, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _encode(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

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
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        capability_match = CAPABILITY_PATH_PATTERN.fullmatch(self.path)
        if capability_match is not None:
            self._post_capability(capability_match.group(1))
            return
        if self.path != "/v1/machines":
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
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

    def _post_capability(self, machine_id: str) -> None:
        idempotency_key = self.headers.get("Idempotency-Key")
        if idempotency_key is None or IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key) is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        capability = self._read_capability_object()
        if capability is None:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        status, body = self._declare_capability(machine_id, idempotency_key, capability)
        self._raw(status, body)

    def _read_capability_object(self) -> dict[str, Any] | None:
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
        required = {"expectedVersion", "name", "protocol", "region", "unit", "capacity"}
        if not isinstance(parsed, dict) or set(parsed) != required:
            return None

        expected_version = parsed["expectedVersion"]
        if isinstance(expected_version, bool) or not isinstance(expected_version, int):
            return None
        if not 0 <= expected_version <= MAX_EXPECTED_VERSION:
            return None

        name = parsed["name"]
        if not isinstance(name, str) or CAPABILITY_NAME_PATTERN.fullmatch(name) is None:
            return None

        protocol = parsed["protocol"]
        if protocol not in CAPABILITY_PROTOCOLS:
            return None

        region = parsed["region"]
        if region not in CAPABILITY_REGIONS:
            return None

        unit = parsed["unit"]
        if unit not in CAPABILITY_UNITS:
            return None

        capacity = parsed["capacity"]
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            return None
        if not 1 <= capacity <= MAX_CAPACITY:
            return None

        return parsed

    def _declare_capability(
        self, machine_id: str, idempotency_key: str, request_object: dict[str, Any]
    ) -> tuple[HTTPStatus, bytes]:
        expected_version = request_object["expectedVersion"]
        name = request_object["name"]
        protocol = request_object["protocol"]
        region = request_object["region"]
        unit = request_object["unit"]
        capacity = request_object["capacity"]
        conflict = self._encode({"error": "conflict"})
        with closing(connect(self.server.database_path)) as database:
            database.execute("BEGIN IMMEDIATE")
            try:
                record = database.execute(
                    "SELECT machine_id, expected_version, name, protocol, region, unit, "
                    "capacity, status_code, response_body "
                    "FROM capability_idempotency_records WHERE key = ?",
                    (idempotency_key,),
                ).fetchone()
                if record is not None:
                    database.execute("ROLLBACK")
                    same_request = (
                        record["machine_id"] == machine_id
                        and record["expected_version"] == expected_version
                        and record["name"] == name
                        and record["protocol"] == protocol
                        and record["region"] == region
                        and record["unit"] == unit
                        and record["capacity"] == capacity
                    )
                    if same_request:
                        return HTTPStatus(record["status_code"]), bytes(record["response_body"])
                    return HTTPStatus.CONFLICT, conflict
                machine = database.execute(
                    "SELECT id FROM machines WHERE id = ?", (machine_id,)
                ).fetchone()
                if machine is None:
                    database.execute("ROLLBACK")
                    return HTTPStatus.NOT_FOUND, self._encode({"error": "not_found"})
                capability_row = database.execute(
                    "SELECT version FROM capabilities WHERE machine_id = ?", (machine_id,)
                ).fetchone()
                if capability_row is None:
                    if expected_version != 0:
                        database.execute("ROLLBACK")
                        return HTTPStatus.CONFLICT, conflict
                    response_body = self._encode({"version": 1})
                    database.execute(
                        "INSERT INTO capabilities(machine_id, version, name, protocol, region, "
                        "unit, capacity) VALUES (?, 1, ?, ?, ?, ?, ?)",
                        (machine_id, name, protocol, region, unit, capacity),
                    )
                    database.execute(
                        "INSERT INTO capability_idempotency_records(key, machine_id, "
                        "expected_version, name, protocol, region, unit, capacity, status_code, "
                        "response_body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            idempotency_key,
                            machine_id,
                            expected_version,
                            name,
                            protocol,
                            region,
                            unit,
                            capacity,
                            HTTPStatus.CREATED,
                            response_body,
                        ),
                    )
                    database.execute("COMMIT")
                    return HTTPStatus.CREATED, response_body
                current_version = capability_row["version"]
                if expected_version != current_version:
                    database.execute("ROLLBACK")
                    return HTTPStatus.CONFLICT, conflict
                new_version = current_version + 1
                response_body = self._encode({"version": new_version})
                database.execute(
                    "UPDATE capabilities SET version = ?, name = ?, protocol = ?, region = ?, "
                    "unit = ?, capacity = ? WHERE machine_id = ?",
                    (new_version, name, protocol, region, unit, capacity, machine_id),
                )
                database.execute(
                    "INSERT INTO capability_idempotency_records(key, machine_id, "
                    "expected_version, name, protocol, region, unit, capacity, status_code, "
                    "response_body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        idempotency_key,
                        machine_id,
                        expected_version,
                        name,
                        protocol,
                        region,
                        unit,
                        capacity,
                        HTTPStatus.OK,
                        response_body,
                    ),
                )
                database.execute("COMMIT")
                return HTTPStatus.OK, response_body
            except BaseException:
                database.execute("ROLLBACK")
                raise

    def _read_request_object(self) -> dict[str, Any] | None:
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
        if not isinstance(parsed, dict) or set(parsed) != {"publicKey"}:
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

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str, port: int, database_path: str) -> None:
    server = ApiServer((host, port), Handler)
    server.database_path = database_path
    server.serve_forever()
