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
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
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
