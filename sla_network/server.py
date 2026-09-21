from __future__ import annotations

import hashlib
import json
import re
from contextlib import closing
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .database import connect, register_machine

IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9-]{1,64}")
PUBLIC_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate object keys")
    return dict(pairs)


def parse_machine_request(raw: bytes) -> str:
    """校验登记请求体，返回 publicKey；任何非法输入都抛出 ValueError。"""
    if not raw:
        raise ValueError("empty body")
    text = raw.decode("utf-8")
    payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(payload, dict) or set(payload) != {"publicKey"}:
        raise ValueError("request object must contain only publicKey")
    public_key = payload["publicKey"]
    if not isinstance(public_key, str) or not PUBLIC_KEY_PATTERN.fullmatch(public_key):
        raise ValueError("invalid publicKey")
    return public_key


class ApiServer(ThreadingHTTPServer):
    database_path: str


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
        if idempotency_key is None or not IDEMPOTENCY_KEY_PATTERN.fullmatch(idempotency_key):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_idempotency_key"})
            return
        try:
            content_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            content_length = 0
        raw_body = self.rfile.read(max(content_length, 0))
        try:
            public_key = parse_machine_request(raw_body)
        except (ValueError, UnicodeDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            return
        machine_id = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
        outcome, stored_public_key = register_machine(
            self.server.database_path, idempotency_key, machine_id, public_key
        )
        if outcome == "idempotency_conflict":
            self._json(HTTPStatus.CONFLICT, {"error": "idempotency_conflict"})
            return
        if outcome == "machine_exists":
            self._json(HTTPStatus.CONFLICT, {"error": "machine_exists"})
            return
        status = HTTPStatus.CREATED if outcome == "created" else HTTPStatus.OK
        self._json(status, {"id": machine_id, "publicKey": stored_public_key or public_key})

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(host: str, port: int, database_path: str) -> None:
    server = ApiServer((host, port), Handler)
    server.database_path = database_path
    server.serve_forever()
