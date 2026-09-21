from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sla_network.server import ApiServer, Handler

PUBLIC_KEY_A = "a" * 64
PUBLIC_KEY_B = "b" * 64


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def post_machine(
        self, body: bytes, idempotency_key: str | None = "key-1"
    ) -> tuple[int, bytes, str]:
        headers = {"Content-Type": "application/json"}
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        request = Request(self.url("/v1/machines"), data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=5) as response:
                return (
                    response.status,
                    response.read(),
                    response.headers["Content-Type"],
                )
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    @staticmethod
    def machine_body(public_key: str = PUBLIC_KEY_A) -> bytes:
        return json.dumps({"publicKey": public_key}).encode("utf-8")

    def test_health_reports_database_schema(self) -> None:
        with urlopen(self.url("/health"), timeout=2) as response:
            payload = json.load(response)
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["schemaVersion"], "1")

    def test_unknown_route_is_json_404(self) -> None:
        with self.assertRaises(HTTPError) as captured:
            urlopen(self.url("/missing"), timeout=2)
        self.assertEqual(captured.exception.code, 404)
        self.assertEqual(json.load(captured.exception), {"error": "not_found"})

    def test_register_machine_created(self) -> None:
        status, body, content_type = self.post_machine(self.machine_body())
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertFalse(body.endswith(b"\n"))
        expected_id = hashlib.sha256(bytes.fromhex(PUBLIC_KEY_A)).hexdigest()
        self.assertEqual(body, json.dumps({"id": expected_id, "publicKey": PUBLIC_KEY_A}, separators=(",", ":")).encode("utf-8"))
        self.assertEqual(list(json.loads(body)), ["id", "publicKey"])

    def test_same_key_same_public_key_replays_200(self) -> None:
        first, _, _ = self.post_machine(self.machine_body())
        second, body, _ = self.post_machine(self.machine_body())
        self.assertEqual((first, second), (201, 200))
        expected_id = hashlib.sha256(bytes.fromhex(PUBLIC_KEY_A)).hexdigest()
        self.assertEqual(json.loads(body), {"id": expected_id, "publicKey": PUBLIC_KEY_A})

    def test_same_key_different_public_key_conflicts(self) -> None:
        self.post_machine(self.machine_body(PUBLIC_KEY_A))
        status, body, _ = self.post_machine(self.machine_body(PUBLIC_KEY_B))
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "idempotency_conflict"})

    def test_different_key_same_machine_conflicts(self) -> None:
        self.post_machine(self.machine_body(PUBLIC_KEY_A), idempotency_key="key-1")
        status, body, _ = self.post_machine(self.machine_body(PUBLIC_KEY_A), idempotency_key="key-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "machine_exists"})

    def test_concurrent_identical_requests_exactly_one_created(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def worker() -> None:
            status, _, _ = self.post_machine(self.machine_body(), idempotency_key="race-key")
            with lock:
                results.append(status)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [200] * 7 + [201])

    def test_missing_idempotency_key(self) -> None:
        status, body, _ = self.post_machine(self.machine_body(), idempotency_key=None)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "invalid_idempotency_key"})

    def test_invalid_idempotency_key(self) -> None:
        for key in ("", "bad key", "x" * 65, "key!"):
            status, body, _ = self.post_machine(self.machine_body(), idempotency_key=key)
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_idempotency_key"})

    def test_invalid_request_bodies(self) -> None:
        cases = [
            b"",  # 空体
            b"\xff\xfe",  # 非 UTF-8
            b"{not json",  # 非法 JSON
            b"[1,2]",  # 非对象
            b'{"publicKey":"' + PUBLIC_KEY_A.encode() + b'","publicKey":"' + PUBLIC_KEY_A.encode() + b'"}',  # 重复键
            b"{}",  # 键集合非法
            json.dumps({"publicKey": PUBLIC_KEY_A, "extra": 1}).encode(),  # 多余键
            json.dumps({"publicKey": "A" * 64}).encode(),  # 非小写
            json.dumps({"publicKey": "a" * 63}).encode(),  # 长度不足
            json.dumps({"publicKey": 123}).encode(),  # 非字符串
        ]
        for body_bytes in cases:
            status, body, _ = self.post_machine(body_bytes)
            self.assertEqual(status, 400, body_bytes)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_replay_survives_restart(self) -> None:
        status, _, _ = self.post_machine(self.machine_body(), idempotency_key="persist-key")
        self.assertEqual(status, 201)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, body, _ = self.post_machine(self.machine_body(), idempotency_key="persist-key")
        self.assertEqual(status, 200)
        expected_id = hashlib.sha256(bytes.fromhex(PUBLIC_KEY_A)).hexdigest()
        self.assertEqual(json.loads(body), {"id": expected_id, "publicKey": PUBLIC_KEY_A})


if __name__ == "__main__":
    unittest.main()

