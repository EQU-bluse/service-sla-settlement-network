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

PUBLIC_KEY_A = "aa" * 32
PUBLIC_KEY_B = "bb" * 32
PUBLIC_KEY_C = "cc" * 32


def machine_id(public_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key)).hexdigest()


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

    def post_machines(self, body: bytes, idempotency_key: str | None = "key-1") -> tuple[int, bytes, str]:
        request = Request(self.url("/v1/machines"), data=body, method="POST")
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def register_body(self, public_key: str = PUBLIC_KEY_A) -> bytes:
        return json.dumps({"publicKey": public_key}).encode("utf-8")

    def test_register_machine_created(self) -> None:
        status, body, content_type = self.post_machines(self.register_body())
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(
            body.decode("utf-8"),
            json.dumps(
                {"id": machine_id(PUBLIC_KEY_A), "publicKey": PUBLIC_KEY_A},
                separators=(",", ":"),
            ),
        )
        self.assertFalse(body.endswith(b"\n"))

    def test_register_machine_replay_returns_200(self) -> None:
        self.assertEqual(self.post_machines(self.register_body())[0], 201)
        status, body, _ = self.post_machines(self.register_body())
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body), {"id": machine_id(PUBLIC_KEY_A), "publicKey": PUBLIC_KEY_A}
        )

    def test_register_machine_replay_survives_restart(self) -> None:
        self.assertEqual(self.post_machines(self.register_body())[0], 201)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, body, _ = self.post_machines(self.register_body())
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body), {"id": machine_id(PUBLIC_KEY_A), "publicKey": PUBLIC_KEY_A}
        )

    def test_same_key_different_public_key_conflicts(self) -> None:
        self.assertEqual(self.post_machines(self.register_body())[0], 201)
        status, body, _ = self.post_machines(self.register_body(PUBLIC_KEY_B))
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "idempotency_conflict"})

    def test_same_machine_different_key_conflicts(self) -> None:
        self.assertEqual(self.post_machines(self.register_body())[0], 201)
        status, body, _ = self.post_machines(self.register_body(), idempotency_key="key-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "machine_exists"})

    def test_concurrent_identical_requests_exactly_one_created(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def register() -> None:
            status, _, _ = self.post_machines(self.register_body())
            with lock:
                results.append(status)

        threads = [threading.Thread(target=register) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [200] * 7 + [201])

    def test_missing_idempotency_key(self) -> None:
        status, body, _ = self.post_machines(self.register_body(), idempotency_key=None)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "invalid_idempotency_key"})

    def test_invalid_idempotency_key(self) -> None:
        for key in ("", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_machines(self.register_body(), idempotency_key=key)
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_idempotency_key"})

    def test_invalid_request_bodies(self) -> None:
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            json.dumps({"publicKey": PUBLIC_KEY_A, "extra": 1}).encode(),
            json.dumps({"publicKey": PUBLIC_KEY_A.upper()}).encode(),
            json.dumps({"publicKey": "aa"}).encode(),
            json.dumps({"publicKey": "gg" * 32}).encode(),
            json.dumps({"publicKey": 123}).encode(),
            b'{"publicKey":"' + PUBLIC_KEY_A.encode() + b'","publicKey":"' + PUBLIC_KEY_B.encode() + b'"}',
        ]
        for body in cases:
            status, response_body, _ = self.post_machines(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})

    def test_success_payload_key_order(self) -> None:
        _, body, _ = self.post_machines(self.register_body())
        self.assertEqual(list(json.loads(body)), ["id", "publicKey"])


def capability_body(
    expected_version: int = 0,
    name: object = "svc-alpha",
    protocol: object = "http",
    region: object = "cn",
    unit: object = "call",
    capacity: object = 100,
) -> bytes:
    return json.dumps(
        {
            "expectedVersion": expected_version,
            "name": name,
            "protocol": protocol,
            "region": region,
            "unit": unit,
            "capacity": capacity,
        }
    ).encode("utf-8")


class CapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.post_machines(
            json.dumps({"publicKey": PUBLIC_KEY_A}).encode(), idempotency_key="register-a"
        )

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def post_machines(
        self, body: bytes, idempotency_key: str | None = "key-1"
    ) -> tuple[int, bytes]:
        request = Request(self.url("/v1/machines"), data=body, method="POST")
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def post_capability(
        self,
        machine: str,
        body: bytes,
        idempotency_key: str | None = "cap-key-1",
    ) -> tuple[int, bytes, str]:
        request = Request(
            self.url(f"/v1/machines/{machine}/capabilities"), data=body, method="POST"
        )
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def test_first_declaration_creates_version_one(self) -> None:
        status, body, content_type = self.post_capability(
            machine_id(PUBLIC_KEY_A), capability_body()
        )
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(body, b'{"version":1}')
        self.assertFalse(body.endswith(b"\n"))
        self.assertEqual(list(json.loads(body)), ["version"])

    def test_replay_returns_same_status_and_bytes(self) -> None:
        body = capability_body()
        first_status, first_body, _ = self.post_capability(machine_id(PUBLIC_KEY_A), body)
        second_status, second_body, _ = self.post_capability(machine_id(PUBLIC_KEY_A), body)
        self.assertEqual(first_status, second_status)
        self.assertEqual(first_body, second_body)
        self.assertEqual(second_status, 201)

    def test_replay_survives_restart(self) -> None:
        body = capability_body()
        status, first_body, _ = self.post_capability(machine_id(PUBLIC_KEY_A), body)
        self.assertEqual(status, 201)
        self.restart()
        status, second_body, _ = self.post_capability(machine_id(PUBLIC_KEY_A), body)
        self.assertEqual(status, 201)
        self.assertEqual(first_body, second_body)

    def test_matching_version_update_increments(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        self.assertEqual(self.post_capability(machine, capability_body())[0], 201)
        status, body, _ = self.post_capability(
            machine, capability_body(expected_version=1, name="svc-beta", capacity=200),
            idempotency_key="cap-key-2",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"version":2}')
        status, body, _ = self.post_capability(
            machine, capability_body(expected_version=1, name="svc-beta", capacity=200),
            idempotency_key="cap-key-2",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"version":2}')

    def test_update_replay_survives_restart(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        self.post_capability(machine, capability_body())
        update = capability_body(expected_version=1)
        status, first_body, _ = self.post_capability(machine, update, idempotency_key="cap-key-2")
        self.assertEqual((status, first_body), (200, b'{"version":2}'))
        self.restart()
        status, second_body, _ = self.post_capability(machine, update, idempotency_key="cap-key-2")
        self.assertEqual(status, 200)
        self.assertEqual(second_body, first_body)

    def test_first_declaration_requires_expected_version_zero(self) -> None:
        status, body, _ = self.post_capability(
            machine_id(PUBLIC_KEY_A), capability_body(expected_version=1)
        )
        self.assertEqual(status, 409)
        self.assertEqual(body, b'{"error":"conflict"}')

    def test_stale_expected_version_conflicts(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        self.post_capability(machine, capability_body())
        self.post_capability(
            machine, capability_body(expected_version=1), idempotency_key="cap-key-2"
        )
        status, body, _ = self.post_capability(
            machine, capability_body(expected_version=1), idempotency_key="cap-key-3"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_version_conflict_is_not_persisted(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        self.post_capability(machine, capability_body())
        status, _, _ = self.post_capability(
            machine, capability_body(expected_version=0), idempotency_key="reused"
        )
        self.assertEqual(status, 409)
        status, body, _ = self.post_capability(
            machine, capability_body(expected_version=1), idempotency_key="reused"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"version":2}')

    def test_unknown_machine_is_not_found(self) -> None:
        status, body, _ = self.post_capability(machine_id(PUBLIC_KEY_B), capability_body())
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_not_found_is_not_persisted(self) -> None:
        missing = machine_id(PUBLIC_KEY_B)
        for _ in range(2):
            status, _, _ = self.post_capability(missing, capability_body())
            self.assertEqual(status, 404)
        self.post_machines(
            json.dumps({"publicKey": PUBLIC_KEY_B}).encode(), idempotency_key="register-b"
        )
        status, body, _ = self.post_capability(missing, capability_body())
        self.assertEqual(status, 201)
        self.assertEqual(body, b'{"version":1}')

    def test_same_key_different_machine_conflicts_even_when_unregistered(self) -> None:
        status, _, _ = self.post_capability(machine_id(PUBLIC_KEY_A), capability_body())
        self.assertEqual(status, 201)
        status, body, _ = self.post_capability(machine_id(PUBLIC_KEY_B), capability_body())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_same_key_different_field_conflicts(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        self.post_capability(machine, capability_body())
        for changed in (
            capability_body(name="svc-beta"),
            capability_body(protocol="mqtt"),
            capability_body(region="eu"),
            capability_body(unit="ms"),
            capability_body(capacity=101),
        ):
            status, _, _ = self.post_capability(machine, changed)
            self.assertEqual(status, 409, changed)

    def test_concurrent_same_key_writes_once_and_replays(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        body = capability_body()
        results: list[tuple[int, bytes]] = []
        lock = threading.Lock()

        def declare() -> None:
            status, response, _ = self.post_capability(machine, body)
            with lock:
                results.append((status, response))

        threads = [threading.Thread(target=declare) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual({status for status, _ in results}, {201})
        self.assertEqual({response for _, response in results}, {b'{"version":1}'})
        status, body, _ = self.post_capability(
            machine, capability_body(expected_version=1), idempotency_key="next"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"version":2}')

    def test_concurrent_distinct_keys_only_one_creates(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        results: list[int] = []
        lock = threading.Lock()

        def declare(index: int) -> None:
            status, _, _ = self.post_capability(
                machine, capability_body(), idempotency_key=f"race-{index}"
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=declare, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [201] + [409] * 7)

    def test_concurrent_distinct_keys_only_one_update_succeeds(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        self.post_capability(machine, capability_body())
        results: list[int] = []
        lock = threading.Lock()

        def update(index: int) -> None:
            status, _, _ = self.post_capability(
                machine,
                capability_body(expected_version=1),
                idempotency_key=f"update-{index}",
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=update, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [200] + [409] * 7)

    def test_missing_or_invalid_idempotency_key(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_capability(machine, capability_body(), idempotency_key=key)
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"}, key)

    def test_invalid_request_bodies(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        valid = {
            "expectedVersion": 0,
            "name": "svc-alpha",
            "protocol": "http",
            "region": "cn",
            "unit": "call",
            "capacity": 100,
        }
        valid_text = json.dumps(valid, separators=(",", ":"))
        vt = valid_text
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            vt.replace('"expectedVersion":0', '"expectedVersion":true').encode(),
            vt.replace('"expectedVersion":0', '"expectedVersion":false').encode(),
            vt.replace('"expectedVersion":0', '"expectedVersion":-1').encode(),
            vt.replace('"expectedVersion":0', '"expectedVersion":2147483647').encode(),
            vt.replace('"expectedVersion":0', '"expectedVersion":"0"').encode(),
            vt.replace('"expectedVersion":0', '"expectedVersion":0.5').encode(),
            vt.replace('"svc-alpha"', '""').encode(),
            vt.replace('"svc-alpha"', '"' + "a" * 33 + '"').encode(),
            vt.replace('"svc-alpha"', '"Svc"').encode(),
            vt.replace('"svc-alpha"', '"svc_alpha"').encode(),
            vt.replace('"http"', '"ftp"').encode(),
            vt.replace('"cn"', '"jp"').encode(),
            vt.replace('"call"', '"volt"').encode(),
            vt.replace('"capacity":100', '"capacity":true').encode(),
            vt.replace('"capacity":100', '"capacity":0').encode(),
            vt.replace('"capacity":100', '"capacity":-5').encode(),
            vt.replace('"capacity":100', '"capacity":2147483648').encode(),
            vt.replace('"capacity":100', '"capacity":"100"').encode(),
            json.dumps(dict(valid, extra=1)).encode(),
            json.dumps({key: value for key, value in valid.items() if key != "unit"}).encode(),
            (
                b'{"expectedVersion":0,"name":"svc-alpha","protocol":"http","region":"cn",'
                b'"unit":"call","capacity":100,"capacity":101}'
            ),
        ]
        for body in cases:
            status, response_body, _ = self.post_capability(machine, body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"}, body)

    def test_boundary_values_accepted(self) -> None:
        machine = machine_id(PUBLIC_KEY_A)
        status, _, _ = self.post_capability(
            machine,
            capability_body(
                name="a" * 32,
                protocol="mqtt",
                region="us",
                unit="ms",
                capacity=2147483647,
            ),
        )
        self.assertEqual(status, 201)
        status, body, _ = self.post_capability(
            machine,
            capability_body(expected_version=1, capacity=1),
            idempotency_key="boundary-2",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"version":2}')

    def test_get_capability_route_unknown(self) -> None:
        request = Request(
            self.url(f"/v1/machines/{machine_id(PUBLIC_KEY_A)}/capabilities"), method="GET"
        )
        with self.assertRaises(HTTPError) as captured:
            urlopen(request, timeout=2)
        self.assertEqual(captured.exception.code, 404)
        self.assertEqual(json.load(captured.exception), {"error": "not_found"})

    def test_post_unknown_capability_route(self) -> None:
        status, body, _ = self.post_capability(
            machine_id(PUBLIC_KEY_A) + "/extra", capability_body()
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})


if __name__ == "__main__":
    unittest.main()

