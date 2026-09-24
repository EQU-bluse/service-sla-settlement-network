from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
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


class CapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        request = Request(
            self.url("/v1/machines"),
            data=json.dumps({"publicKey": PUBLIC_KEY_A}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "register-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def capability_body(self, expected_version: int = 0, **overrides: object) -> bytes:
        fields: dict[str, object] = {
            "expectedVersion": expected_version,
            "name": "pump-01",
            "protocol": "mqtt",
            "region": "cn",
            "unit": "call",
            "capacity": 10,
        }
        fields.update(overrides)
        return json.dumps(fields).encode()

    def post_capability(
        self,
        body: bytes,
        machine_id: str | None = None,
        idempotency_key: str | None = "cap-1",
    ) -> tuple[int, bytes, str]:
        target = machine_id if machine_id is not None else self.machine_id
        request = Request(
            self.url(f"/v1/machines/{target}/capabilities"), data=body, method="POST"
        )
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def test_declare_capability_created(self) -> None:
        status, body, content_type = self.post_capability(self.capability_body())
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(body, b'{"version":1}')

    def test_declare_capability_update_increments_version(self) -> None:
        self.assertEqual(self.post_capability(self.capability_body())[0], 201)
        status, body, _ = self.post_capability(
            self.capability_body(expected_version=1, capacity=20), idempotency_key="cap-2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"version":2}')

    def test_first_declaration_requires_version_zero(self) -> None:
        status, body, _ = self.post_capability(self.capability_body(expected_version=1))
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_stale_expected_version_conflicts(self) -> None:
        self.assertEqual(self.post_capability(self.capability_body())[0], 201)
        status, body, _ = self.post_capability(self.capability_body(), idempotency_key="cap-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_replay_returns_first_response_bytes(self) -> None:
        status, body, _ = self.post_capability(self.capability_body())
        self.assertEqual((status, body), (201, b'{"version":1}'))
        for _ in range(2):
            again_status, again_body, _ = self.post_capability(self.capability_body())
            self.assertEqual((again_status, again_body), (status, body))
        # 重放未重复写入：版本仍为 1。
        status, body, _ = self.post_capability(
            self.capability_body(expected_version=1), idempotency_key="cap-2"
        )
        self.assertEqual((status, body), (200, b'{"version":2}'))

    def test_same_key_different_fields_conflicts(self) -> None:
        self.assertEqual(self.post_capability(self.capability_body())[0], 201)
        status, body, _ = self.post_capability(self.capability_body(capacity=99))
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_same_key_different_machine_conflicts_even_if_unregistered(self) -> None:
        self.assertEqual(self.post_capability(self.capability_body())[0], 201)
        status, body, _ = self.post_capability(
            self.capability_body(), machine_id=machine_id(PUBLIC_KEY_B)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_unregistered_machine_not_found(self) -> None:
        status, body, _ = self.post_capability(
            self.capability_body(), machine_id=machine_id(PUBLIC_KEY_B)
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_failed_request_leaves_no_idempotency_record(self) -> None:
        other_id = machine_id(PUBLIC_KEY_B)
        status, _, _ = self.post_capability(self.capability_body(), machine_id=other_id)
        self.assertEqual(status, 404)
        request = Request(
            self.url("/v1/machines"),
            data=json.dumps({"publicKey": PUBLIC_KEY_B}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "register-2")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        status, body, _ = self.post_capability(self.capability_body(), machine_id=other_id)
        self.assertEqual((status, body), (201, b'{"version":1}'))

    def test_version_conflict_leaves_no_idempotency_record(self) -> None:
        self.assertEqual(self.post_capability(self.capability_body())[0], 201)
        status, _, _ = self.post_capability(self.capability_body(), idempotency_key="cap-2")
        self.assertEqual(status, 409)
        status, body, _ = self.post_capability(
            self.capability_body(expected_version=1), idempotency_key="cap-2"
        )
        self.assertEqual((status, body), (200, b'{"version":2}'))

    def test_replay_survives_restart(self) -> None:
        status, body, _ = self.post_capability(self.capability_body())
        self.assertEqual(status, 201)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        again_status, again_body, _ = self.post_capability(self.capability_body())
        self.assertEqual((again_status, again_body), (status, body))

    def test_concurrent_distinct_keys_single_winner(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def declare(index: int) -> None:
            status, _, _ = self.post_capability(
                self.capability_body(), idempotency_key=f"cap-race-{index}"
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=declare, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [201] + [409] * 7)

    def test_invalid_idempotency_key(self) -> None:
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_capability(
                self.capability_body(), idempotency_key=key
            )
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b"null",
            b"{}",
            json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                }
            ).encode(),
            json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                    "extra": 1,
                }
            ).encode(),
            self.capability_body(expected_version=-1),
            self.capability_body(expected_version=2147483647),
            self.capability_body(expected_version=True),
            self.capability_body(expected_version=1.0),
            self.capability_body(expected_version="0"),
            self.capability_body(name=""),
            self.capability_body(name="a" * 33),
            self.capability_body(name="Pump"),
            self.capability_body(name="pump_01"),
            self.capability_body(name=1),
            self.capability_body(protocol="amqp"),
            self.capability_body(protocol="HTTP"),
            self.capability_body(region="us-east"),
            self.capability_body(unit="bytes"),
            self.capability_body(capacity=0),
            self.capability_body(capacity=-1),
            self.capability_body(capacity=2147483648),
            self.capability_body(capacity=False),
            self.capability_body(capacity="10"),
            b'{"expectedVersion":0,"expectedVersion":0,"name":"pump-01",'
            b'"protocol":"mqtt","region":"cn","unit":"call","capacity":10}',
        ]
        for body in cases:
            status, response_body, _ = self.post_capability(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})

    def test_machine_subpath_without_capabilities_is_404(self) -> None:
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}"),
            data=self.capability_body(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with self.assertRaises(HTTPError) as captured:
            urlopen(request, timeout=5)
        self.assertEqual(captured.exception.code, 404)
        self.assertEqual(json.load(captured.exception), {"error": "not_found"})


    def test_non_string_protocol_region_unit_are_400_without_disconnect(self) -> None:
        for field in ("protocol", "region", "unit"):
            for value in (["http"], {"protocol": "http"}, 1, True, None):
                status, body, _ = self.post_capability(
                    self.capability_body(**{field: value}),
                    idempotency_key=f"bad-{field}-{type(value).__name__}",
                )
                self.assertEqual(status, 400, (field, value))
                self.assertEqual(json.loads(body), {"error": "invalid_request"})
        with urlopen(self.url("/health"), timeout=2) as response:
            self.assertEqual(response.status, 200)


class SlaTemplateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        request = Request(
            self.url("/v1/machines"),
            data=json.dumps({"publicKey": PUBLIC_KEY_A}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "register-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def template_body(self, **overrides: object) -> bytes:
        fields: dict[str, object] = {
            "id": "tpl-1",
            "machineId": self.machine_id,
            "capabilityVersion": 1,
            "priceMicros": 1000,
            "maxLatencyMs": 50,
        }
        fields.update(overrides)
        return json.dumps(fields).encode()

    def post_template(
        self, body: bytes, idempotency_key: str | None = "sla-1"
    ) -> tuple[int, bytes, str]:
        request = Request(self.url("/v1/sla-templates"), data=body, method="POST")
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def test_template_created(self) -> None:
        status, body, content_type = self.post_template(self.template_body())
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(body, b'{"id":"tpl-1"}')
        self.assertFalse(body.endswith(b"\n"))

    def test_replay_returns_first_response_bytes(self) -> None:
        status, body, _ = self.post_template(self.template_body())
        self.assertEqual((status, body), (201, b'{"id":"tpl-1"}'))
        for _ in range(2):
            again_status, again_body, _ = self.post_template(self.template_body())
            self.assertEqual((again_status, again_body), (status, body))

    def test_same_key_different_request_conflicts(self) -> None:
        self.assertEqual(self.post_template(self.template_body())[0], 201)
        for body in (
            self.template_body(id="tpl-2"),
            self.template_body(priceMicros=9999),
            self.template_body(capabilityVersion=2),
        ):
            status, response_body, _ = self.post_template(body)
            self.assertEqual(status, 409, body)
            self.assertEqual(json.loads(response_body), {"error": "conflict"})

    def test_machine_not_found(self) -> None:
        status, body, _ = self.post_template(
            self.template_body(machineId=machine_id(PUBLIC_KEY_B))
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_machine_without_capability_conflicts(self) -> None:
        request = Request(
            self.url("/v1/machines"),
            data=json.dumps({"publicKey": PUBLIC_KEY_B}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "register-2")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        status, body, _ = self.post_template(
            self.template_body(machineId=machine_id(PUBLIC_KEY_B)),
            idempotency_key="sla-2",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_capability_version_mismatch_conflicts(self) -> None:
        status, body, _ = self.post_template(
            self.template_body(capabilityVersion=2), idempotency_key="sla-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_duplicate_id_conflicts(self) -> None:
        self.assertEqual(self.post_template(self.template_body())[0], 201)
        status, body, _ = self.post_template(
            self.template_body(priceMicros=2), idempotency_key="sla-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "template_exists"})

    def test_conflict_leaves_no_idempotency_record(self) -> None:
        status, _, _ = self.post_template(
            self.template_body(capabilityVersion=2), idempotency_key="sla-2"
        )
        self.assertEqual(status, 409)
        status, body, _ = self.post_template(
            self.template_body(capabilityVersion=1), idempotency_key="sla-2"
        )
        self.assertEqual((status, body), (201, b'{"id":"tpl-1"}'))

    def test_replay_survives_restart(self) -> None:
        status, body, _ = self.post_template(self.template_body())
        self.assertEqual(status, 201)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        again_status, again_body, _ = self.post_template(self.template_body())
        self.assertEqual((again_status, again_body), (status, body))

    def test_concurrent_same_key_all_replay_created(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def create() -> None:
            status, _, _ = self.post_template(self.template_body())
            with lock:
                results.append(status)

        threads = [threading.Thread(target=create) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [201] * 8)

    def test_concurrent_distinct_keys_same_id_single_winner(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def create(index: int) -> None:
            status, _, _ = self.post_template(
                self.template_body(), idempotency_key=f"sla-race-{index}"
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=create, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [201] + [409] * 7)

    def test_invalid_idempotency_key(self) -> None:
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_template(self.template_body(), idempotency_key=key)
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        valid = {
            "id": "tpl-1",
            "machineId": self.machine_id,
            "capabilityVersion": 1,
            "priceMicros": 1000,
            "maxLatencyMs": 50,
        }
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            json.dumps(dict(valid, extra=1)).encode(),
            json.dumps({key: value for key, value in valid.items() if key != "id"}).encode(),
            json.dumps(dict(valid, id="")).encode(),
            json.dumps(dict(valid, id="A" * 64)).encode(),
            json.dumps(dict(valid, id="tpl_1")).encode(),
            json.dumps(dict(valid, id="x" * 65)).encode(),
            json.dumps(dict(valid, id=1)).encode(),
            json.dumps(dict(valid, id=["tpl-1"])).encode(),
            json.dumps(dict(valid, machineId="gg" * 32)).encode(),
            json.dumps(dict(valid, machineId=self.machine_id.upper())).encode(),
            json.dumps(dict(valid, machineId="aa" * 31)).encode(),
            json.dumps(dict(valid, machineId=123)).encode(),
            json.dumps(dict(valid, capabilityVersion=0)).encode(),
            json.dumps(dict(valid, capabilityVersion=2147483648)).encode(),
            json.dumps(dict(valid, capabilityVersion=True)).encode(),
            json.dumps(dict(valid, capabilityVersion=1.0)).encode(),
            json.dumps(dict(valid, capabilityVersion="1")).encode(),
            json.dumps(dict(valid, priceMicros=-1)).encode(),
            json.dumps(dict(valid, priceMicros=2147483648)).encode(),
            json.dumps(dict(valid, priceMicros=False)).encode(),
            json.dumps(dict(valid, maxLatencyMs=0)).encode(),
            json.dumps(dict(valid, maxLatencyMs=2147483648)).encode(),
            json.dumps(dict(valid, maxLatencyMs=True)).encode(),
            b'{"id":"tpl-1","id":"tpl-2","machineId":"'
            + self.machine_id.encode()
            + b'","capabilityVersion":1,"priceMicros":1000,"maxLatencyMs":50}',
        ]
        for body in cases:
            status, response_body, _ = self.post_template(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})


class SlaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            request = Request(
                self.url("/v1/machines"),
                data=json.dumps({"publicKey": public_key}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 201)
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        request = Request(
            self.url("/v1/sla-templates"),
            data=json.dumps(
                {
                    "id": "tpl-1",
                    "machineId": self.machine_id,
                    "capabilityVersion": 1,
                    "priceMicros": 1000,
                    "maxLatencyMs": 50,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "tpl-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def sla_body(self, **overrides: object) -> bytes:
        fields: dict[str, object] = {
            "id": "sla-1",
            "templateId": "tpl-1",
            "consumerId": self.consumer_id,
            "start": 1700000000,
            "end": 1700003600,
        }
        fields.update(overrides)
        return json.dumps(fields).encode()

    def post_sla(
        self, body: bytes, idempotency_key: str | None = "sla-1"
    ) -> tuple[int, bytes, str]:
        request = Request(self.url("/v1/slas"), data=body, method="POST")
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def get_sla(self, sla_id: str) -> tuple[int, bytes, str]:
        try:
            with urlopen(self.url(f"/v1/slas/{sla_id}"), timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_sla_created(self) -> None:
        status, body, content_type = self.post_sla(self.sla_body())
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(body, b'{"id":"sla-1"}')
        self.assertFalse(body.endswith(b"\n"))

    def test_get_sla_returns_snapshot_in_key_order(self) -> None:
        self.assertEqual(self.post_sla(self.sla_body())[0], 201)
        status, body, content_type = self.get_sla("sla-1")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(
            body.decode("utf-8"),
            json.dumps(
                {
                    "id": "sla-1",
                    "templateId": "tpl-1",
                    "machineId": self.machine_id,
                    "consumerId": self.consumer_id,
                    "capabilityVersion": 1,
                    "priceMicros": 1000,
                    "maxLatencyMs": 50,
                    "start": 1700000000,
                    "end": 1700003600,
                    "state": "pending",
                },
                separators=(",", ":"),
            ),
        )
        self.assertEqual(
            list(json.loads(body)),
            [
                "id",
                "templateId",
                "machineId",
                "consumerId",
                "capabilityVersion",
                "priceMicros",
                "maxLatencyMs",
                "start",
                "end",
                "state",
            ],
        )

    def test_get_sla_missing_or_invalid_id_is_404(self) -> None:
        for sla_id in ("sla-1", "Bad_Id", "../sla-1", ""):
            status, body, _ = self.get_sla(sla_id)
            self.assertEqual(status, 404, sla_id)
            self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_replay_returns_first_response_bytes(self) -> None:
        status, body, _ = self.post_sla(self.sla_body())
        self.assertEqual((status, body), (201, b'{"id":"sla-1"}'))
        for _ in range(2):
            again_status, again_body, _ = self.post_sla(self.sla_body())
            self.assertEqual((again_status, again_body), (status, body))

    def test_same_key_different_request_conflicts(self) -> None:
        self.assertEqual(self.post_sla(self.sla_body())[0], 201)
        for body in (
            self.sla_body(id="sla-2"),
            self.sla_body(templateId="tpl-2"),
            self.sla_body(end=1700003601),
        ):
            status, response_body, _ = self.post_sla(body)
            self.assertEqual(status, 409, body)
            self.assertEqual(json.loads(response_body), {"error": "conflict"})

    def test_template_missing_conflicts(self) -> None:
        status, body, _ = self.post_sla(self.sla_body(templateId="tpl-9"))
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_stale_capability_version_conflicts(self) -> None:
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 1,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 20,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-2")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
        status, body, _ = self.post_sla(self.sla_body())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_consumer_missing_not_found(self) -> None:
        status, body, _ = self.post_sla(self.sla_body(consumerId=machine_id(PUBLIC_KEY_C)))
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_duplicate_id_conflicts(self) -> None:
        self.assertEqual(self.post_sla(self.sla_body())[0], 201)
        status, body, _ = self.post_sla(self.sla_body(start=1), idempotency_key="sla-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "sla_exists"})

    def test_failed_request_leaves_no_idempotency_record(self) -> None:
        status, _, _ = self.post_sla(self.sla_body(consumerId=machine_id(PUBLIC_KEY_C)))
        self.assertEqual(status, 404)
        request = Request(
            self.url("/v1/machines"),
            data=json.dumps({"publicKey": PUBLIC_KEY_C}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "register-3")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        status, body, _ = self.post_sla(self.sla_body(consumerId=machine_id(PUBLIC_KEY_C)))
        self.assertEqual((status, body), (201, b'{"id":"sla-1"}'))

    def test_replay_survives_restart(self) -> None:
        status, body, _ = self.post_sla(self.sla_body())
        self.assertEqual(status, 201)
        self.restart()
        again_status, again_body, _ = self.post_sla(self.sla_body())
        self.assertEqual((again_status, again_body), (status, body))

    def test_get_survives_restart(self) -> None:
        self.assertEqual(self.post_sla(self.sla_body())[0], 201)
        _, body, _ = self.get_sla("sla-1")
        self.restart()
        status, again_body, _ = self.get_sla("sla-1")
        self.assertEqual(status, 200)
        self.assertEqual(again_body, body)

    def test_concurrent_same_key_all_replay_created(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def create() -> None:
            status, _, _ = self.post_sla(self.sla_body())
            with lock:
                results.append(status)

        threads = [threading.Thread(target=create) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [201] * 8)

    def test_concurrent_distinct_keys_same_id_single_winner(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def create(index: int) -> None:
            status, _, _ = self.post_sla(
                self.sla_body(), idempotency_key=f"sla-race-{index}"
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=create, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [201] + [409] * 7)

    def test_invalid_idempotency_key(self) -> None:
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_sla(self.sla_body(), idempotency_key=key)
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        valid = {
            "id": "sla-1",
            "templateId": "tpl-1",
            "consumerId": self.consumer_id,
            "start": 1700000000,
            "end": 1700003600,
        }
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            json.dumps(dict(valid, extra=1)).encode(),
            json.dumps({key: value for key, value in valid.items() if key != "start"}).encode(),
            json.dumps(dict(valid, id="")).encode(),
            json.dumps(dict(valid, id="Sla_1")).encode(),
            json.dumps(dict(valid, id="x" * 65)).encode(),
            json.dumps(dict(valid, id=1)).encode(),
            json.dumps(dict(valid, templateId="")).encode(),
            json.dumps(dict(valid, templateId="Tpl_1")).encode(),
            json.dumps(dict(valid, templateId=1)).encode(),
            json.dumps(dict(valid, consumerId="gg" * 32)).encode(),
            json.dumps(dict(valid, consumerId=self.consumer_id.upper())).encode(),
            json.dumps(dict(valid, consumerId="aa" * 31)).encode(),
            json.dumps(dict(valid, consumerId=123)).encode(),
            json.dumps(dict(valid, start=-1)).encode(),
            json.dumps(dict(valid, start=2147483648)).encode(),
            json.dumps(dict(valid, start=True)).encode(),
            json.dumps(dict(valid, start=1.0)).encode(),
            json.dumps(dict(valid, start="0")).encode(),
            json.dumps(dict(valid, end=-1)).encode(),
            json.dumps(dict(valid, end=2147483648)).encode(),
            json.dumps(dict(valid, end=False)).encode(),
            json.dumps(dict(valid, start=1700003600, end=1700003600)).encode(),
            json.dumps(dict(valid, start=1700003601, end=1700003600)).encode(),
            b'{"id":"sla-1","id":"sla-2","templateId":"tpl-1","consumerId":"'
            + self.consumer_id.encode()
            + b'","start":1700000000,"end":1700003600}',
        ]
        for body in cases:
            status, response_body, _ = self.post_sla(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})

    def test_boundary_start_end_accepted(self) -> None:
        status, body, _ = self.post_sla(self.sla_body(start=0, end=2147483647))
        self.assertEqual((status, body), (201, b'{"id":"sla-1"}'))


class ConfirmationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            request = Request(
                self.url("/v1/machines"),
                data=json.dumps({"publicKey": public_key}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 201)
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        request = Request(
            self.url("/v1/sla-templates"),
            data=json.dumps(
                {
                    "id": "tpl-1",
                    "machineId": self.machine_id,
                    "capabilityVersion": 1,
                    "priceMicros": 1000,
                    "maxLatencyMs": 50,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "tpl-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        self.create_sla()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def create_sla(
        self,
        sla_id: str = "sla-1",
        template_id: str = "tpl-1",
        consumer_id: str | None = None,
        start: int | None = None,
        end: int | None = None,
        key: str = "sla-1",
    ) -> None:
        current = int(time.time())
        body = json.dumps(
            {
                "id": sla_id,
                "templateId": template_id,
                "consumerId": consumer_id if consumer_id is not None else self.consumer_id,
                "start": current - 10 if start is None else start,
                "end": current + 3600 if end is None else end,
            }
        ).encode()
        request = Request(self.url("/v1/slas"), data=body, method="POST")
        request.add_header("Idempotency-Key", key)
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def confirmation_body(self, party: str, actor_id: str) -> bytes:
        return json.dumps({"party": party, "actorId": actor_id}).encode()

    def post_confirmation(
        self,
        body: bytes,
        sla_id: str = "sla-1",
        idempotency_key: str | None = "conf-1",
    ) -> tuple[int, bytes, str]:
        request = Request(
            self.url(f"/v1/slas/{sla_id}/confirmations"), data=body, method="POST"
        )
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def get_sla(self, sla_id: str = "sla-1") -> tuple[int, bytes, str]:
        try:
            with urlopen(self.url(f"/v1/slas/{sla_id}"), timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_producer_then_consumer_transitions_to_active(self) -> None:
        status, body, content_type = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(body, b'{"state":"pending"}')
        self.assertFalse(body.endswith(b"\n"))
        _, snapshot, _ = self.get_sla()
        self.assertEqual(json.loads(snapshot)["state"], "pending")
        status, body, _ = self.post_confirmation(
            self.confirmation_body("consumer", self.consumer_id), idempotency_key="conf-2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"state":"active"}')
        _, snapshot, _ = self.get_sla()
        self.assertEqual(json.loads(snapshot)["state"], "active")

    def test_consumer_first_then_producer(self) -> None:
        status, body, _ = self.post_confirmation(
            self.confirmation_body("consumer", self.consumer_id)
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), idempotency_key="conf-2"
        )
        self.assertEqual((status, body), (200, b'{"state":"active"}'))

    def test_replay_returns_first_status_and_bytes(self) -> None:
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))
        for _ in range(2):
            again_status, again_body, _ = self.post_confirmation(
                self.confirmation_body("producer", self.machine_id)
            )
            self.assertEqual((again_status, again_body), (status, body))
        self.post_confirmation(
            self.confirmation_body("consumer", self.consumer_id), idempotency_key="conf-2"
        )
        # 首方确认的重放仍返回其首次的 pending 字节。
        again_status, again_body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((again_status, again_body), (200, b'{"state":"pending"}'))

    def test_replay_survives_restart(self) -> None:
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))
        self.restart()
        again_status, again_body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((again_status, again_body), (status, body))

    def test_active_response_replay_survives_restart(self) -> None:
        self.post_confirmation(self.confirmation_body("producer", self.machine_id))
        status, body, _ = self.post_confirmation(
            self.confirmation_body("consumer", self.consumer_id), idempotency_key="conf-2"
        )
        self.assertEqual((status, body), (200, b'{"state":"active"}'))
        self.restart()
        again_status, again_body, _ = self.post_confirmation(
            self.confirmation_body("consumer", self.consumer_id), idempotency_key="conf-2"
        )
        self.assertEqual((again_status, again_body), (status, body))

    def test_same_key_different_sla_conflicts(self) -> None:
        self.create_sla(sla_id="sla-2", key="sla-2")
        self.assertEqual(
            self.post_confirmation(
                self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), sla_id="sla-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_same_key_different_body_conflicts(self) -> None:
        self.assertEqual(
            self.post_confirmation(
                self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        for body in (
            self.confirmation_body("consumer", self.consumer_id),
            self.confirmation_body("producer", self.consumer_id),
        ):
            status, response_body, _ = self.post_confirmation(body)
            self.assertEqual(status, 409)
            self.assertEqual(json.loads(response_body), {"error": "conflict"})

    def test_sla_not_found(self) -> None:
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), sla_id="missing"
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_party_actor_mismatch_is_forbidden(self) -> None:
        # producer 却提供 consumerId
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.consumer_id)
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})
        # consumer 却提供 machineId
        status, body, _ = self.post_confirmation(
            self.confirmation_body("consumer", self.machine_id), idempotency_key="conf-2"
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})
        # 完全无关的第三方
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", machine_id(PUBLIC_KEY_C)),
            idempotency_key="conf-3",
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})

    def test_duplicate_party_with_different_key_is_already_confirmed(self) -> None:
        self.assertEqual(
            self.post_confirmation(
                self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), idempotency_key="conf-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_confirmed"})

    def test_before_start_window_conflicts(self) -> None:
        current = int(time.time())
        self.create_sla(
            sla_id="future",
            key="sla-future",
            start=current + 600,
            end=current + 3600,
        )
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), sla_id="future"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_at_or_after_end_conflicts(self) -> None:
        current = int(time.time())
        self.create_sla(
            sla_id="past",
            key="sla-past",
            start=current - 3600,
            end=current - 1,
        )
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), sla_id="past"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_capability_version_changed_conflicts(self) -> None:
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 1,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 20,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-2")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_failed_request_leaves_no_records(self) -> None:
        # 时间窗不符的失败请求既不写确认，也不占用幂等键。
        current = int(time.time())
        self.create_sla(
            sla_id="past",
            key="sla-past",
            start=current - 3600,
            end=current - 1,
        )
        status, _, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), sla_id="past"
        )
        self.assertEqual(status, 409)
        # 同一幂等键在合法 SLA 上首次使用应当成功（说明失败未占键）。
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))

    def test_forbidden_leaves_no_idempotency_record(self) -> None:
        status, _, _ = self.post_confirmation(
            self.confirmation_body("producer", self.consumer_id)
        )
        self.assertEqual(status, 403)
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))

    def test_concurrent_same_key_all_replay_pending(self) -> None:
        results: list[tuple[int, bytes]] = []
        lock = threading.Lock()

        def confirm() -> None:
            status, body, _ = self.post_confirmation(
                self.confirmation_body("producer", self.machine_id)
            )
            with lock:
                results.append((status, body))

        threads = [threading.Thread(target=confirm) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [(200, b'{"state":"pending"}')] * 8)

    def test_concurrent_distinct_keys_same_party_single_winner(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def confirm(index: int) -> None:
            status, _, _ = self.post_confirmation(
                self.confirmation_body("producer", self.machine_id),
                idempotency_key=f"conf-race-{index}",
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=confirm, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [200] + [409] * 7)

    def test_concurrent_both_parties_active_once(self) -> None:
        states: list[str] = []
        statuses: list[int] = []
        lock = threading.Lock()
        barrier = threading.Barrier(2)

        def confirm(party: str, actor: str) -> None:
            barrier.wait(timeout=5)
            status, body, _ = self.post_confirmation(
                self.confirmation_body(party, actor), idempotency_key=f"conf-{party}"
            )
            with lock:
                statuses.append(status)
                states.append(json.loads(body)["state"])

        threads = [
            threading.Thread(target=confirm, args=("producer", self.machine_id)),
            threading.Thread(target=confirm, args=("consumer", self.consumer_id)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(statuses), [200, 200])
        self.assertEqual(sorted(states), ["active", "pending"])
        _, snapshot, _ = self.get_sla()
        self.assertEqual(json.loads(snapshot)["state"], "active")
        # active 后任何一方再确认均为 already_confirmed。
        status, body, _ = self.post_confirmation(
            self.confirmation_body("producer", self.machine_id), idempotency_key="again-p"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_confirmed"})

    def test_invalid_idempotency_key(self) -> None:
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_confirmation(
                self.confirmation_body("producer", self.machine_id), idempotency_key=key
            )
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            json.dumps({"party": "producer"}).encode(),
            json.dumps({"actorId": self.machine_id}).encode(),
            json.dumps(
                {"party": "producer", "actorId": self.machine_id, "extra": 1}
            ).encode(),
            json.dumps({"party": "broker", "actorId": self.machine_id}).encode(),
            json.dumps({"party": "Producer", "actorId": self.machine_id}).encode(),
            json.dumps({"party": 1, "actorId": self.machine_id}).encode(),
            json.dumps({"party": ["producer"], "actorId": self.machine_id}).encode(),
            json.dumps({"party": None, "actorId": self.machine_id}).encode(),
            json.dumps({"party": "producer", "actorId": "aa"}).encode(),
            json.dumps({"party": "producer", "actorId": "gg" * 32}).encode(),
            json.dumps({"party": "producer", "actorId": self.machine_id.upper()}).encode(),
            json.dumps({"party": "producer", "actorId": 123}).encode(),
            b'{"party":"producer","party":"consumer","actorId":"'
            + self.machine_id.encode()
            + b'"}',
            b'{"party":"producer","actorId":"'
            + self.machine_id.encode()
            + b'","actorId":"'
            + self.consumer_id.encode()
            + b'"}',
        ]
        for body in cases:
            status, response_body, _ = self.post_confirmation(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})


class TelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            request = Request(
                self.url("/v1/machines"),
                data=json.dumps({"publicKey": public_key}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 201)
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        request = Request(
            self.url("/v1/sla-templates"),
            data=json.dumps(
                {
                    "id": "tpl-1",
                    "machineId": self.machine_id,
                    "capabilityVersion": 1,
                    "priceMicros": 1000,
                    "maxLatencyMs": 50,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "tpl-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        current = int(time.time())
        self.start = current - 10
        self.end = current + 3600
        request = Request(
            self.url("/v1/slas"),
            data=json.dumps(
                {
                    "id": "sla-1",
                    "templateId": "tpl-1",
                    "consumerId": self.consumer_id,
                    "start": self.start,
                    "end": self.end,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "sla-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def activate(self, sla_id: str = "sla-1") -> None:
        for key, party, actor in (
            ("conf-p", "producer", self.machine_id),
            ("conf-c", "consumer", self.consumer_id),
        ):
            request = Request(
                self.url(f"/v1/slas/{sla_id}/confirmations"),
                data=json.dumps({"party": party, "actorId": actor}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)

    def digest(self, sla_id: str, event_id: str, timestamp: int, latency_ms: int) -> str:
        message = f"{sla_id}\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine_id}"
        return hashlib.sha256(message.encode("utf-8")).hexdigest()

    def telemetry_body(
        self,
        sla_id: str = "sla-1",
        event_id: str = "evt-1",
        timestamp: int | None = None,
        latency_ms: int = 12,
        digest: str | None = None,
    ) -> bytes:
        if timestamp is None:
            timestamp = self.start * 1000 + 500
        if digest is None:
            digest = self.digest(sla_id, event_id, timestamp, latency_ms)
        return json.dumps(
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": digest,
            }
        ).encode()

    def post_telemetry(
        self,
        body: bytes,
        sla_id: str = "sla-1",
        idempotency_key: str | None = "tel-1",
    ) -> tuple[int, bytes, str]:
        request = Request(
            self.url(f"/v1/slas/{sla_id}/telemetry"), data=body, method="POST"
        )
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def add_event(self, index: int, timestamp: int, latency_ms: int) -> None:
        event_id = f"evt-{index:03d}"
        status, body, _ = self.post_telemetry(
            self.telemetry_body(
                event_id=event_id, timestamp=timestamp, latency_ms=latency_ms
            ),
            idempotency_key=f"tel-{index}",
        )
        self.assertEqual(
            (status, body),
            (201, json.dumps({"eventId": event_id}, separators=(",", ":")).encode()),
        )

    def get_telemetry(
        self, query: str = "", sla_id: str = "sla-1"
    ) -> tuple[int, object, str]:
        suffix = f"?{query}" if query else ""
        try:
            with urlopen(
                self.url(f"/v1/slas/{sla_id}/telemetry{suffix}"), timeout=5
            ) as response:
                return (
                    response.status,
                    json.loads(response.read()),
                    response.headers["Content-Type"],
                )
        except HTTPError as error:
            return error.code, json.loads(error.read()), error.headers["Content-Type"]

    def test_get_telemetry_empty_sla(self) -> None:
        self.activate()
        status, body, content_type = self.get_telemetry("from=0&to=2147483648000")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(list(body), ["events", "summary", "nextCursor"])
        self.assertEqual(body["events"], [])
        self.assertEqual(list(body["summary"]), ["count", "latencySum", "maxLatency", "violations"])
        self.assertEqual(
            body["summary"],
            {"count": 0, "latencySum": 0, "maxLatency": None, "violations": 0},
        )
        self.assertIsNone(body["nextCursor"])

    def test_get_telemetry_order_window_and_summary(self) -> None:
        self.activate()
        base = self.start * 1000
        self.add_event(1, base + 100, 10)
        self.add_event(2, base + 100, 5)  # 同 timestamp 按 eventId 升序
        self.add_event(3, base + 200, 60)  # 违约（> 50）
        self.add_event(4, base + 300, 51)  # 违约
        status, body, _ = self.get_telemetry(f"from={base}&to={base + 400}")
        self.assertEqual(status, 200)
        self.assertEqual(
            [event["eventId"] for event in body["events"]],
            ["evt-001", "evt-002", "evt-003", "evt-004"],
        )
        self.assertEqual(
            list(body["events"][0]), ["eventId", "timestamp", "latencyMs", "digest"]
        )
        self.assertEqual(
            body["summary"],
            {"count": 4, "latencySum": 126, "maxLatency": 60, "violations": 2},
        )
        self.assertIsNone(body["nextCursor"])

    def test_get_telemetry_interval_is_half_open(self) -> None:
        self.activate()
        base = self.start * 1000
        self.add_event(1, base + 100, 10)
        self.add_event(2, base + 200, 10)
        status, body, _ = self.get_telemetry(f"from={base + 100}&to={base + 200}")
        self.assertEqual(status, 200)
        self.assertEqual([event["eventId"] for event in body["events"]], ["evt-001"])
        self.assertEqual(body["summary"]["count"], 1)

    def test_get_telemetry_boundary_from_to_accepted(self) -> None:
        self.activate()
        status, _, _ = self.get_telemetry("from=0&to=2147483648000")
        self.assertEqual(status, 200)

    def test_get_telemetry_pagination(self) -> None:
        self.activate()
        base = self.start * 1000
        for index in range(1, 6):
            self.add_event(index, base + index * 10, index)
        status, page1, _ = self.get_telemetry(f"from={base}&to={base + 1000}&limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(
            [event["eventId"] for event in page1["events"]], ["evt-001", "evt-002"]
        )
        self.assertEqual(page1["nextCursor"], f"5:{base + 20}:evt-002")
        self.assertEqual(page1["summary"]["count"], 5)
        status, page2, _ = self.get_telemetry(
            f"from={base}&to={base + 1000}&limit=2&cursor={page1['nextCursor']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [event["eventId"] for event in page2["events"]], ["evt-003", "evt-004"]
        )
        self.assertEqual(page2["nextCursor"], f"5:{base + 40}:evt-004")
        status, page3, _ = self.get_telemetry(
            f"from={base}&to={base + 1000}&limit=2&cursor={page2['nextCursor']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual([event["eventId"] for event in page3["events"]], ["evt-005"])
        self.assertIsNone(page3["nextCursor"])

    def test_get_telemetry_default_limit_is_50(self) -> None:
        self.activate()
        base = self.start * 1000
        for index in range(1, 52):
            self.add_event(index, base + index, index)
        status, page1, _ = self.get_telemetry(f"from={base}&to={base + 1000}")
        self.assertEqual(status, 200)
        self.assertEqual(len(page1["events"]), 50)
        self.assertEqual(page1["summary"]["count"], 51)
        self.assertIsNotNone(page1["nextCursor"])
        status, page2, _ = self.get_telemetry(
            f"from={base}&to={base + 1000}&cursor={page1['nextCursor']}"
        )
        self.assertEqual(
            [event["eventId"] for event in page2["events"]], ["evt-051"]
        )
        self.assertIsNone(page2["nextCursor"])

    def test_get_telemetry_cursor_pins_cut_against_new_events(self) -> None:
        self.activate()
        base = self.start * 1000
        for index in range(1, 4):
            self.add_event(index, base + index * 10, index)
        status, page1, _ = self.get_telemetry(f"from={base}&to={base + 1000}&limit=2")
        self.assertEqual(status, 200)
        cursor = page1["nextCursor"]
        # 新事件按序会插入到已返回事件之间与之后。
        self.add_event(4, base + 15, 4)
        self.add_event(5, base + 25, 99)
        status, page2, _ = self.get_telemetry(
            f"from={base}&to={base + 1000}&limit=2&cursor={cursor}"
        )
        self.assertEqual(status, 200)
        self.assertEqual([event["eventId"] for event in page2["events"]], ["evt-003"])
        self.assertIsNone(page2["nextCursor"])
        # 汇总同样钉在游标携带的 cut 上，不含新事件。
        self.assertEqual(
            page2["summary"],
            {"count": 3, "latencySum": 6, "maxLatency": 3, "violations": 0},
        )
        # 全新首页使用新 cut，可见全部 5 条。
        status, fresh, _ = self.get_telemetry(f"from={base}&to={base + 1000}")
        self.assertEqual(
            [event["eventId"] for event in fresh["events"]],
            ["evt-001", "evt-004", "evt-002", "evt-005", "evt-003"],
        )
        self.assertEqual(fresh["summary"]["count"], 5)
        self.assertEqual(fresh["summary"]["violations"], 1)

    def test_get_telemetry_cursor_survives_restart(self) -> None:
        self.activate()
        base = self.start * 1000
        for index in range(1, 4):
            self.add_event(index, base + index * 10, index)
        status, page1, _ = self.get_telemetry(f"from={base}&to={base + 1000}&limit=2")
        self.assertEqual(status, 200)
        cursor = page1["nextCursor"]
        self.restart()
        status, page2, _ = self.get_telemetry(
            f"from={base}&to={base + 1000}&limit=2&cursor={cursor}"
        )
        self.assertEqual(status, 200)
        self.assertEqual([event["eventId"] for event in page2["events"]], ["evt-003"])
        self.assertIsNone(page2["nextCursor"])
        self.assertEqual(page2["summary"]["count"], 3)

    def test_get_telemetry_sla_not_found(self) -> None:
        status, body, _ = self.get_telemetry("from=0&to=1", sla_id="missing")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "not_found"})

    def test_get_telemetry_invalid_query(self) -> None:
        self.activate()
        cases = [
            "",
            "to=1",
            "from=0",
            "from=-1&to=1",
            "from=01&to=1",
            "from=1&to=1",
            "from=2&to=1",
            "from=0&to=2147483648001",
            "from=x&to=1",
            "from=1.0&to=2",
            "from=0&to=1&limit=0",
            "from=0&to=1&limit=101",
            "from=0&to=1&limit=01",
            "from=0&to=1&limit=x",
            "from=0&to=1&unknown=2",
            "from=0&to=1&from=0",
            "from=0&to=1&cursor=1%3A5%3Aevt-1",  # SLA 无事件，锚点不存在
            "from=0&to=1&cursor=bad",
            "from=0&to=1&cursor=0:0:evt-1",
            "from=0&to=1&cursor=999999:0:evt-1",
        ]
        for query in cases:
            status, body, _ = self.get_telemetry(query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "invalid_request"})

    def test_get_telemetry_cursor_must_match_range_and_event(self) -> None:
        self.activate()
        base = self.start * 1000
        self.add_event(1, base + 100, 10)
        cursor = f"1:{base + 100}:evt-001"
        for query in (
            f"from={base + 200}&to={base + 300}&cursor={cursor}",
            f"from={base}&to={base + 100}&cursor={cursor}",
            f"from={base}&to={base + 400}&cursor=1:{base + 100}:evt-009",
        ):
            status, body, _ = self.get_telemetry(query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "invalid_request"})

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_telemetry_created(self) -> None:
        self.activate()
        status, body, content_type = self.post_telemetry(self.telemetry_body())
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(body, b'{"eventId":"evt-1"}')
        self.assertFalse(body.endswith(b"\n"))

    def test_pending_sla_conflicts(self) -> None:
        status, body, _ = self.post_telemetry(self.telemetry_body())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_timestamp_out_of_window_conflicts(self) -> None:
        self.activate()
        for timestamp in (self.start * 1000 - 1, self.end * 1000, self.end * 1000 + 1):
            status, body, _ = self.post_telemetry(
                self.telemetry_body(timestamp=timestamp),
                idempotency_key=f"tel-ts-{timestamp}",
            )
            self.assertEqual(status, 409, timestamp)
            self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_window_boundaries_accepted(self) -> None:
        self.activate()
        status, body, _ = self.post_telemetry(
            self.telemetry_body(event_id="evt-lo", timestamp=self.start * 1000)
        )
        self.assertEqual((status, body), (201, b'{"eventId":"evt-lo"}'))
        status, body, _ = self.post_telemetry(
            self.telemetry_body(event_id="evt-hi", timestamp=self.end * 1000 - 1),
            idempotency_key="tel-2",
        )
        self.assertEqual((status, body), (201, b'{"eventId":"evt-hi"}'))

    def test_bad_digest_conflicts(self) -> None:
        self.activate()
        status, body, _ = self.post_telemetry(
            self.telemetry_body(digest="0" * 64)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_sla_not_found(self) -> None:
        status, body, _ = self.post_telemetry(
            self.telemetry_body(sla_id="missing"), sla_id="missing"
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_replay_returns_first_response_bytes(self) -> None:
        self.activate()
        status, body, _ = self.post_telemetry(self.telemetry_body())
        self.assertEqual((status, body), (201, b'{"eventId":"evt-1"}'))
        for _ in range(2):
            again_status, again_body, _ = self.post_telemetry(self.telemetry_body())
            self.assertEqual((again_status, again_body), (status, body))

    def test_replay_survives_restart(self) -> None:
        self.activate()
        status, body, _ = self.post_telemetry(self.telemetry_body())
        self.assertEqual(status, 201)
        self.restart()
        again_status, again_body, _ = self.post_telemetry(self.telemetry_body())
        self.assertEqual((again_status, again_body), (status, body))

    def test_same_key_different_sla_or_body_conflicts(self) -> None:
        self.activate()
        self.assertEqual(self.post_telemetry(self.telemetry_body())[0], 201)
        status, body, _ = self.post_telemetry(
            self.telemetry_body(event_id="evt-2")
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        status, body, _ = self.post_telemetry(
            self.telemetry_body(sla_id="sla-2"), sla_id="sla-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_same_event_id_different_key_is_event_exists(self) -> None:
        self.activate()
        self.assertEqual(self.post_telemetry(self.telemetry_body())[0], 201)
        status, body, _ = self.post_telemetry(
            self.telemetry_body(), idempotency_key="tel-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "event_exists"})

    def test_failed_request_leaves_no_idempotency_record(self) -> None:
        # 未 active 时失败不占键；激活后同键首次使用应成功。
        status, _, _ = self.post_telemetry(self.telemetry_body())
        self.assertEqual(status, 409)
        self.activate()
        status, body, _ = self.post_telemetry(self.telemetry_body())
        self.assertEqual((status, body), (201, b'{"eventId":"evt-1"}'))

    def test_concurrent_same_key_all_replay_created(self) -> None:
        self.activate()
        results: list[tuple[int, bytes]] = []
        lock = threading.Lock()

        def post() -> None:
            status, body, _ = self.post_telemetry(self.telemetry_body())
            with lock:
                results.append((status, body))

        threads = [threading.Thread(target=post) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [(201, b'{"eventId":"evt-1"}')] * 8)

    def test_concurrent_distinct_keys_same_event_single_winner(self) -> None:
        self.activate()
        results: list[int] = []
        lock = threading.Lock()

        def post(index: int) -> None:
            status, _, _ = self.post_telemetry(
                self.telemetry_body(), idempotency_key=f"tel-race-{index}"
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=post, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [201] + [409] * 7)

    def test_invalid_idempotency_key(self) -> None:
        self.activate()
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_telemetry(
                self.telemetry_body(), idempotency_key=key
            )
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        self.activate()
        valid = json.loads(self.telemetry_body())
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            json.dumps(dict(valid, extra=1)).encode(),
            json.dumps(
                {key: value for key, value in valid.items() if key != "digest"}
            ).encode(),
            json.dumps(dict(valid, eventId="")).encode(),
            json.dumps(dict(valid, eventId="Evt_1")).encode(),
            json.dumps(dict(valid, eventId="x" * 65)).encode(),
            json.dumps(dict(valid, eventId=1)).encode(),
            json.dumps(dict(valid, timestamp=-1)).encode(),
            json.dumps(dict(valid, timestamp=2147483648000)).encode(),
            json.dumps(dict(valid, timestamp=True)).encode(),
            json.dumps(dict(valid, timestamp=1.0)).encode(),
            json.dumps(dict(valid, timestamp="0")).encode(),
            json.dumps(dict(valid, latencyMs=-1)).encode(),
            json.dumps(dict(valid, latencyMs=2147483648)).encode(),
            json.dumps(dict(valid, latencyMs=False)).encode(),
            json.dumps(dict(valid, latencyMs="12")).encode(),
            json.dumps(dict(valid, digest="")).encode(),
            json.dumps(dict(valid, digest="g" * 64)).encode(),
            json.dumps(dict(valid, digest="A" * 64)).encode(),
            json.dumps(dict(valid, digest="0" * 63)).encode(),
            json.dumps(dict(valid, digest=123)).encode(),
            b'{"eventId":"evt-1","eventId":"evt-2","timestamp":'
            + str(valid["timestamp"]).encode()
            + b',"latencyMs":12,"digest":"'
            + valid["digest"].encode()
            + b'"}',
        ]
        for body in cases:
            status, response_body, _ = self.post_telemetry(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})


class EvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            request = Request(
                self.url("/v1/machines"),
                data=json.dumps({"publicKey": public_key}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 201)
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        request = Request(
            self.url("/v1/sla-templates"),
            data=json.dumps(
                {
                    "id": "tpl-1",
                    "machineId": self.machine_id,
                    "capabilityVersion": 1,
                    "priceMicros": 1000,
                    "maxLatencyMs": 50,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "tpl-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        current = int(time.time())
        self.start = current - 10
        self.end = current + 3600
        self.create_sla("sla-1", "sla-create-1")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def create_sla(self, sla_id: str, key: str) -> None:
        request = Request(
            self.url("/v1/slas"),
            data=json.dumps(
                {
                    "id": sla_id,
                    "templateId": "tpl-1",
                    "consumerId": self.consumer_id,
                    "start": self.start,
                    "end": self.end,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", key)
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def activate(self, sla_id: str = "sla-1") -> None:
        for index, (party, actor) in enumerate(
            (
                ("producer", self.machine_id),
                ("consumer", self.consumer_id),
            )
        ):
            request = Request(
                self.url(f"/v1/slas/{sla_id}/confirmations"),
                data=json.dumps({"party": party, "actorId": actor}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", f"conf-{sla_id}-{index}")
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)

    def digest(self, sla_id: str, event_id: str, timestamp: int, latency_ms: int) -> str:
        message = f"{sla_id}\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine_id}"
        return hashlib.sha256(message.encode("utf-8")).hexdigest()

    def add_event(
        self, index: int, timestamp: int, latency_ms: int, sla_id: str = "sla-1"
    ) -> None:
        event_id = f"evt-{index:03d}"
        body = json.dumps(
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": self.digest(sla_id, event_id, timestamp, latency_ms),
            }
        ).encode()
        request = Request(
            self.url(f"/v1/slas/{sla_id}/telemetry"), data=body, method="POST"
        )
        request.add_header("Idempotency-Key", f"tel-{sla_id}-{index}")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def evaluation_body(self, start: int | None = None, end: int | None = None) -> bytes:
        if start is None:
            start = self.start * 1000
        if end is None:
            end = self.end * 1000
        return json.dumps({"from": start, "to": end}).encode()

    def post_evaluation(
        self,
        body: bytes | None = None,
        sla_id: str = "sla-1",
        idempotency_key: str | None = "eval-1",
    ) -> tuple[int, bytes, str]:
        if body is None:
            body = self.evaluation_body()
        request = Request(
            self.url(f"/v1/slas/{sla_id}/evaluations"), data=body, method="POST"
        )
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def get_evaluations(
        self, query: str = "", sla_id: str = "sla-1"
    ) -> tuple[int, object, str]:
        suffix = f"?{query}" if query else ""
        try:
            with urlopen(
                self.url(f"/v1/slas/{sla_id}/evaluations{suffix}"), timeout=5
            ) as response:
                return (
                    response.status,
                    json.loads(response.read()),
                    response.headers["Content-Type"],
                )
        except HTTPError as error:
            return error.code, json.loads(error.read()), error.headers["Content-Type"]

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_empty_window_is_insufficient_with_null_max_latency(self) -> None:
        self.activate()
        before = int(time.time() * 1000)
        status, body, content_type = self.post_evaluation()
        after = int(time.time() * 1000)
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(list(json.loads(body)), [
            "evaluationSeq",
            "from",
            "to",
            "cut",
            "count",
            "latencySum",
            "maxLatency",
            "violations",
            "outcome",
            "createdAt",
        ])
        payload = json.loads(body)
        self.assertEqual(payload["evaluationSeq"], 1)
        self.assertEqual(payload["from"], self.start * 1000)
        self.assertEqual(payload["to"], self.end * 1000)
        self.assertEqual(payload["cut"], 0)
        self.assertEqual(payload["count"], 0)
        self.assertEqual(payload["latencySum"], 0)
        self.assertIsNone(payload["maxLatency"])
        self.assertEqual(payload["violations"], 0)
        self.assertEqual(payload["outcome"], "insufficient")
        self.assertIsInstance(payload["createdAt"], int)
        self.assertNotIsInstance(payload["createdAt"], bool)
        self.assertGreaterEqual(payload["createdAt"], 0)
        self.assertTrue(before <= payload["createdAt"] <= after)
        self.assertFalse(body.endswith(b"\n"))

    def test_fulfilled_evaluation_aggregates_window(self) -> None:
        self.activate()
        base = self.start * 1000
        self.add_event(1, base + 100, 10)
        self.add_event(2, base + 100, 5)
        self.add_event(3, base + 200, 50)  # 等于阈值不算违约
        status, body, _ = self.post_evaluation(
            self.evaluation_body(base, base + 400)
        )
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(payload["evaluationSeq"], 1)
        self.assertGreaterEqual(payload["createdAt"], 0)
        self.assertEqual(
            {key: value for key, value in payload.items()
             if key not in ("evaluationSeq", "createdAt")},
            {
                "from": base,
                "to": base + 400,
                "cut": 3,
                "count": 3,
                "latencySum": 65,
                "maxLatency": 50,
                "violations": 0,
                "outcome": "fulfilled",
            },
        )

    def test_breached_evaluation(self) -> None:
        self.activate()
        base = self.start * 1000
        self.add_event(1, base + 100, 10)
        self.add_event(2, base + 200, 60)
        status, body, _ = self.post_evaluation(
            self.evaluation_body(base, base + 400)
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["outcome"], "breached")
        self.assertEqual(json.loads(body)["violations"], 1)

    def test_interval_is_half_open(self) -> None:
        self.activate()
        base = self.start * 1000
        self.add_event(1, base + 100, 10)
        self.add_event(2, base + 200, 51)
        status, body, _ = self.post_evaluation(
            self.evaluation_body(base + 100, base + 200)
        )
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["outcome"], "fulfilled")

    def test_window_boundaries_accepted(self) -> None:
        self.activate()
        status, body, _ = self.post_evaluation(
            self.evaluation_body(self.start * 1000, self.end * 1000)
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["outcome"], "insufficient")

    def test_cut_is_global_max_but_aggregation_scoped_to_sla(self) -> None:
        self.activate()
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        base = self.start * 1000
        self.add_event(1, base + 100, 99, sla_id="sla-2")
        self.add_event(2, base + 200, 99, sla_id="sla-2")
        status, body, _ = self.post_evaluation()
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(payload["cut"], 2)
        self.assertEqual(payload["count"], 0)
        self.assertIsNone(payload["maxLatency"])
        self.assertEqual(payload["outcome"], "insufficient")

    def test_replay_returns_first_status_and_bytes(self) -> None:
        self.activate()
        status, body, _ = self.post_evaluation()
        self.assertEqual(status, 201)
        base = self.start * 1000
        self.add_event(1, base + 100, 99)
        for _ in range(2):
            again_status, again_body, _ = self.post_evaluation()
            self.assertEqual((again_status, again_body), (status, body))

    def test_replay_survives_restart(self) -> None:
        self.activate()
        base = self.start * 1000
        self.add_event(1, base + 100, 99)
        status, body, _ = self.post_evaluation(
            self.evaluation_body(base, base + 400)
        )
        self.assertEqual(status, 201)
        self.add_event(2, base + 200, 99)
        self.restart()
        again_status, again_body, _ = self.post_evaluation(
            self.evaluation_body(base, base + 400)
        )
        self.assertEqual((again_status, again_body), (status, body))

    def test_concurrent_same_key_all_replay_created_bytes(self) -> None:
        self.activate()
        results: list[tuple[int, bytes]] = []
        lock = threading.Lock()

        def evaluate() -> None:
            status, body, _ = self.post_evaluation()
            with lock:
                results.append((status, body))

        threads = [threading.Thread(target=evaluate) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual({status for status, _ in results}, {201})
        self.assertEqual({body for _, body in results}, {results[0][1]})
        self.assertEqual(len(results), 8)

    def test_same_key_different_sla_or_body_conflicts(self) -> None:
        self.activate()
        self.assertEqual(self.post_evaluation()[0], 201)
        base = self.start * 1000
        status, body, _ = self.post_evaluation(
            self.evaluation_body(base, base + 400)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        status, body, _ = self.post_evaluation(sla_id="sla-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_sla_not_found(self) -> None:
        status, body, _ = self.post_evaluation(sla_id="missing")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_pending_sla_conflicts(self) -> None:
        status, body, _ = self.post_evaluation()
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_out_of_window_conflicts(self) -> None:
        self.activate()
        base = self.start * 1000
        limit = self.end * 1000
        for index, body in enumerate(
            (
                self.evaluation_body(base - 1, limit),
                self.evaluation_body(base, limit + 1),
                self.evaluation_body(base + 1, base + 1),
                self.evaluation_body(base + 2, base + 1),
            )
        ):
            status, response_body, _ = self.post_evaluation(
                body, idempotency_key=f"eval-range-{index}"
            )
            self.assertEqual(status, 409, body)
            self.assertEqual(json.loads(response_body), {"error": "conflict"})

    def test_failed_request_leaves_no_idempotency_record(self) -> None:
        # 未 active 时失败不占键；激活后同键首次使用应成功。
        status, _, _ = self.post_evaluation()
        self.assertEqual(status, 409)
        self.activate()
        status, body, _ = self.post_evaluation()
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["outcome"], "insufficient")

    def test_invalid_idempotency_key(self) -> None:
        self.activate()
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_evaluation(idempotency_key=key)
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        self.activate()
        base = self.start * 1000
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            json.dumps({"from": base}).encode(),
            json.dumps({"to": base + 1}).encode(),
            json.dumps({"from": base, "to": base + 1, "extra": 1}).encode(),
            json.dumps({"from": True, "to": base + 1}).encode(),
            json.dumps({"from": False, "to": base + 1}).encode(),
            json.dumps({"from": base, "to": True}).encode(),
            json.dumps({"from": 1.0, "to": 2}).encode(),
            json.dumps({"from": str(base), "to": base + 1}).encode(),
            json.dumps({"from": None, "to": base + 1}).encode(),
            json.dumps({"from": [base], "to": base + 1}).encode(),
            b'{"from":1,"from":2,"to":3}',
        ]
        for body in cases:
            status, response_body, _ = self.post_evaluation(body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})

    def test_seq_is_global_monotonic_across_slas(self) -> None:
        self.activate()
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        _, body2, _ = self.post_evaluation(sla_id="sla-2", idempotency_key="eval-s2")
        _, body1, _ = self.post_evaluation()
        self.assertEqual(json.loads(body2)["evaluationSeq"], 1)
        self.assertEqual(json.loads(body1)["evaluationSeq"], 2)

    def test_failed_request_does_not_allocate_seq(self) -> None:
        # SLA 尚为 pending，评估失败不占序号。
        status, _, _ = self.post_evaluation()
        self.assertEqual(status, 409)
        self.activate()
        _, body, _ = self.post_evaluation()
        self.assertEqual(json.loads(body)["evaluationSeq"], 1)

    def test_replay_keeps_first_seq_and_created_at_bytes(self) -> None:
        self.activate()
        status, body, _ = self.post_evaluation()
        self.assertEqual(status, 201)
        for _ in range(2):
            again_status, again_body, _ = self.post_evaluation()
            self.assertEqual((again_status, again_body), (status, body))

    def test_concurrent_distinct_keys_get_unique_global_seqs(self) -> None:
        self.activate()
        results: list[int] = []
        lock = threading.Lock()

        def evaluate(index: int) -> None:
            status, body, _ = self.post_evaluation(idempotency_key=f"eval-race-{index}")
            with lock:
                self.assertEqual(status, 201)
                results.append(json.loads(body)["evaluationSeq"])

        threads = [threading.Thread(target=evaluate, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), list(range(1, 9)))

    def test_get_evaluations_empty_sla(self) -> None:
        self.activate()
        status, body, content_type = self.get_evaluations()
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(list(body), ["evaluations", "nextCursor"])
        self.assertEqual(body["evaluations"], [])
        self.assertIsNone(body["nextCursor"])

    def test_get_evaluations_order_scope_and_item_shape(self) -> None:
        self.activate()
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        base = self.start * 1000
        self.add_event(1, base + 100, 99, sla_id="sla-2")
        _, s2_body, _ = self.post_evaluation(
            self.evaluation_body(base, base + 400), sla_id="sla-2",
            idempotency_key="eval-s2",
        )
        _, e1_body, _ = self.post_evaluation(self.evaluation_body(base, base + 400))
        _, e2_body, _ = self.post_evaluation(
            self.evaluation_body(base, base + 500), idempotency_key="eval-x"
        )
        status, body, _ = self.get_evaluations()
        self.assertEqual(status, 200)
        seqs = [item["evaluationSeq"] for item in body["evaluations"]]
        self.assertEqual(seqs, [2, 3])  # 序号 1 属于 sla-2，不在本 SLA
        self.assertIsNone(body["nextCursor"])
        item = body["evaluations"][0]
        self.assertEqual(
            list(item),
            [
                "evaluationSeq",
                "from",
                "to",
                "cut",
                "count",
                "latencySum",
                "maxLatency",
                "violations",
                "outcome",
                "createdAt",
            ],
        )
        self.assertEqual(item["evaluationSeq"], json.loads(e1_body)["evaluationSeq"])
        self.assertEqual(item["createdAt"], json.loads(e1_body)["createdAt"])
        self.assertEqual(item["outcome"], "insufficient")
        status, body, _ = self.get_evaluations(sla_id="sla-2")
        self.assertEqual(
            [item["evaluationSeq"] for item in body["evaluations"]], [1]
        )
        self.assertEqual(body["evaluations"][0]["outcome"], "breached")
        self.assertEqual(json.loads(s2_body)["evaluationSeq"], 1)

    def test_get_evaluations_pagination(self) -> None:
        self.activate()
        for index in range(1, 4):
            status, _, _ = self.post_evaluation(idempotency_key=f"eval-page-{index}")
            self.assertEqual(status, 201)
        status, page1, _ = self.get_evaluations("limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["evaluationSeq"] for item in page1["evaluations"]], [1]
        )
        self.assertEqual(page1["nextCursor"], "3:1")
        status, page2, _ = self.get_evaluations(
            f"limit=1&cursor={page1['nextCursor']}"
        )
        self.assertEqual(
            [item["evaluationSeq"] for item in page2["evaluations"]], [2]
        )
        self.assertEqual(page2["nextCursor"], "3:2")
        status, page3, _ = self.get_evaluations(
            f"limit=1&cursor={page2['nextCursor']}"
        )
        self.assertEqual(
            [item["evaluationSeq"] for item in page3["evaluations"]], [3]
        )
        self.assertIsNone(page3["nextCursor"])

    def test_get_evaluations_default_limit_is_50(self) -> None:
        self.activate()
        for index in range(1, 52):
            self.post_evaluation(idempotency_key=f"eval-page-{index}")
        status, page1, _ = self.get_evaluations()
        self.assertEqual(status, 200)
        self.assertEqual(len(page1["evaluations"]), 50)
        self.assertEqual(page1["nextCursor"], "51:50")
        status, page2, _ = self.get_evaluations(f"cursor={page1['nextCursor']}")
        self.assertEqual(
            [item["evaluationSeq"] for item in page2["evaluations"]], [51]
        )
        self.assertIsNone(page2["nextCursor"])

    def test_get_evaluations_cursor_pins_cut_against_new_writes(self) -> None:
        self.activate()
        for index in range(1, 3):
            self.post_evaluation(idempotency_key=f"eval-pin-{index}")
        status, page1, _ = self.get_evaluations("limit=1")
        self.assertEqual(status, 200)
        cursor = page1["nextCursor"]
        self.assertEqual(cursor, "2:1")
        self.post_evaluation(idempotency_key="eval-pin-3")
        status, page2, _ = self.get_evaluations(f"limit=1&cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["evaluationSeq"] for item in page2["evaluations"]], [2]
        )
        self.assertIsNone(page2["nextCursor"])
        status, fresh, _ = self.get_evaluations()
        self.assertEqual(
            [item["evaluationSeq"] for item in fresh["evaluations"]], [1, 2, 3]
        )

    def test_get_evaluations_cursor_survives_restart(self) -> None:
        self.activate()
        for index in range(1, 4):
            self.post_evaluation(idempotency_key=f"eval-restart-{index}")
        status, page1, _ = self.get_evaluations("limit=2")
        self.assertEqual(status, 200)
        cursor = page1["nextCursor"]
        self.restart()
        status, page2, _ = self.get_evaluations(f"limit=2&cursor={cursor}")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["evaluationSeq"] for item in page2["evaluations"]], [3]
        )
        self.assertIsNone(page2["nextCursor"])

    def test_get_evaluations_sla_not_found(self) -> None:
        status, body, _ = self.get_evaluations(sla_id="missing")
        self.assertEqual(status, 404)
        self.assertEqual(body, {"error": "not_found"})

    def test_get_evaluations_invalid_query_is_prior_to_sla_lookup(self) -> None:
        # 纯语法/格式非法在 SLA 查询之前即 400（SLA 缺失也不改成 404）。
        for query in (
            "limit=0",
            "limit=101",
            "limit=01",
            "limit=x",
            "limit=",
            "limit=1&limit=2",
            "cursor=bad",
            "cursor=1",
            "cursor=1:2:3",
            "cursor=01:1",
            "cursor=1:02",
            "unknown=1",
        ):
            status, body, _ = self.get_evaluations(query, sla_id="missing")
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "invalid_request"})

    def test_get_evaluations_bad_cut_or_anchor(self) -> None:
        self.activate()
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        self.post_evaluation(sla_id="sla-2", idempotency_key="eval-s2-1")  # 全库 seq 1
        self.post_evaluation(idempotency_key="eval-s1-1")  # 全库 seq 2
        for query in (
            "cursor=999:2",  # cut 超过当前全库最大值
            "cursor=2:1",  # 序号 1 属于 sla-2，在 sla-1 内锚点不存在
            "cursor=2:5",  # 序号在全库都不存在
        ):
            status, body, _ = self.get_evaluations(query)
            self.assertEqual(status, 400, query)
            self.assertEqual(body, {"error": "invalid_request"})
        # cut>max 是状态校验，在 SLA 查询之后：SLA 缺失仍为 404。
        status, _, _ = self.get_evaluations("cursor=999:1", sla_id="missing")
        self.assertEqual(status, 404)
        # sla-2 用自己的锚点则合法。
        status, page, _ = self.get_evaluations("cursor=2:1", sla_id="sla-2")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["evaluationSeq"] for item in page["evaluations"]], []
        )
        self.assertIsNone(page["nextCursor"])


class EvaluationMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary.name) / "service.db")
        self._build_old_database()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _build_old_database(self) -> None:
        old_snapshot = (
            '{"from":1,"to":2,"cut":0,"count":0,"latencySum":0,'
            '"maxLatency":null,"violations":0,"outcome":"insufficient"}'
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("CREATE TABLE slas (id TEXT PRIMARY KEY)")
            connection.execute("INSERT INTO slas(id) VALUES ('sla-1')")
            connection.execute(
                "CREATE TABLE sla_evaluation_idempotency_records ("
                "key TEXT PRIMARY KEY, sla_id TEXT NOT NULL, request_json TEXT NOT NULL,"
                " status INTEGER NOT NULL, response_json TEXT NOT NULL)"
            )
            for key in ("eval-a", "eval-b", "eval-c"):
                connection.execute(
                    "INSERT INTO sla_evaluation_idempotency_records"
                    "(key, sla_id, request_json, status, response_json)"
                    " VALUES (?, 'sla-1', '{\"from\":1,\"to\":2}', 201, ?)",
                    (key, old_snapshot),
                )
            connection.commit()
        finally:
            connection.close()

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
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def get_evaluations(self, query: str = "") -> tuple[int, object]:
        suffix = f"?{query}" if query else ""
        try:
            with urlopen(
                self.url(f"/v1/slas/sla-1/evaluations{suffix}"), timeout=5
            ) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def test_old_database_renumbered_once_by_rowid(self) -> None:
        status, body = self.get_evaluations()
        self.assertEqual(status, 200)
        self.assertEqual(
            [(item["evaluationSeq"], item["createdAt"]) for item in body["evaluations"]],
            [(1, 0), (2, 0), (3, 0)],
        )
        self.assertEqual(body["evaluations"][0]["outcome"], "insufficient")
        self.assertEqual(body["evaluations"][0]["from"], 1)
        self.assertIsNone(body["nextCursor"])

        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT key, evaluation_seq, created_at_ms, response_json"
                " FROM sla_evaluation_idempotency_records ORDER BY rowid ASC"
            ).fetchall()
            self.assertEqual(
                [(row["key"], row["evaluation_seq"], row["created_at_ms"]) for row in rows],
                [("eval-a", 1, 0), ("eval-b", 2, 0), ("eval-c", 3, 0)],
            )
            # 旧快照字节未被改写：response_json 不含新增字段。
            self.assertNotIn("evaluationSeq", rows[0]["response_json"])
            marker = connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = 'evaluation_seq_renumbered'"
            ).fetchone()
            self.assertIsNotNone(marker)
            index = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='index'"
                " AND name='idx_sla_evaluation_seq_unique'"
            ).fetchone()
            self.assertIsNotNone(index)
        finally:
            connection.close()

        # 重启不重排。
        self.restart()
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT key, evaluation_seq FROM sla_evaluation_idempotency_records"
                " ORDER BY rowid ASC"
            ).fetchall()
            self.assertEqual(
                [(row["key"], row["evaluation_seq"]) for row in rows],
                [("eval-a", 1), ("eval-b", 2), ("eval-c", 3)],
            )
        finally:
            connection.close()

    def test_old_snapshot_replays_original_bytes(self) -> None:
        old_snapshot = (
            b'{"from":1,"to":2,"cut":0,"count":0,"latencySum":0,'
            b'"maxLatency":null,"violations":0,"outcome":"insufficient"}'
        )
        request = Request(
            self.url("/v1/slas/sla-1/evaluations"),
            data=json.dumps({"from": 1, "to": 2}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "eval-a")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
            self.assertEqual(response.read(), old_snapshot)


class FundTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.other_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            request = Request(
                self.url("/v1/machines"),
                data=json.dumps({"publicKey": public_key}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 201)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def deposit_body(self, amount: object = 1000, reference: object = "ref-1") -> bytes:
        return json.dumps({"amountMicros": amount, "reference": reference}).encode()

    def post_deposit(
        self,
        body: bytes | None = None,
        machine: str | None = None,
        idempotency_key: str | None = "fund-1",
    ) -> tuple[int, bytes, str]:
        if body is None:
            body = self.deposit_body()
        if machine is None:
            machine = self.machine_id
        request = Request(self.url(f"/v1/funds/{machine}"), data=body, method="POST")
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def test_deposit_created_with_sequence_and_balance(self) -> None:
        status, body, content_type = self.post_deposit()
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(
            body.decode("utf-8"),
            json.dumps({"depositSeq": 1, "balance": 1000}, separators=(",", ":")),
        )
        self.assertFalse(body.endswith(b"\n"))

    def test_deposit_accumulates_balance_and_sequence(self) -> None:
        self.assertEqual(self.post_deposit()[0], 201)
        status, body, _ = self.post_deposit(
            self.deposit_body(2500, "ref-2"), idempotency_key="fund-2"
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"depositSeq": 2, "balance": 3500})

    def test_deposit_sequences_are_global_across_machines(self) -> None:
        self.assertEqual(self.post_deposit()[0], 201)
        status, body, _ = self.post_deposit(
            self.deposit_body(10, "ref-2"), machine=self.other_id, idempotency_key="fund-2"
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"depositSeq": 2, "balance": 10})

    def test_deposit_writes_opposite_clearing_entry(self) -> None:
        self.assertEqual(self.post_deposit()[0], 201)
        connection = sqlite3.connect(self.server.database_path)
        connection.row_factory = sqlite3.Row
        try:
            entries = connection.execute(
                "SELECT account_id, delta_micros, balance_after_micros"
                " FROM ledger_entries ORDER BY entry_seq ASC"
            ).fetchall()
            self.assertEqual(
                [
                    (row["account_id"], row["delta_micros"], row["balance_after_micros"])
                    for row in entries
                ],
                [(self.machine_id, 1000, 1000), ("external:clearing", -1000, -1000)],
            )
        finally:
            connection.close()

    def test_replay_returns_first_response_bytes(self) -> None:
        _, first, _ = self.post_deposit()
        status, body, _ = self.post_deposit()
        self.assertEqual(status, 201)
        self.assertEqual(body, first)

    def test_same_key_different_request_conflicts(self) -> None:
        self.assertEqual(self.post_deposit()[0], 201)
        status, body, _ = self.post_deposit(self.deposit_body(2000, "ref-1"))
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        status, body, _ = self.post_deposit(machine=self.other_id)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_unknown_machine_is_404(self) -> None:
        status, body, _ = self.post_deposit(machine="ab" * 32)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_missing_or_invalid_idempotency_key(self) -> None:
        status, body, _ = self.post_deposit(idempotency_key=None)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "invalid_request"})
        status, body, _ = self.post_deposit(idempotency_key="bad key!")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        bodies = [
            b"{}",
            b'{"amountMicros":1000}',
            b'{"reference":"ref-1"}',
            b'{"amountMicros":1000,"reference":"ref-1","extra":1}',
            b'{"amountMicros":0,"reference":"ref-1"}',
            b'{"amountMicros":-5,"reference":"ref-1"}',
            b'{"amountMicros":9000000000000001,"reference":"ref-1"}',
            b'{"amountMicros":true,"reference":"ref-1"}',
            b'{"amountMicros":"1000","reference":"ref-1"}',
            b'{"amountMicros":1000,"reference":"BAD_REF"}',
            b'{"amountMicros":1000,"reference":""}',
            b'{"amountMicros":1000,"reference":1}',
            b'{"amountMicros":1000,"amountMicros":1000,"reference":"ref-1"}',
            b"not-json",
        ]
        for index, body in enumerate(bodies):
            with self.subTest(index=index):
                status, payload, _ = self.post_deposit(body, idempotency_key=f"bad-{index}")
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(payload), {"error": "invalid_request"})

    def test_boundary_amount_accepted(self) -> None:
        status, body, _ = self.post_deposit(self.deposit_body(9000000000000000, "ref-1"))
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"depositSeq": 1, "balance": 9000000000000000})

    def test_failed_request_leaves_no_idempotency_record(self) -> None:
        status, _, _ = self.post_deposit(machine="ab" * 32)
        self.assertEqual(status, 404)
        status, body, _ = self.post_deposit()
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["depositSeq"], 1)

    def test_replay_survives_restart(self) -> None:
        _, first, _ = self.post_deposit()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, body, _ = self.post_deposit()
        self.assertEqual(status, 201)
        self.assertEqual(body, first)

    def test_concurrent_same_key_single_deposit(self) -> None:
        results: list[tuple[int, bytes]] = []
        lock = threading.Lock()

        def deposit() -> None:
            outcome = self.post_deposit()
            with lock:
                results.append((outcome[0], outcome[1]))

        threads = [threading.Thread(target=deposit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual([status for status, _ in results], [201] * 8)
        self.assertEqual(len({body for _, body in results}), 1)
        status, body, _ = self.post_deposit(
            self.deposit_body(1, "ref-2"), idempotency_key="fund-2"
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"depositSeq": 2, "balance": 1001})


class SettlementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            request = Request(
                self.url("/v1/machines"),
                data=json.dumps({"publicKey": public_key}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 201)
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        request = Request(
            self.url("/v1/sla-templates"),
            data=json.dumps(
                {
                    "id": "tpl-1",
                    "machineId": self.machine_id,
                    "capabilityVersion": 1,
                    "priceMicros": 1000,
                    "maxLatencyMs": 50,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "tpl-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        current = int(time.time())
        self.start = current - 10
        self.end = current + 3600
        self.create_sla("sla-1", "sla-create-1")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def create_sla(self, sla_id: str, key: str) -> None:
        request = Request(
            self.url("/v1/slas"),
            data=json.dumps(
                {
                    "id": sla_id,
                    "templateId": "tpl-1",
                    "consumerId": self.consumer_id,
                    "start": self.start,
                    "end": self.end,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", key)
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def activate(self, sla_id: str = "sla-1") -> None:
        for index, (party, actor) in enumerate(
            (
                ("producer", self.machine_id),
                ("consumer", self.consumer_id),
            )
        ):
            request = Request(
                self.url(f"/v1/slas/{sla_id}/confirmations"),
                data=json.dumps({"party": party, "actorId": actor}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", f"conf-{sla_id}-{index}")
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)

    def add_event(self, index: int, timestamp: int, latency_ms: int) -> None:
        event_id = f"evt-{index:03d}"
        message = (
            f"sla-1\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine_id}"
        )
        body = json.dumps(
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            }
        ).encode()
        request = Request(self.url("/v1/slas/sla-1/telemetry"), data=body, method="POST")
        request.add_header("Idempotency-Key", f"tel-{index}")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def evaluate(self, key: str = "eval-1") -> int:
        body = json.dumps({"from": self.start * 1000, "to": self.end * 1000}).encode()
        request = Request(self.url("/v1/slas/sla-1/evaluations"), data=body, method="POST")
        request.add_header("Idempotency-Key", key)
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
            return json.loads(response.read())["evaluationSeq"]

    def deposit(self, machine: str, amount: int, key: str) -> None:
        request = Request(
            self.url(f"/v1/funds/{machine}"),
            data=json.dumps({"amountMicros": amount, "reference": "ref-1"}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", key)
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def post_settlement(
        self,
        body: bytes | None = None,
        idempotency_key: str | None = "settle-1",
    ) -> tuple[int, bytes, str]:
        if body is None:
            body = json.dumps({"slaId": "sla-1", "evaluationSeq": 1}).encode()
        request = Request(self.url("/v1/settlements"), data=body, method="POST")
        if idempotency_key is not None:
            request.add_header("Idempotency-Key", idempotency_key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def balance(self, account_id: str) -> int:
        connection = sqlite3.connect(self.server.database_path)
        try:
            row = connection.execute(
                "SELECT balance_micros FROM ledger_accounts WHERE account_id = ?",
                (account_id,),
            ).fetchone()
            return row[0] if row is not None else 0
        finally:
            connection.close()

    def test_fulfilled_charges_consumer_to_producer(self) -> None:
        self.activate()
        self.add_event(1, self.start * 1000 + 1, 10)
        self.add_event(2, self.start * 1000 + 2, 20)
        evaluation_seq = self.evaluate()
        self.deposit(self.consumer_id, 5000, "fund-1")
        before = int(time.time() * 1000)
        status, body, content_type = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        )
        after = int(time.time() * 1000)
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        payload = json.loads(body)
        self.assertEqual(
            list(payload),
            ["settlementSeq", "evaluationSeq", "result", "amount", "createdAt"],
        )
        self.assertEqual(payload["settlementSeq"], 1)
        self.assertEqual(payload["evaluationSeq"], evaluation_seq)
        self.assertEqual(payload["result"], "charged")
        self.assertEqual(payload["amount"], 2000)
        self.assertTrue(before <= payload["createdAt"] <= after)
        self.assertFalse(body.endswith(b"\n"))
        self.assertEqual(self.balance(self.consumer_id), 3000)
        self.assertEqual(self.balance(self.machine_id), 2000)

    def test_breached_compensates_producer_to_consumer(self) -> None:
        self.activate()
        self.add_event(1, self.start * 1000 + 1, 10)
        self.add_event(2, self.start * 1000 + 2, 60)
        self.add_event(3, self.start * 1000 + 3, 70)
        evaluation_seq = self.evaluate()
        self.deposit(self.machine_id, 5000, "fund-1")
        status, body, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(payload["result"], "compensated")
        self.assertEqual(payload["amount"], 2000)
        self.assertEqual(self.balance(self.machine_id), 3000)
        self.assertEqual(self.balance(self.consumer_id), 2000)

    def test_insufficient_creates_zero_pending_without_entries(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        status, body, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(payload["result"], "pending")
        self.assertEqual(payload["amount"], 0)
        connection = sqlite3.connect(self.server.database_path)
        try:
            entries = connection.execute(
                "SELECT COUNT(*) FROM ledger_entries"
            ).fetchone()[0]
            self.assertEqual(entries, 0)
        finally:
            connection.close()

    def test_replay_returns_first_response_bytes(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        body = json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        _, first, _ = self.post_settlement(body)
        status, replay, _ = self.post_settlement(body)
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)

    def test_same_key_different_request_conflicts(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        body = json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        self.assertEqual(self.post_settlement(body)[0], 201)
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq + 1}).encode()
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload), {"error": "conflict"})

    def test_different_key_same_evaluation_is_settlement_exists(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        body = json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        self.assertEqual(self.post_settlement(body)[0], 201)
        status, payload, _ = self.post_settlement(body, idempotency_key="settle-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload), {"error": "settlement_exists"})

    def test_missing_sla_or_evaluation_is_404(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-9", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(payload), {"error": "not_found"})
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq + 100}).encode()
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(payload), {"error": "not_found"})

    def test_pending_sla_conflicts(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        self.create_sla("sla-2", "sla-create-2")
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-2", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload), {"error": "conflict"})

    def test_evaluation_of_other_sla_conflicts(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-2", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload), {"error": "conflict"})

    def test_insufficient_funds_has_no_side_effects(self) -> None:
        self.activate()
        self.add_event(1, self.start * 1000 + 1, 10)
        evaluation_seq = self.evaluate()
        self.deposit(self.consumer_id, 500, "fund-1")
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload), {"error": "insufficient_funds"})
        self.assertEqual(self.balance(self.consumer_id), 500)
        self.assertEqual(self.balance(self.machine_id), 0)
        # 失败不留幂等记录：同键补足余额后可重试。
        self.deposit(self.consumer_id, 500, "fund-2")
        status, body, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["amount"], 1000)

    def test_amount_overflow_on_payee_balance(self) -> None:
        self.activate()
        self.add_event(1, self.start * 1000 + 1, 10)
        evaluation_seq = self.evaluate()
        self.deposit(self.consumer_id, 9000000000000000, "fund-1")
        self.deposit(self.machine_id, 9000000000000000, "fund-2")
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload), {"error": "amount_overflow"})
        self.assertEqual(self.balance(self.consumer_id), 9000000000000000)
        self.assertEqual(self.balance(self.machine_id), 9000000000000000)

    def test_invalid_bodies(self) -> None:
        bodies = [
            b"{}",
            b'{"slaId":"sla-1"}',
            b'{"evaluationSeq":1}',
            b'{"slaId":"sla-1","evaluationSeq":1,"extra":1}',
            b'{"slaId":"BAD","evaluationSeq":1}',
            b'{"slaId":1,"evaluationSeq":1}',
            b'{"slaId":"sla-1","evaluationSeq":0}',
            b'{"slaId":"sla-1","evaluationSeq":-1}',
            b'{"slaId":"sla-1","evaluationSeq":true}',
            b'{"slaId":"sla-1","evaluationSeq":"1"}',
            b"not-json",
        ]
        for index, body in enumerate(bodies):
            with self.subTest(index=index):
                status, payload, _ = self.post_settlement(
                    body, idempotency_key=f"bad-{index}"
                )
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(payload), {"error": "invalid_request"})

    def test_missing_or_invalid_idempotency_key(self) -> None:
        status, payload, _ = self.post_settlement(idempotency_key=None)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload), {"error": "invalid_request"})
        status, payload, _ = self.post_settlement(idempotency_key="bad key!")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload), {"error": "invalid_request"})

    def test_settlement_sequences_are_global(self) -> None:
        self.activate()
        self.add_event(1, self.start * 1000 + 1, 10)
        first_seq = self.evaluate("eval-1")
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        body = json.dumps({"from": self.start * 1000, "to": self.end * 1000}).encode()
        request = Request(self.url("/v1/slas/sla-2/evaluations"), data=body, method="POST")
        request.add_header("Idempotency-Key", "eval-2")
        with urlopen(request, timeout=5) as response:
            second_seq = json.loads(response.read())["evaluationSeq"]
        self.deposit(self.consumer_id, 5000, "fund-1")
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-1", "evaluationSeq": first_seq}).encode()
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(payload)["settlementSeq"], 1)
        status, payload, _ = self.post_settlement(
            json.dumps({"slaId": "sla-2", "evaluationSeq": second_seq}).encode(),
            idempotency_key="settle-2",
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(payload)["settlementSeq"], 2)

    def test_replay_survives_restart(self) -> None:
        self.activate()
        evaluation_seq = self.evaluate()
        body = json.dumps({"slaId": "sla-1", "evaluationSeq": evaluation_seq}).encode()
        _, first, _ = self.post_settlement(body)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, replay, _ = self.post_settlement(body)
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)


class DisputeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            request = Request(
                self.url("/v1/machines"),
                data=json.dumps({"publicKey": public_key}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 201)
        request = Request(
            self.url(f"/v1/machines/{self.machine_id}/capabilities"),
            data=json.dumps(
                {
                    "expectedVersion": 0,
                    "name": "pump-01",
                    "protocol": "mqtt",
                    "region": "cn",
                    "unit": "call",
                    "capacity": 10,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "cap-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        request = Request(
            self.url("/v1/sla-templates"),
            data=json.dumps(
                {
                    "id": "tpl-1",
                    "machineId": self.machine_id,
                    "capabilityVersion": 1,
                    "priceMicros": 1000,
                    "maxLatencyMs": 50,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "tpl-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        current = int(time.time())
        self.start = current - 10
        self.end = current + 3600
        self.create_sla("sla-1", "sla-create-1")
        self.activate("sla-1")

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def post_json(
        self, path: str, payload: object, key: str | None
    ) -> tuple[int, bytes]:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        request = Request(self.url(path), data=data, method="POST")
        if key is not None:
            request.add_header("Idempotency-Key", key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def get_json(self, path: str) -> tuple[int, dict]:
        try:
            with urlopen(self.url(path), timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def create_sla(self, sla_id: str, key: str) -> None:
        status, _ = self.post_json(
            "/v1/slas",
            {
                "id": sla_id,
                "templateId": "tpl-1",
                "consumerId": self.consumer_id,
                "start": self.start,
                "end": self.end,
            },
            key,
        )
        self.assertEqual(status, 201)

    def activate(self, sla_id: str) -> None:
        for index, (party, actor) in enumerate(
            (
                ("producer", self.machine_id),
                ("consumer", self.consumer_id),
            )
        ):
            status, _ = self.post_json(
                f"/v1/slas/{sla_id}/confirmations",
                {"party": party, "actorId": actor},
                f"conf-{sla_id}-{index}",
            )
            self.assertEqual(status, 200)

    def add_event(self, sla_id: str, index: int, latency_ms: int) -> None:
        event_id = f"evt-{sla_id}-{index}"
        timestamp = self.start * 1000 + index
        message = f"{sla_id}\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine_id}"
        status, _ = self.post_json(
            f"/v1/slas/{sla_id}/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            },
            f"tel-{sla_id}-{index}",
        )
        self.assertEqual(status, 201)

    def evaluate(self, sla_id: str, key: str) -> int:
        status, body = self.post_json(
            f"/v1/slas/{sla_id}/evaluations",
            {"from": self.start * 1000, "to": self.end * 1000},
            key,
        )
        self.assertEqual(status, 201)
        return json.loads(body)["evaluationSeq"]

    def deposit(self, account: str, amount: int, key: str) -> None:
        status, _ = self.post_json(
            f"/v1/funds/{account}",
            {"amountMicros": amount, "reference": f"ref-{key}"},
            key,
        )
        self.assertEqual(status, 201)

    def settle(self, sla_id: str, evaluation_seq: int, key: str) -> dict:
        status, body = self.post_json(
            "/v1/settlements",
            {"slaId": sla_id, "evaluationSeq": evaluation_seq},
            key,
        )
        self.assertEqual(status, 201)
        return json.loads(body)

    def create_charged_settlement(self) -> int:
        self.add_event("sla-1", 1, 10)
        evaluation_seq = self.evaluate("sla-1", "eval-1")
        self.deposit(self.consumer_id, 100000, "fund-1")
        settlement = self.settle("sla-1", evaluation_seq, "settle-1")
        self.assertEqual(settlement["result"], "charged")
        self.assertEqual(settlement["amount"], 1000)
        return settlement["settlementSeq"]

    def post_dispute(
        self,
        payload: object,
        key: str | None = "dispute-1",
    ) -> tuple[int, bytes]:
        return self.post_json("/v1/disputes", payload, key)

    def dispute_body(self, settlement_seq: int, **overrides: object) -> dict:
        body: dict[str, object] = {
            "id": "dispute-1",
            "settlementSeq": settlement_seq,
            "claimantId": self.consumer_id,
        }
        body.update(overrides)
        return body

    def post_resolution(
        self,
        dispute_id: str,
        payload: object,
        key: str | None = "resolve-1",
    ) -> tuple[int, bytes]:
        return self.post_json(f"/v1/disputes/{dispute_id}/resolution", payload, key)

    def test_create_dispute_created(self) -> None:
        settlement_seq = self.create_charged_settlement()
        status, body = self.post_dispute(self.dispute_body(settlement_seq))
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(list(payload), ["id", "open", "amount"])
        self.assertEqual(payload, {"id": "dispute-1", "open": True, "amount": 1000})

    def test_dispute_replay_same_key_returns_first_bytes(self) -> None:
        settlement_seq = self.create_charged_settlement()
        status, first = self.post_dispute(self.dispute_body(settlement_seq))
        self.assertEqual(status, 201)
        status, replay = self.post_dispute(self.dispute_body(settlement_seq))
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)

    def test_dispute_same_key_different_request_conflicts(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        status, body = self.post_dispute(
            self.dispute_body(settlement_seq, id="dispute-2")
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_dispute_different_key_duplicate_id_or_settlement(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        status, body = self.post_dispute(
            self.dispute_body(settlement_seq), key="dispute-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "dispute_exists"})
        status, body = self.post_dispute(
            self.dispute_body(settlement_seq, id="dispute-9"), key="dispute-3"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "dispute_exists"})

    def test_dispute_claimant_must_be_payer(self) -> None:
        settlement_seq = self.create_charged_settlement()
        status, body = self.post_dispute(
            self.dispute_body(settlement_seq, claimantId=self.machine_id)
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})

    def test_dispute_missing_settlement_is_not_found(self) -> None:
        self.create_charged_settlement()
        status, body = self.post_dispute(self.dispute_body(999))
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_dispute_pending_settlement_conflicts(self) -> None:
        evaluation_seq = self.evaluate("sla-1", "eval-1")
        settlement = self.settle("sla-1", evaluation_seq, "settle-1")
        self.assertEqual(settlement["result"], "pending")
        status, body = self.post_dispute(self.dispute_body(settlement["settlementSeq"]))
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_dispute_invalid_requests(self) -> None:
        settlement_seq = self.create_charged_settlement()
        cases = [
            b"",
            b"{not json",
            json.dumps({}).encode(),
            json.dumps({"id": "d-1", "settlementSeq": settlement_seq}).encode(),
            json.dumps(
                self.dispute_body(settlement_seq, extra=1)
            ).encode(),
            json.dumps(self.dispute_body(settlement_seq, id="BAD ID")).encode(),
            json.dumps(self.dispute_body(settlement_seq, settlementSeq=0)).encode(),
            json.dumps(self.dispute_body(settlement_seq, settlementSeq=True)).encode(),
            json.dumps(
                self.dispute_body(settlement_seq, settlementSeq="1")
            ).encode(),
            json.dumps(self.dispute_body(settlement_seq, claimantId="zz")).encode(),
        ]
        for index, body in enumerate(cases):
            status, response = self.post_dispute(body, key=f"bad-{index}")
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response), {"error": "invalid_request"})
        status, response = self.post_dispute(self.dispute_body(settlement_seq), key=None)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(response), {"error": "invalid_request"})

    def test_concurrent_dispute_creation_succeeds_once(self) -> None:
        settlement_seq = self.create_charged_settlement()
        results: list[int] = []
        lock = threading.Lock()

        def create(index: int) -> None:
            status, _ = self.post_dispute(
                self.dispute_body(settlement_seq), key=f"race-{index}"
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=create, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [201] + [409] * 7)

    def test_release_resolution(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        status, body = self.post_resolution("dispute-1", {"decision": "release"})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(list(payload), ["id", "released", "amount"])
        self.assertEqual(
            payload, {"id": "dispute-1", "released": True, "amount": 1000}
        )
        status, replay = self.post_resolution("dispute-1", {"decision": "release"})
        self.assertEqual(status, 200)
        self.assertEqual(replay, body)
        status, body = self.post_resolution(
            "dispute-1", {"decision": "release"}, key="resolve-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_resolved"})

    def test_resolution_same_key_different_request_conflicts(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        status, body = self.post_resolution("dispute-1", {"decision": "refund"})
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_resolution_unknown_dispute_is_not_found(self) -> None:
        status, body = self.post_resolution("missing", {"decision": "release"})
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_resolution_invalid_requests(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        cases = [
            b"{}",
            json.dumps({"decision": "hold"}).encode(),
            json.dumps({"decision": 1}).encode(),
            json.dumps({"decision": "release", "extra": 1}).encode(),
        ]
        for index, body in enumerate(cases):
            status, response = self.post_resolution(
                "dispute-1", body, key=f"bad-{index}"
            )
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response), {"error": "invalid_request"})
        status, response = self.post_resolution(
            "dispute-1", {"decision": "release"}, key=None
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(response), {"error": "invalid_request"})

    def test_refund_resolution_writes_ledger_entries(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        status, body = self.post_resolution("dispute-1", {"decision": "refund"})
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body), {"id": "dispute-1", "refunded": True, "amount": 1000}
        )
        status, ledger = self.get_json(f"/v1/accounts/{self.machine_id}/ledger")
        self.assertEqual(status, 200)
        refund_entries = [
            entry
            for entry in ledger["entries"]
            if entry["kind"] == "dispute_refund"
        ]
        self.assertEqual(len(refund_entries), 1)
        entry = refund_entries[0]
        self.assertEqual(entry["referenceSeq"], settlement_seq)
        self.assertIsNone(entry["reference"])
        self.assertEqual(entry["slaId"], "sla-1")
        self.assertEqual(entry["evaluationSeq"], 1)
        self.assertEqual(entry["delta"], -1000)
        self.assertEqual(entry["balanceAfter"], 0)
        status, ledger = self.get_json(f"/v1/accounts/{self.consumer_id}/ledger")
        self.assertEqual(status, 200)
        refund_entries = [
            entry
            for entry in ledger["entries"]
            if entry["kind"] == "dispute_refund"
        ]
        self.assertEqual(len(refund_entries), 1)
        self.assertEqual(refund_entries[0]["delta"], 1000)
        self.assertEqual(refund_entries[0]["balanceAfter"], 100000)

    def test_refund_insufficient_funds_keeps_dispute_open(self) -> None:
        settlement_seq = self.create_charged_settlement()
        # 机器通过赔付结算把 1000 花光，总余额降为 0。
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        self.add_event("sla-2", 1, 100)
        evaluation_seq = self.evaluate("sla-2", "eval-2")
        settlement = self.settle("sla-2", evaluation_seq, "settle-2")
        self.assertEqual(settlement["result"], "compensated")
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        status, body = self.post_resolution("dispute-1", {"decision": "refund"})
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "insufficient_funds"})
        # 入金补足缺口后退款成功。
        self.deposit(self.machine_id, 5000, "fund-2")
        status, body = self.post_resolution(
            "dispute-1", {"decision": "refund"}, key="resolve-2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body), {"id": "dispute-1", "refunded": True, "amount": 1000}
        )

    def test_open_freeze_limits_settlement_spending(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        # 机器总余额 1000 全部被冻结，可用余额为 0，赔付结算失败。
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        self.add_event("sla-2", 1, 100)
        evaluation_seq = self.evaluate("sla-2", "eval-2")
        status, body = self.post_json(
            "/v1/settlements",
            {"slaId": "sla-2", "evaluationSeq": evaluation_seq},
            "settle-2",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "insufficient_funds"})
        # 解冻后同一结算可成功。
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        settlement = self.settle("sla-2", evaluation_seq, "settle-3")
        self.assertEqual(settlement["result"], "compensated")

    def create_open_dispute(self) -> int:
        settlement_seq = self.create_charged_settlement()
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        return settlement_seq

    def test_get_dispute_open(self) -> None:
        settlement_seq = self.create_open_dispute()
        status, payload = self.get_json("/v1/disputes/dispute-1")
        self.assertEqual(status, 200)
        self.assertEqual(
            list(payload),
            [
                "id",
                "state",
                "amount",
                "claimantId",
                "payerId",
                "payeeId",
                "settlementSeq",
                "slaId",
                "evaluationSeq",
                "result",
            ],
        )
        self.assertEqual(payload["id"], "dispute-1")
        self.assertEqual(payload["state"], "open")
        self.assertEqual(payload["amount"], 1000)
        self.assertEqual(payload["claimantId"], self.consumer_id)
        self.assertEqual(payload["payerId"], self.consumer_id)
        self.assertEqual(payload["payeeId"], self.machine_id)
        self.assertEqual(payload["settlementSeq"], settlement_seq)
        self.assertEqual(payload["slaId"], "sla-1")
        self.assertEqual(payload["evaluationSeq"], 1)
        self.assertEqual(payload["result"], "charged")

    def test_get_dispute_states_after_resolution(self) -> None:
        self.create_open_dispute()
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        status, payload = self.get_json("/v1/disputes/dispute-1")
        self.assertEqual(status, 200)
        self.assertEqual(payload["state"], "released")

        # 第二笔 charged 结算由另一 SLA 产生，退款后状态为 refunded。
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        self.add_event("sla-2", 1, 10)
        settlement = self.settle(
            "sla-2", self.evaluate("sla-2", "eval-2"), "settle-2"
        )
        self.assertEqual(settlement["result"], "charged")
        self.assertEqual(
            self.post_dispute(
                self.dispute_body(settlement["settlementSeq"], id="dispute-3"),
                key="dispute-3",
            )[0],
            201,
        )
        self.assertEqual(
            self.post_resolution("dispute-3", {"decision": "refund"}, key="r-3")[0],
            200,
        )
        status, payload = self.get_json("/v1/disputes/dispute-3")
        self.assertEqual(status, 200)
        self.assertEqual(payload["state"], "refunded")
        self.assertEqual(payload["slaId"], "sla-2")

    def test_get_dispute_invalid_or_missing_is_not_found(self) -> None:
        for dispute_id in ("missing", quote("BAD ID"), "x%2Fy"):
            status, payload = self.get_json(f"/v1/disputes/{dispute_id}")
            self.assertEqual(status, 404, dispute_id)
            self.assertEqual(payload, {"error": "not_found"})

    def test_get_dispute_rejects_query_params(self) -> None:
        self.create_open_dispute()
        for suffix in ("?limit=1", "?foo=bar"):
            status, payload = self.get_json(f"/v1/disputes/dispute-1{suffix}")
            self.assertEqual(status, 400, suffix)
            self.assertEqual(payload, {"error": "invalid_request"})
        # 参数校验先于争议查询：不存在的争议同样返回 400。
        status, payload = self.get_json("/v1/disputes/missing?limit=1")
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_dispute_events_records_opened_and_released(self) -> None:
        self.create_open_dispute()
        status, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["events", "nextCursor"])
        self.assertIsNone(payload["nextCursor"])
        events = payload["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(list(events[0]), ["eventSeq", "type", "createdAt"])
        self.assertEqual(events[0]["eventSeq"], 1)
        self.assertEqual(events[0]["type"], "opened")
        self.assertIsInstance(events[0]["createdAt"], int)
        self.assertGreaterEqual(events[0]["createdAt"], 0)

        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        status, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(status, 200)
        self.assertEqual(
            [(event["type"]) for event in payload["events"]],
            ["opened", "released"],
        )
        seqs = [event["eventSeq"] for event in payload["events"]]
        self.assertEqual(seqs, sorted(seqs))
        self.assertEqual(len(set(seqs)), len(seqs))
        self.assertIsNone(payload["nextCursor"])

    def test_refund_event_records_refunded_type(self) -> None:
        self.create_open_dispute()
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "refund"})[0], 200
        )
        status, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(status, 200)
        self.assertEqual(
            [(event["eventSeq"], event["type"]) for event in payload["events"]],
            [(1, "opened"), (2, "refunded")],
        )
        self.assertGreater(payload["events"][1]["createdAt"], 0)

    def test_event_seq_is_global_across_disputes(self) -> None:
        # 第二笔 compensated 结算（机器为付款方）须在 dispute-1 冻结前过账。
        self.add_event("sla-1", 1, 10)
        evaluation_seq = self.evaluate("sla-1", "eval-1")
        self.deposit(self.consumer_id, 100000, "fund-1")
        first = self.settle("sla-1", evaluation_seq, "settle-1")
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        self.add_event("sla-2", 1, 100)
        second = self.settle(
            "sla-2", self.evaluate("sla-2", "eval-2"), "settle-2"
        )
        self.assertEqual(second["result"], "compensated")
        self.assertEqual(
            self.post_dispute(self.dispute_body(first["settlementSeq"]))[0], 201
        )
        self.assertEqual(
            self.post_dispute(
                self.dispute_body(
                    second["settlementSeq"],
                    id="dispute-2",
                    claimantId=self.machine_id,
                ),
                key="dispute-2",
            )[0],
            201,
        )
        _, first_events = self.get_json("/v1/disputes/dispute-1/events")
        _, second_events = self.get_json("/v1/disputes/dispute-2/events")
        self.assertEqual(
            [event["eventSeq"] for event in first_events["events"]], [1]
        )
        self.assertEqual(
            [event["eventSeq"] for event in second_events["events"]], [2]
        )

    def test_replay_writes_no_duplicate_events(self) -> None:
        settlement_seq = self.create_charged_settlement()
        first_status, first = self.post_dispute(self.dispute_body(settlement_seq))
        self.assertEqual(first_status, 201)
        for _ in range(3):
            status, replay = self.post_dispute(self.dispute_body(settlement_seq))
            self.assertEqual(status, 201)
            self.assertEqual(replay, first)
        _, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(len(payload["events"]), 1)
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        for _ in range(3):
            self.assertEqual(
                self.post_resolution("dispute-1", {"decision": "release"})[0], 200
            )
        _, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(
            [event["type"] for event in payload["events"]],
            ["opened", "released"],
        )

    def test_failed_requests_write_no_events(self) -> None:
        settlement_seq = self.create_charged_settlement()
        # 创建失败：非法请求、异请求冲突、重复争议均不得写事件。
        self.assertEqual(
            self.post_dispute(b"{}", key="bad-1")[0], 400
        )
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        self.assertEqual(
            self.post_dispute(
                self.dispute_body(settlement_seq, id="dispute-2")
            )[0],
            409,
        )
        self.assertEqual(
            self.post_dispute(
                self.dispute_body(settlement_seq), key="dispute-2"
            )[0],
            409,
        )
        # 裁决失败：非法请求与异键重复裁决不写事件。
        self.assertEqual(
            self.post_resolution("dispute-1", b"{}", key="bad-2")[0], 400
        )
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        self.assertEqual(
            self.post_resolution(
                "dispute-1", {"decision": "release"}, key="resolve-2"
            )[0],
            409,
        )
        _, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(
            [event["type"] for event in payload["events"]],
            ["opened", "released"],
        )

    def test_insufficient_refund_writes_no_event_then_succeeds_once(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        self.add_event("sla-2", 1, 100)
        self.settle("sla-2", self.evaluate("sla-2", "eval-2"), "settle-2")
        # 机器总余额已为 0，争议冻结 1000；退款失败不留事件。
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        status, body = self.post_resolution("dispute-1", {"decision": "refund"})
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "insufficient_funds"})
        _, dispute = self.get_json("/v1/disputes/dispute-1")
        self.assertEqual(dispute["state"], "open")
        _, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(
            [event["type"] for event in payload["events"]], ["opened"]
        )
        # 失败也不保存幂等结果：补足后新键成功，仅一条 refunded。
        self.deposit(self.machine_id, 5000, "fund-2")
        self.assertEqual(
            self.post_resolution(
                "dispute-1", {"decision": "refund"}, key="resolve-2"
            )[0],
            200,
        )
        _, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(
            [event["type"] for event in payload["events"]],
            ["opened", "refunded"],
        )
        status, ledger = self.get_json(f"/v1/accounts/{self.machine_id}/ledger")
        self.assertEqual(status, 200)
        self.assertEqual(
            len(
                [
                    entry
                    for entry in ledger["entries"]
                    if entry["kind"] == "dispute_refund"
                ]
            ),
            1,
        )

    def test_events_pagination_limit_and_cursor(self) -> None:
        self.create_open_dispute()
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        status, first_page = self.get_json(
            "/v1/disputes/dispute-1/events?limit=1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [event["eventSeq"] for event in first_page["events"]], [1]
        )
        self.assertEqual(first_page["nextCursor"], "2:1")
        status, second_page = self.get_json(
            f"/v1/disputes/dispute-1/events?limit=1&cursor={first_page['nextCursor']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [event["eventSeq"] for event in second_page["events"]], [2]
        )
        self.assertIsNone(second_page["nextCursor"])

    def test_events_cursor_cut_isolates_later_appends(self) -> None:
        self.create_open_dispute()
        _, first_page = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(first_page["nextCursor"], None)
        # 裁决推进全库最大序号；旧 cut=1 的续页不得看到新事件。
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        status, continuation = self.get_json(
            "/v1/disputes/dispute-1/events?cursor=1:1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(continuation["events"], [])
        self.assertIsNone(continuation["nextCursor"])
        # 全新首页取新 cut，可见两条。
        _, fresh = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(len(fresh["events"]), 2)

    def test_events_invalid_query_params(self) -> None:
        self.create_open_dispute()
        for query in (
            "limit=0",
            "limit=101",
            "limit=01",
            "limit=1&limit=2",
            "unknown=1",
            "cursor=1",
            "cursor=x:1",
            "cursor=1:y",
            "cursor=01:1",
        ):
            status, payload = self.get_json(
                f"/v1/disputes/dispute-1/events?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertEqual(payload, {"error": "invalid_request"})
        # 参数错误先于争议查询。
        status, payload = self.get_json("/v1/disputes/missing/events?limit=0")
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_events_cut_ahead_or_missing_anchor(self) -> None:
        self.create_open_dispute()
        self.assertEqual(
            self.post_resolution("dispute-1", {"decision": "release"})[0], 200
        )
        # cut 超过当前全库最大序号。
        status, payload = self.get_json(
            "/v1/disputes/dispute-1/events?cursor=999:1"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        # 锚点不大于 cut 却不存在。
        status, payload = self.get_json(
            "/v1/disputes/dispute-1/events?cursor=2:5"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_events_cross_dispute_anchor_is_invalid(self) -> None:
        settlement_seq = self.create_charged_settlement()
        self.create_sla("sla-2", "sla-create-2")
        self.activate("sla-2")
        self.add_event("sla-2", 1, 100)
        second = self.settle(
            "sla-2", self.evaluate("sla-2", "eval-2"), "settle-2"
        )
        self.assertEqual(
            self.post_dispute(self.dispute_body(settlement_seq))[0], 201
        )
        self.assertEqual(
            self.post_dispute(
                self.dispute_body(
                    second["settlementSeq"],
                    id="dispute-2",
                    claimantId=self.machine_id,
                ),
                key="dispute-2",
            )[0],
            201,
        )
        # 序号 2 属于 dispute-2，作为 dispute-1 的锚点无效。
        status, payload = self.get_json(
            "/v1/disputes/dispute-1/events?cursor=2:2"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_events_unknown_or_invalid_dispute_is_not_found(self) -> None:
        for dispute_id in ("missing", quote("BAD ID")):
            status, payload = self.get_json(f"/v1/disputes/{dispute_id}/events")
            self.assertEqual(status, 404, dispute_id)
            self.assertEqual(payload, {"error": "not_found"})

    def test_concurrent_resolution_records_single_event(self) -> None:
        self.create_open_dispute()
        results: list[int] = []
        lock = threading.Lock()

        def resolve() -> None:
            status, _ = self.post_resolution("dispute-1", {"decision": "release"})
            with lock:
                results.append(status)

        threads = [threading.Thread(target=resolve) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [200] * 8)
        _, payload = self.get_json("/v1/disputes/dispute-1/events")
        self.assertEqual(
            [event["type"] for event in payload["events"]],
            ["opened", "released"],
        )


class DisputeEventMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary.name) / "service.db")
        self._build_old_database()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _build_old_database(self) -> None:
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "CREATE TABLE disputes ("
                "id TEXT PRIMARY KEY, settlement_seq INTEGER NOT NULL UNIQUE,"
                " claimant_id TEXT NOT NULL, payer_id TEXT NOT NULL,"
                " payee_id TEXT NOT NULL, amount_micros INTEGER NOT NULL,"
                " state TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE settlements ("
                "settlement_seq INTEGER PRIMARY KEY, sla_id TEXT NOT NULL,"
                " evaluation_seq INTEGER NOT NULL UNIQUE, result TEXT NOT NULL,"
                " amount_micros INTEGER NOT NULL, payer_id TEXT,"
                " payee_id TEXT, created_at_ms INTEGER NOT NULL)"
            )
            rows = (
                ("d-open", 11, "open"),
                ("d-ref", 12, "refunded"),
                ("d-rel", 13, "released"),
            )
            for index, (dispute_id, settlement_seq, state) in enumerate(rows):
                connection.execute(
                    "INSERT INTO settlements"
                    "(settlement_seq, sla_id, evaluation_seq, result,"
                    " amount_micros, payer_id, payee_id, created_at_ms)"
                    " VALUES (?, 'sla-old', ?, 'charged', 1000, 'p', 'm', 0)",
                    (settlement_seq, 100 + index + 1),
                )
                connection.execute(
                    "INSERT INTO disputes"
                    "(id, settlement_seq, claimant_id, payer_id, payee_id,"
                    " amount_micros, state)"
                    " VALUES (?, ?, 'p', 'p', 'm', 1000, ?)",
                    (dispute_id, settlement_seq, state),
                )
            connection.commit()
        finally:
            connection.close()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def get_json(self, path: str) -> tuple[int, object]:
        try:
            with urlopen(self.url(path), timeout=5) as response:
                return response.status, json.loads(response.read())
        except HTTPError as error:
            return error.code, json.loads(error.read())

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_old_disputes_backfilled_once_by_rowid(self) -> None:
        expected = {
            "d-open": [(1, "opened")],
            "d-ref": [(2, "opened"), (3, "refunded")],
            "d-rel": [(4, "opened"), (5, "released")],
        }
        for dispute_id, events in expected.items():
            status, payload = self.get_json(f"/v1/disputes/{dispute_id}/events")
            self.assertEqual(status, 200)
            self.assertEqual(
                [
                    (event["eventSeq"], event["type"])
                    for event in payload["events"]
                ],
                events,
            )
            self.assertTrue(
                all(event["createdAt"] == 0 for event in payload["events"])
            )
            self.assertIsNone(payload["nextCursor"])

        status, payload = self.get_json("/v1/disputes/d-ref")
        self.assertEqual(status, 200)
        self.assertEqual(payload["state"], "refunded")
        self.assertEqual(payload["amount"], 1000)
        self.assertEqual(payload["settlementSeq"], 12)
        self.assertEqual(payload["slaId"], "sla-old")
        self.assertEqual(payload["result"], "charged")

        status, page = self.get_json("/v1/disputes/d-rel/events?limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(
            [event["eventSeq"] for event in page["events"]], [4]
        )
        self.assertEqual(page["nextCursor"], "5:4")
        status, page = self.get_json(
            f"/v1/disputes/d-rel/events?limit=1&cursor={page['nextCursor']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [event["eventSeq"] for event in page["events"]], [5]
        )
        self.assertIsNone(page["nextCursor"])

        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT event_seq, dispute_id, type, created_at_ms"
                " FROM dispute_events ORDER BY event_seq ASC"
            ).fetchall()
            self.assertEqual(
                [
                    (
                        row["event_seq"],
                        row["dispute_id"],
                        row["type"],
                        row["created_at_ms"],
                    )
                    for row in rows
                ],
                [
                    (1, "d-open", "opened", 0),
                    (2, "d-ref", "opened", 0),
                    (3, "d-ref", "refunded", 0),
                    (4, "d-rel", "opened", 0),
                    (5, "d-rel", "released", 0),
                ],
            )
            # 不虚构旧失败：只有 opened/released/refunded 三类。
            self.assertEqual(
                {row["type"] for row in rows},
                {"opened", "released", "refunded"},
            )
            marker = connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = 'dispute_events_backfilled'"
            ).fetchone()
            self.assertIsNotNone(marker)
            index = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='index'"
                " AND name='idx_dispute_events_dispute_seq'"
            ).fetchone()
            self.assertIsNotNone(index)
            # 既有争议数据未被改动。
            states = {
                row["id"]: row["state"]
                for row in connection.execute("SELECT id, state FROM disputes")
            }
            self.assertEqual(
                states,
                {"d-open": "open", "d-ref": "refunded", "d-rel": "released"},
            )
        finally:
            connection.close()

        # 重启不重复补写、不重排。
        self.restart()
        connection = sqlite3.connect(self.database_path)
        try:
            count = connection.execute("SELECT COUNT(*) FROM dispute_events").fetchone()[0]
            self.assertEqual(count, 5)
        finally:
            connection.close()

    def test_new_dispute_continues_migrated_sequence(self) -> None:
        request = Request(
            self.url("/v1/machines"),
            data=json.dumps({"publicKey": PUBLIC_KEY_A}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "register-1")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        machine = machine_id(PUBLIC_KEY_A)
        request = Request(
            self.url("/v1/machines"),
            data=json.dumps({"publicKey": PUBLIC_KEY_B}).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "register-2")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        consumer = machine_id(PUBLIC_KEY_B)

        def post(path: str, body: dict, key: str) -> tuple[int, bytes]:
            request = Request(
                self.url(path),
                data=json.dumps(body).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            try:
                with urlopen(request, timeout=5) as response:
                    return response.status, response.read()
            except HTTPError as error:
                return error.code, error.read()

        status, _ = post(
            f"/v1/machines/{machine}/capabilities",
            {
                "expectedVersion": 0,
                "name": "pump-01",
                "protocol": "mqtt",
                "region": "cn",
                "unit": "call",
                "capacity": 10,
            },
            "cap-1",
        )
        self.assertEqual(status, 201)
        status, _ = post(
            "/v1/sla-templates",
            {
                "id": "tpl-1",
                "machineId": machine,
                "capabilityVersion": 1,
                "priceMicros": 1000,
                "maxLatencyMs": 50,
            },
            "tpl-1",
        )
        self.assertEqual(status, 201)
        current = int(time.time())
        status, _ = post(
            "/v1/slas",
            {
                "id": "sla-new",
                "templateId": "tpl-1",
                "consumerId": consumer,
                "start": current - 10,
                "end": current + 3600,
            },
            "sla-new",
        )
        self.assertEqual(status, 201)
        for index, (party, actor) in enumerate(
            (("producer", machine), ("consumer", consumer))
        ):
            status, _ = post(
                "/v1/slas/sla-new/confirmations",
                {"party": party, "actorId": actor},
                f"conf-{index}",
            )
            self.assertEqual(status, 200)
        timestamp = (current - 10) * 1000
        message = f"sla-new\nevt-1\n{timestamp}\n10\n{machine}"
        status, _ = post(
            "/v1/slas/sla-new/telemetry",
            {
                "eventId": "evt-1",
                "timestamp": timestamp,
                "latencyMs": 10,
                "digest": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            },
            "tel-1",
        )
        self.assertEqual(status, 201)
        status, body = post(
            "/v1/slas/sla-new/evaluations",
            {"from": (current - 10) * 1000, "to": (current + 3600) * 1000},
            "eval-new",
        )
        self.assertEqual(status, 201)
        evaluation_seq = json.loads(body)["evaluationSeq"]
        status, _ = post(
            f"/v1/funds/{consumer}",
            {"amountMicros": 100000, "reference": "ref-1"},
            "fund-1",
        )
        self.assertEqual(status, 201)
        status, body = post(
            "/v1/settlements",
            {"slaId": "sla-new", "evaluationSeq": evaluation_seq},
            "settle-new",
        )
        self.assertEqual(status, 201)
        settlement_seq = json.loads(body)["settlementSeq"]
        status, _ = post(
            "/v1/disputes",
            {
                "id": "d-new",
                "settlementSeq": settlement_seq,
                "claimantId": consumer,
            },
            "dispute-new",
        )
        self.assertEqual(status, 201)
        # 迁移稠密占用 1..5，新争议 opened 事件序号接续为 6。
        status, payload = self.get_json("/v1/disputes/d-new/events")
        self.assertEqual(status, 200)
        self.assertEqual(
            [
                (event["eventSeq"], event["type"])
                for event in payload["events"]
            ],
            [(6, "opened")],
        )


class DisputeCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine_id = machine_id(PUBLIC_KEY_A)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("register-1", PUBLIC_KEY_A), ("register-2", PUBLIC_KEY_B)):
            status, _ = self.post_json(
                "/v1/machines", {"publicKey": public_key}, key
            )
            self.assertEqual(status, 201)
        status, _ = self.post_json(
            f"/v1/machines/{self.machine_id}/capabilities",
            {
                "expectedVersion": 0,
                "name": "pump-01",
                "protocol": "mqtt",
                "region": "cn",
                "unit": "call",
                "capacity": 10,
            },
            "cap-1",
        )
        self.assertEqual(status, 201)
        status, _ = self.post_json(
            "/v1/sla-templates",
            {
                "id": "tpl-1",
                "machineId": self.machine_id,
                "capabilityVersion": 1,
                "priceMicros": 1000,
                "maxLatencyMs": 50,
            },
            "tpl-1",
        )
        self.assertEqual(status, 201)
        current = int(time.time())
        self.start = current - 10
        self.end = current + 3600

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def post_json(
        self, path: str, payload: object, key: str | None
    ) -> tuple[int, bytes]:
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        request = Request(self.url(path), data=data, method="POST")
        if key is not None:
            request.add_header("Idempotency-Key", key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def get_json(self, path: str) -> tuple[int, dict]:
        try:
            with urlopen(self.url(path), timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def get_collection(self, query: str) -> tuple[int, dict]:
        return self.get_json(f"/v1/disputes?{query}")

    def create_dispute(self, index: int) -> str:
        sla_id = f"sla-{index}"
        status, _ = self.post_json(
            "/v1/slas",
            {
                "id": sla_id,
                "templateId": "tpl-1",
                "consumerId": self.consumer_id,
                "start": self.start,
                "end": self.end,
            },
            f"sla-create-{index}",
        )
        self.assertEqual(status, 201)
        for party_index, (party, actor) in enumerate(
            (("producer", self.machine_id), ("consumer", self.consumer_id))
        ):
            status, _ = self.post_json(
                f"/v1/slas/{sla_id}/confirmations",
                {"party": party, "actorId": actor},
                f"conf-{index}-{party_index}",
            )
            self.assertEqual(status, 200)
        event_id = f"evt-{index}"
        timestamp = self.start * 1000 + 1
        message = f"{sla_id}\n{event_id}\n{timestamp}\n10\n{self.machine_id}"
        status, _ = self.post_json(
            f"/v1/slas/{sla_id}/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": 10,
                "digest": hashlib.sha256(message.encode("utf-8")).hexdigest(),
            },
            f"tel-{index}",
        )
        self.assertEqual(status, 201)
        status, body = self.post_json(
            f"/v1/slas/{sla_id}/evaluations",
            {"from": self.start * 1000, "to": self.end * 1000},
            f"eval-{index}",
        )
        self.assertEqual(status, 201)
        evaluation_seq = json.loads(body)["evaluationSeq"]
        status, _ = self.post_json(
            f"/v1/funds/{self.consumer_id}",
            {"amountMicros": 100000, "reference": f"ref-{index}"},
            f"fund-{index}",
        )
        self.assertEqual(status, 201)
        status, body = self.post_json(
            "/v1/settlements",
            {"slaId": sla_id, "evaluationSeq": evaluation_seq},
            f"settle-{index}",
        )
        self.assertEqual(status, 201)
        settlement_seq = json.loads(body)["settlementSeq"]
        dispute_id = f"dispute-{index}"
        status, _ = self.post_json(
            "/v1/disputes",
            {
                "id": dispute_id,
                "settlementSeq": settlement_seq,
                "claimantId": self.consumer_id,
            },
            f"dispute-create-{index}",
        )
        self.assertEqual(status, 201)
        return dispute_id

    def resolve(self, dispute_id: str, decision: str, key: str) -> None:
        status, _ = self.post_json(
            f"/v1/disputes/{dispute_id}/resolution", {"decision": decision}, key
        )
        self.assertEqual(status, 200)

    def test_missing_account_id_is_400(self) -> None:
        status, payload = self.get_json("/v1/disputes")
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        status, payload = self.get_collection("limit=10")
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_unknown_and_duplicate_params_are_400(self) -> None:
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&foo=1"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&accountId={self.machine_id}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&state=open&state=open"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_invalid_account_id_format_is_400(self) -> None:
        for account in ("not-a-machine", "external:clearing", ""):
            status, payload = self.get_collection(f"accountId={account}")
            self.assertEqual(status, 400)
            self.assertEqual(payload, {"error": "invalid_request"})

    def test_unregistered_machine_is_404(self) -> None:
        status, payload = self.get_collection(f"accountId={machine_id(PUBLIC_KEY_C)}")
        self.assertEqual(status, 404)
        self.assertEqual(payload, {"error": "not_found"})

    def test_invalid_state_is_400(self) -> None:
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&state=pending"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_invalid_limit_and_cursor_are_400(self) -> None:
        for query in (
            "limit=0",
            "limit=101",
            "limit=050",
            "limit=abc",
            "cursor=1",
            "cursor=1:2:3",
            "cursor=01:2",
            "cursor=2:01",
            "cursor=a:2",
        ):
            status, payload = self.get_collection(
                f"accountId={self.consumer_id}&{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertEqual(payload, {"error": "invalid_request"})

    def test_account_without_disputes_returns_empty_page(self) -> None:
        status, payload = self.get_collection(f"accountId={self.consumer_id}")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"disputes": [], "nextCursor": None})

    def test_lists_disputes_for_payer_and_payee_in_key_order(self) -> None:
        self.create_dispute(1)
        self.create_dispute(2)
        status, payload = self.get_collection(f"accountId={self.consumer_id}")
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["disputes", "nextCursor"])
        self.assertIsNone(payload["nextCursor"])
        self.assertEqual(len(payload["disputes"]), 2)
        first = payload["disputes"][0]
        self.assertEqual(
            list(first),
            [
                "id",
                "state",
                "amount",
                "claimantId",
                "payerId",
                "payeeId",
                "settlementSeq",
                "slaId",
                "evaluationSeq",
                "result",
                "openedEventSeq",
                "openedAt",
                "resolvedEventSeq",
                "resolvedAt",
            ],
        )
        self.assertEqual(first["id"], "dispute-1")
        self.assertEqual(first["state"], "open")
        self.assertEqual(first["amount"], 1000)
        self.assertEqual(first["claimantId"], self.consumer_id)
        self.assertEqual(first["payerId"], self.consumer_id)
        self.assertEqual(first["payeeId"], self.machine_id)
        self.assertEqual(first["result"], "charged")
        self.assertEqual(first["openedEventSeq"], 1)
        self.assertGreaterEqual(first["openedAt"], 0)
        self.assertIsNone(first["resolvedEventSeq"])
        self.assertIsNone(first["resolvedAt"])
        second = payload["disputes"][1]
        self.assertEqual(second["id"], "dispute-2")
        self.assertEqual(second["openedEventSeq"], 2)
        # 收款方视角看到同一集合。
        status, payee_payload = self.get_collection(f"accountId={self.machine_id}")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["id"] for item in payee_payload["disputes"]],
            ["dispute-1", "dispute-2"],
        )

    def test_uninvolved_machine_gets_empty_page(self) -> None:
        self.create_dispute(1)
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": PUBLIC_KEY_C}, "register-3"
        )
        self.assertEqual(status, 201)
        status, payload = self.get_collection(f"accountId={machine_id(PUBLIC_KEY_C)}")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"disputes": [], "nextCursor": None})

    def test_resolved_dispute_reports_resolution_fields(self) -> None:
        self.create_dispute(1)
        self.resolve("dispute-1", "release", "resolve-1")
        status, payload = self.get_collection(f"accountId={self.consumer_id}")
        self.assertEqual(status, 200)
        (item,) = payload["disputes"]
        self.assertEqual(item["state"], "released")
        self.assertEqual(item["openedEventSeq"], 1)
        self.assertEqual(item["resolvedEventSeq"], 2)
        self.assertGreaterEqual(item["resolvedAt"], item["openedAt"])

    def test_state_filter_narrows_snapshot_states(self) -> None:
        self.create_dispute(1)
        self.create_dispute(2)
        self.resolve("dispute-2", "release", "resolve-2")
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&state=open"
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in payload["disputes"]], ["dispute-1"])
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&state=released"
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in payload["disputes"]], ["dispute-2"])
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&state=refunded"
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"disputes": [], "nextCursor": None})

    def test_pagination_uses_stable_snapshot(self) -> None:
        self.create_dispute(1)
        self.create_dispute(2)
        status, first_page = self.get_collection(
            f"accountId={self.consumer_id}&limit=1"
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in first_page["disputes"]], ["dispute-1"])
        cursor = first_page["nextCursor"]
        self.assertEqual(cursor, "2:1")
        # 首页之后的裁决与新增争议不进入旧快照。
        self.resolve("dispute-2", "release", "resolve-2")
        self.create_dispute(3)
        status, second_page = self.get_collection(
            f"accountId={self.consumer_id}&limit=1&cursor={cursor}"
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in second_page["disputes"]], ["dispute-2"])
        self.assertEqual(second_page["disputes"][0]["state"], "open")
        self.assertIsNone(second_page["disputes"][0]["resolvedEventSeq"])
        self.assertIsNone(second_page["nextCursor"])
        # 全新首页取新 cut，反映裁决与新增争议。
        status, fresh = self.get_collection(f"accountId={self.consumer_id}")
        self.assertEqual(status, 200)
        self.assertEqual(
            [(item["id"], item["state"]) for item in fresh["disputes"]],
            [("dispute-1", "open"), ("dispute-2", "released"), ("dispute-3", "open")],
        )

    def test_state_filter_applies_to_snapshot_not_current_state(self) -> None:
        self.create_dispute(1)
        status, first_page = self.get_collection(
            f"accountId={self.consumer_id}&state=open&limit=1"
        )
        self.assertEqual(status, 200)
        cursor = first_page["nextCursor"]
        self.assertIsNone(cursor)
        self.create_dispute(2)
        self.resolve("dispute-1", "release", "resolve-1")
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&state=open"
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in payload["disputes"]], ["dispute-2"])

    def test_cursor_ahead_of_cut_is_400(self) -> None:
        self.create_dispute(1)
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&cursor=99:1"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_cursor_anchor_outside_filter_is_400(self) -> None:
        self.create_dispute(1)
        self.create_dispute(2)
        status, first_page = self.get_collection(
            f"accountId={self.consumer_id}&limit=1"
        )
        self.assertEqual(status, 200)
        cursor = first_page["nextCursor"]
        # 锚点争议在快照中不为 released，带状态筛选重放锚点被拒绝。
        status, payload = self.get_collection(
            f"accountId={self.consumer_id}&state=released&cursor={cursor}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        # 锚点不属于其他账户的筛选结果。
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": PUBLIC_KEY_C}, "register-3"
        )
        self.assertEqual(status, 201)
        status, payload = self.get_collection(
            f"accountId={machine_id(PUBLIC_KEY_C)}&cursor={cursor}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_cursor_survives_restart(self) -> None:
        self.create_dispute(1)
        self.create_dispute(2)
        status, first_page = self.get_collection(
            f"accountId={self.consumer_id}&limit=1"
        )
        self.assertEqual(status, 200)
        cursor = first_page["nextCursor"]
        self.restart()
        status, second_page = self.get_collection(
            f"accountId={self.consumer_id}&limit=1&cursor={cursor}"
        )
        self.assertEqual(status, 200)
        self.assertEqual([item["id"] for item in second_page["disputes"]], ["dispute-2"])
        self.assertIsNone(second_page["nextCursor"])


if __name__ == "__main__":
    unittest.main()
