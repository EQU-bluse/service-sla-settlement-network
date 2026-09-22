from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
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
        self.stranger_id = machine_id(PUBLIC_KEY_C)
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
        self.create_sla("sla-1", start=time.time() - 60, end=time.time() + 3600)

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

    def create_sla(self, sla_id: str, start: float, end: float) -> None:
        request = Request(
            self.url("/v1/slas"),
            data=json.dumps(
                {
                    "id": sla_id,
                    "templateId": "tpl-1",
                    "consumerId": self.consumer_id,
                    "start": int(start),
                    "end": int(end),
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", f"create-{sla_id}")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)

    def bump_capability(self) -> None:
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

    def confirmation_body(self, party: str, actor_id: str) -> bytes:
        return json.dumps({"party": party, "actorId": actor_id}).encode()

    def post_confirmation(
        self,
        sla_id: str,
        body: bytes,
        idempotency_key: str | None = "cf-1",
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

    def get_sla(self, sla_id: str) -> tuple[int, bytes, str]:
        try:
            with urlopen(self.url(f"/v1/slas/{sla_id}"), timeout=5) as response:
                return response.status, response.read(), response.headers["Content-Type"]
        except HTTPError as error:
            return error.code, error.read(), error.headers["Content-Type"]

    def test_first_party_pending_second_party_active(self) -> None:
        status, body, content_type = self.post_confirmation(
            "sla-1", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(body, b'{"state":"pending"}')
        self.assertFalse(body.endswith(b"\n"))
        _, snapshot, _ = self.get_sla("sla-1")
        self.assertEqual(json.loads(snapshot)["state"], "pending")
        status, body, _ = self.post_confirmation(
            "sla-1",
            self.confirmation_body("consumer", self.consumer_id),
            idempotency_key="cf-2",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"state":"active"}')
        _, snapshot, _ = self.get_sla("sla-1")
        self.assertEqual(json.loads(snapshot)["state"], "active")

    def test_consumer_first_then_producer(self) -> None:
        status, body, _ = self.post_confirmation(
            "sla-1",
            self.confirmation_body("consumer", self.consumer_id),
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))
        status, body, _ = self.post_confirmation(
            "sla-1",
            self.confirmation_body("producer", self.machine_id),
            idempotency_key="cf-2",
        )
        self.assertEqual((status, body), (200, b'{"state":"active"}'))

    def test_replay_returns_first_response_bytes_even_after_active(self) -> None:
        status, body, _ = self.post_confirmation(
            "sla-1", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))
        self.assertEqual(
            self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )[:2],
            (status, body),
        )
        self.assertEqual(
            self.post_confirmation(
                "sla-1",
                self.confirmation_body("consumer", self.consumer_id),
                idempotency_key="cf-2",
            )[:2],
            (200, b'{"state":"active"}'),
        )
        # 生产者首条请求的重放仍返回首次的 pending，状态转换只发生一次。
        self.assertEqual(
            self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )[:2],
            (status, body),
        )
        _, snapshot, _ = self.get_sla("sla-1")
        self.assertEqual(json.loads(snapshot)["state"], "active")

    def test_replay_survives_restart(self) -> None:
        status, body, _ = self.post_confirmation(
            "sla-1", self.confirmation_body("producer", self.machine_id)
        )
        self.restart()
        again_status, again_body, _ = self.post_confirmation(
            "sla-1", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((again_status, again_body), (status, body))

    def test_same_key_different_sla_conflicts(self) -> None:
        self.create_sla("sla-2", start=time.time() - 60, end=time.time() + 3600)
        self.assertEqual(
            self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        status, response_body, _ = self.post_confirmation(
            "sla-2", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "conflict"})

    def test_same_key_different_body_conflicts(self) -> None:
        self.assertEqual(
            self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        status, response_body, _ = self.post_confirmation(
            "sla-1", self.confirmation_body("consumer", self.consumer_id)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "conflict"})

    def test_sla_not_found(self) -> None:
        status, body, _ = self.post_confirmation(
            "missing", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_party_actor_mismatch_is_forbidden(self) -> None:
        cases = [
            ("producer", self.consumer_id),
            ("consumer", self.machine_id),
            ("producer", self.stranger_id),
            ("consumer", self.stranger_id),
        ]
        for index, (party, actor_id) in enumerate(cases):
            status, body, _ = self.post_confirmation(
                "sla-1",
                self.confirmation_body(party, actor_id),
                idempotency_key=f"bad-actor-{index}",
            )
            self.assertEqual(status, 403, (party, actor_id))
            self.assertEqual(json.loads(body), {"error": "forbidden"})

    def test_different_key_same_party_already_confirmed(self) -> None:
        self.assertEqual(
            self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        status, body, _ = self.post_confirmation(
            "sla-1",
            self.confirmation_body("producer", self.machine_id),
            idempotency_key="cf-other",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_confirmed"})

    def test_forbidden_takes_precedence_over_duplicate_party(self) -> None:
        self.assertEqual(
            self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        # 同方重复但 actorId 不符：参与方校验先于重复方校验。
        status, body, _ = self.post_confirmation(
            "sla-1",
            self.confirmation_body("producer", self.stranger_id),
            idempotency_key="cf-other",
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})

    def test_before_start_conflicts(self) -> None:
        now = time.time()
        self.create_sla("sla-future", start=now + 600, end=now + 3600)
        status, body, _ = self.post_confirmation(
            "sla-future",
            self.confirmation_body("producer", self.machine_id),
            idempotency_key="cf-future",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_after_end_conflicts(self) -> None:
        now = time.time()
        self.create_sla("sla-past", start=now - 3600, end=now - 60)
        status, body, _ = self.post_confirmation(
            "sla-past",
            self.confirmation_body("producer", self.machine_id),
            idempotency_key="cf-past",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_capability_version_drift_conflicts(self) -> None:
        self.bump_capability()
        status, body, _ = self.post_confirmation(
            "sla-1", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_failed_request_leaves_no_idempotency_record(self) -> None:
        status, _, _ = self.post_confirmation(
            "missing", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual(status, 404)
        status, body, _ = self.post_confirmation(
            "sla-1", self.confirmation_body("producer", self.machine_id)
        )
        self.assertEqual((status, body), (200, b'{"state":"pending"}'))

    def test_conflict_leaves_no_confirmation(self) -> None:
        # 时间窗口不符时失败，不写入确认；待窗口内请求仍可由该方首次确认。
        now = time.time()
        self.create_sla("sla-past", start=now - 3600, end=now - 60)
        status, _, _ = self.post_confirmation(
            "sla-past",
            self.confirmation_body("producer", self.machine_id),
            idempotency_key="cf-past",
        )
        self.assertEqual(status, 409)
        _, snapshot, _ = self.get_sla("sla-past")
        self.assertEqual(json.loads(snapshot)["state"], "pending")

    def test_invalid_idempotency_key(self) -> None:
        for key in (None, "", "bad key", "bad_key", "x" * 65, "é"):
            status, body, _ = self.post_confirmation(
                "sla-1",
                self.confirmation_body("producer", self.machine_id),
                idempotency_key=key,
            )
            self.assertEqual(status, 400, key)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_invalid_bodies(self) -> None:
        valid = {"party": "producer", "actorId": self.machine_id}
        cases = [
            b"",
            b"\xff\xfe{}",
            b"{not json",
            b"[1,2]",
            b'"text"',
            b"null",
            b"{}",
            json.dumps(dict(valid, extra=1)).encode(),
            json.dumps({"party": "producer"}).encode(),
            json.dumps({"actorId": self.machine_id}).encode(),
            json.dumps(dict(valid, party="Producer")).encode(),
            json.dumps(dict(valid, party="broker")).encode(),
            json.dumps(dict(valid, party=1)).encode(),
            json.dumps(dict(valid, party=["producer"])).encode(),
            json.dumps(dict(valid, party=True)).encode(),
            json.dumps(dict(valid, party=None)).encode(),
            json.dumps(dict(valid, actorId=self.machine_id.upper())).encode(),
            json.dumps(dict(valid, actorId="aa" * 31)).encode(),
            json.dumps(dict(valid, actorId="gg" * 32)).encode(),
            json.dumps(dict(valid, actorId=123)).encode(),
            b'{"party":"producer","party":"consumer","actorId":"'
            + self.machine_id.encode()
            + b'"}',
            b'{"actorId":"'
            + self.machine_id.encode()
            + b'","actorId":"'
            + self.consumer_id.encode()
            + b'","party":"producer"}',
        ]
        for body in cases:
            status, response_body, _ = self.post_confirmation("sla-1", body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response_body), {"error": "invalid_request"})

    def test_concurrent_same_key_all_replay_first_result(self) -> None:
        results: list[tuple[int, bytes]] = []
        lock = threading.Lock()

        def confirm() -> None:
            status, body, _ = self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )
            with lock:
                results.append((status, body))

        threads = [threading.Thread(target=confirm) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [(200, b'{"state":"pending"}')] * 8)

    def test_concurrent_distinct_keys_per_party_single_success(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def confirm(index: int, party: str, actor_id: str) -> None:
            status, _, _ = self.post_confirmation(
                "sla-1",
                self.confirmation_body(party, actor_id),
                idempotency_key=f"cf-race-{party}-{index}",
            )
            with lock:
                results.append(status)

        threads = []
        for index in range(8):
            threads.append(
                threading.Thread(
                    target=confirm, args=(index, "producer", self.machine_id)
                )
            )
            threads.append(
                threading.Thread(
                    target=confirm, args=(index, "consumer", self.consumer_id)
                )
            )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results).count(200), 2)
        self.assertEqual(sorted(results).count(409), 14)
        _, snapshot, _ = self.get_sla("sla-1")
        self.assertEqual(json.loads(snapshot)["state"], "active")

    def test_active_transition_happens_exactly_once_under_dup_race(self) -> None:
        self.assertEqual(
            self.post_confirmation(
                "sla-1", self.confirmation_body("producer", self.machine_id)
            )[0],
            200,
        )
        self.assertEqual(
            self.post_confirmation(
                "sla-1",
                self.confirmation_body("consumer", self.consumer_id),
                idempotency_key="cf-2",
            )[0],
            200,
        )
        results: list[int] = []
        lock = threading.Lock()

        def confirm(index: int, party: str, actor_id: str) -> None:
            status, _, _ = self.post_confirmation(
                "sla-1",
                self.confirmation_body(party, actor_id),
                idempotency_key=f"cf-dup-{party}-{index}",
            )
            with lock:
                results.append(status)

        threads = []
        for index in range(8):
            threads.append(
                threading.Thread(
                    target=confirm, args=(index, "producer", self.machine_id)
                )
            )
            threads.append(
                threading.Thread(
                    target=confirm, args=(index, "consumer", self.consumer_id)
                )
            )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [409] * 16)
        _, snapshot, _ = self.get_sla("sla-1")
        self.assertEqual(json.loads(snapshot)["state"], "active")


if __name__ == "__main__":
    unittest.main()

