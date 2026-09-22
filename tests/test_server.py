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
        status, body, content_type = self.post_evaluation()
        self.assertEqual(status, 201)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(list(json.loads(body)), [
            "from",
            "to",
            "cut",
            "count",
            "latencySum",
            "maxLatency",
            "violations",
            "outcome",
        ])
        self.assertEqual(
            body,
            json.dumps(
                {
                    "from": self.start * 1000,
                    "to": self.end * 1000,
                    "cut": 0,
                    "count": 0,
                    "latencySum": 0,
                    "maxLatency": None,
                    "violations": 0,
                    "outcome": "insufficient",
                },
                separators=(",", ":"),
            ).encode(),
        )
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
        self.assertEqual(
            json.loads(body),
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

    def test_get_on_evaluations_path_is_404(self) -> None:
        try:
            urlopen(self.url("/v1/slas/sla-1/evaluations"), timeout=5)
        except HTTPError as error:
            self.assertEqual(error.code, 404)
            self.assertEqual(json.load(error), {"error": "not_found"})
        else:
            self.fail("expected HTTPError")


if __name__ == "__main__":
    unittest.main()

