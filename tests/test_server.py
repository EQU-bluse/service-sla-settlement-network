from __future__ import annotations

import concurrent.futures
import hashlib
import json
import re
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from sla_network.server import ApiServer, Handler

PUBLIC_KEY_B = "bb" * 32
PUBLIC_KEY_C = "cc" * 32


def machine_id(public_key: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key)).hexdigest()


def _ed25519_enc(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed25519_public_key(seed: bytes) -> bytes:
    from sla_network.ed25519 import _BASEPOINT, _scalar_multiply

    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return _ed25519_enc(_scalar_multiply(int.from_bytes(scalar, "little"), _BASEPOINT))


def _ed25519_sign(seed: bytes, message: bytes) -> bytes:
    from sla_network.ed25519 import _BASEPOINT, _L, _scalar_multiply

    digest = hashlib.sha512(seed).digest()
    scalar = bytearray(digest[:32])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    secret = int.from_bytes(bytes(scalar), "little")
    public = _scalar_multiply(secret, _BASEPOINT)
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    r_point = _scalar_multiply(r, _BASEPOINT)
    k = int.from_bytes(
        hashlib.sha512(_ed25519_enc(r_point) + _ed25519_enc(public) + message).digest(),
        "little",
    ) % _L
    return _ed25519_enc(r_point) + ((r + k * secret) % _L).to_bytes(32, "little")


# 生产机器使用可签名的真实 Ed25519 密钥对（遥测签名需用对应私钥种子生成）。
PRODUCER_SEED = b"\x01" * 32
PUBLIC_KEY_A = _ed25519_public_key(PRODUCER_SEED).hex()
# 消费者与第三方同样使用可签名密钥对（SLA-Auth、确认/证据/证明均需私钥签名）。
PUBLIC_KEY_SEED_B = b"\x02" * 32
PUBLIC_KEY_SEED_C = b"\x03" * 32
PUBLIC_KEY_B = _ed25519_public_key(PUBLIC_KEY_SEED_B).hex()
PUBLIC_KEY_C = _ed25519_public_key(PUBLIC_KEY_SEED_C).hex()


def telemetry_signature(
    seed: bytes,
    sla_id: str,
    event_id: str,
    timestamp: int,
    latency_ms: int,
    digest: str,
    machine: str,
    key_version: int = 1,
) -> str:
    message = (
        f"telemetry-v2\n{sla_id}\n{event_id}\n{timestamp}\n"
        f"{latency_ms}\n{digest}\n{key_version}\n{machine}"
    )
    return _ed25519_sign(seed, message.encode("utf-8")).hex()


def key_rotation_signatures(
    current_seed: bytes,
    new_seed: bytes,
    machine: str,
    expected_version: int,
    new_public_key: str,
) -> tuple[str, str]:
    message = (
        f"key-rotate-v1\n{machine}\n{expected_version}\n{new_public_key}"
    ).encode("utf-8")
    return (
        _ed25519_sign(current_seed, message).hex(),
        _ed25519_sign(new_seed, message).hex(),
    )


def key_revocation_signature(
    seed: bytes, machine: str, version: int
) -> str:
    message = f"key-revoke-v1\n{machine}\n{version}".encode("utf-8")
    return _ed25519_sign(seed, message).hex()


class _SlaAuthRegistry:
    # 同键同请求的重试、并发与重启后重放必须逐字节复用同一组认证五段
    # （服务规定同键更换认证五段即为冲突）；异键分配不同随机数。
    # 以数据库路径为作用域：重启后服务对象更换但路径不变，重放须复用；
    # 不同用例路径不同，各自取新鲜时间戳，避免长测试运行后时间戳过期。
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counter = 0
        self._headers: dict[tuple[object, ...], str] = {}

    def header(
        self,
        scope: str,
        idempotency_key: str | None,
        seed: bytes,
        actor_id: str,
        method: str,
        path: str,
        body: bytes,
        key_version: int,
        request_time_ms: int | None = None,
        nonce: str | None = None,
    ) -> str:
        use_cache = request_time_ms is None and nonce is None
        cache_key = (
            scope,
            idempotency_key,
            seed,
            actor_id,
            method,
            path,
            body,
            key_version,
        )
        if use_cache:
            # 整段取锁做 get-or-create：同键并发线程必须逐字节复用同一组五段。
            with self._lock:
                cached = self._headers.get(cache_key)
                if cached is None:
                    cached = self._build(
                        cache_key,
                        seed,
                        actor_id,
                        method,
                        path,
                        body,
                        key_version,
                        int(time.time() * 1000),
                        f"nonce-{self._next_counter_locked():020d}",
                    )
                    self._headers[cache_key] = cached
            return cached
        if request_time_ms is None:
            request_time_ms = int(time.time() * 1000)
        if nonce is None:
            with self._lock:
                nonce = f"nonce-{self._next_counter_locked():020d}"
        return self._build(
            cache_key,
            seed,
            actor_id,
            method,
            path,
            body,
            key_version,
            request_time_ms,
            nonce,
        )

    def _next_counter_locked(self) -> int:
        self._counter += 1
        return self._counter

    @staticmethod
    def _build(
        cache_key: tuple[object, ...],
        seed: bytes,
        actor_id: str,
        method: str,
        path: str,
        body: bytes,
        key_version: int,
        request_time_ms: int,
        nonce: str,
    ) -> str:
        body_digest = hashlib.sha256(body).hexdigest()
        message = (
            f"request-auth-v1\n{method}\n{path}\n{body_digest}\n"
            f"{request_time_ms}\n{nonce}\n{key_version}\n{actor_id}"
        ).encode("utf-8")
        signature = _ed25519_sign(seed, message).hex()
        return (
            f"{actor_id};{key_version};{request_time_ms};{nonce};{signature}"
        )


_SLA_AUTH_REGISTRY = _SlaAuthRegistry()


def make_sla_auth(
    server: ApiServer,
    idempotency_key: str | None,
    seed: bytes,
    actor_id: str,
    method: str,
    path: str,
    body: bytes,
    key_version: int = 1,
    *,
    request_time_ms: int | None = None,
    nonce: str | None = None,
) -> str:
    return _SLA_AUTH_REGISTRY.header(
        server.database_path,
        idempotency_key,
        seed,
        actor_id,
        method,
        path,
        body,
        key_version,
        request_time_ms,
        nonce,
    )


# 受保护入口测试中使用的全部已知私钥种子（含他机 b"\x03"*32）。
_KNOWN_SEEDS = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32)


def seed_for_actor(actor_id: str) -> bytes:
    for seed in _KNOWN_SEEDS:
        if machine_id(_ed25519_public_key(seed).hex()) == actor_id:
            return seed
    # 未知机器（资源不存在 404、参与方不符 403 等用例）：结构合法即可，
    # 资源/签名者判定先于验签，签名内容不会被校验。
    return b"\x01" * 32


_SLA_AUTH_PATH_MACHINE = re.compile(r"^/v1/machines/([0-9a-f]{64})/capabilities$")
_SLA_AUTH_CONFIRMATION = re.compile(r"^/v1/slas/([^/]+)/confirmations$")
_SLA_AUTH_EVIDENCE = re.compile(r"^/v1/disputes/([^/]+)/evidence$")


def _sla_auth_actor(path: str, body: bytes) -> str | None:
    match = _SLA_AUTH_PATH_MACHINE.fullmatch(path)
    if match is not None:
        return match.group(1)
    if (
        _SLA_AUTH_CONFIRMATION.fullmatch(path) is not None
        or _SLA_AUTH_EVIDENCE.fullmatch(path) is not None
        or path == "/v1/evidence-proofs"
    ):
        try:
            parsed = json.loads(body)
        except ValueError:
            return None
        if isinstance(parsed, dict) and isinstance(parsed.get("actorId"), str):
            actor = parsed["actorId"]
            if re.fullmatch(r"[0-9a-f]{64}", actor) is not None:
                return actor
    return None


def add_sla_auth(request: Request, server: ApiServer) -> None:
    # 从 Request 对象自身派生认证头：非受保护路径或无法确定签名者时不加。
    path = urlsplit(request.full_url).path
    body = request.data if isinstance(request.data, bytes) else b""
    actor_id = _sla_auth_actor(path, body)
    if actor_id is None:
        return
    idempotency_key = request.headers.get("Idempotency-key")
    request.add_header(
        "SLA-Auth",
        make_sla_auth(
            server,
            idempotency_key,
            seed_for_actor(actor_id),
            actor_id,
            request.get_method(),
            path,
            body,
            1,
        ),
    )


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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
            add_sla_auth(request, self.server)
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
        signature: str | None = None,
        key_version: int = 1,
    ) -> bytes:
        if timestamp is None:
            timestamp = self.start * 1000 + 500
        if digest is None:
            digest = self.digest(sla_id, event_id, timestamp, latency_ms)
        if signature is None:
            signature = telemetry_signature(
                PRODUCER_SEED, sla_id, event_id, timestamp, latency_ms, digest,
                self.machine_id, key_version,
            )
        return json.dumps(
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": digest,
                "keyVersion": key_version,
                "signature": signature,
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
            json.dumps(
                {key: value for key, value in valid.items() if key != "signature"}
            ).encode(),
            json.dumps(dict(valid, signature="")).encode(),
            json.dumps(dict(valid, signature="0" * 127)).encode(),
            json.dumps(dict(valid, signature="0" * 129)).encode(),
            json.dumps(dict(valid, signature="A" * 128)).encode(),
            json.dumps(dict(valid, signature="g" * 128)).encode(),
            json.dumps(dict(valid, signature=123)).encode(),
            json.dumps(
                {key: value for key, value in valid.items() if key != "keyVersion"}
            ).encode(),
            json.dumps(dict(valid, keyVersion=0)).encode(),
            json.dumps(dict(valid, keyVersion=-1)).encode(),
            json.dumps(dict(valid, keyVersion=True)).encode(),
            json.dumps(dict(valid, keyVersion=1.0)).encode(),
            json.dumps(dict(valid, keyVersion="1")).encode(),
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

    def signed_event_row(self, event_id: str = "evt-1") -> sqlite3.Row:
        connection = sqlite3.connect(self.server.database_path)
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute(
                "SELECT signature, commit_seq FROM sla_telemetry_events"
                " WHERE sla_id = 'sla-1' AND event_id = ?",
                (event_id,),
            ).fetchone()
        finally:
            connection.close()

    def test_signature_persisted_with_event(self) -> None:
        self.activate()
        body = json.loads(self.telemetry_body())
        status, _, _ = self.post_telemetry(json.dumps(body).encode())
        self.assertEqual(status, 201)
        row = self.signed_event_row()
        self.assertIsNotNone(row)
        self.assertEqual(row["signature"], body["signature"])
        self.assertEqual(row["commit_seq"], 1)

    def test_tampered_fields_fail_signature(self) -> None:
        self.activate()
        valid = json.loads(self.telemetry_body())
        # 篡改任一业务字段并重算 digest（使摘要检查通过），旧签名必须失效。
        for field, value in (
            ("eventId", "evt-9"),
            ("timestamp", valid["timestamp"] + 1),
            ("latencyMs", valid["latencyMs"] + 1),
        ):
            tampered = dict(valid, **{field: value})
            tampered["digest"] = self.digest(
                "sla-1",
                tampered["eventId"],
                tampered["timestamp"],
                tampered["latencyMs"],
            )
            status, body, _ = self.post_telemetry(
                json.dumps(tampered).encode(), idempotency_key=f"tamper-{field}"
            )
            self.assertEqual(status, 409, field)
            self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # digest 本身被签名覆盖：换用其他 digest 后旧签名失效。
        tampered = dict(valid, latencyMs=valid["latencyMs"] + 1)
        tampered["digest"] = self.digest(
            "sla-1", "evt-1", tampered["timestamp"], tampered["latencyMs"]
        )
        status, body, _ = self.post_telemetry(
            json.dumps(tampered).encode(), idempotency_key="tamper-digest"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})

    def test_signature_binds_sla_id(self) -> None:
        self.activate()
        # 第二个 SLA 绑定同一机器；为 sla-1 签的名不能用于 sla-2。
        request = Request(
            self.url("/v1/slas"),
            data=json.dumps(
                {
                    "id": "sla-2",
                    "templateId": "tpl-1",
                    "consumerId": self.consumer_id,
                    "start": self.start,
                    "end": self.end,
                }
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "sla-2")
        with urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 201)
        for key, party, actor in (
            ("conf-p-2", "producer", self.machine_id),
            ("conf-c-2", "consumer", self.consumer_id),
        ):
            request = Request(
                self.url("/v1/slas/sla-2/confirmations"),
                data=json.dumps({"party": party, "actorId": actor}).encode(),
                method="POST",
            )
            request.add_header("Idempotency-Key", key)
            add_sla_auth(request, self.server)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)
        timestamp = self.start * 1000 + 500
        digest = self.digest("sla-2", "evt-1", timestamp, 12)
        body = {
            "eventId": "evt-1",
            "timestamp": timestamp,
            "latencyMs": 12,
            "digest": digest,
            "keyVersion": 1,
            "signature": telemetry_signature(
                PRODUCER_SEED, "sla-1", "evt-1", timestamp, 12, digest, self.machine_id
            ),
        }
        status, response_body, _ = self.post_telemetry(
            json.dumps(body).encode(), sla_id="sla-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "invalid_signature"})

    def test_wrong_key_signature_rejected(self) -> None:
        self.activate()
        body = json.loads(self.telemetry_body())
        body["signature"] = telemetry_signature(
            b"\x09" * 32,
            "sla-1",
            body["eventId"],
            body["timestamp"],
            body["latencyMs"],
            body["digest"],
            self.machine_id,
        )
        status, response_body, _ = self.post_telemetry(json.dumps(body).encode())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "invalid_signature"})

    def test_missing_machine_public_key_is_invalid_signature(self) -> None:
        # 直接插入一个机器未登记的 active SLA：查不到公钥等同验签失败。
        ghost = "cc" * 32
        connection = sqlite3.connect(self.server.database_path)
        try:
            connection.execute(
                "INSERT INTO slas(id, template_id, machine_id, consumer_id,"
                " capability_version, price_micros, max_latency_ms, start_unix,"
                " end_unix, state) VALUES ('sla-ghost', 'tpl-1', ?, ?, 1, 1000, 50,"
                " ?, ?, 'active')",
                (ghost, self.consumer_id, self.start, self.end),
            )
            connection.commit()
        finally:
            connection.close()
        timestamp = self.start * 1000 + 500
        # digest 消息中的 machineId 取快照值（未登记的 ghost）。
        digest = hashlib.sha256(
            f"sla-ghost\nevt-1\n{timestamp}\n12\n{ghost}".encode()
        ).hexdigest()
        body = {
            "eventId": "evt-1",
            "timestamp": timestamp,
            "latencyMs": 12,
            "digest": digest,
            "keyVersion": 1,
            "signature": telemetry_signature(
                PRODUCER_SEED, "sla-ghost", "evt-1", timestamp, 12, digest, ghost
            ),
        }
        status, response_body, _ = self.post_telemetry(
            json.dumps(body).encode(), sla_id="sla-ghost"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "invalid_signature"})

    def test_signature_checked_after_state_time_and_digest(self) -> None:
        # 非 active：不进入验签。
        body = json.loads(self.telemetry_body(signature="0" * 128))
        status, response_body, _ = self.post_telemetry(json.dumps(body).encode())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "conflict"})
        self.activate()
        # 时间越界：不进入验签。
        late = json.loads(
            self.telemetry_body(timestamp=self.end * 1000, signature="0" * 128)
        )
        status, response_body, _ = self.post_telemetry(
            json.dumps(late).encode(), idempotency_key="tel-late"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "conflict"})
        # 摘要错误：不进入验签。
        bad_digest = json.loads(self.telemetry_body(digest="0" * 64, signature="0" * 128))
        status, response_body, _ = self.post_telemetry(
            json.dumps(bad_digest).encode(), idempotency_key="tel-digest"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "conflict"})
        # SLA 不存在：404 先于签名检查。
        missing = json.loads(
            self.telemetry_body(sla_id="missing", signature="0" * 128)
        )
        status, response_body, _ = self.post_telemetry(
            json.dumps(missing).encode(), sla_id="missing", idempotency_key="tel-missing"
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(response_body), {"error": "not_found"})

    def test_invalid_signature_leaves_no_trace(self) -> None:
        self.activate()
        body = json.loads(self.telemetry_body(signature="ab" * 64))
        status, response_body, _ = self.post_telemetry(json.dumps(body).encode())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response_body), {"error": "invalid_signature"})
        # 同键修正签名后可成功，且提交序号仍为 1（失败未推进序号、未占键）。
        status, response_body, _ = self.post_telemetry(self.telemetry_body())
        self.assertEqual((status, response_body), (201, b'{"eventId":"evt-1"}'))
        row = self.signed_event_row()
        self.assertEqual(row["commit_seq"], 1)

    def test_event_exists_checked_after_signature(self) -> None:
        self.activate()
        self.assertEqual(self.post_telemetry(self.telemetry_body())[0], 201)
        # 异键同 eventId 且签名有效：event_exists。
        status, body, _ = self.post_telemetry(
            self.telemetry_body(), idempotency_key="tel-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "event_exists"})
        # 异键同 eventId 但签名无效：invalid_signature 优先。
        bad = json.loads(self.telemetry_body(signature="0" * 128))
        status, body, _ = self.post_telemetry(
            json.dumps(bad).encode(), idempotency_key="tel-3"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})

    def test_same_key_different_signature_conflicts(self) -> None:
        self.activate()
        self.assertEqual(self.post_telemetry(self.telemetry_body())[0], 201)
        other = json.loads(self.telemetry_body(signature="ab" * 64))
        status, body, _ = self.post_telemetry(json.dumps(other).encode())
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_unsigned_body_without_matching_record_is_invalid(self) -> None:
        self.activate()
        unsigned = {
            "eventId": "evt-1",
            "timestamp": self.start * 1000 + 500,
            "latencyMs": 12,
            "digest": self.digest("sla-1", "evt-1", self.start * 1000 + 500, 12),
        }
        status, body, _ = self.post_telemetry(json.dumps(unsigned).encode())
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def insert_legacy_event(
        self, key: str, event_id: str, timestamp: int, latency_ms: int
    ) -> dict[str, object]:
        # 模拟升级前写入：事件无签名，幂等记录为四字段请求。
        digest = self.digest("sla-1", event_id, timestamp, latency_ms)
        fields: dict[str, object] = {
            "eventId": event_id,
            "timestamp": timestamp,
            "latencyMs": latency_ms,
            "digest": digest,
        }
        request_json = json.dumps(fields, sort_keys=True, separators=(",", ":"))
        response_json = json.dumps({"eventId": event_id}, separators=(",", ":"))
        connection = sqlite3.connect(self.server.database_path)
        try:
            connection.execute(
                "INSERT INTO sla_telemetry_events"
                "(sla_id, event_id, timestamp_ms, latency_ms, digest, commit_seq)"
                " VALUES ('sla-1', ?, ?, ?, ?,"
                " (SELECT COALESCE(MAX(commit_seq), 0) + 1 FROM sla_telemetry_events))",
                (event_id, timestamp, latency_ms, digest),
            )
            connection.execute(
                "INSERT INTO sla_telemetry_idempotency_records"
                "(key, sla_id, request_json, status, response_json)"
                " VALUES (?, 'sla-1', ?, 201, ?)",
                (key, request_json, response_json),
            )
            connection.commit()
        finally:
            connection.close()
        return fields

    def test_legacy_unsigned_record_replays_exact_match(self) -> None:
        self.activate()
        fields = self.insert_legacy_event("tel-old", "evt-old", self.start * 1000 + 5, 12)
        body = json.dumps(fields).encode()
        status, response_body, _ = self.post_telemetry(body, idempotency_key="tel-old")
        self.assertEqual((status, response_body), (201, b'{"eventId":"evt-old"}'))
        self.restart()
        status, response_body, _ = self.post_telemetry(body, idempotency_key="tel-old")
        self.assertEqual((status, response_body), (201, b'{"eventId":"evt-old"}'))

    def test_unsigned_body_against_mismatched_key_is_invalid(self) -> None:
        self.activate()
        self.insert_legacy_event("tel-old", "evt-old", self.start * 1000 + 5, 12)
        # 同键但正文不同：无签名提交按非法正文处理。
        other = {
            "eventId": "evt-other",
            "timestamp": self.start * 1000 + 6,
            "latencyMs": 9,
            "digest": self.digest("sla-1", "evt-other", self.start * 1000 + 6, 9),
        }
        status, body, _ = self.post_telemetry(
            json.dumps(other).encode(), idempotency_key="tel-old"
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "invalid_request"})
        # 无签名的四字段正文命中已签名记录的同键：同样非法。
        self.assertEqual(self.post_telemetry(self.telemetry_body())[0], 201)
        signed = json.loads(self.telemetry_body())
        unsigned = {key: value for key, value in signed.items() if key != "signature"}
        status, body, _ = self.post_telemetry(json.dumps(unsigned).encode())
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body), {"error": "invalid_request"})

    def test_legacy_unsigned_event_visible_in_reads_and_evaluation(self) -> None:
        self.activate()
        self.insert_legacy_event("tel-old", "evt-old", self.start * 1000 + 5, 12)
        status, body, _ = self.get_telemetry(
            f"from={self.start * 1000}&to={self.end * 1000}"
        )
        self.assertEqual(status, 200)
        self.assertEqual([event["eventId"] for event in body["events"]], ["evt-old"])
        self.assertEqual(body["summary"]["count"], 1)
        # 新签名事件接在旧事件之后，序号不重排。
        status, _, _ = self.post_telemetry(
            self.telemetry_body(event_id="evt-new"), idempotency_key="tel-new"
        )
        self.assertEqual(status, 201)
        row = self.signed_event_row("evt-new")
        self.assertEqual(row["commit_seq"], 2)
        request = Request(
            self.url("/v1/slas/sla-1/evaluations"),
            data=json.dumps(
                {"from": self.start * 1000, "to": self.end * 1000}
            ).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", "eval-1")
        with urlopen(request, timeout=5) as response:
            evaluation = json.load(response)
        self.assertEqual(evaluation["count"], 2)


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
        add_sla_auth(request, self.server)
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
            add_sla_auth(request, self.server)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)

    def digest(self, sla_id: str, event_id: str, timestamp: int, latency_ms: int) -> str:
        message = f"{sla_id}\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine_id}"
        return hashlib.sha256(message.encode("utf-8")).hexdigest()

    def add_event(
        self, index: int, timestamp: int, latency_ms: int, sla_id: str = "sla-1"
    ) -> None:
        event_id = f"evt-{index:03d}"
        digest = self.digest(sla_id, event_id, timestamp, latency_ms)
        body = json.dumps(
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    PRODUCER_SEED, sla_id, event_id, timestamp, latency_ms, digest,
                    self.machine_id,
                ),
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


class TelemetrySignatureMigrationTests(unittest.TestCase):
    """签名升级前的旧库：事件表无 signature 列，含无签名事件与四字段幂等记录。"""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary.name) / "service.db")
        self.machine = machine_id(PUBLIC_KEY_A)
        self._build_old_database()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _build_old_database(self) -> None:
        self.legacy_digest = hashlib.sha256(
            f"sla-1\nevt-1\n1500\n10\n{self.machine}".encode()
        ).hexdigest()
        self.legacy_fields = {
            "eventId": "evt-1",
            "timestamp": 1500,
            "latencyMs": 10,
            "digest": self.legacy_digest,
        }
        request_json = json.dumps(
            self.legacy_fields, sort_keys=True, separators=(",", ":")
        )
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO schema_metadata VALUES ('schema_version', '1')"
            )
            # 旧库已完成 commit_seq 迁移，但尚无签名列。
            connection.execute(
                "INSERT INTO schema_metadata"
                " VALUES ('telemetry_commit_seq_renumbered', '1')"
            )
            connection.execute(
                "CREATE TABLE machines (id TEXT PRIMARY KEY, public_key TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO machines VALUES (?, ?)", (self.machine, PUBLIC_KEY_A)
            )
            connection.execute(
                "CREATE TABLE slas (id TEXT PRIMARY KEY, template_id TEXT NOT NULL,"
                " machine_id TEXT NOT NULL, consumer_id TEXT NOT NULL,"
                " capability_version INTEGER NOT NULL, price_micros INTEGER NOT NULL,"
                " max_latency_ms INTEGER NOT NULL, start_unix INTEGER NOT NULL,"
                " end_unix INTEGER NOT NULL, state TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO slas VALUES ('sla-1', 'tpl-1', ?, 'consumer-1', 1, 1000,"
                " 50, 1, 2, 'active')",
                (self.machine,),
            )
            connection.execute(
                "CREATE TABLE sla_telemetry_events ("
                "sla_id TEXT NOT NULL, event_id TEXT NOT NULL,"
                " timestamp_ms INTEGER NOT NULL, latency_ms INTEGER NOT NULL,"
                " digest TEXT NOT NULL, commit_seq INTEGER NOT NULL,"
                " PRIMARY KEY (sla_id, event_id))"
            )
            connection.execute(
                "INSERT INTO sla_telemetry_events"
                " VALUES ('sla-1', 'evt-1', 1500, 10, ?, 1)",
                (self.legacy_digest,),
            )
            connection.execute(
                "CREATE UNIQUE INDEX idx_sla_telemetry_commit_seq_unique"
                " ON sla_telemetry_events(commit_seq)"
            )
            connection.execute(
                "CREATE TABLE sla_telemetry_idempotency_records ("
                "key TEXT PRIMARY KEY, sla_id TEXT NOT NULL, request_json TEXT NOT NULL,"
                " status INTEGER NOT NULL, response_json TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO sla_telemetry_idempotency_records"
                " VALUES ('tel-1', 'sla-1', ?, 201, '{\"eventId\":\"evt-1\"}')",
                (request_json,),
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

    def post_json(self, path: str, payload: object, key: str) -> tuple[int, bytes]:
        request = Request(
            self.url(path),
            data=payload if isinstance(payload, bytes) else json.dumps(payload).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", key)
        add_sla_auth(request, self.server)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def test_signature_column_added_and_legacy_event_untouched(self) -> None:
        with urlopen(
            self.url("/v1/slas/sla-1/telemetry?from=0&to=2147483648000"), timeout=5
        ) as response:
            body = json.load(response)
        self.assertEqual([event["eventId"] for event in body["events"]], ["evt-1"])
        self.assertEqual(body["events"][0]["digest"], self.legacy_digest)
        self.assertEqual(body["summary"]["count"], 1)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(sla_telemetry_events)")
            }
            self.assertIn("signature", columns)
            row = connection.execute(
                "SELECT commit_seq, signature FROM sla_telemetry_events"
                " WHERE event_id = 'evt-1'"
            ).fetchone()
            # 旧事件不补造签名、不重排序号。
            self.assertEqual(row["commit_seq"], 1)
            self.assertIsNone(row["signature"])
            marker = connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = 'telemetry_signature_added'"
            ).fetchone()
            self.assertIsNotNone(marker)
        finally:
            connection.close()
        # 重启后迁移不重复执行，数据不变。
        self.restart()
        connection = sqlite3.connect(self.database_path)
        try:
            row = connection.execute(
                "SELECT commit_seq, signature FROM sla_telemetry_events"
                " WHERE event_id = 'evt-1'"
            ).fetchone()
            self.assertEqual((row[0], row[1]), (1, None))
        finally:
            connection.close()

    def test_legacy_record_replays_original_bytes(self) -> None:
        body = json.dumps(self.legacy_fields).encode()
        status, response_body = self.post_json(
            "/v1/slas/sla-1/telemetry", body, "tel-1"
        )
        self.assertEqual((status, response_body), (201, b'{"eventId":"evt-1"}'))
        self.restart()
        status, response_body = self.post_json(
            "/v1/slas/sla-1/telemetry", body, "tel-1"
        )
        self.assertEqual((status, response_body), (201, b'{"eventId":"evt-1"}'))

    def test_new_signed_event_and_evaluation_after_migration(self) -> None:
        digest = hashlib.sha256(
            f"sla-1\nevt-2\n1600\n20\n{self.machine}".encode()
        ).hexdigest()
        signature = telemetry_signature(
            PRODUCER_SEED, "sla-1", "evt-2", 1600, 20, digest, self.machine, 1
        )
        status, _ = self.post_json(
            "/v1/slas/sla-1/telemetry",
            {
                "eventId": "evt-2",
                "timestamp": 1600,
                "latencyMs": 20,
                "digest": digest,
                "keyVersion": 1,
                "signature": signature,
            },
            "tel-2",
        )
        self.assertEqual(status, 201)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT event_id, commit_seq, signature, key_version"
                " FROM sla_telemetry_events ORDER BY commit_seq ASC"
            ).fetchall()
            self.assertEqual(
                [(row["event_id"], row["commit_seq"]) for row in rows],
                [("evt-1", 1), ("evt-2", 2)],
            )
            self.assertIsNone(rows[0]["signature"])
            self.assertIsNone(rows[0]["key_version"])
            self.assertEqual(rows[1]["signature"], signature)
            self.assertEqual(rows[1]["key_version"], 1)
        finally:
            connection.close()
        # 无签名旧事件与签名新事件一起参与评估。
        status, body = self.post_json(
            "/v1/slas/sla-1/evaluations", {"from": 1000, "to": 2000}, "eval-1"
        )
        self.assertEqual(status, 201)
        evaluation = json.loads(body)
        self.assertEqual(evaluation["count"], 2)
        self.assertEqual(evaluation["latencySum"], 30)


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
        add_sla_auth(request, self.server)
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
            add_sla_auth(request, self.server)
            with urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)

    def add_event(self, index: int, timestamp: int, latency_ms: int) -> None:
        event_id = f"evt-{index:03d}"
        digest = hashlib.sha256(
            f"sla-1\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine_id}".encode()
        ).hexdigest()
        body = json.dumps(
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    PRODUCER_SEED, "sla-1", event_id, timestamp, latency_ms, digest,
                    self.machine_id,
                ),
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
        add_sla_auth(request, self.server)
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
        add_sla_auth(request, self.server)
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
        digest = hashlib.sha256(
            f"{sla_id}\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine_id}".encode()
        ).hexdigest()
        status, _ = self.post_json(
            f"/v1/slas/{sla_id}/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    PRODUCER_SEED, sla_id, event_id, timestamp, latency_ms, digest,
                    self.machine_id,
                ),
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
            add_sla_auth(request, self.server)
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
        digest = hashlib.sha256(
            f"sla-new\nevt-1\n{timestamp}\n10\n{machine}".encode()
        ).hexdigest()
        status, _ = post(
            "/v1/slas/sla-new/telemetry",
            {
                "eventId": "evt-1",
                "timestamp": timestamp,
                "latencyMs": 10,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    PRODUCER_SEED, "sla-new", "evt-1", timestamp, 10, digest, machine,
                ),
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
        add_sla_auth(request, self.server)
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
        digest = hashlib.sha256(
            f"{sla_id}\n{event_id}\n{timestamp}\n10\n{self.machine_id}".encode()
        ).hexdigest()
        status, _ = self.post_json(
            f"/v1/slas/{sla_id}/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": 10,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    PRODUCER_SEED, sla_id, event_id, timestamp, 10, digest,
                    self.machine_id,
                ),
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


class DisputeEvidenceTests(unittest.TestCase):
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
        add_sla_auth(request, self.server)
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
        status, _ = self.post_json(
            "/v1/slas",
            {
                "id": "sla-1",
                "templateId": "tpl-1",
                "consumerId": self.consumer_id,
                "start": self.start,
                "end": self.end,
            },
            "sla-create-1",
        )
        self.assertEqual(status, 201)
        for index, (party, actor) in enumerate(
            (("producer", self.machine_id), ("consumer", self.consumer_id))
        ):
            status, _ = self.post_json(
                "/v1/slas/sla-1/confirmations",
                {"party": party, "actorId": actor},
                f"conf-1-{index}",
            )
            self.assertEqual(status, 200)
        event_id = "evt-1"
        timestamp = self.start * 1000 + 1
        digest = hashlib.sha256(
            f"sla-1\n{event_id}\n{timestamp}\n10\n{self.machine_id}".encode()
        ).hexdigest()
        status, _ = self.post_json(
            "/v1/slas/sla-1/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": 10,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    PRODUCER_SEED, "sla-1", event_id, timestamp, 10, digest,
                    self.machine_id,
                ),
            },
            "tel-1",
        )
        self.assertEqual(status, 201)
        status, body = self.post_json(
            "/v1/slas/sla-1/evaluations",
            {"from": self.start * 1000, "to": self.end * 1000},
            "eval-1",
        )
        self.assertEqual(status, 201)
        evaluation_seq = json.loads(body)["evaluationSeq"]
        status, _ = self.post_json(
            f"/v1/funds/{self.consumer_id}",
            {"amountMicros": 100000, "reference": "ref-fund-1"},
            "fund-1",
        )
        self.assertEqual(status, 201)
        status, body = self.post_json(
            "/v1/settlements",
            {"slaId": "sla-1", "evaluationSeq": evaluation_seq},
            "settle-1",
        )
        self.assertEqual(status, 201)
        self.settlement_seq = json.loads(body)["settlementSeq"]
        status, _ = self.post_json(
            "/v1/disputes",
            {
                "id": "dispute-1",
                "settlementSeq": self.settlement_seq,
                "claimantId": self.consumer_id,
            },
            "dispute-1",
        )
        self.assertEqual(status, 201)

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
        add_sla_auth(request, self.server)
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

    def evidence_body(self, **overrides: object) -> dict:
        body: dict[str, object] = {
            "evidenceId": "ev-1",
            "actorId": self.consumer_id,
            "observedAt": self.start * 1000,
            "digest": "ab" * 32,
        }
        body.update(overrides)
        return body

    def post_evidence(
        self,
        dispute_id: str = "dispute-1",
        payload: object | None = None,
        key: str | None = "evidence-1",
    ) -> tuple[int, bytes]:
        return self.post_json(
            f"/v1/disputes/{dispute_id}/evidence",
            payload if payload is not None else self.evidence_body(),
            key,
        )

    def test_payer_submits_evidence_created(self) -> None:
        status, body = self.post_evidence()
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(list(payload), ["evidenceSeq"])
        self.assertEqual(payload, {"evidenceSeq": 1})
        self.assertEqual(body, b'{"evidenceSeq":1}')

    def test_payee_may_submit_evidence(self) -> None:
        status, body = self.post_evidence(
            payload=self.evidence_body(evidenceId="ev-2", actorId=self.machine_id),
            key="evidence-2",
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"evidenceSeq": 1})

    def test_evidence_replay_same_key_returns_first_bytes(self) -> None:
        status, first = self.post_evidence()
        self.assertEqual(status, 201)
        status, replay = self.post_evidence()
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)

    def test_evidence_replay_survives_restart(self) -> None:
        status, first = self.post_evidence()
        self.assertEqual(status, 201)
        self.restart()
        status, replay = self.post_evidence()
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)
        status, payload = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["evidence"]), 1)
        self.assertEqual(payload["evidence"][0]["evidenceSeq"], 1)

    def test_same_key_different_body_or_path_conflicts(self) -> None:
        status, _ = self.post_evidence()
        self.assertEqual(status, 201)
        status, body = self.post_evidence(
            payload=self.evidence_body(digest="cd" * 32)
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        # 同键异路径同样冲突，即使目标争议不存在也先判幂等记录。
        status, body = self.post_evidence(dispute_id="dispute-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_missing_or_invalid_dispute_is_not_found(self) -> None:
        for dispute_id in ("missing", quote("BAD ID"), "x%2Fy"):
            status, body = self.post_evidence(dispute_id=dispute_id, key="ev-missing")
            self.assertEqual(status, 404, dispute_id)
            self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_actor_must_be_party(self) -> None:
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": PUBLIC_KEY_C}, "register-3"
        )
        self.assertEqual(status, 201)
        status, body = self.post_evidence(
            payload=self.evidence_body(actorId=machine_id(PUBLIC_KEY_C)),
            key="ev-stranger",
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})

    def test_resolved_dispute_rejects_evidence_but_allows_reads(self) -> None:
        status, _ = self.post_evidence()
        self.assertEqual(status, 201)
        status, _ = self.post_json(
            "/v1/disputes/dispute-1/resolution",
            {"decision": "release"},
            "resolve-1",
        )
        self.assertEqual(status, 200)
        status, body = self.post_evidence(
            payload=self.evidence_body(evidenceId="ev-2"),
            key="evidence-2",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_resolved"})
        status, payload = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["evidence"]), 1)

    def test_duplicate_evidence_id_or_digest_is_evidence_exists(self) -> None:
        status, _ = self.post_evidence()
        self.assertEqual(status, 201)
        status, body = self.post_evidence(
            payload=self.evidence_body(digest="cd" * 32), key="evidence-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "evidence_exists"})
        status, body = self.post_evidence(
            payload=self.evidence_body(evidenceId="ev-2"), key="evidence-3"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "evidence_exists"})
        # 失败不推进序号：下一条成功证据序号为 2。
        status, body = self.post_evidence(
            payload=self.evidence_body(
                evidenceId="ev-2", digest="cd" * 32, actorId=self.machine_id
            ),
            key="evidence-4",
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"evidenceSeq": 2})

    def create_second_dispute(self) -> None:
        # dispute-1 已冻结机器（sla-1 charged 收款方）1000，先入金再做赔付结算。
        status, _ = self.post_json(
            f"/v1/funds/{self.machine_id}",
            {"amountMicros": 1000, "reference": "ref-fund-2"},
            "fund-2",
        )
        self.assertEqual(status, 201)
        status, _ = self.post_json(
            "/v1/slas",
            {
                "id": "sla-2",
                "templateId": "tpl-1",
                "consumerId": self.consumer_id,
                "start": self.start,
                "end": self.end,
            },
            "sla-create-2",
        )
        self.assertEqual(status, 201)
        for index, (party, actor) in enumerate(
            (("producer", self.machine_id), ("consumer", self.consumer_id))
        ):
            status, _ = self.post_json(
                "/v1/slas/sla-2/confirmations",
                {"party": party, "actorId": actor},
                f"conf-2-{index}",
            )
            self.assertEqual(status, 200)
        event_id = "evt-2"
        timestamp = self.start * 1000 + 2
        digest = hashlib.sha256(
            f"sla-2\n{event_id}\n{timestamp}\n100\n{self.machine_id}".encode()
        ).hexdigest()
        status, _ = self.post_json(
            "/v1/slas/sla-2/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": 100,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    PRODUCER_SEED, "sla-2", event_id, timestamp, 100, digest,
                    self.machine_id,
                ),
            },
            "tel-2",
        )
        self.assertEqual(status, 201)
        status, body = self.post_json(
            "/v1/slas/sla-2/evaluations",
            {"from": self.start * 1000, "to": self.end * 1000},
            "eval-2",
        )
        self.assertEqual(status, 201)
        evaluation_seq = json.loads(body)["evaluationSeq"]
        status, body = self.post_json(
            "/v1/settlements",
            {"slaId": "sla-2", "evaluationSeq": evaluation_seq},
            "settle-2",
        )
        self.assertEqual(status, 201)
        second_settlement = json.loads(body)["settlementSeq"]
        status, _ = self.post_json(
            "/v1/disputes",
            {
                "id": "dispute-2",
                "settlementSeq": second_settlement,
                "claimantId": self.machine_id,
            },
            "dispute-2",
        )
        self.assertEqual(status, 201)

    def test_digest_may_repeat_across_distinct_disputes(self) -> None:
        status, _ = self.post_evidence()
        self.assertEqual(status, 201)
        self.create_second_dispute()
        # 不同争议可复用 evidenceId 与 digest，序号全库递增。
        status, body = self.post_evidence(dispute_id="dispute-2", key="evidence-2")
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"evidenceSeq": 2})
        # 各争议分页只含本争议证据。
        status, payload = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual([item["evidenceSeq"] for item in payload["evidence"]], [1])
        status, payload = self.get_json("/v1/disputes/dispute-2/evidence")
        self.assertEqual([item["evidenceSeq"] for item in payload["evidence"]], [2])

    def test_evidence_invalid_requests(self) -> None:
        valid = self.evidence_body()
        cases = [
            b"",
            b"{not json",
            json.dumps({}).encode(),
            json.dumps({k: v for k, v in valid.items() if k != "digest"}).encode(),
            json.dumps({**valid, "extra": 1}).encode(),
            json.dumps({**valid, "evidenceId": "BAD ID"}).encode(),
            json.dumps({**valid, "evidenceId": ""}).encode(),
            json.dumps({**valid, "actorId": "zz"}).encode(),
            json.dumps({**valid, "actorId": valid["actorId"].upper()}).encode(),
            json.dumps({**valid, "observedAt": -1}).encode(),
            json.dumps({**valid, "observedAt": 2147483648000}).encode(),
            json.dumps({**valid, "observedAt": True}).encode(),
            json.dumps({**valid, "observedAt": "1"}).encode(),
            json.dumps({**valid, "digest": "zz" * 32}).encode(),
            json.dumps({**valid, "digest": "ab" * 32 + "c"}).encode(),
            json.dumps({**valid, "digest": "AB" * 32}).encode(),
        ]
        for index, body in enumerate(cases):
            status, response = self.post_evidence(payload=body, key=f"bad-{index}")
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response), {"error": "invalid_request"})
        status, response = self.post_evidence(key=None)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(response), {"error": "invalid_request"})
        status, response = self.post_json(
            "/v1/disputes/dispute-1/evidence?foo=bar",
            valid,
            "bad-query",
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(response), {"error": "invalid_request"})

    def test_concurrent_same_evidence_id_succeeds_once(self) -> None:
        results: list[int] = []
        lock = threading.Lock()

        def submit(index: int) -> None:
            status, _ = self.post_evidence(key=f"race-{index}")
            with lock:
                results.append(status)

        threads = [threading.Thread(target=submit, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(sorted(results), [201] + [409] * 7)
        status, payload = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["evidence"]), 1)
        self.assertEqual(payload["evidence"][0]["evidenceSeq"], 1)

    def test_concurrent_same_key_replays_first_status(self) -> None:
        results: list[int] = []
        body = json.dumps(self.evidence_body()).encode()
        lock = threading.Lock()

        def submit() -> None:
            status, _ = self.post_json(
                "/v1/disputes/dispute-1/evidence", body, "same-key"
            )
            with lock:
                results.append(status)

        threads = [threading.Thread(target=submit) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(results, [201] * 6)
        status, payload = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual(len(payload["evidence"]), 1)

    def test_get_evidence_empty_page_for_open_dispute(self) -> None:
        status, payload = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["evidence", "nextCursor"])
        self.assertEqual(payload["evidence"], [])
        self.assertIsNone(payload["nextCursor"])

    def test_get_evidence_lists_records_in_seq_order(self) -> None:
        bodies = [
            self.evidence_body(
                evidenceId="ev-a",
                actorId=self.consumer_id,
                observedAt=1000,
                digest="aa" * 32,
            ),
            self.evidence_body(
                evidenceId="ev-b",
                actorId=self.machine_id,
                observedAt=2000,
                digest="bb" * 32,
            ),
        ]
        for index, body in enumerate(bodies):
            status, _ = self.post_evidence(payload=body, key=f"evidence-{index}")
            self.assertEqual(status, 201)
        status, payload = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual(status, 200)
        evidence = payload["evidence"]
        self.assertEqual(len(evidence), 2)
        self.assertEqual(
            [list(item) for item in evidence],
            [
                ["evidenceSeq", "evidenceId", "actorId", "observedAt", "digest"],
                ["evidenceSeq", "evidenceId", "actorId", "observedAt", "digest"],
            ],
        )
        self.assertEqual([item["evidenceSeq"] for item in evidence], [1, 2])
        self.assertEqual(evidence[0]["evidenceId"], "ev-a")
        self.assertEqual(evidence[0]["actorId"], self.consumer_id)
        self.assertEqual(evidence[0]["observedAt"], 1000)
        self.assertEqual(evidence[0]["digest"], "aa" * 32)
        self.assertEqual(evidence[1]["evidenceId"], "ev-b")
        self.assertEqual(evidence[1]["actorId"], self.machine_id)
        self.assertIsNone(payload["nextCursor"])

    def test_get_evidence_pagination_and_cursor(self) -> None:
        for index in range(3):
            status, _ = self.post_evidence(
                payload=self.evidence_body(
                    evidenceId=f"ev-{index}", digest=f"{index + 1:02x}" * 32
                ),
                key=f"evidence-{index}",
            )
            self.assertEqual(status, 201)
        status, first_page = self.get_json(
            "/v1/disputes/dispute-1/evidence?limit=2"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["evidenceSeq"] for item in first_page["evidence"]], [1, 2]
        )
        self.assertEqual(first_page["nextCursor"], "3:2")
        status, second_page = self.get_json(
            f"/v1/disputes/dispute-1/evidence?limit=2"
            f"&cursor={first_page['nextCursor']}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["evidenceSeq"] for item in second_page["evidence"]], [3]
        )
        self.assertIsNone(second_page["nextCursor"])

    def test_evidence_cursor_cut_isolates_later_appends(self) -> None:
        status, _ = self.post_evidence()
        self.assertEqual(status, 201)
        # 第二争议的证据推进全库最大序号；旧 cut=1 的续页不得看到新证据。
        self.create_second_dispute()
        self.assertEqual(
            self.post_evidence(dispute_id="dispute-2", key="evidence-2")[0], 201
        )
        status, continuation = self.get_json(
            "/v1/disputes/dispute-1/evidence?cursor=1:1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(continuation["evidence"], [])
        self.assertIsNone(continuation["nextCursor"])
        # 全新首页取新 cut，但 dispute-1 仍只含自己的证据。
        _, fresh = self.get_json("/v1/disputes/dispute-1/evidence")
        self.assertEqual(
            [item["evidenceSeq"] for item in fresh["evidence"]], [1]
        )

    def test_evidence_invalid_query_params(self) -> None:
        self.assertEqual(self.post_evidence()[0], 201)
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
                f"/v1/disputes/dispute-1/evidence?{query}"
            )
            self.assertEqual(status, 400, query)
            self.assertEqual(payload, {"error": "invalid_request"})
        # 参数错误先于争议查询。
        status, payload = self.get_json("/v1/disputes/missing/evidence?limit=0")
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_evidence_cut_ahead_or_missing_anchor(self) -> None:
        self.assertEqual(self.post_evidence()[0], 201)
        status, payload = self.get_json(
            "/v1/disputes/dispute-1/evidence?cursor=999:1"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        status, payload = self.get_json(
            "/v1/disputes/dispute-1/evidence?cursor=1:5"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_evidence_cross_dispute_anchor_is_invalid(self) -> None:
        self.assertEqual(self.post_evidence()[0], 201)
        self.create_second_dispute()
        status, _ = self.post_evidence(dispute_id="dispute-2", key="evidence-2")
        self.assertEqual(status, 201)
        # 序号 2 属于 dispute-2，cut=2 合法，但作为 dispute-1 的锚点无效。
        status, payload = self.get_json(
            "/v1/disputes/dispute-1/evidence?cursor=2:2"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        # 不存在争议先返回 404（争议查询先于锚点校验）。
        status, payload = self.get_json("/v1/disputes/missing/evidence?cursor=1:1")
        self.assertEqual(status, 404)
        self.assertEqual(payload, {"error": "not_found"})

    def test_get_evidence_unknown_or_invalid_dispute_is_not_found(self) -> None:
        for dispute_id in ("missing", quote("BAD ID")):
            status, payload = self.get_json(f"/v1/disputes/{dispute_id}/evidence")
            self.assertEqual(status, 404, dispute_id)
            self.assertEqual(payload, {"error": "not_found"})

    def test_evidence_sequences_continue_after_restart(self) -> None:
        status, _ = self.post_evidence()
        self.assertEqual(status, 201)
        self.restart()
        status, body = self.post_evidence(
            payload=self.evidence_body(evidenceId="ev-2", digest="cd" * 32),
            key="evidence-2",
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body), {"evidenceSeq": 2})


class EvidenceProofTests(unittest.TestCase):
    PRODUCER_SEED = b"\x01" * 32
    CONSUMER_SEED = b"\x02" * 32
    STRANGER_SEED = b"\x03" * 32

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        producer_public = _ed25519_public_key(self.PRODUCER_SEED).hex()
        consumer_public = _ed25519_public_key(self.CONSUMER_SEED).hex()
        self.producer_id = machine_id(producer_public)
        self.consumer_id = machine_id(consumer_public)
        for key, public_key in (("register-1", producer_public), ("register-2", consumer_public)):
            status, _ = self.post_json(
                "/v1/machines", {"publicKey": public_key}, key
            )
            self.assertEqual(status, 201)
        status, _ = self.post_json(
            f"/v1/machines/{self.producer_id}/capabilities",
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
                "machineId": self.producer_id,
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
        status, _ = self.post_json(
            "/v1/slas",
            {
                "id": "sla-1",
                "templateId": "tpl-1",
                "consumerId": self.consumer_id,
                "start": self.start,
                "end": self.end,
            },
            "sla-create-1",
        )
        self.assertEqual(status, 201)
        for index, (party, actor) in enumerate(
            (("producer", self.producer_id), ("consumer", self.consumer_id))
        ):
            status, _ = self.post_json(
                "/v1/slas/sla-1/confirmations",
                {"party": party, "actorId": actor},
                f"conf-{index}",
            )
            self.assertEqual(status, 200)
        timestamp = self.start * 1000 + 1
        digest = hashlib.sha256(
            f"sla-1\nevt-1\n{timestamp}\n10\n{self.producer_id}".encode()
        ).hexdigest()
        status, _ = self.post_json(
            "/v1/slas/sla-1/telemetry",
            {
                "eventId": "evt-1",
                "timestamp": timestamp,
                "latencyMs": 10,
                "digest": digest,
                "keyVersion": 1,
                "signature": telemetry_signature(
                    self.PRODUCER_SEED, "sla-1", "evt-1", timestamp, 10, digest,
                    self.producer_id,
                ),
            },
            "tel-1",
        )
        self.assertEqual(status, 201)
        status, body = self.post_json(
            "/v1/slas/sla-1/evaluations",
            {"from": self.start * 1000, "to": self.end * 1000},
            "eval-1",
        )
        self.assertEqual(status, 201)
        evaluation_seq = json.loads(body)["evaluationSeq"]
        status, _ = self.post_json(
            f"/v1/funds/{self.consumer_id}",
            {"amountMicros": 100000, "reference": "ref-fund-1"},
            "fund-1",
        )
        self.assertEqual(status, 201)
        status, body = self.post_json(
            "/v1/settlements",
            {"slaId": "sla-1", "evaluationSeq": evaluation_seq},
            "settle-1",
        )
        self.assertEqual(status, 201)
        settlement_seq = json.loads(body)["settlementSeq"]
        status, _ = self.post_json(
            "/v1/disputes",
            {
                "id": "dispute-1",
                "settlementSeq": settlement_seq,
                "claimantId": self.consumer_id,
            },
            "dispute-1",
        )
        self.assertEqual(status, 201)
        self.digest = "ab" * 32
        status, body = self.post_json(
            "/v1/disputes/dispute-1/evidence",
            {
                "evidenceId": "ev-1",
                "actorId": self.consumer_id,
                "observedAt": self.start * 1000,
                "digest": self.digest,
            },
            "evidence-1",
        )
        self.assertEqual(status, 201)
        self.evidence_seq = json.loads(body)["evidenceSeq"]

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
        add_sla_auth(request, self.server)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def get_json(self, path: str) -> tuple[int, object]:
        try:
            with urlopen(self.url(path), timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def proof_message(
        self,
        seed: bytes,
        *,
        evidence_seq: int | None = None,
        actor: str | None = None,
        dispute_id: str = "dispute-1",
        digest: str | None = None,
    ) -> bytes:
        evidence_seq = self.evidence_seq if evidence_seq is None else evidence_seq
        digest = self.digest if digest is None else digest
        actor = self.actor_for(seed) if actor is None else actor
        return f"proof-v1\n{dispute_id}\n{evidence_seq}\n{digest}\n{actor}".encode("utf-8")

    def actor_for(self, seed: bytes) -> str:
        return machine_id(_ed25519_public_key(seed).hex())

    def proof_body(
        self,
        seed: bytes,
        *,
        evidence_seq: int | None = None,
        actor: str | None = None,
        signature: str | None = None,
        digest: str | None = None,
    ) -> dict[str, object]:
        evidence_seq = self.evidence_seq if evidence_seq is None else evidence_seq
        actor = self.actor_for(seed) if actor is None else actor
        digest = self.digest if digest is None else digest
        if signature is None:
            signature = _ed25519_sign(
                seed,
                self.proof_message(
                    seed, evidence_seq=evidence_seq, actor=actor, digest=digest
                ),
            ).hex()
        return {
            "evidenceSeq": evidence_seq,
            "actorId": actor,
            "signature": signature,
        }

    def post_proof(
        self, payload: object | None = None, key: str = "proof-1"
    ) -> tuple[int, bytes]:
        if payload is None:
            payload = self.proof_body(self.CONSUMER_SEED)
        return self.post_json("/v1/evidence-proofs", payload, key)

    def add_evidence(self, evidence_id: str, digest: str, key: str) -> int:
        status, body = self.post_json(
            "/v1/disputes/dispute-1/evidence",
            {
                "evidenceId": evidence_id,
                "actorId": self.consumer_id,
                "observedAt": self.start * 1000,
                "digest": digest,
            },
            key,
        )
        self.assertEqual(status, 201, body)
        return json.loads(body)["evidenceSeq"]

    def test_proof_created_with_ordered_body(self) -> None:
        status, body = self.post_proof()
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(list(payload), ["proofSeq", "verified", "createdAt"])
        self.assertEqual(payload["proofSeq"], 1)
        self.assertIs(payload["verified"], True)
        self.assertIsInstance(payload["createdAt"], int)
        self.assertGreaterEqual(payload["createdAt"], 0)

    def test_each_party_proves_once_global_sequences(self) -> None:
        status, body = self.post_proof(key="proof-consumer")
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["proofSeq"], 1)
        status, body = self.post_proof(
            self.proof_body(self.PRODUCER_SEED), "proof-producer"
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["proofSeq"], 2)

    def test_replay_returns_first_bytes_and_survives_restart(self) -> None:
        status, first = self.post_proof()
        self.assertEqual(status, 201)
        status, replay = self.post_proof()
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)
        self.restart()
        status, replay = self.post_proof()
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)

    def test_invalid_requests_before_resource_lookup(self) -> None:
        valid = self.proof_body(self.CONSUMER_SEED, evidence_seq=999999)
        invalid_bodies = [
            {**valid, "evidenceSeq": 0},
            {**valid, "evidenceSeq": True},
            {**valid, "evidenceSeq": "1"},
            {**valid, "evidenceSeq": -1},
            {**valid, "actorId": "zz"},
            {**valid, "actorId": "a" * 63},
            {**valid, "signature": "0" * 127},
            {**valid, "signature": "0" * 129},
            {**valid, "signature": "A" * 128},
            {"evidenceSeq": 999999, "actorId": self.consumer_id},
            {**valid, "extra": 1},
        ]
        for index, invalid in enumerate(invalid_bodies):
            status, body = self.post_proof(invalid, f"bad-{index}")
            self.assertEqual(status, 400, invalid)
            self.assertEqual(json.loads(body), {"error": "invalid_request"})
        # 缺少幂等头、重复键、携带查询参数都在资源查询前判为 400。
        status, _ = self.post_json("/v1/evidence-proofs", valid, None)
        self.assertEqual(status, 400)
        status, _ = self.post_json(
            "/v1/evidence-proofs?limit=1", valid, "query-param"
        )
        self.assertEqual(status, 400)
        status, _ = self.post_json(
            "/v1/evidence-proofs",
            b'{"evidenceSeq":999999,"actorId":"'
            + self.consumer_id.encode()
            + b'","signature":"'
            + b"0" * 128
            + b'","signature":"'
            + b"1" * 128
            + b'"}',
            "duplicate-key",
        )
        self.assertEqual(status, 400)

    def test_same_key_different_request_conflicts_even_when_evidence_missing(
        self,
    ) -> None:
        status, first = self.post_proof()
        self.assertEqual(status, 201)
        # 幂等冲突先于资源查询：换不存在的证据仍为 conflict。
        status, body = self.post_proof(
            self.proof_body(self.CONSUMER_SEED, evidence_seq=999999), "proof-1"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        status, body = self.post_proof(
            self.proof_body(self.CONSUMER_SEED, signature="11" * 64), "proof-1"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_missing_evidence_is_not_found(self) -> None:
        status, body = self.post_proof(
            self.proof_body(self.CONSUMER_SEED, evidence_seq=999999), "missing"
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_signer_must_be_payer_or_payee(self) -> None:
        stranger_public = _ed25519_public_key(self.STRANGER_SEED).hex()
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": stranger_public}, "register-3"
        )
        self.assertEqual(status, 201)
        status, body = self.post_proof(
            self.proof_body(self.STRANGER_SEED), "stranger"
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {"error": "forbidden"})

    def test_resolved_dispute_rejects_proofs_but_reads_remain(self) -> None:
        status, _ = self.post_proof()
        self.assertEqual(status, 201)
        status, _ = self.post_json(
            "/v1/disputes/dispute-1/resolution",
            {"decision": "release"},
            "resolve-1",
        )
        self.assertEqual(status, 200)
        status, body = self.post_proof(key="after-resolve")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_resolved"})
        status, payload = self.get_json(f"/v1/evidence/{self.evidence_seq}/proofs")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["proofs"]), 1)

    def test_duplicate_signer_is_proof_exists_after_signature_check(self) -> None:
        status, _ = self.post_proof()
        self.assertEqual(status, 201)
        # 异键、同一证据同一签名者：有效签名到达唯一性判定后返回 proof_exists。
        status, body = self.post_proof(
            self.proof_body(self.CONSUMER_SEED),
            "proof-duplicate",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "proof_exists"})
        # 已存在证明时，垃圾签名仍先在验签阶段失败。
        status, body = self.post_proof(
            self.proof_body(self.CONSUMER_SEED, signature="22" * 64),
            "proof-duplicate-bad-sig",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})

    def test_invalid_signature_does_not_persist_or_advance_sequence(self) -> None:
        wrong_signature = _ed25519_sign(self.CONSUMER_SEED, b"different message").hex()
        status, body = self.post_proof(
            self.proof_body(self.CONSUMER_SEED, signature=wrong_signature),
            "bad-signature",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 失败不推进序号：下一条成功（另一证据）取得 proofSeq 1。
        second_evidence = self.add_evidence("ev-2", "cd" * 32, "evidence-2")
        status, body = self.post_proof(
            self.proof_body(
                self.CONSUMER_SEED, evidence_seq=second_evidence, digest="cd" * 32
            ),
            "proof-next",
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["proofSeq"], 1)

    def test_proofs_list_order_fields_and_empty_page(self) -> None:
        body = self.proof_body(self.CONSUMER_SEED)
        status, _ = self.post_proof(body, "proof-consumer")
        self.assertEqual(status, 201)
        status, _ = self.post_proof(
            self.proof_body(self.PRODUCER_SEED), "proof-producer"
        )
        self.assertEqual(status, 201)
        status, payload = self.get_json(f"/v1/evidence/{self.evidence_seq}/proofs")
        self.assertEqual(status, 200)
        self.assertEqual(list(payload), ["proofs", "nextCursor"])
        proofs = payload["proofs"]
        self.assertEqual([proof["proofSeq"] for proof in proofs], [1, 2])
        self.assertEqual(
            list(proofs[0]),
            ["proofSeq", "actorId", "signature", "verified", "createdAt"],
        )
        self.assertEqual(proofs[0]["actorId"], self.consumer_id)
        self.assertEqual(proofs[0]["signature"], body["signature"])
        self.assertIs(proofs[0]["verified"], True)
        self.assertIsNone(payload["nextCursor"])
        second_evidence = self.add_evidence("ev-2", "cd" * 32, "evidence-2")
        status, payload = self.get_json(f"/v1/evidence/{second_evidence}/proofs")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"proofs": [], "nextCursor": None})

    def test_proofs_pagination_uses_global_cut_snapshot(self) -> None:
        status, _ = self.post_proof(key="proof-consumer")
        self.assertEqual(status, 201)
        status, _ = self.post_proof(
            self.proof_body(self.PRODUCER_SEED), "proof-producer"
        )
        self.assertEqual(status, 201)
        # 第三条证明落在另一证据上，使全库最大 proofSeq 为 3。
        second_evidence = self.add_evidence("ev-2", "cd" * 32, "evidence-2")
        status, _ = self.post_proof(
            self.proof_body(
                self.CONSUMER_SEED, evidence_seq=second_evidence, digest="cd" * 32
            ),
            "proof-second-evidence",
        )
        self.assertEqual(status, 201)
        status, page_one = self.get_json(
            f"/v1/evidence/{self.evidence_seq}/proofs?limit=1"
        )
        self.assertEqual(status, 200)
        self.assertEqual([p["proofSeq"] for p in page_one["proofs"]], [1])
        # cut 为全库最大序号 3，而非该证据局部序号。
        self.assertEqual(page_one["nextCursor"], "3:1")
        status, page_two = self.get_json(
            f"/v1/evidence/{self.evidence_seq}/proofs?limit=1&cursor=3:1"
        )
        self.assertEqual(status, 200)
        self.assertEqual([p["proofSeq"] for p in page_two["proofs"]], [2])
        self.assertIsNone(page_two["nextCursor"])
        # 旧游标快照隔离：携带 cut=3 续页，随后新增证明不改变结果。
        third_evidence = self.add_evidence("ev-3", "ef" * 32, "evidence-3")
        status, _ = self.post_proof(
            self.proof_body(
                self.PRODUCER_SEED, evidence_seq=third_evidence, digest="ef" * 32
            ),
            "proof-third",
        )
        self.assertEqual(status, 201)
        status, replay = self.get_json(
            f"/v1/evidence/{self.evidence_seq}/proofs?limit=1&cursor=3:1"
        )
        self.assertEqual(status, 200)
        self.assertEqual(replay, page_two)

    def test_proofs_pagination_stable_after_restart(self) -> None:
        status, _ = self.post_proof(key="proof-consumer")
        self.assertEqual(status, 201)
        status, page_before = self.get_json(
            f"/v1/evidence/{self.evidence_seq}/proofs"
        )
        self.assertEqual(status, 200)
        self.restart()
        status, page_after = self.get_json(
            f"/v1/evidence/{self.evidence_seq}/proofs"
        )
        self.assertEqual(status, 200)
        self.assertEqual(page_after, page_before)

    def test_proofs_invalid_or_missing_evidence_is_not_found(self) -> None:
        for path in (
            "/v1/evidence/0/proofs",
            "/v1/evidence/01/proofs",
            "/v1/evidence/abc/proofs",
            "/v1/evidence/9999/proofs",
        ):
            status, payload = self.get_json(path)
            self.assertEqual(status, 404, path)
            self.assertEqual(payload, {"error": "not_found"})

    def test_proofs_bad_query_params_are_400_before_evidence_lookup(self) -> None:
        for path in (
            "/v1/evidence/0/proofs?limit=0",
            "/v1/evidence/9999/proofs?limit=101",
            "/v1/evidence/1/proofs?unknown=1",
            "/v1/evidence/1/proofs?limit=1&limit=2",
            "/v1/evidence/1/proofs?cursor=1",
        ):
            status, payload = self.get_json(path)
            self.assertEqual(status, 400, path)
            self.assertEqual(payload, {"error": "invalid_request"})

    def test_proofs_cut_ahead_or_foreign_anchor_is_400(self) -> None:
        status, _ = self.post_proof()
        self.assertEqual(status, 201)
        second_evidence = self.add_evidence("ev-2", "cd" * 32, "evidence-2")
        # cut 超前于当前全库最大序号。
        status, payload = self.get_json("/v1/evidence/1/proofs?cursor=999:0")
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        # 锚点序号存在但属于其他证据。
        status, _ = self.post_proof(
            self.proof_body(
                self.CONSUMER_SEED, evidence_seq=second_evidence, digest="cd" * 32
            ),
            "proof-other",
        )
        self.assertEqual(status, 201)
        other_seq = 2
        status, payload = self.get_json(
            f"/v1/evidence/1/proofs?cursor={other_seq}:{other_seq}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})
        # 锚点不大于 cut 但在该证据内不存在。
        status, payload = self.get_json("/v1/evidence/1/proofs?cursor=2:2")
        self.assertEqual(status, 400)
        self.assertEqual(payload, {"error": "invalid_request"})

    def test_concurrent_same_signer_single_winner(self) -> None:
        def submit(index: int) -> tuple[int, bytes]:
            return self.post_proof(
                self.proof_body(self.CONSUMER_SEED), f"race-{index}"
            )

        with concurrent.futures.ThreadPoolExecutor(8) as executor:
            results = list(executor.map(submit, range(16)))
        created = [result for result in results if result[0] == 201]
        self.assertEqual(len(created), 1, results)
        self.assertTrue(
            all(
                result[0] == 409
                and json.loads(result[1]) == {"error": "proof_exists"}
                for result in results
                if result[0] != 201
            ),
            results,
        )

    def test_concurrent_same_key_all_replay_first_response(self) -> None:
        body = self.proof_body(self.CONSUMER_SEED)

        def submit(_: int) -> tuple[int, bytes]:
            return self.post_proof(body, "same-key")

        with concurrent.futures.ThreadPoolExecutor(8) as executor:
            results = list(executor.map(submit, range(16)))
        self.assertTrue(all(status == 201 for status, _ in results), results)
        self.assertEqual(len({payload for _, payload in results}), 1, results)


class KeyLifecycleTests(unittest.TestCase):
    PRODUCER_SEED = b"\x01" * 32
    NEW_SEED = b"\x02" * 32
    THIRD_SEED = b"\x03" * 32

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.producer_public = _ed25519_public_key(self.PRODUCER_SEED).hex()
        self.new_public = _ed25519_public_key(self.NEW_SEED).hex()
        self.third_public = _ed25519_public_key(self.THIRD_SEED).hex()
        self.machine_id = machine_id(self.producer_public)
        self.consumer_id = machine_id(PUBLIC_KEY_B)
        for key, public_key in (
            ("register-1", self.producer_public),
            ("register-2", PUBLIC_KEY_B),
        ):
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

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def post_json(self, path: str, payload: object, key: str | None) -> tuple[int, bytes]:
        request = Request(
            self.url(path),
            data=payload if isinstance(payload, bytes) else json.dumps(payload).encode(),
            method="POST",
        )
        if key is not None:
            request.add_header("Idempotency-Key", key)
        add_sla_auth(request, self.server)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def rotate_body(
        self,
        expected_version: int = 1,
        new_public: str | None = None,
        current_seed: bytes | None = None,
        new_seed: bytes | None = None,
    ) -> dict[str, object]:
        if new_public is None:
            new_public = self.new_public
        if current_seed is None:
            current_seed = self.PRODUCER_SEED
        if new_seed is None:
            new_seed = self.NEW_SEED
        current_signature, new_signature = key_rotation_signatures(
            current_seed, new_seed, self.machine_id, expected_version, new_public
        )
        return {
            "expectedVersion": expected_version,
            "publicKey": new_public,
            "currentSignature": current_signature,
            "newSignature": new_signature,
        }

    def rotate(
        self,
        body: object | None = None,
        key: str = "rotate-1",
        machine: str | None = None,
    ) -> tuple[int, bytes]:
        if body is None:
            body = self.rotate_body()
        if machine is None:
            machine = self.machine_id
        return self.post_json(f"/v1/machines/{machine}/keys", body, key)

    def revoke(
        self,
        version: int,
        seed: bytes | None = None,
        machine: str | None = None,
        key: str = "revoke-1",
    ) -> tuple[int, bytes]:
        if seed is None:
            seed = self.NEW_SEED
        if machine is None:
            machine = self.machine_id
        body = {"signature": key_revocation_signature(seed, machine, version)}
        return self.post_json(
            f"/v1/machines/{machine}/keys/{version}/revocation", body, key
        )

    def key_rows(self) -> list[sqlite3.Row]:
        connection = sqlite3.connect(self.server.database_path)
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute(
                "SELECT version, public_key, activated_at_ms, revoked"
                " FROM machine_keys WHERE machine_id = ? ORDER BY version",
                (self.machine_id,),
            ).fetchall()
        finally:
            connection.close()

    def test_registration_creates_version_one_history(self) -> None:
        rows = self.key_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            (rows[0]["version"], rows[0]["public_key"], rows[0]["activated_at_ms"]),
            (1, self.producer_public, 0),
        )
        self.assertEqual(rows[0]["revoked"], 0)

    def test_rotation_created_with_ordered_body(self) -> None:
        status, body = self.rotate()
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(list(payload), ["version", "publicKey", "activatedAt", "revoked"])
        self.assertEqual(payload["version"], 2)
        self.assertEqual(payload["publicKey"], self.new_public)
        self.assertIsInstance(payload["activatedAt"], int)
        self.assertGreaterEqual(payload["activatedAt"], 0)
        self.assertIs(payload["revoked"], False)
        rows = self.key_rows()
        self.assertEqual([row["version"] for row in rows], [1, 2])
        self.assertEqual(rows[1]["public_key"], self.new_public)
        self.assertEqual(rows[1]["revoked"], 0)

    def test_rotation_replay_returns_first_bytes_and_survives_restart(self) -> None:
        status, first = self.rotate()
        self.assertEqual(status, 201)
        for _ in range(2):
            again_status, again = self.rotate()
            self.assertEqual((again_status, again), (status, first))
        self.restart()
        again_status, again = self.rotate()
        self.assertEqual((again_status, again), (status, first))
        self.assertEqual(len(self.key_rows()), 2)

    def test_stale_expected_version_conflicts(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        status, body = self.rotate(self.rotate_body(expected_version=1), key="rotate-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        status, body = self.rotate(self.rotate_body(expected_version=3), key="rotate-3")
        self.assertEqual(status, 409)

    def test_reused_historical_public_key_is_key_exists(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        # 复用版本一公钥（即使两签名都有效）：key_exists。
        current_signature, new_signature = key_rotation_signatures(
            self.NEW_SEED,
            self.PRODUCER_SEED,
            self.machine_id,
            2,
            self.producer_public,
        )
        body = {
            "expectedVersion": 2,
            "publicKey": self.producer_public,
            "currentSignature": current_signature,
            "newSignature": new_signature,
        }
        status, response = self.post_json(
            f"/v1/machines/{self.machine_id}/keys", body, "rotate-2"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response), {"error": "key_exists"})
        self.assertEqual(len(self.key_rows()), 2)

    def test_bad_current_or_new_signature_is_invalid_signature(self) -> None:
        good = self.rotate_body()
        bad_current = dict(good, currentSignature="0" * 128)
        status, body = self.rotate(bad_current, key="rotate-bad-current")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        bad_new = dict(good, newSignature="0" * 128)
        status, body = self.rotate(bad_new, key="rotate-bad-new")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 当前密钥以新私钥签署（公钥不匹配）：验签失败。
        wrong = self.rotate_body(current_seed=self.NEW_SEED)
        status, body = self.rotate(wrong, key="rotate-wrong-current")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 失败不留任何写入。
        self.assertEqual([row["version"] for row in self.key_rows()], [1])

    def test_rotation_machine_missing_is_404(self) -> None:
        missing = "ab" * 32
        current_signature, new_signature = key_rotation_signatures(
            self.PRODUCER_SEED, self.NEW_SEED, missing, 1, self.new_public
        )
        body = {
            "expectedVersion": 1,
            "publicKey": self.new_public,
            "currentSignature": current_signature,
            "newSignature": new_signature,
        }
        status, response = self.post_json(
            f"/v1/machines/{missing}/keys", body, "rotate-missing"
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(response), {"error": "not_found"})

    def test_rotation_same_key_different_machine_or_body_conflicts(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        # 同键异机器（即使机器未登记）：冲突先于机器查询。
        missing = "ab" * 32
        status, body = self.rotate(self.rotate_body(), machine=missing)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        # 同键异体。
        other = self.rotate_body(expected_version=2)
        status, body = self.rotate(other)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_rotation_invalid_requests(self) -> None:
        good = self.rotate_body()
        cases = [
            (json.dumps(dict(good, extra=1)).encode(), "rotate-x1"),
            (json.dumps({k: v for k, v in good.items() if k != "expectedVersion"}).encode(), "rotate-x2"),
            (json.dumps(dict(good, expectedVersion=0)).encode(), "rotate-x3"),
            (json.dumps(dict(good, expectedVersion=2147483647)).encode(), "rotate-x4"),
            (json.dumps(dict(good, expectedVersion=True)).encode(), "rotate-x5"),
            (json.dumps(dict(good, expectedVersion="1")).encode(), "rotate-x6"),
            (json.dumps(dict(good, publicKey="A" * 64)).encode(), "rotate-x7"),
            (json.dumps(dict(good, currentSignature="0" * 127)).encode(), "rotate-x8"),
            (json.dumps(dict(good, newSignature="g" * 128)).encode(), "rotate-x9"),
            (b"{}", "rotate-x10"),
            (b"not json", "rotate-x11"),
        ]
        for body, key in cases:
            status, response = self.post_json(
                f"/v1/machines/{self.machine_id}/keys", body, key
            )
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response), {"error": "invalid_request"})
        # 缺少/非法幂等头。
        for key in (None, "", "bad key", "x" * 65):
            status, response = self.post_json(
                f"/v1/machines/{self.machine_id}/keys", good, key
            )
            self.assertEqual(status, 400, key)
        # 查询参数非法先于体校验。
        status, response = self.post_json(
            f"/v1/machines/{self.machine_id}/keys?x=1", good, "rotate-q"
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(response), {"error": "invalid_request"})

    def test_rotation_concurrent_distinct_keys_single_winner(self) -> None:
        def submit(index: int) -> int:
            status, _ = self.rotate(
                self.rotate_body(), key=f"rotate-race-{index}"
            )
            return status

        with concurrent.futures.ThreadPoolExecutor(8) as executor:
            results = list(executor.map(submit, range(8)))
        self.assertEqual(sorted(results), [201] + [409] * 7)
        self.assertEqual([row["version"] for row in self.key_rows()], [1, 2])

    def test_revocation_success_and_replay(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        status, body = self.revoke(1)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"version": 1, "revoked": True})
        self.assertEqual(self.key_rows()[0]["revoked"], 1)
        # 重复吊销（同键重放）返回首次字节；重启后亦然。
        self.assertEqual(self.revoke(1), (200, body))
        self.restart()
        self.assertEqual(self.revoke(1), (200, body))

    def test_revoke_current_version_conflicts(self) -> None:
        status, body = self.revoke(1, seed=self.PRODUCER_SEED)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        self.assertEqual(self.rotate()[0], 201)
        status, body = self.revoke(2)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        self.assertEqual([row["revoked"] for row in self.key_rows()], [0, 0])

    def test_revoke_already_revoked(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        self.assertEqual(self.revoke(1)[0], 200)
        status, body = self.revoke(1, key="revoke-again")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_revoked"})

    def test_revoke_invalid_signature(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        # 用已被轮换的旧密钥签署：验签失败。
        status, body = self.revoke(1, seed=self.PRODUCER_SEED, key="revoke-old")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        status, body = self.post_json(
            f"/v1/machines/{self.machine_id}/keys/1/revocation",
            {"signature": "0" * 128},
            "revoke-bad",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        self.assertEqual([row["revoked"] for row in self.key_rows()], [0, 0])

    def test_revocation_uses_latest_key_after_multiple_rotations(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        current, new = key_rotation_signatures(
            self.NEW_SEED, self.THIRD_SEED, self.machine_id, 2, self.third_public
        )
        status, _ = self.post_json(
            f"/v1/machines/{self.machine_id}/keys",
            {
                "expectedVersion": 2,
                "publicKey": self.third_public,
                "currentSignature": current,
                "newSignature": new,
            },
            "rotate-2",
        )
        self.assertEqual(status, 201)
        # 吊销版本一须由最新（版本三）密钥签署。
        status, body = self.revoke(1, seed=self.NEW_SEED, key="revoke-v2-signer")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        status, body = self.revoke(1, seed=self.THIRD_SEED, key="revoke-v3-signer")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"version": 1, "revoked": True})

    def test_revoke_missing_machine_or_version_is_404(self) -> None:
        # 版本一为当前最新版本，吊销返回 409/conflict，而非 404。
        status, _ = self.post_json(
            f"/v1/machines/{self.machine_id}/keys/1/revocation",
            {"signature": "0" * 128},
            "revoke-current",
        )
        self.assertEqual(status, 409)
        for version_text in ("0", "01", "abc"):
            body = {"signature": "0" * 128}
            status, response = self.post_json(
                f"/v1/machines/{self.machine_id}/keys/{version_text}/revocation",
                body,
                f"revoke-bad-version-{version_text}",
            )
            self.assertEqual(status, 404, version_text)
            self.assertEqual(json.loads(response), {"error": "not_found"})
        missing = "ab" * 32
        status, response = self.post_json(
            f"/v1/machines/{missing}/keys/1/revocation",
            {"signature": "0" * 128},
            "revoke-missing-machine",
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(response), {"error": "not_found"})

    def test_revocation_same_key_different_target_conflicts(self) -> None:
        self.assertEqual(self.rotate()[0], 201)
        self.assertEqual(self.revoke(1)[0], 200)
        # 同键异版本。
        status, body = self.post_json(
            f"/v1/machines/{self.machine_id}/keys/2/revocation",
            {"signature": key_revocation_signature(self.NEW_SEED, self.machine_id, 1)},
            "revoke-1",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_revocation_invalid_requests(self) -> None:
        # 体非法 / 查询参数 / 缺头均为 400。
        for body, key in (
            (b"{}", "r-bad-1"),
            (json.dumps({"signature": "0" * 127}).encode(), "r-bad-2"),
            (json.dumps({"signature": "Z" * 128}).encode(), "r-bad-3"),
            (json.dumps({"signature": 123}).encode(), "r-bad-4"),
            (json.dumps({"signature": "0" * 128, "extra": 1}).encode(), "r-bad-5"),
        ):
            status, response = self.post_json(
                f"/v1/machines/{self.machine_id}/keys/1/revocation", body, key
            )
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response), {"error": "invalid_request"})
        status, response = self.post_json(
            f"/v1/machines/{self.machine_id}/keys/1/revocation?x=1",
            {"signature": "0" * 128},
            "r-bad-query",
        )
        self.assertEqual(status, 400)
        status, _ = self.post_json(
            f"/v1/machines/{self.machine_id}/keys/1/revocation",
            {"signature": "0" * 128},
            None,
        )
        self.assertEqual(status, 400)

    def activate_sla(self) -> None:
        current = int(time.time())
        self.start = current - 3600
        self.end = current + 3600
        capability = {
            "expectedVersion": 0,
            "name": "pump-01",
            "protocol": "mqtt",
            "region": "cn",
            "unit": "call",
            "capacity": 10,
        }
        status, _ = self.post_json(
            f"/v1/machines/{self.machine_id}/capabilities", capability, "cap-1"
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
        status, _ = self.post_json(
            "/v1/slas",
            {
                "id": "sla-1",
                "templateId": "tpl-1",
                "consumerId": self.consumer_id,
                "start": self.start,
                "end": self.end,
            },
            "sla-1",
        )
        self.assertEqual(status, 201)
        for key, party, actor in (
            ("conf-p", "producer", self.machine_id),
            ("conf-c", "consumer", self.consumer_id),
        ):
            status, _ = self.post_json(
                "/v1/slas/sla-1/confirmations",
                {"party": party, "actorId": actor},
                key,
            )
            self.assertEqual(status, 200)

    def telemetry(
        self,
        seed: bytes,
        key_version: int,
        timestamp: int,
        event_id: str,
        idempotency_key: str,
    ) -> tuple[int, bytes]:
        digest = hashlib.sha256(
            f"sla-1\n{event_id}\n{timestamp}\n12\n{self.machine_id}".encode()
        ).hexdigest()
        signature = telemetry_signature(
            seed, "sla-1", event_id, timestamp, 12, digest,
            self.machine_id, key_version,
        )
        return self.post_json(
            "/v1/slas/sla-1/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": 12,
                "digest": digest,
                "keyVersion": key_version,
                "signature": signature,
            },
            idempotency_key,
        )

    def test_telemetry_key_version_windows_and_revocation(self) -> None:
        self.activate_sla()
        # 轮换前：版本一（零时激活）事件有效。
        now_ms = int(time.time() * 1000)
        status, body = self.telemetry(
            self.PRODUCER_SEED, 1, now_ms, "evt-before", "tel-before"
        )
        self.assertEqual((status, body), (201, b'{"eventId":"evt-before"}'))
        # 轮换：记录版本二激活时刻。
        status, rotated = self.rotate(key="rotate-for-telemetry")
        self.assertEqual(status, 201)
        activated_at = json.loads(rotated)["activatedAt"]
        # 旧版本事件在其激活区间（< activatedAt）内仍有效。
        status, body = self.telemetry(
            self.PRODUCER_SEED, 1, activated_at - 1, "evt-v1-old", "tel-v1-old"
        )
        self.assertEqual(status, 201, body)
        # 恰为下一版本激活时刻：旧版本窗外，签名虽有效仍 invalid_signature。
        status, body = self.telemetry(
            self.PRODUCER_SEED, 1, activated_at, "evt-v1-edge", "tel-v1-edge"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 新版本自激活时刻起生效（边界含下界）。
        status, body = self.telemetry(
            self.NEW_SEED, 2, activated_at, "evt-v2-edge", "tel-v2-edge"
        )
        self.assertEqual((status, body), (201, b'{"eventId":"evt-v2-edge"}'))
        # 旧密钥签新版本消息 / 新密钥签旧版本消息：验签失败。
        status, body = self.telemetry(
            self.PRODUCER_SEED, 2, activated_at + 5, "evt-mix-a", "tel-mix-a"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 未知密钥版本：invalid_signature。
        status, body = self.telemetry(
            self.NEW_SEED, 9, activated_at + 5, "evt-mix-b", "tel-mix-b"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 吊销版本一：窗外之外，窗内（历史时刻）事件同样被拒。
        self.assertEqual(self.revoke(1, key="revoke-v1")[0], 200)
        status, body = self.telemetry(
            self.PRODUCER_SEED, 1, activated_at - 1, "evt-v1-revoked", "tel-v1-rev"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 版本二不受影响。
        status, body = self.telemetry(
            self.NEW_SEED, 2, activated_at + 10, "evt-v2-ok", "tel-v2-ok"
        )
        self.assertEqual(status, 201)

    def test_telemetry_version_failure_leaves_no_trace_or_seq(self) -> None:
        self.activate_sla()
        status, body = self.rotate(key="rotate-for-telemetry")
        self.assertEqual(status, 201)
        activated_at = json.loads(body)["activatedAt"]
        # 失败（窗外）不占幂等键、不写事件、不推进 commit_seq。
        fail_status, _ = self.telemetry(
            self.PRODUCER_SEED, 1, activated_at, "evt-x", "tel-x"
        )
        self.assertEqual(fail_status, 409)
        status, body = self.telemetry(
            self.NEW_SEED, 2, activated_at, "evt-x", "tel-x"
        )
        self.assertEqual(status, 201)
        connection = sqlite3.connect(self.server.database_path)
        try:
            seq = connection.execute(
                "SELECT commit_seq FROM sla_telemetry_events"
                " WHERE sla_id = 'sla-1' AND event_id = 'evt-x'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(seq, 1)


class MachineKeysMigrationTests(unittest.TestCase):
    """密钥历史升级前的旧库：machines 已存在但无 machine_keys 历史。"""

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
                "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute("INSERT INTO schema_metadata VALUES ('schema_version', '1')")
            connection.execute(
                "CREATE TABLE machines (id TEXT PRIMARY KEY, public_key TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO machines VALUES (?, ?)",
                (machine_id(PUBLIC_KEY_A), PUBLIC_KEY_A),
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

    def post_json(self, path: str, payload: object, key: str) -> tuple[int, bytes]:
        request = Request(
            self.url(path),
            data=json.dumps(payload).encode(),
            method="POST",
        )
        request.add_header("Idempotency-Key", key)
        add_sla_auth(request, self.server)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def test_old_machines_backfilled_with_version_one(self) -> None:
        # 任意请求触发服务端连接并执行一次性迁移。
        with urlopen(self.url("/health"), timeout=5):
            pass
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT machine_id, version, public_key, activated_at_ms, revoked"
                " FROM machine_keys ORDER BY machine_id"
            ).fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(
                (
                    rows[0]["machine_id"],
                    rows[0]["version"],
                    rows[0]["public_key"],
                    rows[0]["activated_at_ms"],
                    rows[0]["revoked"],
                ),
                (machine_id(PUBLIC_KEY_A), 1, PUBLIC_KEY_A, 0, 0),
            )
            marker = connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = 'machine_keys_backfilled'"
            ).fetchone()
            self.assertIsNotNone(marker)
        finally:
            connection.close()
        # 重启不重复补写。
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        connection = sqlite3.connect(self.database_path)
        try:
            count = connection.execute("SELECT COUNT(*) FROM machine_keys").fetchone()[0]
            self.assertEqual(count, 1)
        finally:
            connection.close()

    def test_rotation_works_from_backfilled_history(self) -> None:
        new_seed = b"\x02" * 32
        new_public = _ed25519_public_key(new_seed).hex()
        machine = machine_id(PUBLIC_KEY_A)
        current_signature, new_signature = key_rotation_signatures(
            PRODUCER_SEED, new_seed, machine, 1, new_public
        )
        status, body = self.post_json(
            f"/v1/machines/{machine}/keys",
            {
                "expectedVersion": 1,
                "publicKey": new_public,
                "currentSignature": current_signature,
                "newSignature": new_signature,
            },
            "rotate-1",
        )
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)["version"], 2)

    def test_new_registration_after_migration_creates_version_one(self) -> None:
        new_public = _ed25519_public_key(b"\x07" * 32).hex()
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": new_public}, "register-new"
        )
        self.assertEqual(status, 201)
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT version, activated_at_ms, revoked FROM machine_keys"
                " WHERE machine_id = ?",
                (machine_id(new_public),),
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(
                (row["version"], row["activated_at_ms"], row["revoked"]), (1, 0, 0)
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
class SlaAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "sla.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.producer = machine_id(PUBLIC_KEY_A)
        self.consumer = machine_id(PUBLIC_KEY_B)
        for key, public_key in (
            ("reg-a", PUBLIC_KEY_A),
            ("reg-b", PUBLIC_KEY_B),
        ):
            self.assertEqual(self.post("/v1/machines", json.dumps(
                {"publicKey": public_key}).encode(), key, auth=None)[0], 201)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def post(
        self,
        path: str,
        body: bytes,
        key: str | None,
        *,
        seed: bytes | None = None,
        actor: str | None = None,
        key_version: int = 1,
        auth: str | bool | None = None,
        request_time_ms: int | None = None,
        nonce: str | None = None,
    ) -> tuple[int, bytes]:
        request = Request(self.url(path), data=body, method="POST")
        if key is not None:
            request.add_header("Idempotency-Key", key)
        if auth is None and seed is not None:
            auth = True
        if auth is True:
            if actor is None:
                raise ValueError("actor required")
            request.add_header(
                "SLA-Auth",
                make_sla_auth(
                    self.server, key, seed, actor, "POST", path, body,
                    key_version, request_time_ms=request_time_ms, nonce=nonce,
                ),
            )
        elif isinstance(auth, str):
            request.add_header("SLA-Auth", auth)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def cap_body(self, expected: int = 0, capacity: int = 10) -> bytes:
        return json.dumps({
            "expectedVersion": expected, "name": "pump-01", "protocol": "mqtt",
            "region": "cn", "unit": "call", "capacity": capacity,
        }).encode()

    @property
    def cap_path(self) -> str:
        return f"/v1/machines/{self.producer}/capabilities"

    def test_missing_duplicate_or_malformed_header_is_400_before_resource(self) -> None:
        body = self.cap_body()
        status, payload = self.post(self.cap_path, body, "k1", auth=None)
        self.assertEqual((status, json.loads(payload)), (400, {"error": "invalid_request"}))
        ghost = f"/v1/machines/{machine_id(PUBLIC_KEY_C)}/capabilities"
        status, payload = self.post(ghost, body, "k2", auth=None)
        self.assertEqual((status, json.loads(payload)), (400, {"error": "invalid_request"}))
        now = int(time.time() * 1000)
        for raw in (
            "x",
            "a;b;c;d",
            f"{self.producer};01;{now};nonce-0123456789ab;{'a' * 128}",
            f"{self.producer};1;01;nonce-0123456789ab;{'a' * 128}",
            f"{self.producer};1;{now};short;{'a' * 128}",
            f"{self.producer};1;{now};nonce-0123456789ab;{'A' * 128}",
            f"{'A' * 64};1;{now};nonce-0123456789ab;{'a' * 128}",
        ):
            status, response = self.post(self.cap_path, body, "k3", auth=raw)
            self.assertEqual((status, json.loads(response)),
                             (400, {"error": "invalid_request"}), raw)
        # 重复认证头同样 400（urllib 会同名去重，直接用 http.client 发两个头）。
        import http.client
        target = urlsplit(self.url(self.cap_path))
        connection = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
        connection.putrequest("POST", target.path)
        connection.putheader("Idempotency-Key", "k4")
        connection.putheader("Content-Length", str(len(body)))
        connection.putheader("SLA-Auth", "a")
        connection.putheader("SLA-Auth", "b")
        connection.endheaders()
        connection.send(body)
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(response.read()), {"error": "invalid_request"})
        connection.close()

    def test_resource_check_precedes_authentication(self) -> None:
        body = self.cap_body()
        status, payload = self.post(
            f"/v1/machines/{machine_id(PUBLIC_KEY_C)}/capabilities", body,
            "k5", seed=PUBLIC_KEY_SEED_C, actor=machine_id(PUBLIC_KEY_C),
        )
        self.assertEqual((status, json.loads(payload)), (404, {"error": "not_found"}))

    def test_declare_and_replay_preserves_first_response(self) -> None:
        body = self.cap_body()
        status, payload = self.post(
            self.cap_path, body, "cap", seed=PRODUCER_SEED,
            actor=self.producer, auth=True
        )
        self.assertEqual((status, payload), (201, b'{"version":1}'))
        status, payload = self.post(
            self.cap_path, body, "cap", seed=PRODUCER_SEED,
            actor=self.producer, auth=True
        )
        self.assertEqual((status, payload), (201, b'{"version":1}'))

    def test_machine_mismatch_is_403(self) -> None:
        body = self.cap_body()
        status, payload = self.post(
            self.cap_path, body, "k6", seed=PUBLIC_KEY_SEED_B, actor=self.consumer
        )
        self.assertEqual((status, json.loads(payload)), (403, {"error": "forbidden"}))

    def test_stale_request_time_is_401(self) -> None:
        for delta in (-400_000, 400_000):
            status, payload = self.post(
                self.cap_path, self.cap_body(), f"stale-{delta}",
                seed=PRODUCER_SEED, actor=self.producer,
                request_time_ms=int(time.time() * 1000) + delta,
            )
            self.assertEqual((status, json.loads(payload)),
                             (401, {"error": "stale_request"}), delta)

    def test_unknown_not_latest_and_revoked_key_are_401(self) -> None:
        body = self.cap_body()
        status, payload = self.post(
            self.cap_path, body, "ver-missing", seed=PRODUCER_SEED,
            actor=self.producer, key_version=9,
        )
        self.assertEqual((status, json.loads(payload)),
                         (401, {"error": "invalid_authentication"}))
        # 轮换到版本二：版本一不再是最新。
        new_seed = b"\x0a" * 32
        new_public = _ed25519_public_key(new_seed).hex()
        current_sig, new_sig = key_rotation_signatures(
            PRODUCER_SEED, new_seed, self.producer, 1, new_public
        )
        rotation = json.dumps({
            "expectedVersion": 1, "publicKey": new_public,
            "currentSignature": current_sig, "newSignature": new_sig,
        }).encode()
        status, _ = self.post(
            f"/v1/machines/{self.producer}/keys", rotation, "rotate-1", auth=None
        )
        self.assertEqual(status, 201)
        status, payload = self.post(
            self.cap_path, self.cap_body(1, 20), "ver-old",
            seed=PRODUCER_SEED, actor=self.producer, key_version=1,
        )
        self.assertEqual((status, json.loads(payload)),
                         (401, {"error": "invalid_authentication"}))
        # 再轮换到版本三后吊销版本二：已吊销版本签名拒绝。
        third_seed = b"\x0b" * 32
        third_public = _ed25519_public_key(third_seed).hex()
        c2, n2 = key_rotation_signatures(
            new_seed, third_seed, self.producer, 2, third_public
        )
        status, _ = self.post(
            f"/v1/machines/{self.producer}/keys",
            json.dumps({"expectedVersion": 2, "publicKey": third_public,
                        "currentSignature": c2, "newSignature": n2}).encode(),
            "rotate-2", auth=None,
        )
        self.assertEqual(status, 201)
        revoke = json.dumps({
            "signature": key_revocation_signature(third_seed, self.producer, 2)
        }).encode()
        status, _ = self.post(
            f"/v1/machines/{self.producer}/keys/2/revocation", revoke,
            "revoke-2", auth=None,
        )
        self.assertEqual(status, 200)
        status, payload = self.post(
            self.cap_path, self.cap_body(1, 20), "ver-revoked",
            seed=new_seed, actor=self.producer, key_version=2,
        )
        self.assertEqual((status, json.loads(payload)),
                         (401, {"error": "invalid_authentication"}))

    def test_body_digest_tampering_is_401(self) -> None:
        signed = self.cap_body(1, 30)
        tampered = self.cap_body(1, 31)
        status, payload = self._post_presigned_body(
            self.cap_path, signed, tampered, "digest-1"
        )
        self.assertEqual((status, json.loads(payload)),
                         (401, {"error": "invalid_authentication"}))

    def _post_presigned_body(
        self, path: str, signed_body: bytes, sent_body: bytes, key: str
    ) -> tuple[int, bytes]:
        header = make_sla_auth(
            self.server, key, PRODUCER_SEED, self.producer, "POST",
            path, signed_body, 1,
        )
        return self.post(path, sent_body, key, auth=header)

    def test_nonce_reuse_is_replay_detected_but_replay_does_not_consume(self) -> None:
        body = self.cap_body()
        header = make_sla_auth(
            self.server, "nonce-1", PRODUCER_SEED, self.producer, "POST",
            self.cap_path, body, 1,
        )
        status, _ = self.post(self.cap_path, body, "nonce-1", auth=header)
        self.assertEqual(status, 201)
        # 异键复用同一五段（同随机数）：409 replay_detected。
        status, payload = self.post(self.cap_path, body, "nonce-2", auth=header)
        self.assertEqual((status, json.loads(payload)),
                         (409, {"error": "replay_detected"}))
        # 同键同请求照常重放首次响应，不再次消费随机数。
        status, payload = self.post(self.cap_path, body, "nonce-1", auth=header)
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(payload), {"version": 1})

    def test_same_key_different_auth_is_conflict(self) -> None:
        body = self.cap_body()
        self.assertEqual(self.post(
            self.cap_path, body, "same-key", seed=PRODUCER_SEED,
            actor=self.producer)[0], 201)
        status, payload = self.post(
            self.cap_path, body, "same-key", seed=PRODUCER_SEED,
            actor=self.producer, nonce="nonce-different-0000001",
        )
        self.assertEqual((status, json.loads(payload)),
                         (409, {"error": "conflict"}))

    def test_business_failure_does_not_consume_nonce(self) -> None:
        bad_body = self.cap_body(99)
        ts = int(time.time() * 1000)
        nonce = "nonce-business-fail-01"
        status, payload = self.post(
            self.cap_path, bad_body, "biz-fail", seed=PRODUCER_SEED,
            actor=self.producer, request_time_ms=ts, nonce=nonce,
        )
        self.assertEqual((status, json.loads(payload)),
                         (409, {"error": "conflict"}))
        good_body = self.cap_body()
        status, payload = self.post(
            self.cap_path, good_body, "biz-ok", seed=PRODUCER_SEED,
            actor=self.producer, request_time_ms=ts, nonce=nonce,
        )
        self.assertEqual((status, payload), (201, b'{"version":1}'))

    def test_expired_nonce_can_be_reused_after_retention(self) -> None:
        connection = sqlite3.connect(self.server.database_path)
        try:
            connection.execute(
                "INSERT INTO auth_nonce_records(machine_id, nonce, request_time_ms)"
                " VALUES (?, ?, ?)",
                (self.producer, "nonce-expired-0001", int(time.time() * 1000) - 601_000),
            )
            connection.commit()
        finally:
            connection.close()
        body = self.cap_body()
        status, _ = self.post(
            self.cap_path, body, "expired", seed=PRODUCER_SEED,
            actor=self.producer, nonce="nonce-expired-0001",
        )
        self.assertEqual(status, 201)

    def test_confirmation_requires_actor_signature(self) -> None:
        # 建能力、模板与 SLA。
        self.assertEqual(self.post(
            self.cap_path, self.cap_body(), "cap", seed=PRODUCER_SEED,
            actor=self.producer)[0], 201)
        self.assertEqual(self.post(
            "/v1/sla-templates",
            json.dumps({"id": "t1", "machineId": self.producer,
                        "capabilityVersion": 1, "priceMicros": 100,
                        "maxLatencyMs": 50}).encode(),
            "tpl", auth=None)[0], 201)
        now = int(time.time())
        self.assertEqual(self.post(
            "/v1/slas",
            json.dumps({"id": "s1", "templateId": "t1",
                        "consumerId": self.consumer, "start": now - 100,
                        "end": now + 3600}).encode(),
            "sla", auth=None)[0], 201)
        path = "/v1/slas/s1/confirmations"
        producer_body = json.dumps(
            {"party": "producer", "actorId": self.producer}).encode()
        # 生产方由消费者私钥代签：机器标识不等于 actorId -> 403。
        status, payload = self.post(
            path, producer_body, "conf-wrong", seed=PUBLIC_KEY_SEED_B,
            actor=self.consumer,
        )
        self.assertEqual((status, json.loads(payload)),
                         (403, {"error": "forbidden"}))
        # 正确签名确认成功。
        status, payload = self.post(
            path, producer_body, "conf-p", seed=PRODUCER_SEED, actor=self.producer
        )
        self.assertEqual((status, payload), (200, b'{"state":"pending"}'))
        consumer_body = json.dumps(
            {"party": "consumer", "actorId": self.consumer}).encode()
        status, payload = self.post(
            path, consumer_body, "conf-c", seed=PUBLIC_KEY_SEED_B,
            actor=self.consumer,
        )
        self.assertEqual((status, payload), (200, b'{"state":"active"}'))

    def test_legacy_idempotency_record_replays_without_auth(self) -> None:
        body = self.cap_body()
        request_json = json.dumps(json.loads(body), sort_keys=True,
                                  separators=(",", ":"))
        connection = sqlite3.connect(self.server.database_path)
        try:
            connection.execute(
                "INSERT INTO capability_idempotency_records"
                "(key, machine_id, request_json, status, response_json)"
                " VALUES (?, ?, ?, ?, ?)",
                ("legacy", self.producer, request_json, 200, '{"version":7}'),
            )
            connection.commit()
        finally:
            connection.close()
        # 无认证头、坏认证头都按旧记录重放。
        status, payload = self.post(self.cap_path, body, "legacy", auth=None)
        self.assertEqual((status, payload), (200, b'{"version":7}'))
        status, payload = self.post(self.cap_path, body, "legacy", auth="garbage")
        self.assertEqual((status, payload), (200, b'{"version":7}'))
        # 同键异体不再走旧重放：坏头 400，合法头 409。
        other = self.cap_body(0, 11)
        status, _ = self.post(self.cap_path, other, "legacy", auth="garbage")
        self.assertEqual(status, 400)
        status, payload = self.post(
            self.cap_path, other, "legacy", seed=PRODUCER_SEED, actor=self.producer
        )
        self.assertEqual((status, json.loads(payload)),
                         (409, {"error": "conflict"}))


DELEGATE_SEED = b"\x09" * 32
DELEGATE_PUBLIC_KEY = _ed25519_public_key(DELEGATE_SEED).hex()


def make_delegation_auth(
    delegation_id: str,
    seed: bytes,
    method: str,
    path: str,
    body: bytes,
    request_time_ms: int,
    nonce: str,
) -> str:
    body_digest = hashlib.sha256(body).hexdigest()
    message = (
        f"delegation-auth-v1\n{method}\n{path}\n{body_digest}\n"
        f"{request_time_ms}\n{nonce}\n0\n{delegation_id}"
    ).encode("utf-8")
    signature = _ed25519_sign(seed, message).hex()
    return f"{delegation_id};0;{request_time_ms};{nonce};{signature}"


class DelegationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.producer = machine_id(PUBLIC_KEY_A)
        self.consumer = machine_id(PUBLIC_KEY_B)
        for key, public_key in (("reg-a", PUBLIC_KEY_A), ("reg-b", PUBLIC_KEY_B)):
            self.assertEqual(
                self.post(
                    "/v1/machines",
                    json.dumps({"publicKey": public_key}).encode(),
                    key,
                )[0],
                201,
            )
        self._nonce_counter = 0
        self._issue_bodies: dict[str, bytes] = {}

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def post(
        self,
        path: str,
        body: bytes | None,
        key: str | None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        request = Request(self.url(path), data=body, method="POST")
        if key is not None:
            request.add_header("Idempotency-Key", key)
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def sla_auth(
        self,
        key: str,
        path: str,
        body: bytes,
        seed: bytes = PRODUCER_SEED,
        actor: str | None = None,
        key_version: int = 1,
    ) -> dict[str, str]:
        return {
            "SLA-Auth": make_sla_auth(
                self.server,
                key,
                seed,
                actor if actor is not None else self.producer,
                "POST",
                path,
                body,
                key_version,
            )
        }

    def next_nonce(self) -> str:
        self._nonce_counter += 1
        return f"delegation-nonce-{self._nonce_counter:016d}"

    def delegation_auth(
        self,
        delegation_id: str,
        path: str,
        body: bytes,
        nonce: str | None = None,
        request_time_ms: int | None = None,
        seed: bytes = DELEGATE_SEED,
    ) -> dict[str, str]:
        return {
            "SLA-Delegation": make_delegation_auth(
                delegation_id,
                seed,
                "POST",
                path,
                body,
                request_time_ms
                if request_time_ms is not None
                else int(time.time() * 1000),
                nonce if nonce is not None else self.next_nonce(),
            )
        }

    @property
    def cap_path(self) -> str:
        return f"/v1/machines/{self.producer}/capabilities"

    def cap_body(self, expected: int = 0) -> bytes:
        return json.dumps({
            "expectedVersion": expected, "name": "pump-01", "protocol": "mqtt",
            "region": "cn", "unit": "call", "capacity": 10,
        }).encode()

    def issue_body(
        self, delegation_id: str = "del-1", expires_in_ms: int = 3_600_000
    ) -> bytes:
        return json.dumps({
            "id": delegation_id,
            "delegatePublicKey": DELEGATE_PUBLIC_KEY,
            "expiresAt": int(time.time() * 1000) + expires_in_ms,
        }).encode()

    def issue(
        self, delegation_id: str = "del-1", key: str = "issue-1"
    ) -> tuple[int, bytes]:
        # 重放须逐字节复用首次正文（expiresAt 取自构建时刻）。
        body = self._issue_bodies.get(delegation_id)
        if body is None:
            body = self.issue_body(delegation_id)
            self._issue_bodies[delegation_id] = body
        return self.post(
            "/v1/delegations", body, key, self.sla_auth(key, "/v1/delegations", body)
        )

    def test_issue_created_and_replay(self) -> None:
        status, payload = self.issue()
        self.assertEqual(status, 201)
        self.assertEqual(list(json.loads(payload)), ["id", "expiresAt"])
        self.assertEqual(json.loads(payload)["id"], "del-1")
        status, replay = self.issue()
        self.assertEqual((status, replay), (201, payload))

    def test_issue_replay_survives_restart(self) -> None:
        status, payload = self.issue()
        self.assertEqual(status, 201)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = str(Path(self.temporary.name) / "service.db")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, replay = self.issue()
        self.assertEqual((status, replay), (201, payload))

    def test_issue_same_key_different_body_conflicts(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        other = self.issue_body("del-2")
        status, payload = self.post(
            "/v1/delegations", other, "issue-1",
            self.sla_auth("issue-1", "/v1/delegations", other),
        )
        self.assertEqual((status, json.loads(payload)), (409, {"error": "conflict"}))

    def test_issue_duplicate_id_conflicts(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        body = self.issue_body("del-1")
        status, payload = self.post(
            "/v1/delegations", body, "issue-2",
            self.sla_auth("issue-2", "/v1/delegations", body),
        )
        self.assertEqual((status, json.loads(payload)), (409, {"error": "conflict"}))

    def test_issue_invalid_requests(self) -> None:
        body = self.issue_body()
        # 查询参数、缺失认证头均为 400。
        status, _ = self.post(
            "/v1/delegations?x=1", body, "q1",
            self.sla_auth("q1", "/v1/delegations", body),
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.post("/v1/delegations", body, "q2")[0], 400)
        now_ms = int(time.time() * 1000)
        bad_bodies = [
            b"",
            b"{}",
            json.dumps({"id": "del-1", "delegatePublicKey": DELEGATE_PUBLIC_KEY}).encode(),
            json.dumps({"id": "del-1", "delegatePublicKey": DELEGATE_PUBLIC_KEY,
                        "expiresAt": now_ms + 1000, "extra": 1}).encode(),
            json.dumps({"id": "BAD", "delegatePublicKey": DELEGATE_PUBLIC_KEY,
                        "expiresAt": now_ms + 1000}).encode(),
            json.dumps({"id": "del-1", "delegatePublicKey": "zz",
                        "expiresAt": now_ms + 1000}).encode(),
            json.dumps({"id": "del-1", "delegatePublicKey": DELEGATE_PUBLIC_KEY,
                        "expiresAt": "soon"}).encode(),
            json.dumps({"id": "del-1", "delegatePublicKey": DELEGATE_PUBLIC_KEY,
                        "expiresAt": now_ms - 1}).encode(),
            json.dumps({"id": "del-1", "delegatePublicKey": DELEGATE_PUBLIC_KEY,
                        "expiresAt": now_ms + 86_401_000}).encode(),
        ]
        for index, bad in enumerate(bad_bodies):
            key = f"bad-{index}"
            headers = self.sla_auth(key, "/v1/delegations", bad) if bad else None
            status, payload = self.post("/v1/delegations", bad or None, key, headers)
            self.assertEqual(
                (status, json.loads(payload)), (400, {"error": "invalid_request"}), bad
            )

    def test_issue_unregistered_machine_is_401(self) -> None:
        body = self.issue_body()
        status, payload = self.post(
            "/v1/delegations", body, "ghost",
            self.sla_auth("ghost", "/v1/delegations", body,
                          seed=PUBLIC_KEY_SEED_C, actor=machine_id(PUBLIC_KEY_C)),
        )
        self.assertEqual(
            (status, json.loads(payload)), (401, {"error": "invalid_authentication"})
        )

    def test_capability_via_delegation_created_then_consumed(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        body = self.cap_body()
        headers = self.delegation_auth("del-1", self.cap_path, body)
        status, payload = self.post(self.cap_path, body, "cap-1", headers)
        self.assertEqual((status, payload), (201, b'{"version":1}'))
        # 凭证已消费：异键再次使用（即使同一组认证五段）返回 401。
        status, payload = self.post(self.cap_path, body, "cap-2", headers)
        self.assertEqual(
            (status, json.loads(payload)), (401, {"error": "invalid_authentication"})
        )
        # 同键同请求重放首次响应，不重复消费。
        status, payload = self.post(self.cap_path, body, "cap-1", headers)
        self.assertEqual((status, payload), (201, b'{"version":1}'))

    def test_capability_both_auth_headers_is_400(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        body = self.cap_body()
        headers = self.sla_auth("both-1", self.cap_path, body)
        headers.update(self.delegation_auth("del-1", self.cap_path, body))
        status, payload = self.post(self.cap_path, body, "both-1", headers)
        self.assertEqual(
            (status, json.loads(payload)), (400, {"error": "invalid_request"})
        )

    def test_capability_delegation_bad_format_is_400(self) -> None:
        body = self.cap_body()
        now_ms = int(time.time() * 1000)
        for raw in (
            "x",
            "del-1;0;1;n;s",
            f"del-1;1;{now_ms};{self.next_nonce()};{'a' * 128}",
            f"del-1;0;{now_ms};short;{'a' * 128}",
            f"del-1;0;{now_ms};{self.next_nonce()};{'A' * 128}",
        ):
            status, payload = self.post(
                self.cap_path, body, "fmt-1", {"SLA-Delegation": raw}
            )
            self.assertEqual(
                (status, json.loads(payload)), (400, {"error": "invalid_request"}), raw
            )

    def test_capability_delegation_unknown_is_401(self) -> None:
        body = self.cap_body()
        headers = self.delegation_auth("del-unknown", self.cap_path, body)
        status, payload = self.post(self.cap_path, body, "unk-1", headers)
        self.assertEqual(
            (status, json.loads(payload)), (401, {"error": "invalid_authentication"})
        )

    def test_capability_delegation_expired_is_401(self) -> None:
        connection = sqlite3.connect(self.server.database_path)
        try:
            connection.execute(
                "INSERT INTO delegations"
                "(id, machine_id, delegate_public_key, expires_at_ms,"
                " key_version, revoked, consumed)"
                " VALUES (?, ?, ?, ?, 1, 0, 0)",
                (
                    "del-expired",
                    self.producer,
                    DELEGATE_PUBLIC_KEY,
                    int(time.time() * 1000) - 1000,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        body = self.cap_body()
        headers = self.delegation_auth("del-expired", self.cap_path, body)
        status, payload = self.post(self.cap_path, body, "exp-1", headers)
        self.assertEqual(
            (status, json.loads(payload)), (401, {"error": "invalid_authentication"})
        )

    def test_capability_delegation_revoked_is_401(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        self.assertEqual(self.revoke()[0], 200)
        body = self.cap_body()
        headers = self.delegation_auth("del-1", self.cap_path, body)
        status, payload = self.post(self.cap_path, body, "rev-1", headers)
        self.assertEqual(
            (status, json.loads(payload)), (401, {"error": "invalid_authentication"})
        )

    def test_capability_delegation_wrong_machine_is_403(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        path = f"/v1/machines/{self.consumer}/capabilities"
        body = self.cap_body()
        headers = self.delegation_auth("del-1", path, body)
        status, payload = self.post(path, body, "wm-1", headers)
        self.assertEqual((status, json.loads(payload)), (403, {"error": "forbidden"}))

    def test_capability_delegation_issuing_key_rotated_is_401(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        new_seed = b"\x0a" * 32
        new_public = _ed25519_public_key(new_seed).hex()
        current_sig, new_sig = key_rotation_signatures(
            PRODUCER_SEED, new_seed, self.producer, 1, new_public
        )
        rotation = json.dumps({
            "expectedVersion": 1, "publicKey": new_public,
            "currentSignature": current_sig, "newSignature": new_sig,
        }).encode()
        self.assertEqual(
            self.post(f"/v1/machines/{self.producer}/keys", rotation, "rot-1")[0], 201
        )
        body = self.cap_body()
        headers = self.delegation_auth("del-1", self.cap_path, body)
        status, payload = self.post(self.cap_path, body, "rot-use", headers)
        self.assertEqual(
            (status, json.loads(payload)), (401, {"error": "invalid_authentication"})
        )

    def test_capability_delegation_business_failure_does_not_consume(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        bad = self.cap_body(5)
        status, payload = self.post(
            self.cap_path, bad, "fail-1",
            self.delegation_auth("del-1", self.cap_path, bad),
        )
        self.assertEqual((status, json.loads(payload)), (409, {"error": "conflict"}))
        # 失败不消费凭证：换新随机数后仍可成功。
        good = self.cap_body()
        status, payload = self.post(
            self.cap_path, good, "ok-1",
            self.delegation_auth("del-1", self.cap_path, good),
        )
        self.assertEqual((status, payload), (201, b'{"version":1}'))

    def test_capability_delegation_same_key_auth_change_conflicts(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        body = self.cap_body()
        status, _ = self.post(
            self.cap_path, body, "same-1",
            self.delegation_auth("del-1", self.cap_path, body),
        )
        self.assertEqual(status, 201)
        # 同键更换认证随机数即冲突（幂等判定先于委托状态检查）。
        status, payload = self.post(
            self.cap_path, body, "same-1",
            self.delegation_auth("del-1", self.cap_path, body),
        )
        self.assertEqual((status, json.loads(payload)), (409, {"error": "conflict"}))

    def test_capability_delegation_stale_time_is_401(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        body = self.cap_body()
        headers = self.delegation_auth(
            "del-1", self.cap_path, body,
            request_time_ms=int(time.time() * 1000) - 400_000,
        )
        status, payload = self.post(self.cap_path, body, "stale-1", headers)
        self.assertEqual(
            (status, json.loads(payload)), (401, {"error": "stale_request"})
        )

    def revoke(
        self, delegation_id: str = "del-1", key: str = "revoke-1"
    ) -> tuple[int, bytes]:
        path = f"/v1/delegations/{delegation_id}/revocation"
        return self.post(path, b"{}", key, self.sla_auth(key, path, b"{}"))

    def test_revoke_created_and_replay(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        status, payload = self.revoke()
        self.assertEqual((status, payload), (200, b'{"id":"del-1","revoked":true}'))
        status, replay = self.revoke()
        self.assertEqual((status, replay), (200, payload))

    def test_revoke_missing_is_404(self) -> None:
        status, payload = self.revoke("del-missing")
        self.assertEqual((status, json.loads(payload)), (404, {"error": "not_found"}))

    def test_revoke_non_issuer_is_403(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        path = "/v1/delegations/del-1/revocation"
        status, payload = self.post(
            path, b"{}", "revoke-other",
            self.sla_auth("revoke-other", path, b"{}",
                          seed=PUBLIC_KEY_SEED_B, actor=self.consumer),
        )
        self.assertEqual((status, json.loads(payload)), (403, {"error": "forbidden"}))

    def test_revoke_duplicate_different_key_conflicts(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        self.assertEqual(self.revoke()[0], 200)
        status, payload = self.revoke(key="revoke-2")
        self.assertEqual((status, json.loads(payload)), (409, {"error": "conflict"}))

    def test_revoke_invalid_requests(self) -> None:
        self.assertEqual(self.issue()[0], 201)
        path = "/v1/delegations/del-1/revocation"
        # 非空对象正文、查询参数、缺失认证头均为 400。
        status, _ = self.post(
            path, b'{"x":1}', "ri-1", self.sla_auth("ri-1", path, b'{"x":1}')
        )
        self.assertEqual(status, 400)
        status, _ = self.post(
            path + "?x=1", b"{}", "ri-2", self.sla_auth("ri-2", path, b"{}")
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.post(path, b"{}", "ri-3")[0], 400)
