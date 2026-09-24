from __future__ import annotations

import concurrent.futures
import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sla_network.server import ApiServer, Handler


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


SEED1 = b"\x01" * 32
SEED2 = b"\x02" * 32
SEED3 = b"\x03" * 32
PUB1 = _ed25519_public_key(SEED1).hex()
PUB2 = _ed25519_public_key(SEED2).hex()
PUB3 = _ed25519_public_key(SEED3).hex()
CONSUMER_SEED = b"\x09" * 32
CONSUMER_PUB = _ed25519_public_key(CONSUMER_SEED).hex()


def rotate_signatures(
    current_seed: bytes,
    new_seed: bytes,
    machine: str,
    expected_version: int,
    new_public_key: str,
) -> tuple[str, str]:
    message = f"key-rotate-v1\n{machine}\n{expected_version}\n{new_public_key}".encode()
    return (
        _ed25519_sign(current_seed, message).hex(),
        _ed25519_sign(new_seed, message).hex(),
    )


def revoke_signature(seed: bytes, machine: str, version: int) -> str:
    message = f"key-revoke-v1\n{machine}\n{version}".encode()
    return _ed25519_sign(seed, message).hex()


def telemetry_signature(
    seed: bytes,
    sla_id: str,
    event_id: str,
    timestamp: int,
    latency_ms: int,
    digest: str,
    machine: str,
    key_version: int,
) -> str:
    message = (
        f"telemetry-v2\n{sla_id}\n{event_id}\n{timestamp}\n"
        f"{latency_ms}\n{digest}\n{key_version}\n{machine}"
    )
    return _ed25519_sign(seed, message.encode()).hex()


class KeyLifecycleTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary.name) / "service.db")
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.machine = machine_id(PUB1)
        self.consumer = machine_id(CONSUMER_PUB)
        self.register("reg-1", PUB1)
        self.register("reg-2", CONSUMER_PUB)

    def register(self, key: str, public_key: str) -> None:
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": public_key}, key
        )
        self.assertEqual(status, 201)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def post_json(
        self, path: str, payload: object, key: str | None = "k-1"
    ) -> tuple[int, bytes]:
        request = Request(
            self.url(path),
            data=payload if isinstance(payload, bytes) else json.dumps(payload).encode(),
            method="POST",
        )
        if key is not None:
            request.add_header("Idempotency-Key", key)
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def restart(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def activate_sla(self) -> None:
        capability = {
            "expectedVersion": 0,
            "name": "pump-01",
            "protocol": "mqtt",
            "region": "cn",
            "unit": "call",
            "capacity": 10,
        }
        status, _ = self.post_json(
            f"/v1/machines/{self.machine}/capabilities", capability, "cap-1"
        )
        self.assertEqual(status, 201)
        template = {
            "id": "tpl-1",
            "machineId": self.machine,
            "capabilityVersion": 1,
            "priceMicros": 1000,
            "maxLatencyMs": 50,
        }
        status, _ = self.post_json("/v1/sla-templates", template, "tpl-1")
        self.assertEqual(status, 201)
        current = int(time.time())
        self.start = current - 3600
        self.end = current + 3600
        sla = {
            "id": "sla-1",
            "templateId": "tpl-1",
            "consumerId": self.consumer,
            "start": self.start,
            "end": self.end,
        }
        status, _ = self.post_json("/v1/slas", sla, "sla-1")
        self.assertEqual(status, 201)
        for key, party, actor in (
            ("conf-p", "producer", self.machine),
            ("conf-c", "consumer", self.consumer),
        ):
            status, _ = self.post_json(
                f"/v1/slas/sla-1/confirmations",
                {"party": party, "actorId": actor},
                key,
            )
            self.assertEqual(status, 200)

    def rotate(
        self,
        expected_version: int,
        new_public_key: str,
        current_seed: bytes,
        new_seed: bytes,
        key: str = "rot-1",
        machine: str | None = None,
    ) -> tuple[int, bytes]:
        machine = self.machine if machine is None else machine
        current_signature, new_signature = rotate_signatures(
            current_seed, new_seed, machine, expected_version, new_public_key
        )
        return self.post_json(
            f"/v1/machines/{machine}/keys",
            {
                "expectedVersion": expected_version,
                "publicKey": new_public_key,
                "currentSignature": current_signature,
                "newSignature": new_signature,
            },
            key,
        )

    def revoke(
        self,
        version: int,
        seed: bytes,
        key: str = "rev-1",
        machine: str | None = None,
        raw_signature: str | None = None,
    ) -> tuple[int, bytes]:
        machine = self.machine if machine is None else machine
        signature = (
            revoke_signature(seed, machine, version)
            if raw_signature is None
            else raw_signature
        )
        return self.post_json(
            f"/v1/machines/{machine}/keys/{version}/revocation",
            {"signature": signature},
            key,
        )

    def telemetry(
        self,
        timestamp: int,
        seed: bytes,
        key_version: int,
        event_id: str = "evt-1",
        latency_ms: int = 12,
        key: str = "tel-1",
    ) -> tuple[int, bytes]:
        digest = hashlib.sha256(
            f"sla-1\n{event_id}\n{timestamp}\n{latency_ms}\n{self.machine}".encode()
        ).hexdigest()
        signature = telemetry_signature(
            seed, "sla-1", event_id, timestamp, latency_ms, digest,
            self.machine, key_version,
        )
        return self.post_json(
            "/v1/slas/sla-1/telemetry",
            {
                "eventId": event_id,
                "timestamp": timestamp,
                "latencyMs": latency_ms,
                "digest": digest,
                "keyVersion": key_version,
                "signature": signature,
            },
            key,
        )

    def key_rows(self) -> list[sqlite3.Row]:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute(
                "SELECT version, public_key, activated_at_ms, revoked"
                " FROM machine_keys WHERE machine_id = ?"
                " ORDER BY version ASC",
                (self.machine,),
            ).fetchall()
        finally:
            connection.close()


class KeyRotationTests(KeyLifecycleTestBase):
    def test_registration_seeds_version_one(self) -> None:
        rows = self.key_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            (rows[0]["version"], rows[0]["public_key"], rows[0]["activated_at_ms"]),
            (1, PUB1, 0),
        )
        self.assertEqual(rows[0]["revoked"], 0)

    def test_rotate_created_payload_and_persistence(self) -> None:
        before = int(time.time() * 1000)
        status, body = self.rotate(1, PUB2, SEED1, SEED2)
        after = int(time.time() * 1000)
        self.assertEqual(status, 201)
        payload = json.loads(body)
        self.assertEqual(list(payload), ["version", "publicKey", "activatedAt", "revoked"])
        self.assertEqual(payload["version"], 2)
        self.assertEqual(payload["publicKey"], PUB2)
        self.assertFalse(payload["revoked"])
        self.assertTrue(before <= payload["activatedAt"] <= after)
        rows = self.key_rows()
        self.assertEqual([row["version"] for row in rows], [1, 2])
        self.assertEqual(rows[0]["public_key"], PUB1)
        self.assertEqual(rows[1]["public_key"], PUB2)
        self.assertEqual(rows[1]["activated_at_ms"], payload["activatedAt"])

    def test_replay_returns_first_response_bytes(self) -> None:
        status, first = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual(status, 201)
        status, second = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual((status, second), (201, first))
        self.restart()
        status, third = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual((status, third), (201, first))
        # 重放不产生新版本。
        self.assertEqual([row["version"] for row in self.key_rows()], [1, 2])

    def test_same_key_different_request_conflicts(self) -> None:
        status, _ = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual(status, 201)
        status, body = self.rotate(2, PUB3, SEED2, SEED3, key="rot-1")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_same_key_different_machine_conflicts_even_when_unknown(self) -> None:
        status, _ = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual(status, 201)
        ghost = "aa" * 32
        status, body = self.rotate(
            1, PUB3, SEED1, SEED3, key="rot-1", machine=ghost
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_version_mismatch_conflicts(self) -> None:
        status, body = self.rotate(2, PUB2, SEED1, SEED2)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})
        # 失败后仍可按正确版本轮换。
        status, _ = self.rotate(1, PUB2, SEED1, SEED2)
        self.assertEqual(status, 201)

    def test_historical_public_key_reuse_is_key_exists(self) -> None:
        status, _ = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual(status, 201)
        # 轮换回版本一的历史公钥：key_exists，先于验签失败。
        status, body = self.rotate(2, PUB1, SEED2, SEED1, key="rot-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "key_exists"})
        self.assertEqual([row["version"] for row in self.key_rows()], [1, 2])

    def test_current_signature_invalid(self) -> None:
        current_signature, new_signature = rotate_signatures(
            SEED1, SEED2, self.machine, 1, PUB2
        )
        status, body = self.post_json(
            f"/v1/machines/{self.machine}/keys",
            {
                "expectedVersion": 1,
                "publicKey": PUB2,
                "currentSignature": "0" * 128,
                "newSignature": new_signature,
            },
            "rot-bad",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})

    def test_new_signature_invalid(self) -> None:
        current_signature, new_signature = rotate_signatures(
            SEED1, SEED2, self.machine, 1, PUB2
        )
        status, body = self.post_json(
            f"/v1/machines/{self.machine}/keys",
            {
                "expectedVersion": 1,
                "publicKey": PUB2,
                "currentSignature": current_signature,
                "newSignature": "0" * 128,
            },
            "rot-bad2",
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})

    def test_unknown_machine_not_found(self) -> None:
        ghost = machine_id("ab" * 32)
        status, body = self.rotate(
            1, PUB2, SEED1, SEED2, key="rot-x", machine=ghost
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})

    def test_failure_leaves_no_write(self) -> None:
        status, _ = self.rotate(2, PUB2, SEED1, SEED2, key="rot-fail")
        self.assertEqual(status, 409)
        self.assertEqual([row["version"] for row in self.key_rows()], [1])
        connection = sqlite3.connect(self.database_path)
        try:
            row = connection.execute(
                "SELECT 1 FROM machine_key_idempotency_records WHERE key = 'rot-fail'"
            ).fetchone()
            self.assertIsNone(row)
        finally:
            connection.close()

    def test_invalid_requests(self) -> None:
        current_signature, new_signature = rotate_signatures(
            SEED1, SEED2, self.machine, 1, PUB2
        )
        valid = {
            "expectedVersion": 1,
            "publicKey": PUB2,
            "currentSignature": current_signature,
            "newSignature": new_signature,
        }
        path = f"/v1/machines/{self.machine}/keys"
        cases = [
            dict(valid, expectedVersion=0),
            dict(valid, expectedVersion=2147483647),
            dict(valid, expectedVersion=True),
            dict(valid, expectedVersion="1"),
            dict(valid, publicKey="g" * 64),
            dict(valid, publicKey=PUB2.upper()),
            dict(valid, currentSignature="0" * 127),
            dict(valid, newSignature="A" * 128),
            {key: value for key, value in valid.items() if key != "publicKey"},
            {**valid, "extra": 1},
        ]
        for body in cases:
            status, response = self.post_json(path, body, "rot-invalid")
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response), {"error": "invalid_request"})
        # 缺少或非法幂等头。
        request = Request(
            self.url(path), data=json.dumps(valid).encode(), method="POST"
        )
        try:
            with urlopen(request, timeout=5) as response:
                status = response.status
        except HTTPError as error:
            status = error.code
        self.assertEqual(status, 400)
        # 查询参数不被接受。
        status, _ = self.post_json(path + "?x=1", valid, "rot-query")
        self.assertEqual(status, 400)

    def test_concurrent_same_key_single_write(self) -> None:
        def call() -> tuple[int, bytes]:
            return self.rotate(1, PUB2, SEED1, SEED2, key="rot-conc")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: call(), range(8)))
        statuses = [status for status, _ in results]
        self.assertEqual(set(statuses), {201})
        self.assertEqual([row["version"] for row in self.key_rows()], [1, 2])

    def test_concurrent_distinct_keys_single_winner(self) -> None:
        def call(index: int) -> int:
            if index == 0:
                status, _ = self.rotate(1, PUB2, SEED1, SEED2, key=f"rot-c{index}")
            else:
                status, _ = self.rotate(1, PUB3, SEED1, SEED3, key=f"rot-c{index}")
            return status

        barrier = threading.Barrier(6)

        def gated(index: int) -> int:
            barrier.wait()
            return call(index)

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            statuses = list(pool.map(gated, range(6)))
        self.assertEqual(statuses.count(201), 1)
        self.assertEqual(len(self.key_rows()), 2)


class KeyRevocationTests(KeyLifecycleTestBase):
    def setUp(self) -> None:
        super().setUp()
        status, _ = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual(status, 201)

    def test_revoke_old_version_ok(self) -> None:
        status, body = self.revoke(1, SEED2)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"version": 1, "revoked": True})
        rows = {row["version"]: row["revoked"] for row in self.key_rows()}
        self.assertEqual(rows, {1: 1, 2: 0})

    def test_replay_returns_first_response_bytes(self) -> None:
        status, first = self.revoke(1, SEED2, key="rev-1")
        self.assertEqual(status, 200)
        status, again = self.revoke(1, SEED2, key="rev-1")
        self.assertEqual((status, again), (200, first))
        self.restart()
        status, again = self.revoke(1, SEED2, key="rev-1")
        self.assertEqual((status, again), (200, first))

    def test_current_version_conflicts(self) -> None:
        status, body = self.revoke(2, SEED2)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_duplicate_revocation_already_revoked(self) -> None:
        status, _ = self.revoke(1, SEED2, key="rev-1")
        self.assertEqual(status, 200)
        # 异键重复吊销。
        status, body = self.revoke(1, SEED2, key="rev-2")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "already_revoked"})

    def test_invalid_signature(self) -> None:
        status, body = self.revoke(1, SEED1, key="rev-bad")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 坏签名同样失败且无写入。
        status, body = self.revoke(
            1, SEED2, key="rev-bad2", raw_signature="0" * 128
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})

    def test_missing_version_or_machine_not_found(self) -> None:
        status, body = self.revoke(9, SEED2, key="rev-9")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})
        ghost = machine_id("ab" * 32)
        status, body = self.revoke(1, SEED2, key="rev-g", machine=ghost)
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "not_found"})
        # 非法路径版本按不存在处理。
        status, body = self.post_json(
            f"/v1/machines/{self.machine}/keys/0x1/revocation",
            {"signature": "0" * 128},
            "rev-path",
        )
        self.assertEqual(status, 404)

    def test_invalid_body_and_query(self) -> None:
        cases = [
            {},
            {"signature": "0" * 127},
            {"signature": "A" * 128},
            {"signature": 123},
            {"signature": "0" * 128, "extra": 1},
        ]
        path = f"/v1/machines/{self.machine}/keys/1/revocation"
        for body in cases:
            status, response = self.post_json(path, body, "rev-invalid")
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(response), {"error": "invalid_request"})
        status, _ = self.post_json(path + "?x=1", {"signature": "0" * 128}, "rev-q")
        self.assertEqual(status, 400)

    def test_same_key_different_request_conflicts(self) -> None:
        status, _ = self.revoke(1, SEED2, key="rev-1")
        self.assertEqual(status, 200)
        # 同键用于不同版本：冲突。
        status, body = self.revoke(2, SEED2, key="rev-1")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "conflict"})

    def test_failure_leaves_no_write(self) -> None:
        status, _ = self.revoke(1, SEED1, key="rev-fail")
        self.assertEqual(status, 409)
        connection = sqlite3.connect(self.database_path)
        try:
            row = connection.execute(
                "SELECT revoked FROM machine_keys"
                " WHERE machine_id = ? AND version = 1",
                (self.machine,),
            ).fetchone()
            self.assertEqual(row[0], 0)
            row = connection.execute(
                "SELECT 1 FROM machine_key_revocation_idempotency_records"
                " WHERE key = 'rev-fail'"
            ).fetchone()
            self.assertIsNone(row)
        finally:
            connection.close()


class TelemetryKeyVersionTests(KeyLifecycleTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.activate_sla()

    def test_missing_key_version_is_invalid_request(self) -> None:
        timestamp = self.start * 1000 + 500
        digest = hashlib.sha256(
            f"sla-1\nevt-1\n{timestamp}\n12\n{self.machine}".encode()
        ).hexdigest()
        body = {
            "eventId": "evt-1",
            "timestamp": timestamp,
            "latencyMs": 12,
            "digest": digest,
            "signature": "0" * 128,
        }
        status, response = self.post_json("/v1/slas/sla-1/telemetry", body, "tel-no")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(response), {"error": "invalid_request"})

    def test_unknown_version_is_invalid_signature(self) -> None:
        timestamp = self.start * 1000 + 500
        status, body = self.telemetry(timestamp, SEED1, 7, key="tel-7")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})

    def test_version_window_enforced_across_rotation(self) -> None:
        status, rotated = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual(status, 201)
        activated_at = json.loads(rotated)["activatedAt"]
        # 版本一激活窗内（恰在版本二激活前一毫秒）：旧密钥仍可签名。
        status, _ = self.telemetry(
            activated_at - 1, SEED1, 1, event_id="evt-old", key="tel-old"
        )
        self.assertEqual(status, 201)
        # 窗口下界：版本二激活时刻用旧密钥拒绝。
        status, body = self.telemetry(
            activated_at, SEED1, 1, event_id="evt-edge", key="tel-edge"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 同一时刻用新密钥接受。
        status, _ = self.telemetry(
            activated_at, SEED2, 2, event_id="evt-new", key="tel-new"
        )
        self.assertEqual(status, 201)

    def test_revoked_version_rejects_telemetry(self) -> None:
        status, rotated = self.rotate(1, PUB2, SEED1, SEED2, key="rot-1")
        self.assertEqual(status, 201)
        activated_at = json.loads(rotated)["activatedAt"]
        status, _ = self.revoke(1, SEED2, key="rev-1")
        self.assertEqual(status, 200)
        # 吊销后即使事件时刻位于版本一激活窗内也拒绝。
        timestamp = activated_at - 1
        status, body = self.telemetry(
            timestamp, SEED1, 1, event_id="evt-rev", key="tel-rev"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body), {"error": "invalid_signature"})
        # 当前版本不受影响。
        status, _ = self.telemetry(
            activated_at, SEED2, 2, event_id="evt-ok", key="tel-ok"
        )
        self.assertEqual(status, 201)

    def test_version_check_runs_after_digest_before_duplicate(self) -> None:
        # 摘要错误先于版本校验，返回 conflict 而非 invalid_signature。
        timestamp = self.start * 1000 + 500
        status, _ = self.telemetry(timestamp, SEED1, 1, key="tel-1")
        self.assertEqual(status, 201)
        digest = "0" * 64
        signature = telemetry_signature(
            SEED1, "sla-1", "evt-dup", timestamp, 12, digest, self.machine, 1
        )
        body = {
            "eventId": "evt-dup",
            "timestamp": timestamp,
            "latencyMs": 12,
            "digest": digest,
            "keyVersion": 1,
            "signature": signature,
        }
        status, response = self.post_json(
            "/v1/slas/sla-1/telemetry", body, "tel-baddigest"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response), {"error": "conflict"})
        # 未知版本 + 重复 eventId：版本/验签判定先于事件重复。
        good_digest = hashlib.sha256(
            f"sla-1\nevt-1\n{timestamp}\n12\n{self.machine}".encode()
        ).hexdigest()
        signature = telemetry_signature(
            SEED1, "sla-1", "evt-1", timestamp, 12, good_digest, self.machine, 3
        )
        body = {
            "eventId": "evt-1",
            "timestamp": timestamp,
            "latencyMs": 12,
            "digest": good_digest,
            "keyVersion": 3,
            "signature": signature,
        }
        status, response = self.post_json(
            "/v1/slas/sla-1/telemetry", body, "tel-dup"
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(response), {"error": "invalid_signature"})

    def test_failed_telemetry_does_not_advance_commit_seq(self) -> None:
        timestamp = self.start * 1000 + 500
        status, _ = self.telemetry(timestamp, SEED1, 9, key="tel-bad")
        self.assertEqual(status, 409)
        status, _ = self.telemetry(timestamp, SEED1, 1, key="tel-ok")
        self.assertEqual(status, 201)
        connection = sqlite3.connect(self.database_path)
        try:
            seq = connection.execute(
                "SELECT commit_seq FROM sla_telemetry_events"
                " WHERE sla_id = 'sla-1' AND event_id = 'evt-1'"
            ).fetchone()[0]
            self.assertEqual(seq, 1)
        finally:
            connection.close()


class MachineKeysMigrationTests(KeyLifecycleTestBase):
    """升级前旧库只有 machines：迁移补版本一（零时激活、未吊销）。"""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database_path = str(Path(self.temporary.name) / "service.db")
        self.machine = machine_id(PUB1)
        self.consumer = machine_id(CONSUMER_PUB)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO schema_metadata VALUES ('schema_version', '1')"
            )
            connection.execute(
                "CREATE TABLE machines (id TEXT PRIMARY KEY, public_key TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO machines VALUES (?, ?)", (self.machine, PUB1)
            )
            connection.commit()
        finally:
            connection.close()
        self.server = ApiServer(("127.0.0.1", 0), Handler)
        self.server.database_path = self.database_path
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def test_existing_machine_seeded_with_version_one(self) -> None:
        # 首个请求触发 connect() 的建表与一次性迁移。
        with urlopen(self.url("/health"), timeout=5):
            pass
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT version, public_key, activated_at_ms, revoked"
                " FROM machine_keys WHERE machine_id = ?",
                (self.machine,),
            ).fetchone()
            self.assertEqual(
                (row["version"], row["public_key"], row["activated_at_ms"], row["revoked"]),
                (1, PUB1, 0, 0),
            )
            marker = connection.execute(
                "SELECT 1 FROM schema_metadata WHERE key = 'machine_keys_seeded'"
            ).fetchone()
            self.assertIsNotNone(marker)
        finally:
            connection.close()
        # 重启后迁移不重复执行。
        self.restart()
        connection = sqlite3.connect(self.database_path)
        try:
            count = connection.execute(
                "SELECT COUNT(*) FROM machine_keys WHERE machine_id = ?",
                (self.machine,),
            ).fetchone()[0]
            self.assertEqual(count, 1)
        finally:
            connection.close()

    def test_seeded_version_one_signs_v2_telemetry(self) -> None:
        # 旧机器补版本一后可走完整 SLA 与 v2 遥测。
        self.register("reg-2", CONSUMER_PUB)
        self.activate_sla()
        timestamp = self.start * 1000 + 500
        status, _ = self.telemetry(timestamp, SEED1, 1, key="tel-1")
        self.assertEqual(status, 201)


if __name__ == "__main__":
    unittest.main()
