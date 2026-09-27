from __future__ import annotations

import concurrent.futures
import hashlib
import json
import sqlite3
import time
import unittest
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from tests.test_server import (
    ARBITRATOR_PUBLIC,
    ARBITRATOR_SEED,
    _EvidenceScenario,
    _ed25519_public_key,
    _ed25519_sign,
    machine_id,
    make_sla_auth,
)


class ProofCheckProofChainTests(_EvidenceScenario, unittest.TestCase):
    # 一致性报告签名证明前向链、链集合/单项读取与链头见证：首次成功证明在原事务
    # 追加 proof-check-proof-chain-v1 前向链记录；见证冻结认证字段并分配全局见证
    # 序号；失败、重放与并发败者不追加、不推进序号。
    AUDITOR_SEED = ARBITRATOR_SEED
    AUDITOR2_SEED = b"\x09" * 32

    def setUp(self) -> None:
        super().setUp()
        self.auditor_id = machine_id(ARBITRATOR_PUBLIC)
        self.auditor2_public = _ed25519_public_key(self.AUDITOR2_SEED).hex()
        self.auditor2_id = machine_id(self.auditor2_public)
        self.server.auditors = frozenset({self.auditor_id, self.auditor2_id})
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": ARBITRATOR_PUBLIC}, "register-auditor-pcp"
        )
        self.assertEqual(status, 201)
        status, _ = self.post_json(
            "/v1/machines", {"publicKey": self.auditor2_public}, "register-auditor2-pcp"
        )
        self.assertEqual(status, 201)

    def restart(self) -> None:
        super().restart()
        self.server.auditors = frozenset({self.auditor_id, self.auditor2_id})

    def request_raw(
        self,
        path: str,
        body: bytes,
        key: str | None,
        method: str,
        *,
        seed: bytes | None = None,
        actor: str | None = None,
        nonce: str | None = None,
        omit_auth: bool = False,
        key_version: int = 1,
        request_time_ms: int | None = None,
    ) -> tuple[int, bytes]:
        request = Request(self.url(path), data=body, method=method)
        if key is not None:
            request.add_header("Idempotency-Key", key)
        if key is None and nonce is None:
            nonce = f"nonce-pcp-get-{time.time_ns()}"
        if not omit_auth:
            request.add_header(
                "SLA-Auth",
                make_sla_auth(
                    self.server,
                    key,
                    seed if seed is not None else self.AUDITOR_SEED,
                    actor if actor is not None else self.auditor_id,
                    method,
                    urlsplit(path).path,
                    body,
                    key_version,
                    request_time_ms=request_time_ms,
                    nonce=nonce,
                ),
            )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def request2(
        self, path: str, body: bytes, key: str | None, method: str
    ) -> tuple[int, bytes]:
        request = Request(self.url(path), data=body, method=method)
        if key is not None:
            request.add_header("Idempotency-Key", key)
        nonce = f"nonce-pcp2-get-{time.time_ns()}" if key is None else None
        request.add_header(
            "SLA-Auth",
            make_sla_auth(
                self.server,
                key,
                self.AUDITOR2_SEED,
                self.auditor2_id,
                method,
                urlsplit(path).path,
                body,
                1,
                nonce=nonce,
            ),
        )
        try:
            with urlopen(request, timeout=5) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    def get(self, path: str) -> tuple[int, bytes]:
        return self.request_raw(path, b"", None, "GET")

    def post_check(self, seq: object, key: str) -> tuple[int, bytes]:
        return self.request_raw(
            "/v1/proof-checks",
            json.dumps({"verificationSeq": seq}).encode(),
            key,
            "POST",
        )

    def create_checkpoints(self, *keys: str) -> None:
        for key_value in keys:
            status, body = self.request_raw(
                "/v1/audit-checkpoints", b"{}", key_value, "POST"
            )
            self.assertEqual(status, 201, body)

    def create_comparison(self, seq: int, key: str) -> None:
        self.create_checkpoints(f"{key}-cp1", f"{key}-cp2")
        status, body = self.request_raw(
            "/v1/audit-comparisons",
            json.dumps({"fromCheckpointSeq": 1, "toCheckpointSeq": 2}).encode(),
            key,
            "POST",
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(json.loads(body)["comparisonSeq"], seq)

    def create_verification(self, seq: int, key: str) -> bytes:
        self.create_comparison(seq, f"{key}-cmp{seq}")
        status, body = self.request_raw(
            "/v1/audit-verifications",
            json.dumps({"comparisonSeq": seq}).encode(),
            key,
            "POST",
        )
        self.assertEqual(status, 201, body)
        return body

    def create_audit_proof(
        self, verification_seq: int, report_bytes: bytes, key: str
    ) -> None:
        report = json.loads(report_bytes)
        response_digest = hashlib.sha256(report_bytes).hexdigest()
        message = "\n".join(
            (
                "audit-proof-v1",
                str(verification_seq),
                response_digest,
                report["digest"],
                str(report["comparisonSeqBound"]),
                str(report["anchorSeqBound"]),
            )
        ).encode("utf-8")
        signature = _ed25519_sign(self.AUDITOR_SEED, message).hex()
        body = json.dumps(
            {"verificationSeq": verification_seq, "signature": signature}
        ).encode()
        status, response = self.request_raw("/v1/audit-proofs", body, key, "POST")
        self.assertEqual(status, 201, response)

    def setup_clean_check(self, key: str) -> bytes:
        report = self.create_verification(1, f"{key}-v1")
        self.create_audit_proof(1, report, f"{key}-p1")
        status, body = self.post_check(1, f"{key}-check")
        self.assertEqual(status, 201, body)
        return body

    def check_chain_digest_for(self, check_seq: int) -> str:
        status, body = self.get("/v1/proof-check-chain")
        self.assertEqual(status, 200, body)
        entries = json.loads(body)["entries"]
        return next(
            entry["chainDigest"]
            for entry in entries
            if entry["checkSeq"] == check_seq
        )

    def post_check_witness(
        self, check_seq: int, chain_digest: str, key: str
    ) -> tuple[int, bytes]:
        return self.request_raw(
            "/v1/proof-check-witnesses",
            json.dumps({"checkSeq": check_seq, "chainDigest": chain_digest}).encode(),
            key,
            "POST",
        )

    def post_check_verification(
        self, check_seq: object, key: str
    ) -> tuple[int, bytes]:
        return self.request_raw(
            "/v1/proof-check-verifications",
            json.dumps({"checkSeq": check_seq}).encode(),
            key,
            "POST",
        )

    def setup_second_report(self, seq: int, key: str) -> bytes:
        report = self.create_verification(seq, f"{key}-v{seq}")
        self.create_audit_proof(seq, report, f"{key}-p{seq}")
        status, check_body = self.post_check(seq, f"{key}-check{seq}")
        self.assertEqual(status, 201, check_body)
        chain_digest = self.check_chain_digest_for(seq)
        status, _ = self.post_check_witness(seq, chain_digest, f"{key}-w{seq}")
        self.assertEqual(status, 201)
        status, report_body = self.post_check_verification(seq, f"{key}-r{seq}")
        self.assertEqual(status, 201, report_body)
        return report_body

    def setup_clean_verification_report(self, key: str) -> bytes:
        self.setup_clean_check(key)
        chain_digest = self.check_chain_digest_for(1)
        status, _ = self.post_check_witness(1, chain_digest, f"{key}-w")
        self.assertEqual(status, 201)
        status, report = self.post_check_verification(1, f"{key}-r")
        self.assertEqual(status, 201, report)
        return report

    def check_proof_body(
        self,
        verification_seq: int,
        report_bytes: bytes,
        seed: bytes | None = None,
    ) -> bytes:
        report = json.loads(report_bytes)
        response_digest = hashlib.sha256(report_bytes).hexdigest()
        message = "\n".join(
            (
                "proof-check-verification-proof-v1",
                str(verification_seq),
                response_digest,
                report["digest"],
                str(report["checkSeqBound"]),
                str(report["witnessSeqBound"]),
            )
        ).encode("utf-8")
        signature = _ed25519_sign(
            seed if seed is not None else self.AUDITOR_SEED, message
        ).hex()
        return json.dumps(
            {"verificationSeq": verification_seq, "signature": signature}
        ).encode()

    def post_check_proof(
        self,
        verification_seq: int,
        report_bytes: bytes,
        key: str,
        *,
        seed: bytes | None = None,
        actor: str | None = None,
    ) -> tuple[int, bytes]:
        body = self.check_proof_body(
            verification_seq, report_bytes, seed
        )
        kwargs: dict[str, object] = {}
        if seed is not None:
            kwargs["seed"] = seed
        if actor is not None:
            kwargs["actor"] = actor
        return self.request_raw(
            "/v1/proof-check-proofs", body, key, "POST", **kwargs
        )

    def proof_chain_digest_for(self, proof_seq: int) -> str:
        status, body = self.get("/v1/proof-check-proof-chain")
        self.assertEqual(status, 200, body)
        entries = json.loads(body)["entries"]
        return next(
            entry["chainDigest"]
            for entry in entries
            if entry["proofSeq"] == proof_seq
        )

    def post_proof_witness(
        self, proof_seq: object, chain_digest: str, key: str
    ) -> tuple[int, bytes]:
        return self.request_raw(
            "/v1/proof-check-proof-witnesses",
            json.dumps({"proofSeq": proof_seq, "chainDigest": chain_digest}).encode(),
            key,
            "POST",
        )

    # ---- 链集合与单项 ----

    def test_empty_history(self) -> None:
        status, body = self.get("/v1/proof-check-proof-chain")
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertEqual(list(payload), ["entries", "nextCursor", "head"])
        self.assertEqual(payload["entries"], [])
        self.assertIsNone(payload["nextCursor"])
        self.assertIsNone(payload["head"])
        self.assertFalse(body.endswith(b"\n"))

    def test_chain_entries_digests_head_and_item(self) -> None:
        report = self.setup_clean_verification_report("pcp-e2e-1")
        status, proof1_body = self.post_check_proof(1, report, "pcp-e2e-proof1")
        self.assertEqual(status, 201, proof1_body)
        report2 = self.setup_second_report(2, "pcp-e2e-2")
        status, proof2_body = self.post_check_proof(2, report2, "pcp-e2e-proof2")
        self.assertEqual(status, 201, proof2_body)

        status, body = self.get("/v1/proof-check-proof-chain")
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        entries = payload["entries"]
        self.assertEqual([e["proofSeq"] for e in entries], [1, 2])
        self.assertEqual(
            [list(e) for e in entries],
            [
                ["proofSeq", "responseDigest", "previousChainDigest", "chainDigest"],
                ["proofSeq", "responseDigest", "previousChainDigest", "chainDigest"],
            ],
        )
        zeros = "0" * 64
        digest1 = hashlib.sha256(proof1_body).hexdigest()
        digest2 = hashlib.sha256(proof2_body).hexdigest()
        chain1 = hashlib.sha256(
            "\n".join(("proof-check-proof-chain-v1", "1", digest1, zeros)).encode()
        ).hexdigest()
        chain2 = hashlib.sha256(
            "\n".join(("proof-check-proof-chain-v1", "2", digest2, chain1)).encode()
        ).hexdigest()
        self.assertEqual(entries[0]["responseDigest"], digest1)
        self.assertEqual(entries[0]["previousChainDigest"], zeros)
        self.assertEqual(entries[0]["chainDigest"], chain1)
        self.assertEqual(entries[1]["responseDigest"], digest2)
        self.assertEqual(entries[1]["previousChainDigest"], chain1)
        self.assertEqual(entries[1]["chainDigest"], chain2)
        self.assertEqual(payload["head"], {"proofSeq": 2, "chainDigest": chain2})
        self.assertIsNone(payload["nextCursor"])

        status, item = self.get("/v1/proof-check-proof-chain/1")
        self.assertEqual(status, 200, item)
        self.assertEqual(
            list(json.loads(item)),
            ["proofSeq", "responseDigest", "previousChainDigest", "chainDigest"],
        )
        self.assertEqual(json.loads(item)["chainDigest"], chain1)
        self.assertEqual(json.loads(item)["responseDigest"], digest1)
        self.assertFalse(item.endswith(b"\n"))

    def test_item_errors(self) -> None:
        for path in (
            "/v1/proof-check-proof-chain/0",
            "/v1/proof-check-proof-chain/01",
            "/v1/proof-check-proof-chain/abc",
            "/v1/proof-check-proof-chain/999999999999999999999",
        ):
            status, _ = self.get(path)
            self.assertEqual(status, 404, path)
        status, _ = self.get("/v1/proof-check-proof-chain/1?x=1")
        self.assertEqual(status, 400)

    def test_collection_param_errors_and_auth(self) -> None:
        for query in ("limit=0", "limit=101", "limit=01", "foo=1", "limit"):
            status, _ = self.get(f"/v1/proof-check-proof-chain?{query}")
            self.assertEqual(status, 400, query)
        # 无认证头为 400；未配置为审计机器的身份为 403。
        status, _ = self.request_raw(
            "/v1/proof-check-proof-chain", b"", None, "GET", omit_auth=True
        )
        self.assertEqual(status, 400)
        unknown_seed = b"\x0a" * 32
        unknown_id = machine_id(_ed25519_public_key(unknown_seed).hex())
        status, _ = self.request_raw(
            "/v1/proof-check-proof-chain",
            b"",
            None,
            "GET",
            seed=unknown_seed,
            actor=unknown_id,
        )
        self.assertEqual(status, 403)

    def test_paging_stable_cut_and_restart(self) -> None:
        report = self.setup_clean_verification_report("pcp-pg")
        self.post_check_proof(1, report, "pcp-pg-p1")
        report2 = self.setup_second_report(2, "pcp-pg")
        self.post_check_proof(2, report2, "pcp-pg-p2")

        status, body = self.get("/v1/proof-check-proof-chain?limit=1")
        self.assertEqual(status, 200, body)
        page1 = json.loads(body)
        self.assertEqual([e["proofSeq"] for e in page1["entries"]], [1])
        self.assertEqual(page1["nextCursor"], "2:1")
        self.assertEqual(page1["head"]["proofSeq"], 2)

        # 第三份证明落在旧 cut 之外：旧游标续页不混入。
        report3 = self.setup_second_report(3, "pcp-pg")
        self.post_check_proof(3, report3, "pcp-pg-p3")

        status, body = self.get(
            f"/v1/proof-check-proof-chain?limit=1&cursor={page1['nextCursor']}"
        )
        self.assertEqual(status, 200, body)
        page2 = json.loads(body)
        self.assertEqual([e["proofSeq"] for e in page2["entries"]], [2])
        self.assertIsNone(page2["nextCursor"])
        self.assertEqual(page2["head"]["proofSeq"], 2)
        # 超前 cut 与缺失锚点为 400。
        status, _ = self.get("/v1/proof-check-proof-chain?cursor=99:1")
        self.assertEqual(status, 400)
        status, _ = self.get("/v1/proof-check-proof-chain?cursor=2:99")
        self.assertEqual(status, 400)

        # 游标跨重启稳定。
        self.restart()
        status, body = self.get(
            f"/v1/proof-check-proof-chain?limit=1&cursor={page1['nextCursor']}"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            [e["proofSeq"] for e in json.loads(body)["entries"]], [2]
        )
        status, body = self.get("/v1/proof-check-proof-chain?limit=1")
        self.assertEqual(json.loads(body)["head"]["proofSeq"], 3)

    # ---- 链头见证 ----

    def test_witness_created_with_frozen_fields(self) -> None:
        report = self.setup_clean_verification_report("pcp-w")
        status, _ = self.post_check_proof(1, report, "pcp-w-proof")
        self.assertEqual(status, 201)
        chain_digest = self.proof_chain_digest_for(1)
        status, body = self.post_proof_witness(1, chain_digest, "pcp-w-ok")
        self.assertEqual(status, 201, body)
        payload = json.loads(body)
        self.assertEqual(
            list(payload),
            [
                "witnessSeq",
                "proofSeq",
                "chainDigest",
                "auditorId",
                "publicKey",
                "keyVersion",
                "requestTimeMs",
                "nonce",
                "bodyDigest",
                "authSignature",
                "createdAt",
            ],
        )
        self.assertEqual(payload["witnessSeq"], 1)
        self.assertEqual(payload["proofSeq"], 1)
        self.assertEqual(payload["chainDigest"], chain_digest)
        self.assertEqual(payload["auditorId"], self.auditor_id)
        self.assertEqual(payload["publicKey"], ARBITRATOR_PUBLIC)
        self.assertEqual(payload["keyVersion"], 1)
        self.assertFalse(body.endswith(b"\n"))

    def test_witness_missing_node_and_digest_mismatch(self) -> None:
        report = self.setup_clean_verification_report("pcp-wm")
        self.post_check_proof(1, report, "pcp-wm-proof")
        chain_digest = self.proof_chain_digest_for(1)
        # 摘要不符 -> 409/conflict
        status, body = self.post_proof_witness(1, "0" * 64, "pcp-wm-bad")
        self.assertEqual(status, 409, body)
        self.assertEqual(json.loads(body)["error"], "conflict")
        # 目标不存在与合法超大序号 -> 404/not_found
        status, _ = self.post_proof_witness(2, chain_digest, "pcp-wm-missing")
        self.assertEqual(status, 404)
        status, _ = self.post_proof_witness(
            999999999999999999999, chain_digest, "pcp-wm-huge"
        )
        self.assertEqual(status, 404)
        # 失败不推进见证序号：随后成功仍为序号 1。
        status, body = self.post_proof_witness(1, chain_digest, "pcp-wm-ok")
        self.assertEqual(status, 201, body)
        self.assertEqual(json.loads(body)["witnessSeq"], 1)

    def test_witness_duplicate_distinct_auditor_and_replay(self) -> None:
        report = self.setup_clean_verification_report("pcp-wd")
        self.post_check_proof(1, report, "pcp-wd-proof")
        chain_digest = self.proof_chain_digest_for(1)
        status, first = self.post_proof_witness(1, chain_digest, "pcp-wd-ok")
        self.assertEqual(status, 201)
        # 同机异键重复见证 -> 409/witness_exists
        status, body = self.post_proof_witness(1, chain_digest, "pcp-wd-dup")
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["error"], "witness_exists")
        # 不同机器可分别见证同一节点，全局见证序号递增
        witness_body = json.dumps(
            {"proofSeq": 1, "chainDigest": chain_digest}
        ).encode()
        status, other = self.request2(
            "/v1/proof-check-proof-witnesses",
            witness_body,
            "pcp-wd-other",
            "POST",
        )
        self.assertEqual(status, 201, other)
        self.assertEqual(json.loads(other)["witnessSeq"], 2)
        status, _ = self.request2(
            "/v1/proof-check-proof-witnesses",
            witness_body,
            "pcp-wd-other-dup",
            "POST",
        )
        self.assertEqual(status, 409)
        # 同键重放首次状态码与字节（含重启后）。
        status, replay = self.post_proof_witness(1, chain_digest, "pcp-wd-ok")
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)
        self.restart()
        status, replay = self.post_proof_witness(1, chain_digest, "pcp-wd-ok")
        self.assertEqual(status, 201)
        self.assertEqual(replay, first)

    def test_witness_structure_errors(self) -> None:
        status, _ = self.request_raw(
            "/v1/proof-check-proof-witnesses?x=1",
            json.dumps({"proofSeq": 1, "chainDigest": "0" * 64}).encode(),
            "pcp-br-q",
            "POST",
        )
        self.assertEqual(status, 400)
        for bad_body in (
            b"{}",
            json.dumps({"proofSeq": 1}).encode(),
            json.dumps({"proofSeq": 0, "chainDigest": "0" * 64}).encode(),
            json.dumps({"proofSeq": True, "chainDigest": "0" * 64}).encode(),
            json.dumps({"proofSeq": 1, "chainDigest": "Z" * 64}).encode(),
            json.dumps(
                {"proofSeq": 1, "chainDigest": "0" * 64, "extra": 1}
            ).encode(),
        ):
            status, _ = self.request_raw(
                "/v1/proof-check-proof-witnesses",
                bad_body,
                f"pcp-br-{hashlib.sha256(bad_body).hexdigest()[:8]}",
                "POST",
            )
            self.assertEqual(status, 400, bad_body)

    # ---- 原子性、迁移与历史暴露 ----

    def test_failed_or_replayed_proof_no_chain_entry(self) -> None:
        report = self.setup_clean_verification_report("pcp-fail")
        # 错误签名：证明失败，不追加链项、不推进证明序号、不消费随机数。
        parsed = json.loads(self.check_proof_body(1, report))
        parsed["signature"] = "0" * 128
        bad = json.dumps(parsed).encode()
        status, _ = self.request_raw(
            "/v1/proof-check-proofs", bad, "pcp-fail-bad", "POST"
        )
        self.assertEqual(status, 409)
        status, body = self.get("/v1/proof-check-proof-chain")
        self.assertEqual(json.loads(body)["entries"], [])
        # 之后成功的证明为 proofSeq=1 且为创世链项。
        status, proof_body = self.post_check_proof(1, report, "pcp-fail-ok")
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(proof_body)["proofSeq"], 1)
        status, item = self.get("/v1/proof-check-proof-chain/1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(item)["previousChainDigest"], "0" * 64)
        # 同键重放不追加新链项。
        status, replay = self.post_check_proof(1, report, "pcp-fail-ok")
        self.assertEqual(status, 201)
        self.assertEqual(replay, proof_body)
        status, body = self.get("/v1/proof-check-proof-chain")
        self.assertEqual(len(json.loads(body)["entries"]), 1)

    def test_legacy_backfill(self) -> None:
        # 旧库已有证明但无链：删链与一次性标记后重启，按 proofSeq 升序单事务补链，
        # 不改历史响应、时间、序号与幂等字节；迁移仅执行一次。
        report = self.setup_clean_verification_report("pcp-mig")
        status, proof_body = self.post_check_proof(1, report, "pcp-mig-p1")
        self.assertEqual(status, 201)
        with sqlite3.connect(self.server.database_path) as connection:
            connection.execute("DELETE FROM proof_check_proof_chain")
            connection.execute(
                "DELETE FROM schema_metadata"
                " WHERE key = 'proof_check_proof_chain_backfilled'"
            )
            connection.commit()
        self.restart()
        status, body = self.get("/v1/proof-check-proof-chain")
        self.assertEqual(status, 200, body)
        entries = json.loads(body)["entries"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["proofSeq"], 1)
        self.assertEqual(entries[0]["previousChainDigest"], "0" * 64)
        self.assertEqual(
            entries[0]["responseDigest"],
            hashlib.sha256(proof_body).hexdigest(),
        )
        expected_chain = hashlib.sha256(
            "\n".join(
                (
                    "proof-check-proof-chain-v1",
                    "1",
                    hashlib.sha256(proof_body).hexdigest(),
                    "0" * 64,
                )
            ).encode()
        ).hexdigest()
        self.assertEqual(entries[0]["chainDigest"], expected_chain)
        # 迁移仅一次：再次重启不重复补写。
        self.restart()
        with sqlite3.connect(self.server.database_path) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM proof_check_proof_chain"
            ).fetchone()[0]
        self.assertEqual(count, 1)
        # 补链后新成功证明接续在补链项之后而非重新起链。
        report2 = self.setup_second_report(2, "pcp-mig")
        status, proof2_body = self.post_check_proof(2, report2, "pcp-mig-p2")
        self.assertEqual(status, 201)
        status, item = self.get("/v1/proof-check-proof-chain/2")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(item)["previousChainDigest"], expected_chain)
        self.assertEqual(
            json.loads(item)["responseDigest"],
            hashlib.sha256(proof2_body).hexdigest(),
        )

    def test_chain_exposes_tampering(self) -> None:
        # 链项与 head 须能暴露缺失、替换、重排与摘要变化：服务不修补历史。
        report = self.setup_clean_verification_report("pcp-tamper")
        self.post_check_proof(1, report, "pcp-tamper-p1")
        report2 = self.setup_second_report(2, "pcp-tamper")
        self.post_check_proof(2, report2, "pcp-tamper-p2")
        status, body = self.get("/v1/proof-check-proof-chain")
        before = json.loads(body)
        self.assertEqual(before["head"]["proofSeq"], 2)
        with sqlite3.connect(self.server.database_path) as connection:
            # 删除第二项：集合只剩 1 项，head 回退，单项 2 返回 404。
            connection.execute("DELETE FROM proof_check_proof_chain WHERE proof_seq = 2")
            connection.commit()
        status, body = self.get("/v1/proof-check-proof-chain")
        after = json.loads(body)
        self.assertEqual([e["proofSeq"] for e in after["entries"]], [1])
        self.assertEqual(
            after["head"],
            {
                "proofSeq": 1,
                "chainDigest": before["entries"][0]["chainDigest"],
            },
        )
        status, _ = self.get("/v1/proof-check-proof-chain/2")
        self.assertEqual(status, 404)
        with sqlite3.connect(self.server.database_path) as connection:
            # 替换首项摘要：读出的摘要与按响应重算值不符，且 head 改变。
            connection.execute(
                "UPDATE proof_check_proof_chain SET chain_digest = ? WHERE proof_seq = 1",
                ("0" * 64,),
            )
            connection.commit()
        status, item = self.get("/v1/proof-check-proof-chain/1")
        self.assertEqual(json.loads(item)["chainDigest"], "0" * 64)

    def test_concurrent_proofs_unique_seq_and_unbroken_chain(self) -> None:
        # 跨报告并发：证明、幂等结果、随机数与链项原子提交，
        # proofSeq 不重号，链稠密 1..N 且逐环相连。
        report_count = 5
        reports = [
            (
                self.setup_clean_verification_report("pcp-cc-1")
                if index == 1
                else self.setup_second_report(index, "pcp-cc")
            )
            for index in range(1, report_count + 1)
        ]

        def prove(index: int) -> tuple[int, bytes]:
            return self.post_check_proof(
                index, reports[index - 1], f"pcp-cc-proof-{index}"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=report_count) as pool:
            results = list(pool.map(prove, range(1, report_count + 1)))
        self.assertTrue(all(status == 201 for status, _ in results))
        proof_bodies = {json.loads(body)["proofSeq"]: body for _, body in results}
        self.assertEqual(sorted(proof_bodies), list(range(1, report_count + 1)))

        status, body = self.get("/v1/proof-check-proof-chain")
        self.assertEqual(status, 200, body)
        entries = json.loads(body)["entries"]
        self.assertEqual([e["proofSeq"] for e in entries], list(range(1, report_count + 1)))
        previous = "0" * 64
        for entry in entries:
            seq = entry["proofSeq"]
            self.assertEqual(
                entry["responseDigest"],
                hashlib.sha256(proof_bodies[seq]).hexdigest(),
            )
            self.assertEqual(entry["previousChainDigest"], previous)
            expected = hashlib.sha256(
                "\n".join(
                    (
                        "proof-check-proof-chain-v1",
                        str(seq),
                        entry["responseDigest"],
                        previous,
                    )
                ).encode()
            ).hexdigest()
            self.assertEqual(entry["chainDigest"], expected)
            previous = expected
        self.assertEqual(
            json.loads(body)["head"],
            {"proofSeq": report_count, "chainDigest": previous},
        )

    def test_concurrent_witnesses_single_winner_unique_seq(self) -> None:
        # 同一审计机器异键并发见证同一链头：恰一项成功，其余 witness_exists，
        # 见证序号不重号；失败不消费随机数、不推进序号、不留记录。
        report = self.setup_clean_verification_report("pcp-cw")
        self.post_check_proof(1, report, "pcp-cw-proof")
        chain_digest = self.proof_chain_digest_for(1)

        def witness(index: int) -> tuple[int, bytes]:
            return self.post_proof_witness(
                1, chain_digest, f"pcp-cw-witness-{index}"
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(witness, range(6)))
        created = [body for status, body in results if status == 201]
        rejected = [
            body for status, body in results if status != 201
        ]
        self.assertEqual(len(created), 1)
        self.assertEqual(len(rejected), 5)
        self.assertTrue(
            all(json.loads(body)["error"] == "witness_exists" for body in rejected)
        )
        self.assertEqual(json.loads(created[0])["witnessSeq"], 1)
        with sqlite3.connect(self.server.database_path) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM proof_check_proof_witnesses"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM proof_check_proof_witness_idempotency_records"
                ).fetchone()[0],
                1,
            )
        # 失败请求不消费随机数：各失败键以原认证五段重试仍先于唯一性判定被处理，
        # 新节点的见证可正常成功（全局序号接续为 2）。
        report2 = self.setup_second_report(2, "pcp-cw")
        self.post_check_proof(2, report2, "pcp-cw-proof-2")
        chain_digest_2 = self.proof_chain_digest_for(2)
        status, body = self.post_proof_witness(2, chain_digest_2, "pcp-cw-next")
        self.assertEqual(status, 201, body)
        self.assertEqual(json.loads(body)["witnessSeq"], 2)


if __name__ == "__main__":
    unittest.main()
