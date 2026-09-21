# Service SLA Settlement Network

面向 API、Agent 与设备协作的后端服务基线。系统将机器服务协议、可验证遥测、结算与争议处理组织为可审计的 HTTP 能力。

## 环境

- Python 3.12+
- SQLite（Python 标准库）

## 启动

```bash
python3 -m sla_network --host 127.0.0.1 --port 8080 --database var/service-sla.db
```

服务启动后提供：

- `GET /health`：返回 JSON 健康状态，成功响应为 `200`。
- `POST /v1/machines`：登记机器身份。请求须携带 `Idempotency-Key` 头（`[A-Za-z0-9-]{1,64}`），JSON 请求体仅含 `publicKey`（64 位小写十六进制）。`id` 为 `SHA-256(bytes.fromhex(publicKey))` 的十六进制摘要。首次登记返回 `201`；同键同 `publicKey` 重放返回 `200`；同键异 `publicKey` 返回 `409 idempotency_conflict`；异键同机器返回 `409 machine_exists`。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

所有时间均使用 UTC。HTTP 响应使用 JSON，未知路由返回 JSON 格式的 `404`。

