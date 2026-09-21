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
- `POST /v1/machines`：登记机器身份。请求须携带 `Idempotency-Key` 头（`[A-Za-z0-9-]{1,64}`），JSON 请求体仅含 `publicKey`（`[0-9a-f]{64}`）。`id` 为 `SHA-256(bytes.fromhex(publicKey))` 的小写十六进制。首次登记返回 `201`；同键同 `publicKey` 重放返回 `200`；同键异 `publicKey` 返回 `409`/`idempotency_conflict`；异键同 `id` 返回 `409`/`machine_exists`。登记与幂等记录在同一原子提交中持久化，重启后重放语义不变。
- `POST /v1/machines/{id}/capabilities`：为已登记机器声明能力。请求须携带 `Idempotency-Key` 头（格式同上），JSON 请求体恰含 `expectedVersion`（非布尔整数 `0..2147483646`）、`name`（`[a-z0-9-]{1,32}`）、`protocol`（`http|mqtt`）、`region`（`cn|eu|us`）、`unit`（`call|byte|ms`）、`capacity`（非布尔整数 `1..2147483647`），键不得重复或缺失。`protocol`、`region`、`unit` 必须为字符串（数组、对象等非字符串值返回 `400`，不断连）。首次声明仅接受 `expectedVersion: 0`，原子写入版本 `1` 并返回 `201`；更新须匹配当前版本，原子加一并返回 `200`。成功体仅 `{"version":新版本}`。判定顺序为头、体、幂等记录、机器、版本：头或体非法返回 `400`/`invalid_request`；同键异 `id` 或异字段返回 `409`/`conflict`（即使 `id` 未登记）；无幂等记录且机器不存在返回 `404`/`not_found`；版本不符返回 `409`/`conflict`。同键同请求重放（含并发与重启后）返回首次状态码与响应字节，仅写入一次；异键竞争同一机器版本仅一项成功。声明与幂等结果原子持久化，失败不留记录。
- `POST /v1/sla-templates`：为机器当前能力版本创建 SLA 模板。请求须携带 `Idempotency-Key` 头（格式同上），JSON 请求体仅含且不得重复 `id`（`[a-z0-9-]{1,64}`）、`machineId`（`[0-9a-f]{64}`）、`capabilityVersion`（非布尔整数 `1..2147483647`）、`priceMicros`（非布尔整数 `0..2147483647`）、`maxLatencyMs`（非布尔整数 `1..2147483647`）。机器须已登记，且其能力当前版本等于 `capabilityVersion`。首次创建原子返回 `201`，正文仅 `{"id":请求id}`。判定顺序为头、体、幂等记录、机器、能力版本、id：头或体非法返回 `400`/`invalid_request`；同键异请求返回 `409`/`conflict`；机器不存在返回 `404`/`not_found`；无能力或版本不符返回 `409`/`conflict`；id 已存在返回 `409`/`template_exists`。同键同请求并发或重启后重放首次响应字节与状态码；创建与幂等记录原子持久化，失败不留记录；异键同 id 并发仅一项成功。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

所有时间均使用 UTC。HTTP 响应使用 JSON，未知路由返回 JSON 格式的 `404`。

