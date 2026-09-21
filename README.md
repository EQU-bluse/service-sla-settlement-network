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
- `POST /v1/machines/{id}/capabilities`：声明或更新机器能力，`id` 须为已登记机器。请求须携带 `Idempotency-Key` 头（格式同上）。JSON 请求体恰好包含 `expectedVersion,name,protocol,region,unit,capacity`（键不得重复）：`expectedVersion` 与 `capacity` 为非布尔整数，范围分别为 `0..2147483646`、`1..2147483647`；`name` 为 `[a-z0-9-]{1,32}`；`protocol` 为 `http|mqtt`；`region` 为 `cn|eu|us`；`unit` 为 `call|byte|ms`。首次声明仅接受 `expectedVersion=0`，原子写入版本 `1` 并返回 `201`；更新须匹配当前版本，原子加一并返回 `200`。成功响应体仅为 `{"version":新版本}`。头或体非法返回 `400`/`invalid_request`；已有同键记录而 `id` 或任一字段不同（即使 `id` 未登记）返回 `409`/`conflict`；无幂等记录且机器不存在返回 `404`/`not_found`；版本不符返回 `409`/`conflict`。同键同请求的并发或重启重放返回首次的状态码与响应字节，可产生多个相同 2xx 但只写一次；异键竞争同一机器版本仅一项成功。能力声明与幂等结果在同一原子提交中持久化，失败不产生记录。不提供 GET。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

所有时间均使用 UTC。HTTP 响应使用 JSON，未知路由返回 JSON 格式的 `404`。

