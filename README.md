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
- `POST /v1/slas`：基于 SLA 模板为消费者创建 SLA。请求须携带 `Idempotency-Key` 头（格式同上），JSON 请求体仅含且不得重复 `id`（`[a-z0-9-]{1,64}`）、`templateId`（格式同 `id`）、`consumerId`（`[0-9a-f]{64}`）、`start`、`end`（均为非布尔整数 `0..2147483647`，UTC Unix 秒，且 `start < end`）。模板须存在、其机器当前能力版本等于模板绑定版本、消费者已登记；首次创建原子保存请求与模板快照，初态 `pending`，返回 `201`，正文仅 `{"id":请求id}`。判定顺序为头、体、幂等记录、模板、能力版本、消费者、id：头或体非法返回 `400`/`invalid_request`；同键异请求、模板缺失或版本失效返回 `409`/`conflict`；消费者缺失返回 `404`/`not_found`；异键同 id 返回 `409`/`sla_exists`。同键同请求并发或重启后重放首次响应字节与状态码；创建与幂等记录原子持久化，失败不留记录；异键同 id 并发仅一项成功。
- `POST /v1/slas/{id}/confirmations`：生产方或消费方确认 SLA。请求须携带 `Idempotency-Key` 头（格式同上），JSON 请求体仅含且不得重复 `party`（`producer|consumer`）、`actorId`（`[0-9a-f]{64}`）；`producer` 的 `actorId` 须等于快照中的 `machineId`，`consumer` 的 `actorId` 须等于快照中的 `consumerId`。事务取 UTC Unix 整秒 `now`，仅当 `start<=now<end` 且生产者能力当前版本等于快照版本时接受。每方限一次：首方确认后仍为 `pending`，第二方确认原子转为 `active`。成功返回 `200`，正文仅 `{"state":"pending"}` 或 `{"state":"active"}`。判定顺序为幂等头、体、幂等记录、SLA、参与方、重复方、时间/版本：头或体非法返回 `400`/`invalid_request`；同键异 id 或异体返回 `409`/`conflict`；SLA 不存在返回 `404`/`not_found`；`party` 与 `actorId` 不符返回 `403`/`forbidden`；异键同方重复确认返回 `409`/`already_confirmed`；时间窗外或版本不符返回 `409`/`conflict`。同键同请求并发或重启后重放首次状态码与响应字节；确认、幂等记录与状态变更在同一事务中持久化，失败不留任何记录或确认；异键并发每方至多成功一次且 `active` 仅转换一次。
- `GET /v1/slas/{id}`：返回 `200`，正文键序为 `id,templateId,machineId,consumerId,capabilityVersion,priceMicros,maxLatencyMs,start,end,state`，同名值取创建时请求或模板快照，`state` 为 `pending` 或双方确认后的 `active`。无记录（含非法 id）返回 `404`/`not_found`。
- `POST /v1/slas/{id}/telemetry`：为 active 状态的 SLA 写入一条遥测事件。请求须携带 `Idempotency-Key` 头（格式同上），JSON 请求体仅含且不得重复 `eventId`（`[a-z0-9-]{1,64}`）、`timestamp`（非布尔整数 `0..2147483647999`，UTC Unix 毫秒）、`latencyMs`（非布尔整数 `0..2147483647`）、`digest`（`[0-9a-f]{64}`）。`digest` 等于 UTF-8 字符串 `id\neventId\ntimestamp\nlatencyMs\nmachineId` 的 SHA-256（整数为无前导零十进制，`machineId` 取 SLA 快照）。仅当 SLA 为 `active` 且 `start*1000<=timestamp<end*1000` 时接受。首次原子写入事件及幂等结果，返回 `201`，正文仅 `{"eventId":请求值}`。判定顺序为头、体、幂等记录、SLA、状态/时间、摘要、eventId：头或体非法返回 `400`/`invalid_request`；同键异 id 或异体返回 `409`/`conflict`；SLA 不存在返回 `404`/`not_found`；非 active、时间越界或摘要错误返回 `409`/`conflict`；异键重复 eventId 返回 `409`/`event_exists`。同键同请求并发或重启后重放首次状态码与响应字节；事件、幂等结果与提交序号原子持久化，失败不留记录；异键同 eventId 并发仅一项成功。全库共享持久化提交序号：空库首个事件为 `1`，首次成功请求的 `commit_seq` 等于提交前全库最大值加一且全库唯一，失败或同键重放不推进序号，跨 SLA 并发不得重复。迁移旧库时，在单事务内按 `sla_telemetry_events.rowid` 升序将既有事件重编号为 `1..N` 并写入一次性迁移标记；事件内容与幂等记录不得改变，重启后不得再次重编号。
- `GET /v1/slas/{id}/telemetry`：分页读取 SLA 遥测事件。查询参数仅允许且每项限单值 `from`、`to`、`limit`、`cursor`；`from`、`to` 必填，为无前导零十进制整数且 `0<=from<to<=2147483648000`；`limit` 缺省 `50`、范围 `1..100`。缺项、未知/重复参数、格式或范围非法均为 `400`/`invalid_request`；SLA 不存在（含非法 id）为 `404`/`not_found`。无 `cursor` 时，在同一读事务起点取全库最大提交序号为 `cut`（空库为 `0`），只读目标 SLA 内 `commit_seq<=cut` 且 `timestamp∈[from,to)` 的事件，按 `timestamp,eventId` 升序；`events` 与 `summary` 始终只含目标 SLA 的事件，其他 SLA 的提交仅推进后续首页的 `cut`。`cursor=cut:lastTimestamp:lastEventId`（数字无前导零）：续页沿用游标携带的 `cut`，并发新增或重启均不改变其快照；锚点事件须属于目标 SLA、`commit_seq<=cut` 且位于当前 `[from,to)` 区间；`cut` 大于当前全库最大序号、锚点事件不存在或不匹配均为 `400`/`invalid_request`。成功为 `200`，正文键序 `events,summary,nextCursor`：`events` 为对象数组，元素键序 `eventId,timestamp,latencyMs,digest`；`summary` 键序 `count,latencySum,maxLatency,violations`，依次为整个 `cut` 区间（非仅当前页）的事件数、延迟和、最大延迟（空为 `null`）、延迟严格大于 SLA 快照 `maxLatencyMs` 的事件数，非 null 值均为非负整数。有后页时 `nextCursor` 取本页末事件游标，否则为 `null`。`cut` 由游标携带并跨重启稳定；读取期间的并发新增不影响续页与汇总（全新首页才取新 `cut`）。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

所有时间均使用 UTC。HTTP 响应使用 JSON，未知路由返回 JSON 格式的 `404`。

