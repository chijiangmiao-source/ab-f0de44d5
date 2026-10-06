# 深空地面站 · 终端授权族凭证轮换

操作员在页面上创建**绑定终端标识的授权族**，凭当前刷新凭证与**稳定轮换标识**
发起轮换；服务对同标识重传（含服务重启、并发）严格幂等，并对异标识重放
已轮换凭证执行整族撤销。纯 Python 标准库实现，SQLite 持久化。

## 运行

```bash
# 默认宿主机端口 8080（可用 HOST_PORT 配置）
HOST_PORT=8080 docker compose up -d --build
# 打开 http://localhost:8080/

# 启用“提交后断回应”故障注入（每进程首次轮换触发一次）
RESPONSE_FAULT=1 docker compose up -d
```

健康检查：`GET /health` → `200 {"status":"ok",...}`，Compose 以该端点
做容器健康判定，宿主机通过可配置端口（`HOST_PORT`，默认 8080）访问。

## 操作语义

| 场景 | 结果 |
|---|---|
| 首次轮换（旧凭证有效 + 新 rotation_id） | `accepted`：展示唯一新凭证、代次 +1、仍可用 |
| 同旧凭证 + **同** rotation_id 重传（重启后/并发落败者亦然） | `replayed`：取回与首次**完全一致**的新凭证与代次，不再推进 |
| 已轮换旧凭证配**不同** rotation_id 再次使用 | `revoked`：返回并展示授权族撤销原因，整族撤销 |
| 撤销后再用此前发出的后继凭证 | 一律 `revoked` 拒绝（各代凭证逐行作废） |
| 提交后断回应（`RESPONSE_FAULT=1`） | 事务已落盘但无 HTTP 响应；重启后原样重传 → `replayed` 恢复已持久化后继，代次不重复推进 |

幂等键为 `(family_id, old_credential, rotation_id)`；所有推进在
`BEGIN IMMEDIATE` 单事务内完成（`synchronous=FULL`），故并发同标识
请求只有一个 `accepted`，其余全部观察到同一结果。

## 页面（`/`）

- 创建授权族（终端标识必填），一次性展示初始刷新凭证；
- 轮换卡片明确徽标 **接受 accepted / 重放 replayed / 已撤销 revoked**，
  展示唯一新凭证、代次、仍可用状态、轮换标识；
- 断回应时展示故障提示，引导原样重传恢复；
- 状态区呈现授权族撤销原因与当前可用状态。

## 验收（Compose verify）

```bash
docker compose --profile verify run --rm verify
```

`tests/verify.py`（仅标准库，退出码即验收结论）覆盖：

1. 代码层：接受 → 同标识重放恒定 → 重开库（模拟重启）后仍一致、
   代次不推进；异标识重放撤销整族并作废后继凭证；
2. HTTP/页面冒烟：`/health`、页面可观察标记（接受/重放/已撤销、
   新凭证、代次、可用、撤销原因、断回应提示）；
3. 8 路并发同标识：仅 1 个 accepted、7 个 replayed，同一新凭证、
   代次停在 1，重启后仍一致；
4. 断回应恢复：故障下首次请求收不到响应，重启后原标识重放恢复、
   代次仍为 1，且后继链路可继续推进到代次 2；
5. 异标识重放：返回 409 `revoked` 与撤销原因，状态接口同样呈现，
   此前后继凭证随后被拒绝；
6. 对 Compose 中运行的 `app` 容器再做一轮真实 API/HTTP 冒烟（`APP_URL`）。

本地无 Docker 时可直接运行：`python3 -m tests.verify`（自动起停本机
子进程完成全部故障/重启/并发场景；设置 `APP_URL` 可附加远端冒烟）。
