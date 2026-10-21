# 中台管理 API v1

在“系统设置 → 管理 API”创建密钥，选择权限和有效期。默认只读，有效期 30 天，可设 1–365 天。完整密钥仅在创建时返回一次；服务端只保存 SHA-256 摘要。撤销立即生效，重启后仍保持。此密钥与业务隧道令牌分开。

入口：`https://datahub.chitanda.net/tunnel/api/v1`。来源限制与现有管理面板一致，未开放额外公网 IP。其他部署使用自己的面板域名。业务数据仍通过原 HTTPS 隧道入口收发。

```bash
export CHITANDA_MANAGEMENT_KEY='填写管理API密钥'
curl --fail-with-body \
  -H "Authorization: Bearer ${CHITANDA_MANAGEMENT_KEY}" \
  'https://datahub.chitanda.net/tunnel/api/v1/status'
```

所有请求使用 Bearer 密钥；写入使用 `Content-Type: application/json`。需要空请求体的写入操作也发送 `{}`。无需 Cookie 或 CSRF 值；管理面板原有会话及 CSRF 规则不变。

登录面板后可打开 [API 文档与权限](https://datahub.chitanda.net/tunnel/api-docs)，展开接口查看参数，并填写管理密钥测试状态、节点及隧道查询。密钥仅保留在当前页面，刷新或关闭后清除。测试请求只使用填写的密钥，不借用管理员登录权限。

原始 OpenAPI JSON：`/tunnel/api/management-openapi?format=json`（管理员会话），或 `/tunnel/api/v1/openapi.json`（管理 API 密钥）。浏览器打开旧文档地址时会自动进入可读文档页；程序以 JSON 请求时返回格式不变。

## 权限与接口

| 方法与相对路径 | 权限 | 用途 |
| --- | --- | --- |
| GET `/status` | `status:read` | 版本、配置版本、节点和隧道数量 |
| GET `/nodes`、`/nodes/{id}` | `nodes:read` | 节点列表和运行状态 |
| POST `/nodes` | `nodes:write` | 创建节点，身份自动分配 |
| PATCH `/nodes/{id}` | `nodes:write` | 修改名称、已管理的证书根域名 |
| DELETE `/nodes/{id}` | `nodes:write` | 删除节点；有隧道关联时默认返回 409 |
| GET `/tunnels`、`/tunnels/{id}` | `tunnels:read` | 隧道及各方向的线路和测活状态 |
| POST `/tunnels` | `tunnels:write` | 创建隧道 |
| PATCH `/tunnels/{id}` | `tunnels:write` | 修改配置、暂停或启用 |
| DELETE `/tunnels/{id}` | `tunnels:write` | 删除；已发布域名的保护规则与面板相同 |
| PUT `/tunnels/{id}/http` | `tunnels:write` | 更新各方向允许的业务地址 |
| GET `/ports/available?nodeId=...` | `nodes:read` | 选择空闲入口端口，可传 preferred、routeId、多个 avoid |
| POST `/routes/{id}/test` | `checks:write` | 发起测活，返回 202 |
| GET `/routes/{id}/check` | `status:read` | 查询测活结果及节点是否就绪 |
| GET `/openapi.json` | 任一有效管理密钥 | OpenAPI 3.1 文档 |

列表返回 `{ "items": [...], "revision": 119 }`，单个资源返回对应对象。配置版本数字由实际状态决定，不能写死。节点 ID 和隧道 ID 通过创建响应或列表获取；测活使用隧道的 `routeIds`，双向分别测试。

API 不返回节点凭据、证书私钥、管理密码或业务隧道令牌，也不能创建其他 API 密钥。安装指令、账号、证书来源、DNS 凭据及密钥管理保留在已登录的面板内。

## 常用写入

创建节点：

```json
{"name":"国内节点","purpose":"mainland"}
```

purpose 可选 `mainland`（国内隧道）、`international`（国际入口）、`relay`（优化机）。优化机可附 `port` 和 `serverName`。创建后在面板获取安装指令。

创建双向隧道时 POST `/tunnels`：

```json
{
  "name":"业务同步",
  "mode":"bidirectional",
  "source":"填国内节点ID",
  "target":"填国际节点ID",
  "relayIds":["填优化机ID"],
  "transport":"h2",
  "listenPort":15081,
  "targetPort":5081,
  "reverseListenPort":15082,
  "reverseTargetPort":5081
}
```

`relayIds: []` 表示两端直连；多个 ID 按顺序串联。单向用 `mode: "single"`，无需反向端口。协议可选 `h2`、`h3`、`stream`；可用性取决于节点版本和网络。URL 请求模式在创建后通过 `/http` 配置。

暂停：

```bash
curl --fail-with-body -X PATCH \
  -H "Authorization: Bearer ${CHITANDA_MANAGEMENT_KEY}" \
  -H 'Content-Type: application/json' \
  --data '{"enabled":false}' \
  'https://datahub.chitanda.net/tunnel/api/v1/tunnels/填写隧道ID'
```

`enabled` 和 `cascade` 必须为 JSON 布尔值，不能传字符串。重复暂停已暂停的隧道不会再次增加配置版本。删除节点时 `{"cascade":true}` 会清理关联隧道及凭据，同时需要 `nodes:write` 和 `tunnels:write`，已绑定域名仍需先处理。

配置生效与面板一致：节点周期同步最新完整配置，离线恢复后补同步。HTTP 写入成功表示中台已接受，检查返回的配置版本与各节点版本确认落地。测活提交后需查询结果，202 不代表测活通过。

## 限流、错误与审计

每密钥每分钟最多 120 次读取、30 次写入；每来源 IP 每分钟总计 240 次请求。超限返回 429 和 Retry-After。只读权限不会隐含写入或测活权限；写入审计记录密钥的名称和 ID，不记录完整密钥。

400 参数错误，401 密钥无效/过期/撤销，403 来源或权限不允许，404 资源或方法不存在，409 资源冲突或保护规则，415 请求格式不符。程序应检查 HTTP 状态和 JSON 的 `error`。

创建操作暂不提供幂等键；网络中断后先查询列表确认结果，避免直接重试而重复创建。暂停状态更新可安全重复。不要把完整密钥写入公共脚本或日志。

登录面板后打开 `/tunnel/api-docs` 查看文档与权限说明；原始 JSON 使用 `/tunnel/api/management-openapi?format=json`。文档入口仍要求管理员会话。
