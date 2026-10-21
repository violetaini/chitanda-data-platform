# HTTPS 请求头接入

请求发往隧道 HTTPS 入口，用隧道令牌选择通道，用 `X-Target-URL` 指定真实业务的完整 HTTPS 地址。出口直接请求现有业务接口，保留方法、查询参数和请求体。

面板 2.20.3 的“使用指南”及隧道详情“URL 接入教程”按实际配置生成：先选择隧道、请求方向，有多个目标时再选择目标业务。入口地址、允许范围、curl 与 Chitanda 环境变量一起更新；切换教程不会修改隧道。未绑定、未启用或等待节点应用时会提示。本文域名仅用于演示，以面板生成的地址为准。

```bash
CHITANDA_TUNNEL_TOKEN='填写本隧道令牌'
curl --fail-with-body --connect-timeout 5 --max-time 30 \
  -H "Authorization: Bearer ${CHITANDA_TUNNEL_TOKEN}" \
  -H 'X-Target-URL: https://www.chitanda.net/api/sync/status' \
  'https://data-test.chitanda.net/'
```

上例读取对端 Chitanda 状态。令牌在对应隧道详情查看，请勿写入公共脚本；调用方还须符合入口来源权限。

```text
业务程序 → HTTPS 入口 → 按令牌选择隧道 → 出口节点
         → 按 X-Target-URL 请求真实业务域名 → 业务原有接口
```

出口使用真实业务域名设置 Host、TLS SNI，并验证公有证书，因此同一 IP 的多个网站可以正确区分。无需在业务源站另建转接服务或隧道专用网站。

## 面板配置

1. 两端安装或升级节点并创建隧道。节点之间可选 H2、H3 或 Stream，所选协议须在实际网络中可用。
2. 源节点须已有 HTTPS 入口和来源授权。在“系统设置 → SSL 证书”先添加根域名，再选择自动申请、DNS 面板同步或自行上传；三种模式均只接受对应泛域名证书。在节点管理中选择证书根域名并确认应用。一个入口可以服务多个隧道，由各自令牌区分；创建隧道不会自动开放防火墙。
3. 展开隧道详情，打开“URL 请求接入”，为每个方向填写允许的业务地址范围，例如 `https://www.chitanda.net/api/sync/`，保存后自动下发。
4. 在隧道详情查看或复制自动生成的隧道令牌。请求入口时携带该令牌和完整 `X-Target-URL`，目标必须落在该方向允许的域名、端口和路径范围内。
5. 打开“URL 接入教程”查看本隧道的实际示例。“前往当前隧道”可返回并展开对应配置。普通业务请使用真实存在的接口，不要假定服务提供 `/status`；指南仅在允许范围覆盖 Chitanda 状态接口时选择 `/api/sync/status`。

每方向可配置多个目标。范围 `/api/sync/` 允许自身及子路径，不允许 `/api/sync-other`。请求可以有查询参数，配置范围本身不接受查询参数。

“固定回源地址”通常留空，由出口解析业务域名。如果域名经过 CDN、地区解析或可能回到隧道入口，可集中指定实际源站的公开 `IP:端口`；Host、SNI 和证书验证仍使用业务域名。无需在每台业务服务器新增映射。

URL 模式不使用原始目标端口；关闭模式恢复原始 TCP 行为。原始 TCP 业务不使用 `X-Target-URL`。

## Chitanda 环境变量

```dotenv
CHITANDA_SYNC_PEERS=https://data-test.chitanda.net
CHITANDA_TUNNEL_TOKEN=本隧道令牌
CHITANDA_SYNC_TARGET=https://www.chitanda.net
```

客户端把原同步接口路径和查询参数拼到 SYNC_TARGET，通过 X-Target-URL 发送。CHITANDA_SYNC_TARGET 填目标站点地址，不填写同步接口路径。两端已配置相同域名的地区解析时可使用同一入口；否则分别使用各自可达的入口。目标同域名、源站不同 IP 时，在面板为各方向集中配置实际回源地址。保存业务环境后，需按原部署方式重启或重新加载 Chitanda 后台。现有服务端内部同步密钥可以保留，Chitanda 同步接口也支持同一个隧道令牌。

隧道详情重置令牌后会自动下发节点；使用该令牌的业务程序也必须同步修改并重新加载。离线节点恢复联系后应用最新配置。

兼容改动见 [请求头集成补丁](../integrations/chitanda-header-url.patch)，前一版见 [单令牌补丁](../integrations/chitanda-single-token.patch)。应用前检查本地差异，避免覆盖业务已有修改。

## 发送实际数据

URL 模式仍按业务原来的 HTTP 接口工作。比如 POST JSON：请求 URL 填隧道入口，请求头填令牌、完整 X-Target-URL 和 Content-Type，请求体填业务原有 JSON。方法、查询参数和载体交给目标接口处理；隧道不会创建业务接口或代替业务同步逻辑。大文件继续使用业务分片。

## 请求与权限

- Authorization Bearer 用于隧道鉴权，默认继续交给目标业务；目标服务仍负责业务权限。若业务需要另一项 Authorization，可用 `X-Target-Authorization`；出口用它替换并移除此辅助头。Chitanda 当前无需此项。
- Cookie、伪造转发地址、管理 CSRF 头及旧 X-Sync-Token 不转发给业务。不跟随重定向，304 保留。
- 只接受允许范围内的 HTTPS 域名，拒绝私网、回环、链路本地及元数据地址，保持 TLS 1.3 和证书验证。
- 单请求最大 16 MiB，入口并发上限 8。大文件使用业务分片；请求体与响应流式处理。不支持 WebSocket Upgrade、CONNECT 或 TRACE。

## 排查

| 现象 | 检查项 |
| --- | --- |
| 400 | 是否提供合法完整的 X-Target-URL |
| 401 | 当前隧道令牌、节点配置是否已应用，以及业务自身鉴权 |
| 403 | 入口来源权限、目标范围，以及业务自身权限 |
| 404 | 目标网站、接口路径和方法是否正确 |
| 502 / 超时 | 节点通道、出口到源站网络、DNS、证书和业务响应 |
| 测活成功但业务失败 | URL 模式测活确认隧道和 HTTP 处理器就绪；真实业务 API 须另行调用 |

生产验证见 [2.18.0 核验](verification-2.18.0-20261020.md)。
