# HTTPS 请求头接入（2.18.0）

请求发往隧道 HTTPS 入口，用隧道令牌选择通道，用 `X-Target-URL` 指定真实业务的完整 HTTPS 地址。出口直接请求现有业务接口，保留方法、查询参数和请求体。

```bash
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
2. 源节点须已有 HTTPS 入口、对应证书和来源授权。一个入口可以服务多个隧道，由各自令牌区分；创建隧道不会自动申请证书或开放防火墙。
3. 展开隧道详情，打开“URL 请求接入”，为每个方向填写允许的业务地址范围，例如 `https://www.chitanda.net/api/sync/`，保存后自动下发。
4. 请求入口时携带本隧道令牌和完整 `X-Target-URL`，目标必须落在该方向允许的域名、端口和路径范围内。

每方向可配置多个目标。范围 `/api/sync/` 允许自身及子路径，不允许 `/api/sync-other`。请求可以有查询参数，配置范围本身不接受查询参数。

“固定回源地址”通常留空，由出口解析业务域名。如果域名经过 CDN、地区解析或可能回到隧道入口，可集中指定实际源站的公开 `IP:端口`；Host、SNI 和证书验证仍使用业务域名。无需在每台业务服务器新增映射。

URL 模式不使用原始目标端口；关闭模式恢复原始 TCP 行为。原始 TCP 业务不使用 `X-Target-URL`。

## Chitanda 环境变量

```dotenv
CHITANDA_SYNC_PEERS=https://data-test.chitanda.net
CHITANDA_TUNNEL_TOKEN=本隧道令牌
CHITANDA_SYNC_TARGET=https://www.chitanda.net
```

客户端把原同步接口路径和查询参数拼到 SYNC_TARGET，通过 X-Target-URL 发送。国内和国际可使用同一套变量；各方向实际回源 IP 在面板集中配置。现有服务端内部同步密钥可以保留，Chitanda 同步接口也支持同一个隧道令牌。

兼容改动见 [请求头集成补丁](../integrations/chitanda-header-url.patch)，前一版见 [单令牌补丁](../integrations/chitanda-single-token.patch)。应用前检查本地差异，避免覆盖业务已有修改。

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
| 502 / 超时 | 节点通道、出口到源站网络、DNS、证书和业务响应 |
| 测活成功但业务失败 | URL 模式测活确认隧道和 HTTP 处理器就绪；真实业务 API 须另行调用 |

生产验证见 [2.18.0 核验](verification-2.18.0-20261020.md)。
