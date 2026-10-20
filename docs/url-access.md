# 用 HTTPS URL 接入业务数据

面板“使用指南”会按当前绑定的业务域名、隧道及两端端口生成接入示例；在数据通道展开详情，也可点“URL 接入教程”。示例不包含生产凭据。

## 现在的 Chitanda 如何使用

当前业务 URL 为 `https://data-test.chitanda.net`，调用方是国内和国际的 Chitanda 后台服务。国内请求进入国内节点，沿隧道到香港节点，再由固定源站适配器进入国际后台；反方向相反。国内和国际使用同一个 URL，两端填写同一个隧道令牌。

```text
业务后台 → HTTPS 业务域名:443 → 邻近节点的固定 HTTPS 入口
        → 源节点 127.0.0.1:<接入端口> → 隧道
        → 目标节点 127.0.0.1:<目标端口> → 固定真实源站
```

业务 URL 使用业务域名。面板域名用于管理；`ct-*.tunnel.*` 是 DNS 调度目标，通常不直接作为业务 URL 或证书名称。

Chitanda 后台原环境配置使用：

```dotenv
CHITANDA_SYNC_PEERS=https://data-test.chitanda.net
CHITANDA_TUNNEL_TOKEN='填写隧道详情中的令牌'
```

打开数据通道并展开对应隧道详情，即可查看、复制或重置隧道令牌。创建时自动生成，双向共用；重置后自动下发到相关入口节点，业务程序也需要更换新令牌。节点应用后旧令牌失效。

接入方只维护 URL 和 CHITANDA_TUNNEL_TOKEN。现有业务后台的内部同步密钥由固定源站适配器处理，保留服务端原配置；无需在业务接入示例再填两项旧凭据。完整说明见 [隧道令牌](tunnel-tokens.md)。

在已授权的业务服务器加载同一套环境变量后，可先测试状态接口：

```bash
curl --fail-with-body --connect-timeout 5 --max-time 30 \
  -H "Authorization: Bearer ${CHITANDA_TUNNEL_TOKEN}" \
  'https://data-test.chitanda.net/api/sync/status'
```

这会读取对端业务后台状态。返回 HTTP 200 才表示本次完整业务调用成功。浏览器直接打开根 URL 没有业务鉴权头，也可能不在源站 IP 授权范围内，因此出现 401 / 403 不能直接判断隧道故障。

业务新增、修改与文件分片仍交给 Chitanda 已有同步流程。入口目前只开放既有同步接口：状态、事件、设置、文件 prepare/chunk/complete、番剧缓存与封面等；并非通用网站入口或任意文件上传地址。当前每个 HTTP 请求最大 16 MiB、每入口最多 8 个并发，大文件使用业务分片机制。

## 新增 HTTP 业务的配置顺序

1. 两端安装节点程序，创建所需隧道，并先确认目标服务或适配器在目标节点的回环端口可用。
2. 在入口节点部署 HTTPS 接入：业务域名、公有证书、来源授权、鉴权，以及到源节点回环接入端口的固定映射。
3. 如果真实业务源站不在目标节点同机，在目标回环端口部署固定源站适配器：跨机器用 HTTPS，固定拨号到真实源站 IP，同时验证源站证书的正确域名。避免再用入口域名解析真实源站，否则会形成循环。
4. 将已部署的入口信息纳入节点本地启动配置和证书管理。当前单个节点入口配置来自 `dataGateway` 或 `httpsIngress`，安装器不会为任意新域名自动生成适配器或申请证书。
5. 在隧道中绑定业务域名，预览、校验 SSL 并发布 DNS，再从获授权的业务源站调用实际接口。

对于已有 Nginx 的 HTTP 业务，可以按以下固定映射配置。替换占位符、证书路径、鉴权和实际业务路径后，先 `nginx -t` 再重载；模板不会自动应用。

入口节点示意：

```nginx
server {
    listen 443 ssl;
    server_name data.example.com;
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;
    ssl_protocols TLSv1.3;
    allow <授权业务源站IP>;
    deny all;
    location /api/ {
        # 本例源隧道接入端口为 15082；保持应用自己的业务鉴权。
        proxy_pass http://127.0.0.1:15082;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
    }
    location / { return 404; }
}
```

目标节点示意：

```nginx
server {
    listen 127.0.0.1:16082;
    server_name _;
    location /api/ {
        # 使用真实源站 IP，源站证书覆盖 origin.example.com。
        proxy_pass https://<真实源站IP>:443;
        proxy_set_header Host origin.example.com;
        proxy_ssl_server_name on;
        proxy_ssl_name origin.example.com;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_ssl_protocols TLSv1.3;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
    }
    location / { return 404; }
}
```

同机业务源站可用回环 HTTP，跨机器仍用 HTTPS。已有 Chitanda 入口使用带独立逐跳凭据和路径校验的适配器，不要用这份通用模板覆盖其生产配置。

## 协议与排查

H2 / H3 / Stream 是节点间协议。外层业务为 HTTP 时仍可通过 HTTPS URL 调用；原始 TCP 业务使用回环端口。当前固定 HTTP 适配器不接受任意 WebSocket Upgrade。

| 现象 | 检查项 |
| --- | --- |
| 401 | 是否使用当前隧道令牌，入口是否已应用最新版本 |
| 403 | 实际源站 IP、域名 Host、允许路径和方法 |
| 502 / 超时 | 隧道、目标回环端口、固定源站、DNS 和证书 |
| 测活成功但 API 失败 | 测活只检查通道和目标 TCP 端口，另查 HTTP 鉴权与响应 |
| URL 命中错误地区 | 检查调用方实际 DNS / 缓存；TTL 不是实际请求完成时间 |

2026-10-19 已从两端生产业务源站各做只读 HTTPS 状态请求，均返回 200 / TLS 1.3；国内实际入口为 110.42.98.254，对端为 international-168，国际入口为 47.243.148.109，对端为 mainland。没有新增或删除业务数据。
