# 下载服务的部署与迁移

本文面向部署维护者。日常管理员在中台维护白名单，不需要手工登记服务。

文中使用示例域名 `downloads.example.com`、地址占位符 `<OLD_ORIGIN_IP>` / `<NEW_ORIGIN_IP>` 和节点占位符 `<NODE_ID>`，不包含真实公网 IP、业务域名或凭据。`127.0.0.1` 为固定本机回环地址；`203.0.113.10` 属于文档示例地址段。

## 部署结构

```text
白名单内的业务服务器
    │ HTTPS：下载域名
    ▼
承接节点现有 443 入口
    ├─ 原隧道路径 → 原协议认证与数据通道
    └─ 下载域名 → 实际来源 IP 校验 → 本机下载程序 → Docker / GitHub
                                     127.0.0.1:5000

管理员 → SSO → 中台保存白名单与版本
                   │ 节点定期同步（通常约 15 秒）
                   ▼
             应用策略并回报版本、就绪状态
```

下载数据直接经过承接节点，不经过控制面板。原生下载程序复用节点现有 HTTPS 入口，无需为此安装 Docker、Nginx 或宝塔。下载白名单有独立版本，修改名单不会调整原隧道的端口、令牌或路线。

## 部署顺序

### 1. 备份与核验旧服务

备份旧实例配置、白名单、域名记录、节点配置和缓存、中台状态。备份仅 root 可读，不能提交 Git。

如果旧站同时使用 Web 服务器限制与应用限制，先确认最终允许的来源，不直接合并名单放宽权限。旧程序来自容器时，可提取已核验的程序：

```sh
docker cp hubproxy:/app/hubproxy ./hubproxy
file ./hubproxy
sha256sum ./hubproxy
```

经可信维护通道送到新节点，核对 SHA-256、CPU 架构和动态库要求。不能把不匹配架构的容器程序直接复制运行。

### 2. 部署回环后端

将已核验的程序安装为 `/opt/chitanda-download/chitanda-download`，创建独立系统用户 `chitanda-download`，使用 [download.service](../deploy/tunnel-control/download.service) 管理。

模板中的关键配置：

```ini
User=chitanda-download
Environment=SERVER_HOST=127.0.0.1
Environment=SERVER_PORT=5000
Environment=ENABLE_FRONTEND=false
Environment=IP_WHITELIST=127.0.0.1
```

模板还包含只读系统目录、空能力集合及内存/任务上限。部署后检查：

```sh
systemctl status chitanda-download
curl --noproxy '*' -fsS http://127.0.0.1:5000/v2/
ss -ltnp
```

5000 必须只监听回环地址，不对公网开放。应用内的回环白名单用于限制后端；公网来源名单由节点入口校验，转发前清除外部自填的来源地址头。

### 3. 启用节点入口与证书

要求面板至少 2.24.0、节点至少 2.13.1，并已完成正常节点接入。

备份节点本地配置，在保留现有身份、控制端、TLS 和通道配置的基础上，加入：

```json
{"downloadBackendEnabled": true}
```

这是本地能力开关；控制端选择一个普通节点不会自动安装或打开未知后端。重启节点后核对版本和在线状态。下载程序只使用固定回环地址，不接受任意转发目标或远程命令。

公共证书继续由系统设置中的泛域名证书管理和下发，必须覆盖下载域名。内部通道 CA 不能代替公共下载域名证书。节点按域名选择证书，保留原隧道的协议认证。

### 4. 初始化中台服务配置

由部署维护工具调用 [download-access.cjs](../deploy/tunnel-control/download-access.cjs) 的 `create`、`add` 校验方法，初始化承接节点、域名及原有白名单。脱敏示例：

```json
{
  "name": "镜像与文件下载",
  "domain": "downloads.example.com",
  "nodeId": "<NODE_ID>",
  "entries": [{"address": "203.0.113.10", "note": "业务服务器公网出口"}]
}
```

初始化时先停止面板并备份状态，校验全部条目后原子写入，再恢复面板。保留状态文件原属主和权限，禁止在面板运行时直接覆盖 `state.json`。不得修改无关账号、节点凭据、隧道或数据库。

日常页面只维护已部署服务：添加/移除 IP 或网段、备注、暂停与启用。节点同步后，策略版本一致且后端、证书均就绪时显示“已生效”；离线时显示离线。

### 5. 先测新节点，再切 DNS

从白名单内的业务服务器固定连接到新节点，仍校验正式下载域名的证书：

```sh
curl --noproxy '*' --resolve 'downloads.example.com:443:<NEW_ORIGIN_IP>' \
  -fS 'https://downloads.example.com/v2/'
curl --noproxy '*' --resolve 'downloads.example.com:443:<NEW_ORIGIN_IP>' \
  -fS 'https://downloads.example.com/https://raw.githubusercontent.com/OWNER/REPO/main/README.md'
```

再从不在名单内的来源测试拒绝；携带伪造的 `X-Forwarded-For`、`X-Real-IP` 或 `CF-Connecting-IP` 也不能放行。

通过后仅修改下载域名的目标，保留 TTL、线路、状态及其他记录。双栈域名检查 A/AAAA，避免 IPv6 仍去旧机。当前实现要求下载域名直连节点；加入 CDN 前应另行实现可信来源传递，不能直接采信客户端自填的头。

通过实际解析再次验证，并完整拉取一次镜像：

```sh
docker pull downloads.example.com/library/alpine:latest
```

确认流量已切换后，停止旧实例并关闭自动重启，保留程序、配置和 DNS 快照作回退。

## 生效、离线与回退

- 添加/移除地址后等待节点确认新版本。新请求按当前名单校验，在途下载不强制中断。
- 空名单或暂停服务都拒绝访问，不能用空名单表示公开服务。
- 控制端暂时不可达时保留最后接收的配置，恢复后补收最新策略。
- 节点身份失效时清空许可并清理本地缓存，避免离线重启恢复旧权限。
- 回退时恢复下载域名原目标并启动旧实例，再检查实际拉取；不要为恢复服务放开全部来源或关闭证书校验。
- 回退节点程序时保留原身份及对应配置备份，不应改动中台账号或其他业务数据库。

验证及恢复只输出版本、状态和结果，避免输出环境文件、完整节点配置、令牌或证书私钥。
