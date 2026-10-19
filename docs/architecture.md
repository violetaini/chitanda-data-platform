# 架构与运行边界

更新时间：2026-10-19

面板使用独立域名 `datahub.chitanda.net`，CDN HTTPS 回源国内，宝塔保留原域名；部署模板与精确来源校验见 [域名与 CDN 边界](datahub-domain.md)。

控制端登记节点、管理线路、生成拓扑并签发工作区证书；控制端与业务源站可同机，但无需承担跨境节点工作。业务源站以普通 HTTPS 接入附近的数据节点，国内数据节点与境外优化节点之间使用 Chitanda H2 / TLS 1.3，H3 与原生 Stream 为可选配置，具体线路需实际验证。境外优化节点再通过 HTTPS 请求固定业务源站；反方向复用既定线路。

优化节点使用单 Go 进程，无需面板、Node.js、数据库或 Docker。多个优化节点可独立登记、选用；当前实现不自动进行线路故障切换。引擎为 2.7.0，控制面板为 2.9.0，面板从运行目录 package.json 获取自身版本；TLS 与协议能力通过节点鉴权心跳自动更新，见 [采集与维护](node-telemetry.md)。

“系统设置”统一管理 SSL 证书及自动测活开关、间隔与结果有效期，保存到控制端私有状态，无需修改源码。后台调度与浏览器会话无关，最近完成结果保存在同目录的 `route-checks.json`，更新和备份应一并保留；详见 [通道测试](route-tests.md)。

## 构建 Go 节点

节点 `engine/` 是加入上游模块的 `package main`，不能直接在该目录 `go build`。Windows 可使用 PowerShell 构建脚本；Linux 使用 `bash deploy/tunnel-control/build-engine.sh`（ARM64 可加 `GOARCH=arm64`）。两个入口都会校验固定上游并自动应用受检视的 TLS 观察补丁。手动构建时也必须先应用补丁：

```sh
mkdir -p tmp
git clone https://github.com/chitanda-project/chitanda.git tmp/chitanda-tunnel-core
git -C tmp/chitanda-tunnel-core checkout 2926cf2c41c85d2177536a4ba2d9931f1ec675f9
git -C tmp/chitanda-tunnel-core apply "$(pwd)/patches/chitanda-tls-observer.patch"
mkdir -p tmp/chitanda-tunnel-core/cmd/chitanda-transit
cp deploy/tunnel-control/engine/*.go tmp/chitanda-tunnel-core/cmd/chitanda-transit/
cd tmp/chitanda-tunnel-core
go test -mod=mod ./cmd/chitanda-transit
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -mod=mod -trimpath -ldflags='-s -w' -o ../chitanda-transit ./cmd/chitanda-transit
```

ARM64 目标使用 `GOARCH=arm64`。跨平台真实网络集成测试应在目标 Linux 上运行；本机交叉编译只能确认编译兼容性。

独立 `gateway/` 自带模块，可以通过 `go -C deploy/tunnel-control/gateway test ./...` 验证，或在该目录构建。当前香港节点已将相关固定目标接入能力整合到主引擎；该模块保留用于独立源站适配。

## 配置与权限

- 面板环境：`CT_PORT`、`CT_DATA`、`CT_USERNAME`、`CT_PASSWORD_HASH`、`CT_ALLOWED_IPS`、`CT_CONTROLLER_URL`，可选 `CT_OPENSSL`。源码监听固定回环；`CT_ALLOWED_IPS` 必须与 Nginx 配置同步维护。
- 首次账号通过环境中的用户名及 scrypt 哈希初始化；已有 `account.json` 后以私有账号文件为准，重新部署不会覆盖账号。面板支持修改用户名、密码及头像，修改凭据会撤销已有会话。
- 管理写入校验会话、来源、CSRF、Origin 与内容类型；登录防御持久记录失败和冷却时间。节点同步接口与管理权限隔离，节点身份及优化节点内部校验身份分别限定作用域。
- 优化节点获取自身证书与必要线路信息，接入节点获得相关的派生校验身份、公共 CA 及本机配置；只有显式选中应用 HTTPS 证书的节点才能获得对应入口私钥。不得复制控制端 CA 私钥到节点。
- Nginx 必须覆盖 `X-Real-IP`，应用仅信任本机反向入口；不得将 Node 监听改到公网后依靠可伪造请求头判断来源。
- systemd 模板中的账号、目录、文件权限和可写范围需在部署时创建并核对。账号 / 状态 / 节点配置 0600，私有目录 0700；CA、私钥及历史备份都在仓库之外。

## 生产历史

`deployment-history.md` 与 `data-gateway-history.md` 来自原项目，记录既有机器和验证历程，包含已被后续生产切换取代的测试阶段。本文及实际私有配置优先；这些文档不包含恢复生产身份所需的密钥。新仓库独立发布不会自动修改线上部署位置、既有域名、白名单或运行凭据。

证书统一管理、国内 Nginx 自动应用和原生 Stream 的监听 / 防火墙边界见 [证书与 Stream](certificates-stream.md)。

## 域名控制面

控制端通过 DNS Manager API 管理业务域名到 CNAME 目标的映射，域名在数据通道页绑定到单向或双向隧道。单向目标只有默认线路的一个入口 IP，双向将两个相反方向作为一个对象管理，并按默认 / 境外解析到两个入口 IP。底层线路保留节点通信格式。数据不经过控制面板。业务 HTTPS 域名必须与节点入口及其公开证书一致，通道内部的工作区 CA / SNI 保持独立。配置预览、发布与失败回退见 [域名与地区调度](domain-routing.md)。
