# Chitanda 数据中台管理

独立控制面板、轻量 Go 节点和 HTTPS 业务接入组件。此私有仓库从 Chitanda 项目中提取当前实现，保留 UI、动态图表、自动拓扑、账号与头像管理、多优化节点、H2 / H3 配置、访问控制及回归测试。

## 目录

| 路径 | 内容 |
| --- | --- |
| `deploy/tunnel-control/` | Node.js 面板、静态 UI、账号和登录防御 |
| `deploy/tunnel-control/engine/` | 轻量节点，香港端可在同一进程提供 HTTPS 数据入口 |
| `deploy/tunnel-control/gateway/` | 独立 HTTPS 固定目标适配器及测试 |
| `deploy/tunnel-control/*.service` | 低权限 systemd 单元模板 |
| `deploy/tunnel-control/*.conf` | Nginx 管理入口白名单配置 |
| `scripts/` | 本地隔离的权限、账号与界面回归 |
| `docs/` | 架构、运行边界和原部署历史 |

## 本地启动

需要 Node.js 22+、npm 和 OpenSSL；Go 组件另需 Go 及 Git。Windows 可以使用 Git 附带的 OpenSSL，通过 `CT_OPENSSL` 指定其可执行文件。

```sh
npm ci
```

复制 `.env.example` 为 `.env.local`，设置独立用户名与 scrypt 密码哈希。哈希由 `deploy/tunnel-control/password-auth.cjs` 导出的 `createAdminPasswordHash` 生成；不将明文密码写入文件。然后运行：

```sh
npm start
```

本地地址为 `http://127.0.0.1:5092/tunnel/`。示例只允许回环访问，未设置密码哈希时登录不可用。账号、节点凭据和工作区 CA 将保存在 `CT_DATA`；这些运行文件受 Git 忽略规则保护，生产环境应置于仓库外的私有目录。

源码保留原部署的域名、初始演示节点及固定接入地址。这些是历史部署默认值，不能当成新环境实际拓扑；真实节点、线路、源站关系和独立身份保存在私有状态中。迁入新的环境前应明确配置接入地址及节点角色。当前生产私有状态未随源码上传。

TLS、证书、协议与程序版本自动从节点运行状态采集，维护方式见 [节点自动采集](docs/node-telemetry.md)。

数据通道支持点击测试当前完整路径的连通性与往返耗时，结果由源节点实测并上报，详见 [通道测试](docs/route-tests.md)。

## 验证与构建

```sh
npm test
npm run test:gateway
```

界面测试需要安装 Playwright Chromium：`npx playwright install chromium`，再运行 `npm run test:ui`。所有测试使用临时账号与状态目录，不对生产管理员做错误密码压力测试。

Windows 节点构建：

```powershell
npm run build:engine
```

构建脚本在忽略的 `tmp/` 目录获取固定上游提交 `2926cf2c41c85d2177536a4ba2d9931f1ec675f9`，加入本仓库节点源码，再输出 Linux amd64 程序 `tmp/chitanda-transit`。Linux 或 ARM 环境按 [架构与运维](docs/architecture.md) 中的步骤构建。上游固定提交的 `go.mod` 决定所需 Go 工具链版本。

## 生产部署

管理服务仅监听回环，Nginx 和应用必须同时保持精确来源白名单；反向入口必须覆盖客户端提供的来源头。线上启用 HTTPS，取消 `CT_INSECURE=1`。节点仅使用其独立登记凭据，不能获得管理员凭据或工作区 CA 私钥。

仓库包含服务及 Nginx 模板，未包含一键生产安装器。部署前配置低权限服务账号、私有状态目录、真实域名和合法来源；不要将原部署历史中的一次性迁移步骤直接重放。

## 私有资料与第三方代码

本仓库不存放生产密码、哈希、节点令牌、证书私钥、SSH 身份、数据库或运行配置；`.env.example` 仅提供空白模板。也不包含 Chitanda 主站源码、其他已迁业务和历史备份。

节点依赖 Chitanda 上游，固定提交的许可证副本见 `third_party/chitanda-LICENSE`；依赖及品牌资源保留各自权利，不因本仓库建立而另行开放授权。详见 [第三方说明](THIRD_PARTY_NOTICES.md)。
