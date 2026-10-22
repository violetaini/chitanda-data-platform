# Node.js 运行环境安全更新（2026-10-22）

已针对 Node.js 2026-10-21 安全公告将生产控制面板运行环境更新到 **22.23.4 LTS**。这次更新修复 Node 本身及其内置依赖，不能用单独更新 npm 包替代。

官方公告：<https://nodejs.org/en/blog/vulnerability/october-2026-security-releases>；发行记录：<https://github.com/nodejs/node/releases/tag/v22.23.4>。

- `deploy/tunnel-control/panel-runtime.json` 固定官方 x64 发行包和 SHA-256；重新部署时继续核对该校验值。
- 生产进程已重启并检查实际 `/proc/<pid>/exe`，不是只更新 shell 的 `node --version`。
- 账号、管理 API 密钥、SSO 客户端配置与节点状态保留；账号和密钥文件与更新前私有备份逐字节一致。
- 使用修复版 Node、独立临时数据目录及固定测试凭据运行 89 项中台回归，全部通过，包括管理 API 权限、限流、会话撤销、CSRF、来源校验、SSO 与节点操作。
- 服务、证书和节点配置没有因运行环境更新而重新初始化。运行包、旧二进制与配置回退副本留在服务器 root 私有备份目录，均不进入 Git。

本记录覆盖本次 Node 公告，不代表对未来漏洞或所有第三方依赖作永久安全保证。
