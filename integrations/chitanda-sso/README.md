# Chitanda SSO

数据中台使用的统一账号服务，Node.js 22.23.3、SQLite、RS256 和 OIDC 授权码流程。版本 1.1.1。

从仓库根目录运行：

```sh
npm ci
npm test --workspace=chitanda-sso
npm run test:sso
```

服务运行前通过环境变量设置 `SSO_DATA_DIR`、`SSO_ISSUER`、`HOST=127.0.0.1` 和 `PORT=9787`。首次创建空数据库还需明确提供 `CHITANDA_ADMIN_USERNAME` 与 `CHITANDA_ADMIN_PASSWORD_HASH`；已有数据库继续使用原账号，不会重置密码。不要使用测试数据库或测试账号部署生产。

生产数据位于 `/var/lib/chitanda-sso`，目录 0700；数据库、密码哈希、签名私钥与环境文件禁止上传。运行服务使用独立账号、只读系统目录和独立 Node.js 运行时。SQLite WAL 数据库备份应使用 SQLite backup API，不能只复制正在写入的主数据库文件。

接入、权限和来源策略见 [统一登录文档](../../docs/sso.md)，本次修复与验证见 [安全审查](../../docs/audit-2.23.0.md)。

1.1.1 补充安全审查见 [SSO 安全复查](../../docs/sso-audit-1.1.1.md)。启用两步验证前需重新确认密码；关闭时需同时提供密码和未使用的动态验证码。修改两步验证会撤销其他设备的会话。
