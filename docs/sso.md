# 统一账号接入

生产中台使用 `https://sso.chitanda.net` 统一登录。访问 `https://datahub.chitanda.net/tunnel/` 后自动跳转授权；已登录统一账号时会自动返回。用户名、密码和两步验证在统一账号中心维护，中台保留自己的头像设置。SSO 使用仅账号域名可用的 `__Host-` Cookie，其他子站不会收到它；升级时撤销了旧共享 Cookie 会话，首次需要重新登录一次。

生产配置为 `CT_AUTH_MODE=sso`，原密码登录和密码修改接口返回 410，不会在 SSO 故障时自动切换本地登录。管理 API 密钥、节点身份及业务隧道令牌继续各自独立。

## 后端配置

以下内容放入 root 私有的 `/etc/chitanda-transit-panel.env`，权限 0600；不要放进前端、仓库或 URL：

```ini
CT_AUTH_MODE=sso
CT_SSO_ISSUER=https://sso.chitanda.net
CT_SSO_CLIENT_ID=data-platform
CT_SSO_CLIENT_SECRET=填写随机生成的客户端密钥
CT_SSO_ADMIN_SUBJECTS=填写允许管理中台的SSO用户sub
CT_CONTROLLER_URL=https://datahub.chitanda.net
CT_ACCESS_MODE=subnet
CT_BLOCKED_SUBNETS=110.42.32.0/24,168.138.209.0/24
CT_SOURCE_EXCEPTIONS=110.42.32.161,168.138.209.1,127.0.0.1,::1
```

SSO 应用中精确登记回调 `https://datahub.chitanda.net/tunnel/sso/callback`。客户端密钥使用加密随机数生成，不能通过用户名推导。管理员按稳定的 `sub` 明确授权，并要求当前身份具有 `admin` 或 `root` 角色；不按用户名自动赋予权限。

## 登录与退出

- 使用授权码、PKCE S256、state 和 nonce；登录流程绑定发起浏览器和来源地址，五分钟内有效且只能完成一次。
- 中台验证 RS256 签名、issuer、audience、nonce、有效期和 SSO 会话标识后创建自己的 HttpOnly、Secure 会话及 CSRF 凭据。
- 只读请求最多缓存五秒的会话有效性；写入强制核验，读完请求体后再次核验，避免在途请求使用已撤销的身份。
- access token 到期前由后端轮换 refresh token。修改密码、撤销 SSO 会话或退出统一账号后，中台失去相应授权。SSO 不可用时拒绝管理操作，不放行失败校验。
- 中台退出按钮先销毁本地会话，再跳转 SSO 退出，回到登录提示页。

SSO 1.1.1 中，启用两步验证前需确认当前密码，关闭时需同时输入密码与有效且未使用的动态验证码。更新两步验证后撤销其他设备会话，当前设备继续使用。验证码消费记录保存在私有 SQLite 中，覆盖完整时钟容差窗口并能跨服务重启防重放；密码校验和二维码生成结束后再次确认账号凭据、两步验证状态及会话仍有效。详见 [补充安全审查](sso-audit-1.1.1.md)。

SSO 源码位于 [integrations/chitanda-sso](../integrations/chitanda-sso)。会话、授权码和刷新令牌保存在私有 SQLite 中；会话令牌、授权码及刷新令牌按哈希存储，客户端密钥只供后端使用。

## 独立认证路径

国内到国际 SSO 的直连存在偶发超时。当前认证后端经香港 `47.243.148.109:19443` 到达国际 SSO，配置为：

```ini
CT_SSO_CONNECT_ADDRESS=47.243.148.109:19443
```

这个 TCP 服务仅接受国内控制端来源，不解密 TLS。中台始终验证 `sso.chitanda.net` 的证书与主机名。它不由业务隧道配置创建、暂停或删除，因此不会把控制台登录依赖于待管理的隧道。

服务文件为 [sso-tls-bridge.py](../deploy/tunnel-control/sso-tls-bridge.py)，运行于独立低权限服务 `chitanda-sso-bridge`，限制连接数、缓冲、空闲时间和内存。跨境路径失效会导致认证不可用，不会自动降低验证要求。

## 来源与 WAF

生产已取消固定访客 IP 白名单，禁止两台服务器所在的公网 `/24`，排除两台服务器自身和回环地址。SSO 与中台均在宝塔 WAF 登记并开启 IDC 限制；来源判定使用可信回源链，浏览器自行填写的转发头不能改变身份。

IDC 限制在管理页面和 API 前执行。节点生命周期接口继续独立鉴权；SSO 后端换票仅对必要的服务器来源和路径作例外。管理 JSON 可能包含域名、证书和配置文本，由应用执行身份、Origin、CSRF、权限、字段、大小及频次校验，避免通用 WAF 请求体解析器消耗请求体导致 408。

自维护文件：

- `/www/server/btwaf/chitanda-identity-access.json`：站点角色、可信来源变量、服务器地址与认证中转来源。
- `/www/server/btwaf/chitanda-{sso,datahub}-access.lua`：部署自 [identity-waf.lua](../deploy/tunnel-control/identity-waf.lua)。
- [identity-access-policy.py](../deploy/tunnel-control/identity-access-policy.py)：登记现有站点、修改来源策略和开启 WAF，保留其他站点。
- [harden-waf-geo.py](../deploy/tunnel-control/harden-waf-geo.py)：修复国外 IP 的 IDC 标签缓存及 IPv6 标签丢失。ARM 服务器还需确保 WAF 能加载系统的 ARM `libmaxminddb`。

WAF 升级后应复核原生库、标签缓存修复、站点开关及来源规则。IDC 识别取决于 IP 数据库覆盖范围，不能保证识别全部机房来源。
