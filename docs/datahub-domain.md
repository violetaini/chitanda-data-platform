# 数据中台独立域名（2026-10-18）

管理入口为 `https://datahub.chitanda.net/`，规范到 `/tunnel/`。`control.chitanda.net` 保留为国内宝塔的原绑定域名及安全入口；已移除原来插在宝塔虚拟主机中的中台根入口、页面和节点心跳路由。

## DNS、CDN 与证书

- DNS 管理面板只为 `datahub.chitanda.net` 建立独立 CNAME，指向既有 ESA 接入名 `all.chitanda.net.a1.inituu.com`，TTL 60 秒。这样不会沿用主站别名的境外 Cloudflare 分流；ESA 已有泛域名源站为国内 `110.42.32.161`。
- 专用 ESA 规则对这个主机使用 HTTPS / 443 回源，Host 与 SNI 均为新域名，启用源站证书验证。其他域名及默认源站不变。
- 套餐缓存规则数量已满，因此只在现有 `ChitandaApiDynamicBypass` 条件前加新主机的独立 OR 条件，原 API 条件及缓存参数保留。该规则在公共静态资源规则之前，覆盖新域名所有路径，不缓存登录、接口或静态面板资源；源站仍发送 no-store。
- 国内宝塔登记独立站点，证书采用已有有效的 `*.chitanda.net`。DNS 面板原有国内宝塔账户 6 / 证书部署任务 2 已加入新站，首次自动部署成功。仅向宝塔 API 的既有来源名单追加实际 DNS 管理机 `168.138.209.1`，未更改密钥及其他 API 配置。

## 授权来源与回源校验

只允许配置中明确登记的管理员公网 IPv4 / IPv6 或回环来源管理。保留原公网 IPv4，管理员当前 IPv6 另存于源站私有配置。CDN 出口地址不属于管理员白名单，不直接信任访客提供的 X-Real-IP、X-Forwarded-For 或 CF 来源头。

浏览器可能优先使用 IPv6；即使同一台电脑的 IPv4 未变，IPv6 未登记也会被拒绝。新增授权地址须同时更新私有 Nginx map 的直连名单、已验证 CDN 的访客精确匹配，以及 `/etc/chitanda-transit-panel.env` 的 `CT_ALLOWED_IPS`，检查 Nginx 配置后重新加载 Nginx 并重启控制端。只加入实际确认的完整地址，不放行整个网段或所有 CDN 访客。IPv6 地址发生变化时需重新登记，原来源绑定会话可能要求重新登录。

2026-10-19 修复验收：通过既有 TLS / PROXY protocol 入口模拟 CDN 回源，当前授权 IPv6 的页面与脚本返回 200，未登录会话接口返回 401；原 IPv4 返回 200。未登记 IPv6、缺失或错误回源凭据、重复访客来源头均返回 403，共 8 项检查通过。私有配置修改前备份位于 `/var/backups/chitanda-transit/ipv6-access-20261019T082502Z/`。

ESA 仅在新主机范围内设置 `X-Chitanda-Edge-Key` 和动态 `X-Chitanda-Visitor-IP`（`ip.src`）。源站必须先验证私有回源凭据，再精确匹配访客授权 IP。没有有效回源凭据时，只按实际直连 IP 判断；伪造或重复的值不能满足严格匹配。应用收到由 Nginx 重新设置的来源头后再次执行原白名单、会话和 CSRF 校验。

凭据保存在国内 `/etc/chitanda-datahub-edge.key` 及 root 私有 Nginx map 中，均为 0600，不写入 Git、浏览器、访问日志或公开配置。模板为 `deploy/tunnel-control/datahub-access.conf.example` 与 `datahub-vhost.conf`，需适配部署环境和精确白名单后使用。本次源站继承现有本地 TLS / PROXY protocol 入口，不能把普通公网来源头当成可信来源。

## 控制端与节点

控制端 `CT_CONTROLLER_URL`、两个节点的 `config.json` 与 `runtime.json` 中 `controller` 均改为 `https://datahub.chitanda.net`；节点继续通过已有 `controllerAddress=110.42.32.161:443` 直达国内源站，以新主机名正常验证 TLS，保持实际节点地址采集准确。心跳接口仍独立鉴权，不开放面板访问权限。

账号、节点身份、密钥、通道端口、系统设置和线路版本 15 均保留。现有通道中的 `control.chitanda.net` 是工作区私有 TLS 的 SNI 标识，继续正常验证；它不代表管理页面还在宝塔域名上，也不会因为本次入口迁移而强制重新签发通道证书。

## 部署与回退

国内及两个节点的备份目录为 `/var/backups/chitanda-transit/datahub-domain-20261018T132322Z`；国内包含原宝塔虚拟主机、面板环境 / 源码、账号 / 状态 / 测活结果、宝塔站点 SQLite 和 API 配置备份。DNS 及证书任务变更前资料位于 DNS 管理机的 `/root/chitanda-datahub-domain-20261018`。CDN 配置及私有凭据另在本地忽略的临时运维目录保留，不能上传。

后续面板发布只增量更新应用文件，并保留此独立虚拟主机和私有 map；不要再次向 `control.chitanda.net` 注入旧的中台 include。原项目的历史 `stage_panel` 已加入独立域名检查，防止旧安装流程恢复混用入口。备份或迁机还应保留回源凭据、证书自动部署成员及节点新控制端 URL。

验收包括新域名浏览器登录、2 / 2 在线节点及通道自动测活、24 项源站来源校验、9 项公网未授权 / 伪造头拒绝，以及 118 项管理入口来源检查。主站两端全部内容及 7 个媒体一致，原业务同步未改变。
