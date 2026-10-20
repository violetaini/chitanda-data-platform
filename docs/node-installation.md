# 节点安装、更新和卸载

新增节点后自动弹出安装指令；关闭后可随时从节点卡片重新打开。窗口保留 GitHub / 源站两个来源，默认展示短指令和复制按钮；缺少 curl 时可展开兼容指令。首次鉴权心跳确认安装后，在线节点默认显示卸载指令，并可切换“重新安装”；离线节点优先显示恢复安装指令，也可查看卸载指令。历史状态仍持久保存，不根据离线推断是否卸载。卸载器成功通知中台后恢复安装指令；网络不可达时保留最近确认状态。支持多种 Linux 发行版、8 种架构和 systemd / OpenRC / runit / SysV，具体边界及实测版本见 [Linux 支持范围](linux-support.md)。节点不需要安装整个面板、数据库、容器或编译工具。

## 节点用途

逻辑链路为“国际隧道入口 ↔ 优化机 ↔ 国内隧道”，双向通道可反向使用。入口负责对应一侧业务，优化机负责中间路径；业务源站与这些节点分别显示。同一台优化机可兼任入口，面板根据源站的 endpoint 关联自动标示相应职责。

既有“国内接入”“国际接入”按新名称展示，原节点 ID、名称、凭据、协议和配置保持。添加节点不再分两次选择“业务接入 / 优化节点”和地区；后端继续兼容旧版本字段。

## 安装

1. 添加节点名称，直接选择“国际隧道入口”“优化机”或“国内隧道”；节点 ID 与独立凭据由面板生成。
2. 点“安装指令”，复制安装命令，到目标服务器的 root 终端执行。普通账户需先使用 `sudo -i` 进入 root 环境。
3. 安装器自动识别架构，从同一个 HTTPS 控制端领取配置和下载安装包，校验大小、SHA-256 与程序版本，建立低权限系统服务并启动。
4. 返回面板确认上线；地址来自鉴权心跳。安装节点程序不自动部署任意业务 HTTPS 入口和源站适配器，继续按 [URL 接入教程](url-access.md) 配置。

默认短指令需要已有 curl 与 CA，地址放在开头，GitHub / 源站切换后显示和复制内容同步变化。没有 curl 的精简系统，展开“缺少 curl 时使用兼容指令”，由 `/bin/sh` 自动安装 curl 与 CA。两种指令随后使用同一个 POSIX 引导脚本，自动补齐 Bash、Python 3.6+、coreutils、flock、用户管理和 libcap 工具。支持 apt、dnf、microdnf、yum、apk、zypper、pacman 和 xbps。Python 用于安装、更新和维护，不是常驻节点进程的运行依赖；不替换系统 Python，也不安装 Docker、Node.js 或 Go。

请直接复制面板完整命令。下例只适用于已有 curl 和 CA 的机器；面板折叠的兼容指令还包括缺少下载环境时的自动引导，不要用占位凭据执行：

```bash
curl -q -fsSL --proto '=https' --proto-redir '=https' https://datahub.example.com/install.sh -o /tmp/chitanda-bootstrap.sh
sh /tmp/chitanda-bootstrap.sh install --server 'https://datahub.example.com' --ticket '从面板复制的15分钟安装凭据'
```

可选择 GitHub 下载公开启动脚本，或通过源站 `/install.sh` 下载；源站方式固定回源地址，同时保持域名与 TLS 验证。公开项目地址为 [chitanda-data-platform](https://github.com/violetaini/chitanda-data-platform)，启动脚本为 [node-bootstrap.sh](https://github.com/violetaini/chitanda-data-platform/blob/main/deploy/tunnel-control/node-bootstrap.sh)。公开启动脚本不包含生产身份，完整安装器先下载到私有临时目录并验证固定摘要，再执行和清理；节点配置仍需短期凭据领取。

默认路径：

| 用途 | 路径 |
| --- | --- |
| 程序 | `/usr/local/bin/chitanda-transit` |
| 本机管理命令 | `/usr/local/sbin/chitanda-node` |
| 启动配置 | `/etc/chitanda-transit/config.json` |
| 缓存 | `/var/lib/chitanda-transit/` |
| 服务 | systemd：`chitanda-transit.service`；其他 init：`chitanda-transit` |
| 自动更新状态 | `/etc/chitanda-transit/update-state.json` |
| 更新任务 | systemd timer，或对应 init 管理的独立更新进程 |

脚本不自动修改防火墙、Nginx 或证书任务。优化节点监听的 TCP / UDP 端口应空闲并仅向需要的节点来源开放；主机已有 443 服务时，可在添加优化节点时选其他可用端口。Stream 默认另用 TCP 11323。

## 更新与排查

已安装节点以 root 执行：

```bash
chitanda-node update
chitanda-node status
chitanda-node logs
```

旧节点尚无本机管理命令时，可使用公开启动脚本的 `update` 操作更新；安装 / 卸载窗口仅展示当前需要的操作。更新要求已有服务使用标准程序和配置路径；保留原节点 ID、凭据、HTTPS 入口、本机业务配置、缓存及已有服务定义。不同节点身份不会直接覆盖。每次更换程序前在 `/var/backups/chitanda-node.*` 留存私有备份，下载、校验或启动失败时恢复原程序和配置。

安装器不自动修改独立证书同步器、源站适配器或来源授权。现有特殊配置仍需要新程序兼容。

## 自动更新

新安装和更新成功后自动注册本机更新任务。「系统设置 → 节点自动更新」统一设置开关、版本检查间隔（默认 60 分钟，5 分钟至 24 小时）和失败冷却（默认 360 分钟，10 分钟至 7 天）。本机调度约每 5 分钟唤醒，读取身份鉴权的控制端发布清单，并按策略决定是否检查或更新；不是每次唤醒都下载程序。策略通过本节点 HTTPS 身份获取，不开放匿名更新接口。

已有相同版本时不重启业务；仅维护器变化时只更新维护器。新版本先验证平台、大小、SHA-256、实际版本，再备份和替换，启动失败自动回退；同一失败版本在冷却期内不会反复重启。自动更新不降级，不拉起管理员主动停止的服务，不恢复已经卸载的节点。已被更新进程暂停的中断下载可安全重试；过期安装租约需要回面板重新复制。

本机可独立暂停或恢复：

```sh
chitanda-node auto-update-disable
chitanda-node auto-update-enable
chitanda-node auto-update
```

手动 `update` 可立即检查更新。只有旧维护器部署完成的节点才能自动更新；不能仅靠修改面板就更新尚未安装维护器的远端机器。systemd 更新日志用 `journalctl -u chitanda-node-update.service` 查看；OpenRC / SysV 用 `/var/log/chitanda-node-update.log`，runit 由其 supervise 输出采集。离线恢复仍从节点卡片复制安装 / 修复命令。

## 卸载

```bash
chitanda-node uninstall
```

面板中的 GitHub / 源站卸载指令通过启动脚本获取已校验安装器，兼容尚无本机助手的旧部署；先校验标准服务的程序与配置路径，遇到其他服务定义会停止并提示人工检查。默认停止并移除本机节点程序、服务和本机管理命令，保留配置、缓存、证书及面板记录，便于以新安装命令恢复原节点。要撤销权限，在面板处理关联隧道后删除节点。

需要明确清除本机配置时，可在卸载前执行 `chitanda-node uninstall --purge`。它删除已知启动配置和节点缓存，仍保留证书、外置入口、其他服务及备份。卸载后本机管理命令已移除，如需再次执行安装器操作，从面板重新复制命令。

## 安装凭据与下载

安装命令使用 15 分钟租约，只能领取指定节点的配置，第一次领取后绑定来源地址；同一来源可在期限内重试以恢复丢失响应。查看卸载指令不生成安装租约或回显长期凭据；选择重新安装时，签发原节点身份对应的短期安装租约，不更换 ID 或凭据。服务器只保存租约摘要；原有管理员会话、CSRF、来源白名单继续保护安装命令生成。删除或更换节点凭据会立即使旧租约失效。

脚本下载地址公开且不含凭据；领取配置需要租约，读取版本与下载程序需要本节点独立身份，节点不能生成其他节点安装命令。长期凭据不放进下载 URL 或 curl 参数，保存在本机 0600 私有配置及临时凭据文件中；临时文件结束后清理。面板关闭安装窗口会清空命令与配置展示。

控制端地址来自 `CT_CONTROLLER_URL`。可选 `CT_CONTROLLER_ADDRESS=IP:端口` 让安装和节点同步直达源站，仍按控制端域名验证 TLS；不要关闭证书校验。

## 发布安装包

```powershell
powershell -NoProfile -File deploy/tunnel-control/build-node-release.ps1
```

使用固定 SDK 和本仓库源码构建 Linux amd64 / arm64 / armv7 / 386 / riscv64 / loong64 / ppc64le / s390x，引擎 2.7.2 提供 `-version` 校验。armv7 下载名使用 GOARM=6 构建以兼容 ARMv6/v7。产物在忽略的 `tmp/node-release/`；将完整目录由管理员部署到独立版本目录并配置 `CT_RELEASE_DIR`，包含 `manifest.json` 和各架构固定文件名的程序。目录和程序由 root 管理，面板服务仅需读取。发布前需同时运行 `python scripts/sync-node-installer.py` 同步完整安装器摘要；不要将生产身份或状态打进安装包。

安装交互参考 [Komari Agent](https://github.com/komari-monitor/komari-agent) 和 [Nezha 安装 Agent](https://nezha.wiki/guide/agent) 的命令生成、架构选择与服务生命周期方式；实现使用本项目独立协议与凭据，不执行这些项目的安装脚本。

## 本次发布核验（2026-10-19）

控制端 2.11.0 已发布引擎 2.7.2 的两种架构安装包。已核验节点身份下载、完整文件摘要、管理来源限制和安装凭据失效行为；在隔离 Linux 路径中验证安装、重复安装、更新失败回退、卸载保留及显式清理。amd64 / arm64 原机版本检查通过，现有两台生产节点未升级或重启。

控制端升级保留账号、CA、白名单和当时版本 29 的节点与线路配置；期间用户新增的待安装节点仍保留。两端使用既有业务鉴权请求 HTTPS 状态接口均返回 200。发布前备份位于 `/var/backups/chitanda-transit/onboarding-20261019T133300Z`；恢复时使用该备份中的应用、环境及 Nginx 配置，并先核对升级后是否有用户配置变更，不直接覆盖当前运行数据。

## 2.12.0 卸载与界面核验（2026-10-20）

节点安装状态以鉴权心跳和卸载通知为依据，与在线状态分开保存；首次添加自动展示安装指令，后续始终可从节点卡片重新打开。默认卸载不删除面板节点或业务外置适配器；网络不可达时会明确提示中台未收到通知，可恢复网络后重试同一卸载命令，不会伪报已同步。

39 项隔离安装器检查覆盖标准安装、校验、回退、早期无助手卸载和非标准服务拒绝。另在独立命名、无业务端口的真实 systemd 临时服务上通过 12 项卸载检查，确认停止、禁用和删除程序 / 单元实际生效，配置、缓存、证书及外置文件保留，重复卸载安全；测试服务已清理。生产节点未执行卸载或重启。发布备份 `/var/backups/chitanda-transit/node-lifecycle-20261020T013426Z`，当前配置版本 33 保留。


## 离线恢复（2.12.1）

服务异常、关机、断网和手工卸载均可能表现为离线。离线节点默认展示安装 / 修复命令，沿用原节点 ID 和凭据；程序还在时保留既有入口配置进行覆盖修复，已删除时重新安装。在线节点的卸载窗口也可点“重新安装”，手动选择不会被自动刷新覆盖。GitHub / 源站两个下载来源保持不变。


## 2.13.0 Linux 与自动更新核验（2026-10-20）

15 个官方发行版镜像依赖准备通过。Debian 12 / Alpine 3.22 从缺少 curl、Python 的精简环境执行面板完整指令，实际安装 Go 节点并收到 TLS 鉴权心跳，再卸载成功；OpenRC、runit、SysV 另做原生生命周期验证。自动更新使用真实独立 systemd 单元验证身份、HTTPS、同版本不重启、配置保留、启动失败回退和失败冷却。具体发行版、架构执行情况和限制见 [支持范围](linux-support.md)。

控制端 2.13.0 发布后保留配置版本 33、账号、CA 与管理来源限制；八种架构包由 root 管理并验证面板低权限账号可读。发布备份 `/var/backups/chitanda-transit/portable-20261020T023209Z`。升级中不重新部署独立证书同步器和业务适配器。

国内与香港两台现有节点已升级到 2.7.2，启用 systemd 更新任务；已验证同版本自动检查不重启、配置与原服务定义保持一致，鉴权心跳报告版本 2.7.2。节点更新前备份分别位于国内 `/var/backups/chitanda-transit/auto-update-20261020T023949Z` 和香港 `/var/backups/chitanda-transit/auto-update-20261020T023905Z`。两端既有鉴权业务 URL 均返回 200。
