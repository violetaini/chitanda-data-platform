# Linux 安装支持范围（2.13.0）

安装器尽量兼容常见 Linux；不能把发行版、内核、CPU 和软件源的所有组合视为已实测。普通服务器需要 root、有可用的服务管理器、可验证签名的软件源及到控制端的 HTTPS；普通没有 init 的容器不作为节点系统服务目标。

## 发行版和环境补齐

| 系列 | 包管理器 | 本次验证 |
| --- | --- | --- |
| Debian | apt | 10 / 11 / 12 / 13 精简官方镜像依赖准备通过；12 完整面板命令、原生节点鉴权心跳和卸载通过 |
| Ubuntu | apt | 18.04 / 20.04 / 22.04 / 24.04 官方镜像依赖准备通过 |
| Rocky / Alma / RHEL / CentOS Stream / Fedora | dnf、microdnf、yum | Rocky 8 / 9 minimal、AlmaLinux 9 minimal、Fedora 44 官方镜像依赖准备通过；其余按相同包管理器处理，未逐版本实测 |
| Alpine | apk | 3.20 / 3.22 官方镜像依赖准备通过；3.22 完整面板命令、原生节点鉴权心跳和卸载通过 |
| openSUSE | zypper | Tumbleweed 官方镜像依赖准备通过 |
| Arch | pacman | 已实现包管理器分支；本次测试主机未取得匹配架构镜像，未做发行版实测 |
| Void | xbps | 已实现包管理器和 runit 分支；本次未做 Void 发行版实测，runit 在隔离 Debian 容器实际启动 / 停止通过 |

精简系统可从只有 `/bin/sh` 开始，缺少 curl、CA、Bash、Python 3.6+、基础文件工具、flock、用户管理和 setcap 时自动安装。已有 curl-minimal / coreutils-single 的系统不强制换成冲突的大包。包管理和下载有有界重试，下载失败再尝试 IPv4 / IPv6，直达源站仍按域名验证 TLS。

Debian 10 / 11 默认源失效时，可使用 Debian 官方归档的临时源和列表目录，保留签名验证，不覆盖系统 sources.list。其他已停止维护且软件源失效的版本会明确报错；不会下载不明源或关闭签名。Arch 不执行局部刷新 `pacman -Sy`，包数据库为空或系统长期未升级时，应由管理员先完成正常系统更新。

## CPU 与内核

提供 8 种固定平台安装包：amd64（GOAMD64=v1）、arm64（v8.0）、armv7（GOARM=6，覆盖 ARMv6/v7）、386（softfloat）、riscv64、loong64、ppc64le、s390x。所有平台交叉构建成功；amd64、386 和 arm64 另做原机版本执行验证，其余尚未在对应 CPU 上执行。

节点静态构建（CGO=0），兼容 glibc / musl，不要求系统安装 Go。最低内核仍受固定 Go 工具链约束；Go 官方要求 Go 1.24+ 通常为 Linux 3.2+，loong64 为 5.19+，发行版兼容还需满足其他平台要求，见 [Go 最低要求](https://go.dev/wiki/MinimumRequirements)。不承诺在更老内核上运行。

## 服务与更新

按系统检测 systemd、OpenRC、runit、SysV。服务使用独立低权限账号；非 systemd 环境通过文件 capability 允许必要的低端口监听。服务启用、停止、更新和卸载使用该系统原生工具，拒绝覆盖不属于本项目的服务。

自动更新默认每小时检查，失败冷却 6 小时；系统设置可修改，节点也可本地暂停。下载须通过节点身份、TLS、大小、摘要和版本校验；启动失败回退，冷却期不重复尝试失败版本，现有相同版本不重启。更新器本身可通过经过摘要验证的安装器升级。具体命令见 [节点安装与维护](node-installation.md)。

## 验证方法

`node-distro-matrix.test.py` 在不挂载宿主配置的容器准备环境；`node-init-containers.test.py` 检查真实 init 工具；`node-command-container.test.py` 执行面板命令和真实 Go 心跳；`node-update-systemd.test.py` 用独立命名的真实 systemd 单元验证 HTTPS 更新和回退；其他安装测试使用隔离路径和临时身份。容器环境验证依赖和服务工具，不能代替不同真实内核、网络及 CPU 的验证。
