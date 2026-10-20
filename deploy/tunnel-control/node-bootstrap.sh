#!/bin/sh
# Public POSIX launcher; no node identity is embedded.
set -eu
umask 077
# BEGIN ENVIRONMENT
# Shared POSIX dependency preparation. Embedded in both published scripts.
ct_retry() {
 ct_attempt=1
 while ! "$@"; do
  [ "$ct_attempt" -lt 3 ] || return 1
  echo "操作失败，重试 $ct_attempt / 3……" >&2
  sleep "$((ct_attempt * 3))"; ct_attempt=$((ct_attempt + 1))
 done
}
ct_apt_archive() {
 [ -r /etc/os-release ] || return 1
 . /etc/os-release
 [ "${ID:-}" = debian ] || return 1
 case ${VERSION_ID:-} in 10) ct_suite=buster;; 11) ct_suite=bullseye;; *) return 1;; esac
 echo "当前软件源不可用，尝试 Debian 官方归档（仅临时来源，保留签名验证）……"
 ct_apt_dir=$(mktemp -d /var/tmp/chitanda-apt.XXXXXXXX) || return 1
 chmod 755 "$ct_apt_dir"; mkdir -p "$ct_apt_dir/lists/partial"
 printf 'deb http://archive.debian.org/debian %s main\ndeb http://archive.debian.org/debian-security %s-security main\n' "$ct_suite" "$ct_suite" >"$ct_apt_dir/sources.list"
 if [ "$ct_suite" = buster ]; then printf 'deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n' >"$ct_apt_dir/sources.list"; fi
 ct_apt_result=0
 env DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist="$ct_apt_dir/sources.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$ct_apt_dir/lists" -o Acquire::Retries=3 update &&
 env DEBIAN_FRONTEND=noninteractive apt-get -o Dir::Etc::sourcelist="$ct_apt_dir/sources.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$ct_apt_dir/lists" -o DPkg::Lock::Timeout=120 -y --no-install-recommends install "$@" || ct_apt_result=$?
 rm -rf -- "$ct_apt_dir"
 return "$ct_apt_result"
}
ct_packages() {
 ct_curl=curl; command -v curl >/dev/null 2>&1 && ct_curl=
 ct_coreutils=coreutils
 if command -v sha256sum >/dev/null 2>&1 && command -v install >/dev/null 2>&1; then ct_coreutils=; fi
 if command -v apt-get >/dev/null 2>&1; then
  if ct_retry env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -o Acquire::Retries=3 -o Acquire::http::No-Cache=true update &&
   ct_retry env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -y --no-install-recommends install ca-certificates $ct_curl bash python3 $ct_coreutils util-linux passwd libcap2-bin; then return 0; fi
  ct_apt_archive ca-certificates $ct_curl bash python3 $ct_coreutils util-linux passwd libcap2-bin
 elif command -v dnf >/dev/null 2>&1; then ct_retry dnf -y --setopt=retries=3 install ca-certificates $ct_curl bash python3 $ct_coreutils util-linux shadow-utils libcap
 elif command -v microdnf >/dev/null 2>&1; then ct_retry microdnf -y install ca-certificates $ct_curl bash python3 $ct_coreutils util-linux shadow-utils libcap
 elif command -v yum >/dev/null 2>&1; then ct_retry yum -y --setopt=retries=3 install ca-certificates $ct_curl bash python3 $ct_coreutils util-linux shadow-utils libcap
 elif command -v apk >/dev/null 2>&1; then ct_retry apk add --no-cache ca-certificates $ct_curl bash python3 $ct_coreutils util-linux shadow libcap
 elif command -v zypper >/dev/null 2>&1; then ct_retry zypper --non-interactive install --no-recommends ca-certificates $ct_curl bash /usr/bin/python3 $ct_coreutils util-linux shadow libcap-progs
 elif command -v pacman >/dev/null 2>&1; then ct_retry pacman -S --needed --noconfirm ca-certificates $ct_curl bash python $ct_coreutils util-linux shadow libcap
 elif command -v xbps-install >/dev/null 2>&1; then ct_retry xbps-install -Sy ca-certificates $ct_curl bash python3 $ct_coreutils util-linux shadow libcap
 else echo '未识别可用包管理器，请安装 bash、curl、Python 3.6+、CA 证书、coreutils、util-linux 和用户管理工具。' >&2; return 1
 fi
}
ct_prepare() {
 [ "$(uname -s)" = Linux ] || { echo '仅支持 Linux。' >&2; return 1; }
 [ "$(id -u)" = 0 ] || { echo '请先使用 sudo -i 进入 root 终端。' >&2; return 1; }
 ct_missing=''
 for ct_cmd in bash curl python3 sha256sum install flock useradd groupadd setcap; do
  command -v "$ct_cmd" >/dev/null 2>&1 || ct_missing="$ct_missing $ct_cmd"
 done
 [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] || [ -s /etc/ssl/ca-bundle.pem ] || ct_missing="$ct_missing CA"
 if [ -n "$ct_missing" ]; then
  echo "自动安装缺失依赖：$ct_missing"
  ct_packages || { echo '依赖安装失败；请检查软件源、网络、磁盘和包管理锁，不会关闭签名或证书校验。' >&2; return 1; }
 fi
 for ct_cmd in bash curl python3 sha256sum install flock useradd groupadd setcap; do
  command -v "$ct_cmd" >/dev/null 2>&1 || { echo "仍缺少 $ct_cmd" >&2; return 1; }
 done
 python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)' || { echo '需要 Python 3.6+；不会替换系统默认 Python。' >&2; return 1; }
}
# END ENVIRONMENT
action=${1:-help}
if [ "$action" = help ] || [ "$action" = --help ]; then echo '在节点管理复制安装命令；支持 install / update / uninstall / prepare。'; exit 0; fi
ct_prepare
if [ "$action" = prepare ]; then echo '依赖准备完成。'; exit 0; fi
server=''; address=''
ct_previous=''
for ct_value in "$@"; do
 case $ct_previous in --server) server=$ct_value;; --server-address) address=$ct_value;; esac
 ct_previous=$ct_value
done
work=$(mktemp -d /var/tmp/chitanda-launcher.XXXXXXXX)
trap 'rm -rf -- "$work"' 0 1 2 15
python3 - "$action" "$server" "$address" >"$work/connection" <<'PY'
import sys,json,pathlib,urllib.parse,ipaddress
action,server,address=sys.argv[1:]
if action!='install':
 c=json.loads(pathlib.Path('/etc/chitanda-transit/config.json').read_text());server=c['controller'];address=c.get('controllerAddress','')
u=urllib.parse.urlsplit(server)
if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/'):
 raise SystemExit('需要有效的 HTTPS 控制端根地址。')
resolve=''
if address:
 host,port=address.rsplit(':',1);ip=ipaddress.ip_address(host.strip('[]'))
 if int(port)!=(u.port or 443):raise SystemExit('直达端口与 HTTPS 不一致。')
 resolve=f'{u.hostname}:{u.port or 443}:'+('['+str(ip)+']' if ip.version==6 else str(ip))
print(server.rstrip('/'));print(resolve)
PY
ct_server=$(sed -n '1p' "$work/connection"); ct_resolve=$(sed -n '2p' "$work/connection")
ct_download(){ curl -q -fsS --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 180 "$@" "$ct_server/transit-node/install.sh" -o "$work/install.sh"; }
if [ -n "$ct_resolve" ]; then ct_retry ct_download --noproxy '*' --resolve "$ct_resolve"; else ct_retry ct_download; fi
# Keep this digest in step with the reviewed full installer.
printf '%s  %s\n' '8f7eab718d00638c495d73370c6d7505d89a44009c96f0d39f02456721dcf1a3' "$work/install.sh" | sha256sum -c - >/dev/null
bash "$work/install.sh" "$@"
