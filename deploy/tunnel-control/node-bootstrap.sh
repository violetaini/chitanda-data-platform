#!/usr/bin/env bash
# Public launcher: contains no node identity or installation credential.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo '请先执行 sudo -i，进入 root 终端。' >&2; exit 1; }
for cmd in curl python3 sha256sum; do command -v "$cmd" >/dev/null || { echo "缺少 $cmd" >&2; exit 1; }; done
action=${1:-help}
if [[ $action == help || $action == --help ]]; then
 echo '请在数据中台的节点管理 → 安装指令复制完整命令。'
 echo '支持 install / update / uninstall / status / logs；卸载默认保留配置。'
 exit 0
fi
server=''; address=''
args=("$@")
for ((i=1;i<${#args[@]};i++)); do
 case ${args[i]} in
  --server) i=$((i+1)); server=${args[i]:-};;
  --server-address) i=$((i+1)); address=${args[i]:-};;
 esac
done
work=$(mktemp -d /var/tmp/chitanda-launcher.XXXXXXXX)
trap 'rm -rf -- "$work"' EXIT
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
mapfile -t connection <"$work/connection"
download=(curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120)
[[ -z ${connection[1]:-} ]] || download+=(--resolve "${connection[1]}")
"${download[@]}" "${connection[0]}/transit-node/install.sh" -o "$work/install.sh"
# Keep this digest in step with the reviewed full installer.
printf '%s  %s\n' '78177e2d4267e7510a891ce7730d5bec354d798e977340c649e3d0c27863bc8b' "$work/install.sh" | sha256sum -c - >/dev/null
bash "$work/install.sh" "$@"
