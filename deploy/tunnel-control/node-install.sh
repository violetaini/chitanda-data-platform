#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
SERVICE=chitanda-transit
ETC=/etc/chitanda-transit
STATE=/var/lib/chitanda-transit
BIN=/usr/local/bin/chitanda-transit
HELPER=/usr/local/sbin/chitanda-node
UNIT=/etc/systemd/system/chitanda-transit.service
MARKER=/etc/chitanda-transit/installer.json
action=${1:-help}; [[ $# -eq 0 ]] || shift
die(){ printf '错误：%s\n' "$*" >&2; exit 1; }
say(){ printf '%s\n' "$*"; }
if [[ $action == help || $action == --help ]]; then
 say 'Chitanda 节点管理：install / update / status / logs / uninstall [--purge]'
 say '安装命令从中台的节点管理页面获取。更新保留身份、入口和缓存；卸载默认保留配置。'; exit 0
fi
[[ $EUID -eq 0 ]] || die '请使用 root 或 sudo 执行。'
case "$action" in install|update|uninstall|status|logs) ;; *) die '不支持此操作。';; esac
[[ $(uname -s) == Linux ]] || die '当前安装器支持 Linux/systemd。'
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || die '需要正在运行的 systemd。'
if [[ $action == status ]]; then exec systemctl status "$SERVICE" --no-pager; fi
if [[ $action == logs ]]; then exec journalctl -u "$SERVICE" -n 50 --no-pager; fi
command -v flock >/dev/null || die '请先安装 util-linux（flock）。'
exec 9>/run/chitanda-node-install.lock
flock -n 9 || die '另一个节点管理任务正在执行。'
for p in "$ETC" "$STATE" "$BIN" "$HELPER" "$UNIT" "$MARKER" "$ETC/config.json"; do
 [[ ! -L $p ]] || die '目标路径包含符号链接，已停止以保护现有文件。'
done
if [[ $action == uninstall ]]; then
 purge=false
 if [[ ${1:-} == --purge ]]; then purge=true; shift; fi
 [[ $# -eq 0 ]] || die '卸载仅支持 --purge 参数。'
 [[ -f $MARKER ]] || die '没有安装器登记记录，请先使用安装或更新命令接管此节点。'
 systemctl stop "$SERVICE"
 systemctl disable "$SERVICE" >/dev/null 2>&1 || true
 rm -f -- "$UNIT" "$BIN" "$HELPER" "$MARKER"
 systemctl daemon-reload
 systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
 if $purge; then
  # Fixed known files only: never remove shared certificates or other services.
  rm -f -- "$ETC/config.json" "$STATE/runtime.json" "$STATE/relay-ca.pem" "$STATE/replay.db" "$STATE/replay.db-wal" "$STATE/replay.db-shm"
  say '节点程序、启动配置和通道缓存已清除；证书、外置入口及面板记录保留。'
 else
  say '节点程序已卸载；启动配置、证书和缓存已保留，可用新安装命令恢复原身份。'
 fi
 exit 0
fi
for cmd in curl python3 sha256sum install getent; do command -v "$cmd" >/dev/null || die "缺少 $cmd，请先安装后重试。"; done
server=''; address=''; ticket=''
while [[ $# -gt 0 ]]; do
 case "$1" in
  --server|--server-address|--ticket)
   [[ $# -ge 2 && -n $2 ]] || die '安装参数缺少值。'
   case "$1" in --server) server=$2;; --server-address) address=$2;; --ticket) ticket=$2;; esac
   shift 2;;
  *) die '安装参数不正确。';;
 esac
done
case $(uname -m) in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die '当前安装包支持 amd64 / arm64。';; esac
if [[ $action == install ]]; then [[ $ticket =~ ^[a-f0-9]{64}$ ]] || die '安装凭据无效，请在面板重新生成。'; fi
if [[ $action == update ]]; then [[ -f $ETC/config.json ]] || die '未找到已有配置，请使用面板安装命令。'; fi
work=$(mktemp -d /var/tmp/chitanda-node.XXXXXXXX)
backup=''; changed=false; was_active=false; was_enabled=false
cleanup(){
 result=$?
 if [[ $result -ne 0 ]] && $changed; then
  say '启动未通过，正在恢复更新前的程序与配置。' >&2
  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  for pair in "binary:$BIN" "config:$ETC/config.json" "unit:$UNIT" "helper:$HELPER" "marker:$MARKER"; do
   key=${pair%%:*}; target=${pair#*:}
   if [[ -f $backup/$key ]]; then cp -a -- "$backup/$key" "$target"; else rm -f -- "$target"; fi
  done
  systemctl daemon-reload || true
  if $was_enabled; then systemctl enable "$SERVICE" >/dev/null 2>&1 || true; else systemctl disable "$SERVICE" >/dev/null 2>&1 || true; fi
  if $was_active; then systemctl start "$SERVICE" || true; fi
 fi
 rm -rf -- "$work"
}
trap cleanup EXIT
python3 - "$action" "$server" "$address" "$ETC/config.json" >"$work/connection" <<'PY'
import sys,json,ipaddress,urllib.parse,pathlib
action,server,address,config=sys.argv[1:]
if action=='update':
 c=json.loads(pathlib.Path(config).read_text());server=c['controller'];address=c.get('controllerAddress','')
u=urllib.parse.urlsplit(server)
if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/'):
 raise SystemExit('控制端必须是 HTTPS 根地址。')
port=u.port or 443
resolve=''
if address:
 host,p=address.rsplit(':',1);ip=ipaddress.ip_address(host.strip('[]'))
 if int(p)!=port:raise SystemExit('控制端直达端口与 HTTPS 端口不同。')
 resolve=f'{u.hostname}:{port}:'+('['+str(ip)+']' if ip.version==6 else str(ip))
print(server.rstrip('/'));print(resolve)
PY
mapfile -t connection <"$work/connection"
server=${connection[0]}; resolve=${connection[1]:-}
CURL=(curl -fsS --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 120)
[[ -z $resolve ]] || CURL+=(--resolve "$resolve")
if [[ $action == install ]]; then
 printf '{"ticket":"%s"}' "$ticket" >"$work/claim.json"
 "${CURL[@]}" -H 'Content-Type: application/json' --data-binary "@$work/claim.json" "$server/transit-node/enroll" -o "$work/claim-response.json" || die '领取配置失败；请核对凭据有效期、服务器时间与 HTTPS。'
fi
python3 - "$work" "$action" "$ETC/config.json" "$server" <<'PY'
import sys,pathlib,json,re
work=pathlib.Path(sys.argv[1]);action,oldfile,server=sys.argv[2:]
old=json.loads(pathlib.Path(oldfile).read_text()) if pathlib.Path(oldfile).exists() else {}
if action=='install':
 response=json.loads((work/'claim-response.json').read_text());c=response['config']
 if old and old.get('id')!=c.get('id'):raise SystemExit('本机已有不同节点身份；请勿覆盖，请先确认原配置。')
 c={**old,**c};(work/'manifest.json').write_text(json.dumps(response['release']))
else:c=old
if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',c.get('id','')) or not re.fullmatch(r'[a-f0-9]{64}',c.get('token','')) or c.get('role') not in ('agent','relay') or c.get('controller','').rstrip('/')!=server:
 raise SystemExit('节点配置校验失败。')
(work/'config.json').write_text(json.dumps(c,indent=2))
(work/'curl-auth.conf').write_text('header = '+json.dumps('X-Node-ID: '+c['id'])+'\nheader = '+json.dumps('Authorization: Bearer '+c['token'])+'\n')
PY
if [[ $action == update ]]; then
 "${CURL[@]}" --config "$work/curl-auth.conf" "$server/transit-node/release" -o "$work/manifest.json" || die '读取安装包失败，旧程序未修改。'
fi
python3 - "$work" "$arch" >"$work/asset" <<'PY'
import json,pathlib,sys,re
work=pathlib.Path(sys.argv[1]);arch=sys.argv[2];m=json.loads((work/'manifest.json').read_text());v=m.get('version','');asset=m.get('assets',{}).get('linux-'+arch,{})
if not re.fullmatch(r'\d+\.\d+\.\d+',v) or asset.get('url')!='/transit-node/releases/linux-'+arch or not re.fullmatch(r'[a-f0-9]{64}',asset.get('sha256','')) or not 0<asset.get('size',0)<=80*1024*1024:
 raise SystemExit('安装包清单校验失败或没有对应架构。')
print(v);print(asset['sha256']);print(asset['url']);print(asset['size'])
PY
mapfile -t asset <"$work/asset"
say "正在获取 Linux/$arch 节点 ${asset[0]}……"
"${CURL[@]}" --config "$work/curl-auth.conf" "$server${asset[2]}" -o "$work/binary" || die '下载失败，旧程序未修改。'
[[ $(wc -c <"$work/binary") -eq ${asset[3]} ]] || die '安装包大小不符。'
printf '%s  %s\n' "${asset[1]}" "$work/binary" | sha256sum -c - >/dev/null || die '安装包 SHA-256 不符，未执行。'
chmod 700 "$work/binary"
[[ $("$work/binary" -version) == "${asset[0]}" ]] || die '节点版本或架构校验失败。'
if [[ -f $UNIT ]]; then
 grep -Fq "ExecStart=$BIN -config $ETC/config.json" "$UNIT" || die '已有服务使用其他程序或配置路径，请人工核对。'
fi
backup=$(mktemp -d /var/backups/chitanda-node.XXXXXXXX)
for pair in "binary:$BIN" "config:$ETC/config.json" "unit:$UNIT" "helper:$HELPER" "marker:$MARKER"; do
 key=${pair%%:*}; target=${pair#*:}; [[ ! -f $target ]] || cp -a -- "$target" "$backup/$key"
done
systemctl is-active --quiet "$SERVICE" && was_active=true || true
systemctl is-enabled --quiet "$SERVICE" && was_enabled=true || true
getent group chitanda-transit >/dev/null || groupadd --system chitanda-transit
id -u chitanda-transit >/dev/null 2>&1 || useradd --system --gid chitanda-transit --no-create-home --home-dir "$STATE" --shell /usr/sbin/nologin chitanda-transit
changed=true
install -d -m 0750 -o root -g chitanda-transit "$ETC"
install -d -m 0700 -o chitanda-transit -g chitanda-transit "$STATE"
install -m 0600 -o chitanda-transit -g chitanda-transit "$work/config.json" "$ETC/config.json"
install -m 0755 "$work/binary" "$BIN.new"
mv -f -- "$BIN.new" "$BIN"
if [[ ! -f $UNIT ]]; then
 cat >"$UNIT" <<EOF
# Managed by Chitanda node installer
[Unit]
Description=Chitanda data node
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=chitanda-transit
Group=chitanda-transit
WorkingDirectory=$STATE
Environment=GOMEMLIMIT=32MiB
Environment=GOGC=50
Environment=GOMAXPROCS=1
ExecStart=$BIN -config $ETC/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$STATE
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UMask=0077
MemoryMax=96M
TasksMax=48
LimitNOFILE=1024
[Install]
WantedBy=multi-user.target
EOF
fi
install -m 0755 "${BASH_SOURCE[0]}" "$HELPER.new"
mv -f -- "$HELPER.new" "$HELPER"
python3 - "$MARKER" "${asset[0]}" "$arch" <<'PY'
import pathlib,json,sys,datetime
pathlib.Path(sys.argv[1]).write_text(json.dumps({'version':sys.argv[2],'arch':sys.argv[3],'installedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
PY
chmod 600 "$MARKER"
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null
systemctl restart "$SERVICE"
sleep 2
systemctl is-active --quiet "$SERVICE" || die '节点服务未能启动。'
changed=false
say "节点 ${asset[0]} 已安装并启动；身份与已有业务入口配置保留。"
say "备份：$backup"
say '返回中台查看节点是否上线。若未上线：sudo chitanda-node logs'
say '更新：sudo chitanda-node update'
say '卸载并保留配置：sudo chitanda-node uninstall'
