#!/usr/bin/env bash
set -Eeuo pipefail
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
case "$action" in install|update|auto-update|setup-auto-update|uninstall|status|logs|prepare|watch-updates|auto-update-disable|auto-update-enable) ;; *) die '不支持此操作。';; esac
ct_prepare || die '环境准备未通过。'
if [[ $action == prepare ]]; then say '依赖准备完成。'; exit 0; fi
# BEGIN RUNTIME
# Embedded runtime: service backends and update scheduling.
RUNIT_DIR=/etc/sv/chitanda-transit
RUNIT_LINK=/var/service/chitanda-transit
UPDATE_UNIT=/etc/systemd/system/chitanda-node-update.service
UPDATE_TIMER=/etc/systemd/system/chitanda-node-update.timer
UPDATE_INIT=/etc/init.d/chitanda-node-update
UPDATE_RUNIT=/etc/sv/chitanda-node-update
UPDATE_LINK=/var/service/chitanda-node-update
detect_init(){
 if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then INIT=systemd
 elif command -v rc-service >/dev/null && command -v openrc-run >/dev/null; then INIT=openrc
 elif command -v sv >/dev/null && command -v chpst >/dev/null && [[ -d /var/service ]]; then INIT=runit
 elif command -v start-stop-daemon >/dev/null && { command -v update-rc.d >/dev/null || command -v chkconfig >/dev/null; }; then INIT=sysv
 else die '没有可用服务管理器，需要 systemd、OpenRC、runit 或 SysV；普通无 init 容器不能安装系统服务。'; fi
}
service_file(){ case $INIT in systemd) printf '%s\n' "$UNIT";; openrc|sysv) printf '/etc/init.d/%s\n' "$SERVICE";; runit) printf '%s/run\n' "$RUNIT_DIR";; esac; }
service_owned(){
 case $INIT in
  systemd) grep -Fxq "ExecStart=$BIN -config $ETC/config.json" "$UNIT";;
  *) grep -Fq '# Managed by Chitanda node installer' "$UNIT" && grep -Fq "$BIN" "$UNIT" && grep -Fq "$ETC/config.json" "$UNIT";;
 esac
}
service_active(){ case $INIT in systemd) systemctl is-active --quiet "$SERVICE";; openrc) rc-service "$SERVICE" status >/dev/null;; runit) sv status "$RUNIT_LINK" 2>/dev/null | grep -q '^run:';; sysv) [[ -f $UNIT ]] && "$UNIT" status >/dev/null;; esac; }
service_status(){ case $INIT in systemd) systemctl status "$SERVICE" --no-pager;; openrc) rc-service "$SERVICE" status;; runit) sv status "$RUNIT_LINK";; sysv) "$UNIT" status;; esac; }
service_enabled(){ case $INIT in systemd) systemctl is-enabled --quiet "$SERVICE";; openrc) rc-update show default | grep -q "$SERVICE";; runit) [[ -L $RUNIT_LINK ]];; sysv) find /etc/rc2.d /etc/rc3.d /etc/rc5.d -name "S*$SERVICE" 2>/dev/null | grep -q .;; esac; }
service_stop(){ case $INIT in systemd) systemctl stop "$SERVICE";; openrc) rc-service "$SERVICE" stop;; runit) sv -w 15 down "$RUNIT_LINK";; sysv) "$UNIT" stop;; esac; }
service_start()( exec 9>&-; case $INIT in systemd) systemctl start "$SERVICE";; openrc) rc-service "$SERVICE" start;; runit) for attempt in {1..30}; do [[ -p $RUNIT_DIR/supervise/ok ]] && break; sleep 0.5; done; sv -w 15 up "$RUNIT_LINK";; sysv) "$UNIT" start;; esac; )
service_restart()( exec 9>&-; case $INIT in systemd) systemctl restart "$SERVICE";; openrc) rc-service "$SERVICE" restart;; runit) sv -w 15 restart "$RUNIT_LINK";; sysv) "$UNIT" restart;; esac; )
service_reload(){ [[ $INIT != systemd ]] || systemctl daemon-reload; }
service_enable(){
 case $INIT in
  systemd) systemctl enable "$SERVICE";; openrc) rc-update add "$SERVICE" default;;
  runit) if [[ -e $RUNIT_LINK || -L $RUNIT_LINK ]]; then [[ $(readlink "$RUNIT_LINK") == "$RUNIT_DIR" ]] || die 'runit 启动项已被其他服务占用。'; else ln -s "$RUNIT_DIR" "$RUNIT_LINK"; fi;;
  sysv) if command -v update-rc.d >/dev/null; then update-rc.d "$SERVICE" defaults; else chkconfig --add "$SERVICE"; chkconfig "$SERVICE" on; fi;;
 esac
}
service_disable(){ case $INIT in systemd) systemctl disable "$SERVICE";; openrc) rc-update del "$SERVICE" default;; runit) [[ ! -L $RUNIT_LINK ]] || { [[ $(readlink "$RUNIT_LINK") == "$RUNIT_DIR" ]] && rm -f -- "$RUNIT_LINK"; };; sysv) if command -v update-rc.d >/dev/null; then update-rc.d -f "$SERVICE" remove; else chkconfig "$SERVICE" off; chkconfig --del "$SERVICE"; fi;; esac; }
write_service(){
 case $INIT in
 systemd)
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
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$STATE
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
UMask=0077
MemoryLimit=96M
TasksMax=48
LimitNOFILE=1024
[Install]
WantedBy=multi-user.target
EOF
 ;;
 openrc)
 cat >"$UNIT" <<EOF
#!/sbin/openrc-run
# Managed by Chitanda node installer
name="Chitanda data node"
supervisor="supervise-daemon"
command="$BIN"
command_args="-config $ETC/config.json"
command_user="chitanda-transit:chitanda-transit"
directory="$STATE"
respawn_delay=5
respawn_max=0
output_log="/var/log/chitanda-transit.log"
error_log="/var/log/chitanda-transit.log"
export GOMEMLIMIT=32MiB GOGC=50 GOMAXPROCS=1
start_pre() { checkpath --file --mode 0640 --owner chitanda-transit:chitanda-transit /var/log/chitanda-transit.log; }
depend() { need net; }
EOF
 chmod 755 "$UNIT";;
 runit)
 install -d -m 0755 "$RUNIT_DIR"
 cat >"$UNIT" <<EOF
#!/bin/sh
# Managed by Chitanda node installer
export GOMEMLIMIT=32MiB GOGC=50 GOMAXPROCS=1
cd "$STATE" || exit 1
exec 2>&1
exec chpst -u chitanda-transit:chitanda-transit "$BIN" -config "$ETC/config.json"
EOF
 chmod 755 "$UNIT";;
 sysv) write_sysv "$UNIT" "$SERVICE" "$BIN" "-config $ETC/config.json" chitanda-transit;;
 esac
}
write_sysv(){
 local target=$1 name=$2 program=$3 arguments=$4 user=$5
 cat >"$target" <<EOF
#!/bin/sh
# Managed by Chitanda node installer
# chkconfig: 2345 95 05
### BEGIN INIT INFO
# Provides: $name
# Required-Start: \$network \$remote_fs
# Required-Stop: \$network \$remote_fs
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
### END INIT INFO
export GOMEMLIMIT=32MiB GOGC=50 GOMAXPROCS=1
case \${1:-} in
 start) start-stop-daemon --start --background --no-close --make-pidfile --pidfile /run/$name.pid --chuid $user --exec $program -- $arguments >>/var/log/$name.log 2>&1;;
 stop) start-stop-daemon --stop --retry TERM/15/KILL/5 --pidfile /run/$name.pid --user $user; result=\$?; rm -f /run/$name.pid; exit \$result;;
 restart) "\$0" stop || true; "\$0" start;;
 status) [ -r /run/$name.pid ] || exit 3; pid=\$(cat /run/$name.pid); [ -r /proc/\$pid/stat ] || exit 3; [ "\$(awk '{print \$3}' /proc/\$pid/stat)" != Z ] || exit 3; start-stop-daemon --status --pidfile /run/$name.pid;;
 *) exit 2;;
esac
EOF
 chmod 755 "$target"
}
setup_updates(){
 for f in "$UPDATE_UNIT" "$UPDATE_TIMER" "$UPDATE_INIT" "$UPDATE_RUNIT/run"; do [[ ! -L $f ]] || die '更新任务路径不能是符号链接。'; if [[ -f $f ]]; then grep -Fq '# Managed by Chitanda node installer' "$f" || die '更新任务已被其他服务占用。'; fi; done
 install -d -m 0750 "$ETC"
 if [[ $INIT == systemd ]]; then
  cat >"$UPDATE_UNIT" <<EOF
# Managed by Chitanda node installer
[Unit]
Description=Chitanda node automatic update
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$HELPER auto-update
UMask=0077
Nice=10
EOF
  cat >"$UPDATE_TIMER" <<EOF
# Managed by Chitanda node installer
[Unit]
Description=Check Chitanda node release policy
[Timer]
OnActiveSec=5min
OnUnitActiveSec=5min
RandomizedDelaySec=60
Unit=chitanda-node-update.service
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now chitanda-node-update.timer
 elif [[ $INIT == openrc ]]; then
  cat >"$UPDATE_INIT" <<EOF
#!/sbin/openrc-run
# Managed by Chitanda node installer
name="Chitanda update watcher"
supervisor="supervise-daemon"
command="$HELPER"
command_args="watch-updates"
command_user="root"
respawn_delay=30
respawn_max=0
output_log="/var/log/chitanda-node-update.log"
error_log="/var/log/chitanda-node-update.log"
depend() { need net; }
EOF
  chmod 755 "$UPDATE_INIT"; rc-update add chitanda-node-update default; rc-service chitanda-node-update status >/dev/null 2>&1 || (exec 9>&-; rc-service chitanda-node-update start)
 elif [[ $INIT == runit ]]; then
  install -d -m 0755 "$UPDATE_RUNIT"
  printf '#!/bin/sh\n# Managed by Chitanda node installer\nexec "%s" watch-updates\n' "$HELPER" >"$UPDATE_RUNIT/run"; chmod 755 "$UPDATE_RUNIT/run"
  if [[ -L $UPDATE_LINK || -e $UPDATE_LINK ]]; then [[ -L $UPDATE_LINK && $(readlink "$UPDATE_LINK") == "$UPDATE_RUNIT" ]] || die 'runit 更新入口被其他服务占用。'; else ln -s "$UPDATE_RUNIT" "$UPDATE_LINK"; fi
 else
  write_sysv "$UPDATE_INIT" chitanda-node-update "$HELPER" watch-updates root
  if command -v update-rc.d >/dev/null; then update-rc.d chitanda-node-update defaults; else chkconfig --add chitanda-node-update; chkconfig chitanda-node-update on; fi
  "$UPDATE_INIT" status >/dev/null 2>&1 || (exec 9>&-; "$UPDATE_INIT" start)
 fi
}
remove_updates(){
 for f in "$UPDATE_UNIT" "$UPDATE_TIMER" "$UPDATE_INIT" "$UPDATE_RUNIT/run"; do if [[ -e $f || -L $f ]]; then [[ ! -L $f ]] && grep -Fq '# Managed by Chitanda node installer' "$f" || die '更新任务不属于本安装器，已停止卸载。'; fi; done
 case $INIT in
 systemd) systemctl disable --now chitanda-node-update.timer >/dev/null 2>&1 || true; systemctl stop chitanda-node-update.service >/dev/null 2>&1 || true; rm -f -- "$UPDATE_UNIT" "$UPDATE_TIMER";;
 openrc) if [[ -f $UPDATE_INIT ]]; then rc-service chitanda-node-update stop || true; rc-update del chitanda-node-update default || true; rm -f -- "$UPDATE_INIT"; fi;;
 runit) if [[ -L $UPDATE_LINK && $(readlink "$UPDATE_LINK") == "$UPDATE_RUNIT" ]]; then sv -w 15 down "$UPDATE_LINK" || true; rm -f -- "$UPDATE_LINK"; fi; rm -f -- "$UPDATE_RUNIT/run"; rmdir "$UPDATE_RUNIT" 2>/dev/null || true;;
 sysv) if [[ -f $UPDATE_INIT ]]; then "$UPDATE_INIT" stop || true; if command -v update-rc.d >/dev/null; then update-rc.d -f chitanda-node-update remove; else chkconfig --del chitanda-node-update; fi; rm -f -- "$UPDATE_INIT"; fi;;
 esac
}
fetch(){
 if "${CURL[@]}" "$@"; then return 0; fi
 echo '下载失败，分别尝试 IPv4 / IPv6……' >&2
 "${CURL[@]}" -4 "$@" || "${CURL[@]}" -6 "$@"
}
# END RUNTIME
# BEGIN UPDATES
# Embedded update policy and atomic update bookkeeping.
record_update(){
 python3 - "$ETC/update-state.json" "$1" "${target_version:-}" "${target_digest:-}" "${target_installer:-}" <<'PY'
import json,pathlib,sys,time,os
p=pathlib.Path(sys.argv[1]);d=json.loads(p.read_text()) if p.exists() else {}
d.update(lastAttemptAt=int(time.time()),status=sys.argv[2],targetVersion=sys.argv[3])
if sys.argv[2]=='failed':d.update(failedAt=int(time.time()),failedVersion=sys.argv[3],failedDigest=sys.argv[4],failedInstaller=sys.argv[5])
elif sys.argv[2]=='updated':
 d['updatedAt']=int(time.time())
 for k in ['failedAt','failedVersion','failedDigest','failedInstaller']:d.pop(k,None)
t=p.with_name(p.name+'.tmp');t.write_text(json.dumps(d));os.chmod(str(t),0o600);t.replace(p)
PY
}
check_update(){
 python3 - "$work" "$arch" "$BIN" "$HELPER" "${BASH_SOURCE[0]}" "$ETC/update-state.json" "$automatic" <<'PY'
import json,pathlib,sys,re,subprocess,hashlib,time,os
work=pathlib.Path(sys.argv[1]);arch,binary,helper,script,statefile,automatic=sys.argv[2:];automatic=automatic=='true';m=json.loads((work/'manifest.json').read_text());v=m.get('version','');a=m.get('assets',{}).get('linux-'+arch,{})
if not re.fullmatch(r'\d+\.\d+\.\d+',v) or a.get('url')!='/transit-node/releases/linux-'+arch or not re.fullmatch(r'[a-f0-9]{64}',a.get('sha256','')) or not isinstance(a.get('size'),int) or not 0<a['size']<=80*1024*1024:raise SystemExit('安装包清单无效或没有对应架构。')
policy=m.get('updatePolicy',{});statepath=pathlib.Path(statefile);state=json.loads(statepath.read_text()) if statepath.exists() else {};now=int(time.time());reason=''
if automatic:
 if policy.get('enabled',True) is not True:reason='控制端已暂停自动更新'
 elif os.environ.get('CT_UPDATE_DELEGATED')!='1' and now-state.get('lastCheckAt',0)<max(300,int(policy.get('intervalSeconds',3600))):reason='未到检查间隔'
 elif state.get('failedVersion')==v and state.get('failedDigest')==a['sha256'] and state.get('failedInstaller','')==m.get('installer',{}).get('sha256','') and now-state.get('failedAt',0)<max(600,int(policy.get('failureCooldownSeconds',21600))):reason='该版本失败后暂缓重试'
try:current=subprocess.run([binary,'-version'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,universal_newlines=True).stdout.strip()
except Exception:current=''
sem=lambda x:tuple(map(int,x.split('.')))
if re.fullmatch(r'\d+\.\d+\.\d+',current) and sem(v)<sem(current):reason='发布版本较旧，保留当前程序'
installer=m.get('installer');delegate=False;helper_changed=False
if installer is not None:
 if installer.get('url')!='/transit-node/install.sh' or not re.fullmatch(r'[a-f0-9]{64}',installer.get('sha256','')) or not isinstance(installer.get('size'),int) or not 0<installer['size']<=1024*1024:raise SystemExit('安装器元数据无效。')
 digest=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() if pathlib.Path(p).exists() else ''
 delegate=automatic and digest(script)!=installer['sha256'];helper_changed=digest(helper)!=installer['sha256']
if automatic and not reason and current==v and not helper_changed and not delegate:reason='已是当前版本'
if automatic and reason not in ['未到检查间隔','该版本失败后暂缓重试']:
 state['lastCheckAt']=now;state['status']=reason or 'checking';tmp=statepath.with_name(statepath.name+'.tmp');tmp.write_text(json.dumps(state));os.chmod(str(tmp),0o600);tmp.replace(statepath)
out={'skip':reason,'binaryChanged':current!=v,'delegate':delegate,'version':v,'digest':a['sha256'],'installer':installer or {}}
(work/'update-decision.json').write_text(json.dumps(out))
print(reason);print('yes' if delegate else 'no');print('yes' if current!=v else 'no');print(v);print(a['sha256']);print((installer or {}).get('sha256',''));print((installer or {}).get('size',0))
PY
}
# END UPDATES
detect_init
UNIT=$(service_file)
if [[ $action == watch-updates ]]; then while [[ -f $ETC/config.json && -x $HELPER ]]; do "$HELPER" auto-update || true; sleep 300; done; exit 0; fi
if [[ $action == auto-update-disable ]]; then touch "$ETC/updates.disabled"; say '本机自动更新已暂停。'; exit 0; fi
if [[ $action == auto-update-enable ]]; then rm -f -- "$ETC/updates.disabled"; setup_updates; say '本机自动更新已启用。'; exit 0; fi
if [[ $action == status ]]; then service_status; exit $?; fi
if [[ $action == logs ]]; then if [[ $INIT == systemd ]]; then exec journalctl -u "$SERVICE" -n 50 --no-pager; else tail -n 50 /var/log/chitanda-transit.log; exit; fi; fi
mkdir -p /run
if [[ $action == auto-update ]]; then [[ ! -f $ETC/updates.disabled ]] || exit 0; service_active || exit 0; automatic=true; action=update; else automatic=false; fi
exec 9>/run/chitanda-node-install.lock
if $automatic; then flock -n 9 || exit 0; else flock -w 60 9 || die '另一个节点管理任务仍在执行，请稍后重试。'; fi

for p in "$ETC" "$STATE" "$BIN" "$HELPER" "$UNIT" "$MARKER" "$ETC/config.json"; do
 [[ ! -L $p ]] || die '目标路径包含符号链接，已停止以保护现有文件。'
done
if [[ $action == setup-auto-update ]]; then [[ -f $ETC/config.json ]] || die '缺少节点配置。'; install -m 0755 "${BASH_SOURCE[0]}" "$HELPER.new"; mv -f -- "$HELPER.new" "$HELPER"; setup_updates; say '自动更新任务已安装。'; exit 0; fi
if [[ $action == uninstall ]]; then
 purge=false
 if [[ ${1:-} == --purge ]]; then purge=true; shift; fi
 [[ $# -eq 0 ]] || die '卸载仅支持 --purge 参数。'
 # Early deployments have the standard unit but no local helper or marker.
 if [[ -f $UNIT ]]; then
  service_owned || die '服务使用其他程序或配置路径，未执行卸载。'
  service_stop
 elif [[ ! -f $MARKER && ( -f $BIN || -f $HELPER ) ]]; then
  die '程序归属无法确认，未执行卸载。'
 fi
 service_disable >/dev/null 2>&1 || true
 remove_updates
 rm -f -- "$UNIT" "$BIN" "$HELPER" "$MARKER"
 if [[ $INIT == runit ]]; then rm -f -- "$RUNIT_DIR/run" "$RUNIT_DIR/down"; rmdir "$RUNIT_DIR" 2>/dev/null || true; fi
 service_reload
 [[ $INIT != systemd ]] || systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
 if command -v python3 >/dev/null && [[ -f $ETC/config.json ]]; then
  python3 - "$ETC/config.json" <<'PY' || say '本机已卸载；中台暂未收到卸载状态，恢复网络后可重试本命令。'
import pathlib,sys,json,urllib.parse,ipaddress,http.client,ssl,socket
try:
 c=json.loads(pathlib.Path(sys.argv[1]).read_text());u=urllib.parse.urlsplit(c['controller'])
 if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/'):raise ValueError()
 conn=http.client.HTTPSConnection(u.hostname,u.port or 443,context=ssl.create_default_context(),timeout=10)
 if c.get('controllerAddress'):
  host,port=c['controllerAddress'].rsplit(':',1);ip=ipaddress.ip_address(host.strip('[]'))
  if int(port)!=(u.port or 443):raise ValueError()
  conn._create_connection=lambda *a,**k:socket.create_connection((str(ip),int(port)),timeout=10)
 conn.request('POST','/transit-node/uninstalled',body=b'{}',headers={'Content-Type':'application/json','X-Node-ID':c['id'],'Authorization':'Bearer '+c['token']})
 response=conn.getresponse();response.read();conn.close()
 if response.status!=200:raise ValueError()
except Exception:raise SystemExit(1)
PY
 fi
 if $purge; then
  # Fixed known files only: never remove shared certificates or other services.
  rm -f -- "$ETC/config.json" "$STATE/runtime.json" "$STATE/relay-ca.pem" "$STATE/replay.db" "$STATE/replay.db-wal" "$STATE/replay.db-shm"
  say '节点程序、启动配置和通道缓存已清除；证书、外置入口及面板记录保留。'
 else
  say '节点程序已卸载；启动配置、证书和缓存已保留，可用新安装命令恢复原身份。'
 fi
 exit 0
fi
for cmd in curl python3 sha256sum install; do command -v "$cmd" >/dev/null || die "缺少 $cmd，请先安装后重试。"; done
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
case $(uname -m) in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; armv7*|armv6*) arch=armv7;; i386|i486|i586|i686) arch=386;; riscv64|loongarch64|ppc64le|s390x) arch=$(uname -m); [[ $arch != loongarch64 ]] || arch=loong64;; *) die '此 CPU 架构暂无安装包。';; esac
if [[ $action == install ]]; then [[ $ticket =~ ^[a-f0-9]{64}$ ]] || die '安装凭据无效，请在面板重新生成。'; fi
if [[ $action == update ]]; then [[ -f $ETC/config.json ]] || die '未找到已有配置，请使用面板安装命令。'; fi
work=$(mktemp -d /var/tmp/chitanda-node.XXXXXXXX)
backup=''; changed=false; was_active=false; was_enabled=false
cleanup(){
 result=$?
 if [[ $result -ne 0 && -n ${target_version:-} && -d $ETC ]]; then record_update failed || true; fi
 if [[ $result -ne 0 ]] && $changed; then
  say '启动未通过，正在恢复更新前的程序与配置。' >&2
  service_stop >/dev/null 2>&1 || true
  for pair in "binary:$BIN" "config:$ETC/config.json" "unit:$UNIT" "helper:$HELPER" "marker:$MARKER"; do
   key=${pair%%:*}; target=${pair#*:}
   if [[ -f $backup/$key ]]; then cp -a -- "$backup/$key" "$target"; else rm -f -- "$target"; fi
  done
  service_reload || true
  if $was_enabled; then service_enable >/dev/null 2>&1 || true; else service_disable >/dev/null 2>&1 || true; fi
  if $was_active; then service_start || true; fi
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
CURL=(curl -q -fsS --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 10 --max-time 180)
[[ -z $resolve ]] || CURL+=(--noproxy '*' --resolve "$resolve")
if [[ $action == install ]]; then
 printf '{"ticket":"%s"}' "$ticket" >"$work/claim.json"
 fetch -H 'Content-Type: application/json' --data-binary "@$work/claim.json" "$server/transit-node/enroll" -o "$work/claim-response.json" || die '领取配置失败；请核对凭据有效期、服务器时间与 HTTPS。'
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
 fetch --config "$work/curl-auth.conf" "$server/transit-node/release" -o "$work/manifest.json" || die '读取安装包失败，旧程序未修改。'
fi
if [[ $action == update ]]; then
 check_update >"$work/decision" || die '更新清单校验失败。'
 mapfile -t decision <"$work/decision"
 if [[ -n ${decision[0]} ]]; then say "${decision[0]}"; exit 0; fi
 target_version=${decision[3]}; target_digest=${decision[4]}; target_installer=${decision[5]}
 if [[ ${decision[1]} == yes ]]; then
  fetch --config "$work/curl-auth.conf" "$server/transit-node/install.sh" -o "$work/new-installer.sh" || die '安装器下载失败。'
  [[ $(wc -c <"$work/new-installer.sh") -eq ${decision[6]} ]] || die '安装器大小不符。'
  printf '%s  %s\n' "$target_installer" "$work/new-installer.sh" | sha256sum -c - >/dev/null || die '安装器摘要不符。'
  flock -u 9
  CT_UPDATE_DELEGATED=1 bash "$work/new-installer.sh" auto-update
  exit $?
 fi
 if [[ ${decision[2]} == no ]]; then
  install -m 0755 "${BASH_SOURCE[0]}" "$HELPER.new"; mv -f -- "$HELPER.new" "$HELPER"
  setup_updates; record_update updated; say '程序版本已是最新，已更新本机维护器与自动更新任务。'; exit 0
 fi
fi
python3 - "$work" "$arch" >"$work/asset" <<'PY'
import json,pathlib,sys,re
work=pathlib.Path(sys.argv[1]);arch=sys.argv[2];m=json.loads((work/'manifest.json').read_text());v=m.get('version','');asset=m.get('assets',{}).get('linux-'+arch,{})
if not re.fullmatch(r'\d+\.\d+\.\d+',v) or asset.get('url')!='/transit-node/releases/linux-'+arch or not re.fullmatch(r'[a-f0-9]{64}',asset.get('sha256','')) or not 0<asset.get('size',0)<=80*1024*1024:
 raise SystemExit('安装包清单校验失败或没有对应架构。')
print(v);print(asset['sha256']);print(asset['url']);print(asset['size'])
PY
mapfile -t asset <"$work/asset"
target_version=${asset[0]}; target_digest=${asset[1]}
say "正在获取 Linux/$arch 节点 ${asset[0]}……"
fetch --config "$work/curl-auth.conf" "$server${asset[2]}" -o "$work/binary" || die '下载失败，旧程序未修改。'
[[ $(wc -c <"$work/binary") -eq ${asset[3]} ]] || die '安装包大小不符。'
printf '%s  %s\n' "${asset[1]}" "$work/binary" | sha256sum -c - >/dev/null || die '安装包 SHA-256 不符，未执行。'
chmod 700 "$work/binary"
[[ $("$work/binary" -version) == "${asset[0]}" ]] || die '节点版本或架构校验失败。'
if [[ -f $UNIT ]]; then
 service_owned || die '已有服务使用其他程序或配置路径，请人工核对。'
fi
mkdir -p /var/backups
backup=$(mktemp -d /var/backups/chitanda-node.XXXXXXXX)
for pair in "binary:$BIN" "config:$ETC/config.json" "unit:$UNIT" "helper:$HELPER" "marker:$MARKER"; do
 key=${pair%%:*}; target=${pair#*:}; [[ ! -f $target ]] || cp -a -- "$target" "$backup/$key"
done
service_active && was_active=true || true
service_enabled && was_enabled=true || true
if command -v getent >/dev/null; then getent group chitanda-transit >/dev/null || groupadd --system chitanda-transit; else grep -q "^chitanda-transit:" /etc/group || groupadd --system chitanda-transit; fi
nologin=$(command -v nologin || printf /bin/false)
id -u chitanda-transit >/dev/null 2>&1 || useradd --system --gid chitanda-transit --no-create-home --home-dir "$STATE" --shell "$nologin" chitanda-transit
changed=true
install -d -m 0755 -- "$(dirname "$BIN")" "$(dirname "$HELPER")"
install -d -m 0750 -o root -g chitanda-transit "$ETC"
install -d -m 0700 -o chitanda-transit -g chitanda-transit "$STATE"
install -m 0600 -o chitanda-transit -g chitanda-transit "$work/config.json" "$ETC/config.json"
install -m 0755 "$work/binary" "$BIN.new"
mv -f -- "$BIN.new" "$BIN"
if [[ $INIT != systemd ]]; then command -v setcap >/dev/null || die '缺少 setcap，请安装 libcap 工具。'; setcap cap_net_bind_service=+ep "$BIN"; fi
if [[ ! -f $UNIT ]]; then write_service; fi
install -m 0755 "${BASH_SOURCE[0]}" "$HELPER.new"
mv -f -- "$HELPER.new" "$HELPER"
python3 - "$MARKER" "${asset[0]}" "$arch" <<'PY'
import pathlib,json,sys,datetime
pathlib.Path(sys.argv[1]).write_text(json.dumps({'version':sys.argv[2],'arch':sys.argv[3],'installedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
PY
chmod 600 "$MARKER"
service_reload
service_enable >/dev/null
service_restart
for stable in 1 2 3; do sleep 2; service_active || die '节点服务未能稳定运行。'; done
changed=false
setup_updates
record_update updated
say "节点 ${asset[0]} 已安装并启动；身份与已有业务入口配置保留。"
say "备份：$backup"
say '返回中台查看节点是否上线。若未上线：sudo chitanda-node logs'
say '更新：sudo chitanda-node update'
say '卸载并保留配置：sudo chitanda-node uninstall'
