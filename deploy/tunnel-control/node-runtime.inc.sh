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
