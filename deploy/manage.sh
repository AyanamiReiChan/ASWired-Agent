#!/bin/sh

set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.' >&2; exit 1; }
[ "$#" -ge 2 ] || { echo 'Usage: manage.sh install|upgrade|rollback|uninstall agent|home [BINARY CONFIG VERSION SHA256]' >&2; exit 2; }
operation=$1
case "$2" in agent) name=aswired-agent; config_name=agent.json;; home) name=aswired-speedtest; config_name=speedtest.json;; *) echo 'Invalid component.' >&2; exit 2;; esac
shift 2
target="/usr/local/bin/$name"
config_dir="/etc/$name"
data_dir="/var/lib/$name"
history_dir="/var/lib/aswired-install/$name"
config_path="$config_dir/$config_name"
pidfile="/run/$name.pid"
maintainer=${ASWIRED_MAINTAIN:-aswired-maintain}
supervise=
select_mode() {
 supervise=
 if [ "$name" = aswired-agent ] && "$target" -help 2>&1 | grep -q -- '-supervise'; then supervise=-supervise; fi
}
reset_worker() {
 if [ "$name" = aswired-agent ] && [ -d "$data_dir/agent-update" ]; then
  # The service is stopped. Keep identity, counters and Xray configuration.
  rm -f "$data_dir/agent-update/current" "$data_dir/agent-update/next" "$data_dir/agent-update/previous" "$data_dir/agent-update/state.json"
 fi
}
init=none
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then init=systemd
elif command -v rc-service >/dev/null 2>&1; then init=openrc; fi
stop_service() {
 case "$init" in
 systemd) if systemctl is-active --quiet "$name"; then systemctl stop "$name"; fi;;
 openrc) if rc-service "$name" status >/dev/null 2>&1; then rc-service "$name" stop; fi;;
 none)
  if [ -f "$pidfile" ]; then
   pid=$(cat "$pidfile")
   case "$pid" in ''|*[!0-9]*) echo 'Invalid managed PID.' >&2; return 1;; esac
   if kill -0 "$pid" 2>/dev/null; then
    [ "$(readlink "/proc/$pid/exe")" = "$target" ] || { echo 'PID belongs to another executable.' >&2; return 1; }
    kill "$pid"
    attempts=0
    while kill -0 "$pid" 2>/dev/null; do attempts=$((attempts+1)); [ "$attempts" -lt 30 ] || return 1; sleep 1; done
   fi
   rm -f "$pidfile"
  fi;;
 esac
}
start_service() {
 case "$init" in
 systemd) systemctl daemon-reload && systemctl enable "$name" && systemctl restart "$name" && systemctl is-active --quiet "$name";;
 openrc) rc-update add "$name" default && rc-service "$name" restart && rc-service "$name" status;;
 none) (cd "$data_dir"; nohup "$target" $supervise -config "$config_path" >>"$data_dir/service.log" 2>&1 & echo $! >"$pidfile"); sleep 2; kill -0 "$(cat "$pidfile")";;
 esac
}
install_service() {
 select_mode
 case "$init" in
 systemd)
 cat >"/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=ASWired managed service
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$data_dir
ExecStart=$target $supervise -config $config_path
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
 chmod 644 "/etc/systemd/system/$name.service";;
 openrc)
 cat >"/etc/init.d/$name" <<EOF
#!/sbin/openrc-run
command="$target"
command_args="$supervise -config $config_path"
command_background=true
pidfile="$pidfile"
directory="$data_dir"
output_log="$data_dir/service.log"
error_log="$data_dir/service.log"
depend() { need net; }
EOF
 chmod 755 "/etc/init.d/$name";;
 none)
 cat >"$history_dir/start.sh" <<EOF
#!/bin/sh
cd "$data_dir"
nohup "$target" $supervise -config "$config_path" >>"$data_dir/service.log" 2>&1 &
echo \$! >"$pidfile"
EOF
 chmod 755 "$history_dir/start.sh"
 if [ ! -e /etc/rc.local ]; then printf '#!/bin/sh\n' >/etc/rc.local; chmod 755 /etc/rc.local; fi
 entry="$history_dir/start.sh # ASWired:$name"
 if ! grep -F "$entry" /etc/rc.local >/dev/null 2>&1; then
  awk -v entry="$entry" 'BEGIN{added=0} /^[[:space:]]*exit[[:space:]]+0[[:space:]]*$/&&!added{print entry;added=1} {print} END{if(!added)print entry}' /etc/rc.local >"$history_dir/rc.local.next"
  cat "$history_dir/rc.local.next" >/etc/rc.local
  rm -f "$history_dir/rc.local.next"
 fi
 echo 'nohup fallback installed; verify this distribution executes /etc/rc.local at boot.';;
 esac
}
install -d -m 700 "$config_dir" "$data_dir" "$history_dir"
case "$operation" in
install|upgrade)
 [ "$#" -eq 4 ] || { echo 'Supply BINARY CONFIG EXACT_VERSION SHA256.' >&2; exit 2; }
 candidate=$1; incoming=$2; version=$3; checksum=$4
 "$maintainer" -verify "$candidate" -version "$version" -sha256 "$checksum"
 [ -f "$incoming" ] || { echo 'Configuration is missing.' >&2; exit 1; }
 "$candidate" -config "$incoming" -check
 if [ "$operation" = upgrade ] && [ ! -f "$target" ]; then echo 'No installed binary.' >&2; exit 1; fi
 stop_service
 if [ -f "$target" ]; then
  effective=$target
  if [ "$name" = aswired-agent ] && [ -f "$data_dir/agent-update/current" ]; then effective="$data_dir/agent-update/current"; fi
  previous_version=$("$effective" -version)
  previous_sha=$(sha256sum "$effective" | awk '{print $1}')
  "$maintainer" -verify "$effective" -version "$previous_version" -sha256 "$previous_sha"
  install -m 755 "$effective" "$history_dir/previous"
  printf '%s\n' "$previous_version" >"$history_dir/previous.version"
  printf '%s\n' "$previous_sha" >"$history_dir/previous.sha256"
 fi
 if [ -f "$config_path" ]; then install -m 600 "$config_path" "$history_dir/previous-config.json"; fi
 install -m 755 "$candidate" "$target.next"
 mv -f "$target.next" "$target"
 reset_worker
 if [ "$incoming" != "$config_path" ]; then install -m 600 "$incoming" "$config_path"; fi
 install_service
 if ! start_service; then
  echo 'New release failed its service check; attempting previous release.' >&2
  stop_service || true
  if [ -f "$history_dir/previous" ]; then
   install -m 755 "$history_dir/previous" "$target"
   reset_worker
   install_service
   if [ -f "$history_dir/previous-config.json" ]; then install -m 600 "$history_dir/previous-config.json" "$config_path"; fi
   if ! start_service; then echo 'Rollback could not restart the previous release; inspect logs.' >&2; fi
  fi
  exit 1
 fi
 printf '%s\n' "$version" >"$history_dir/current.version"
 printf '%s\n' "$checksum" >"$history_dir/current.sha256"
 echo "$name $version is running. Check controller reconnection and actual proxy/measurement behavior.";;
rollback)
 [ -f "$history_dir/previous" ] || { echo 'No previous release.' >&2; exit 1; }
 "$maintainer" -verify "$history_dir/previous" -version "$(cat "$history_dir/previous.version")" -sha256 "$(cat "$history_dir/previous.sha256")"
 stop_service
 install -m 755 "$history_dir/previous" "$target"
 reset_worker
 install_service
 if [ -f "$history_dir/previous-config.json" ]; then install -m 600 "$history_dir/previous-config.json" "$config_path"; fi
 start_service
 echo 'Previous release restored. Data retained; verify data-format compatibility and controller reconnection.';;
uninstall)
 stop_service
 case "$init" in
 systemd) systemctl disable "$name"; rm -f "/etc/systemd/system/$name.service"; systemctl daemon-reload;;
 openrc) rc-update del "$name" default; rm -f "/etc/init.d/$name";;
 none) if [ -f /etc/rc.local ]; then awk -v marker="# ASWired:$name" 'index($0,marker)==0{print}' /etc/rc.local >"$history_dir/rc.local.next"; cat "$history_dir/rc.local.next" >/etc/rc.local; rm -f "$history_dir/rc.local.next"; fi;;
 esac
 rm -f "$target" "$pidfile"
 echo 'Selected program removed. Configuration, data, kernel tunnels and separate Xray/Nginx services retained.';;
*) echo 'Unknown operation.' >&2; exit 2;;
esac
