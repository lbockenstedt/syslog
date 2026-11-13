#!/bin/bash
# Sets up an LM syslog collector on Debian/Ubuntu. Used by the LM
# "syslog-collector" deploy role (the agent passes --infra-only, --tenant and
# the hub-issued TLS files it wrote to /etc/lm-syslog/tls/).
#
# rsyslog receives on UDP 514, TCP 514 and TCP 6514 (TLS) and writes each
# message as one JSON line to /var/lib/lm/syslog/<UTC day>/<UTC hour>.jsonl.
# The LM "syslog" role (src/syslog_spoke.py) reads those files and writes the
# drop-rule and archive-forward includes in /etc/lm-syslog/.
#
# Re-running is safe: it rewrites the LM config file and keeps stored data.
# Every step is logged to /var/log/lm/syslog-collector-install.log, which ends
# with "OK" or "FAILED: <step>" (the hub reads it through SYSLOG_DIAG).
set -eE -o pipefail
TENANT=""; TLS_CA=""; TLS_CERT=""; TLS_KEY=""
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --infra-only|--all-prereqs) ;;
    --tenant) TENANT="$2"; shift ;;
    --tls-ca) TLS_CA="$2"; shift ;;
    --tls-cert) TLS_CERT="$2"; shift ;;
    --tls-key) TLS_KEY="$2"; shift ;;
    *) echo "Unknown parameter: $1"; exit 1 ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

# Log everything to the install log as well as the console.
LOG=/var/log/lm/syslog-collector-install.log
mkdir -p /var/log/lm
exec > >(tee -a "$LOG") 2>&1
STEP="start"
log() { echo "$(date -u +%FT%TZ) [syslog-collector] $*"; logger -t lm-syslog-collector "$*" 2>/dev/null || true; }
trap 'log "FAILED: $STEP"' ERR
log "install starting (version $(cat "$(dirname "$0")/VERSION" 2>/dev/null || echo unknown), tenant '${TENANT:-none}')"

STEP="check distro"
. /etc/os-release
case "$ID $ID_LIKE" in *debian*|*ubuntu*) ;; *) log "unsupported distro: ID=$ID (need Debian/Ubuntu)"; false ;; esac

STEP="install rsyslog packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q rsyslog rsyslog-gnutls
RSV=$(rsyslogd -v | head -1 | awk '{print $2}' | tr -d ',')
log "rsyslog $RSV installed"
# Per-listener and per-action TLS files need rsyslog 8.2106 or newer.
STEP="check rsyslog version ($RSV, need 8.2106+)"
[ "$(printf '%s\n' 8.2106 "$RSV" | sort -V | head -1)" = "8.2106" ]

STEP="check ports 514/6514 are free for LM"
# Another config already listening on the network would clash with ours.
if grep -lE '^\s*(module\(load="im(udp|tcp)"|\$ModLoad im(udp|tcp))' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null \
    | grep -v 40-lm-syslog.conf; then
  log "another rsyslog config already loads imudp/imtcp (listed above); comment it out and re-run"
  false
fi

STEP="create directories"
# rsyslog drops privileges to this user on Ubuntu (root on Debian).
RSUSER=$(awk '/^\$PrivDropToUser/{print $2}' /etc/rsyslog.conf); RSUSER=${RSUSER:-root}
install -d -m 750 -o "$RSUSER" -g adm /var/lib/lm/syslog
# Record the owner before rsyslog listens, so messages stored from now on belong
# to this tenant. An existing marker is left alone (the spoke handles a move);
# without one the spoke empties the store when its first tenant arrives.
if [ -n "$TENANT" ] && [ ! -s /var/lib/lm/syslog/.tenant ]; then
    printf '%s' "$TENANT" > /var/lib/lm/syslog/.tenant
fi
install -d -m 755 /etc/lm-syslog /var/spool/rsyslog
chown "$RSUSER" /var/spool/rsyslog
[ -f /etc/lm-syslog/drop.rsyslog ] || echo "# No drop rules yet (managed by LM)." > /etc/lm-syslog/drop.rsyslog
[ -f /etc/lm-syslog/archive.rsyslog ] || echo "# No archive connected (managed by LM)." > /etc/lm-syslog/archive.rsyslog

STEP="check TLS files"
TLS_INPUT=""
if [ -n "$TLS_CERT" ]; then
  for f in "$TLS_CA" "$TLS_CERT" "$TLS_KEY"; do [ -s "$f" ] || { log "missing TLS file $f"; false; }; done
  # rsyslog reads the key after dropping privileges on Ubuntu.
  chgrp "$(id -gn "$RSUSER")" "$TLS_KEY"; chmod 640 "$TLS_KEY"
  TLS_INPUT="input(type=\"imtcp\" port=\"6514\" ruleset=\"lm_syslog\" name=\"lm_tls\"
      streamDriver.name=\"gtls\" streamDriver.mode=\"1\" streamDriver.authMode=\"anon\"
      streamDriver.CAFile=\"$TLS_CA\" streamDriver.CertFile=\"$TLS_CERT\" streamDriver.KeyFile=\"$TLS_KEY\")"
else
  log "no TLS files given: TLS listener 6514 not enabled"
fi

STEP="apparmor override"
# Ubuntu may confine rsyslogd; let it write the store and read LM's config.
if [ -f /etc/apparmor.d/usr.sbin.rsyslogd ] && [ ! -e /etc/apparmor.d/disable/usr.sbin.rsyslogd ]; then
  mkdir -p /etc/apparmor.d/local
  # Append between markers so other local rules survive; a re-run replaces only ours.
  AA=/etc/apparmor.d/local/usr.sbin.rsyslogd
  touch "$AA"
  sed -i '/^# BEGIN lm-syslog$/,/^# END lm-syslog$/d' "$AA"
  cat >> "$AA" <<'EOF'
# BEGIN lm-syslog
/var/lib/lm/syslog/ rw,
/var/lib/lm/syslog/** rwk,
/etc/lm-syslog/ r,
/etc/lm-syslog/** r,
# END lm-syslog
EOF
  apparmor_parser -r /etc/apparmor.d/usr.sbin.rsyslogd 2>/dev/null || log "apparmor reload skipped"
fi

STEP="write /etc/rsyslog.d/40-lm-syslog.conf"
cat > /etc/rsyslog.d/40-lm-syslog.conf <<EOF
# Managed by the LM syslog-collector installer. Re-run the installer to change it.
module(load="imudp")
module(load="imtcp" maxSessions="2000")

# One JSON line per message, keyed by receive time (UTC).
template(name="lm_json" type="list" option.json="on") {
  constant(value="{\"ts\":") property(name="timegenerated" dateFormat="unixtimestamp")
  constant(value=",\"frac\":\"") property(name="timegenerated" dateFormat="subseconds")
  constant(value="\",\"host\":\"") property(name="hostname")
  constant(value="\",\"src_ip\":\"") property(name="fromhost-ip")
  constant(value="\",\"program\":\"") property(name="programname")
  constant(value="\",\"sev\":") property(name="syslogseverity")
  constant(value=",\"fac\":") property(name="syslogfacility")
  constant(value=",\"msg\":\"") property(name="msg" droplastlf="on")
  constant(value="\"}\n")
}
template(name="lm_file" type="string"
  string="/var/lib/lm/syslog/%timegenerated:1:10:date-rfc3339,date-utc%/%timegenerated:12:13:date-rfc3339,date-utc%.jsonl")
# Archive forward: RFC5424 with the original hostname plus sender IP and tenant
# as structured data, so any syslog server can store and route it. The header
# time is the receive time, the same clock the local store files by, so a query
# split between local and archive at one cut-off has no gap or overlap even
# when a device clock is wrong; the device's own time is kept as dev_ts.
template(name="lm_fwd" type="string"
  string="<%PRI%>1 %timegenerated:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% [lm@32473 src_ip=\"%fromhost-ip%\" lm_tenant=\"%\$.lm_tenant%\" dev_ts=\"%TIMESTAMP:::date-rfc3339%\"] %msg%")

ruleset(name="lm_syslog" queue.type="LinkedList" queue.size="100000") {
  include(file="/etc/lm-syslog/drop.rsyslog" mode="optional")
  action(type="omfile" dynaFile="lm_file" template="lm_json" dynaFileCacheSize="4"
         asyncWriting="on" flushInterval="1" ioBufferSize="64k" closeTimeout="10"
         dirCreateMode="0750" fileCreateMode="0640" fileOwner="$RSUSER" fileGroup="adm")
  include(file="/etc/lm-syslog/archive.rsyslog" mode="optional")
  stop
}

input(type="imudp" port="514" ruleset="lm_syslog" name="lm_udp")
input(type="imtcp" port="514" ruleset="lm_syslog" name="lm_tcp")
$TLS_INPUT
EOF

STEP="validate rsyslog config (rsyslogd -N1)"
rsyslogd -N1 2>&1 | tail -5

STEP="restart rsyslog"
systemctl enable rsyslog >/dev/null 2>&1 || true
systemctl restart rsyslog
sleep 2
systemctl is-active --quiet rsyslog

STEP="check listeners"
ss -lnup | grep -q ':514 ' || { log "UDP 514 not listening"; false; }
ss -lntp | grep -q ':514 ' || { log "TCP 514 not listening"; false; }
[ -z "$TLS_INPUT" ] || ss -lntp | grep -q ':6514 ' || { log "TLS 6514 not listening"; false; }

log "listening on UDP 514, TCP 514${TLS_INPUT:+, TLS 6514}; store /var/lib/lm/syslog"
log "OK"
