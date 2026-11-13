#!/bin/bash
# Installs a Graylog Open archive for LM syslog on Debian 12 / Ubuntu 22.04 / 24.04.
# Used by the LM "syslog-graylog" deploy role: the agent writes the hub's
# generated admin and reader passwords to 0600 files (--admin-password-file,
# --reader-password-file; read once, then deleted) and the hub-CA TLS files to
# /etc/lm-syslog/tls/. No secret is ever on a command line.
#
# Stack: MongoDB 8.0 + OpenSearch 2.19 (localhost only) + Graylog 7.0.
# Self-managed OpenSearch is used instead of Graylog Data Node because the Data
# Node needs an interactive first-start step in Graylog's web UI.
#
# Result:
#   - HTTPS API/UI on 9000 (hub CA cert), syslog TCP+TLS input on 1514
#     (RFC5424; structured data params stored as plain src_ip / lm_tenant fields)
#   - read-only user "lm-reader" that LM queries with
#   - /etc/lm-syslog/graylog-status.json (versions, ports, input id, services)
# Every step is logged to /var/log/lm/syslog-graylog-install.log, which ends
# with "OK" or "FAILED: <step>". Passwords are never written to the log.
# Re-running is safe: it updates config, keeps data, and resets both passwords.
set -eE -o pipefail
ADMIN_PW_FILE=""; READER_PW_FILE=""; TLS_CA=""; TLS_CERT=""; TLS_KEY=""; RETENTION_DAYS=90
while [[ "$#" -gt 0 ]]; do
  case $1 in
    --infra-only|--all-prereqs) ;;
    --admin-password-file) ADMIN_PW_FILE="$2"; shift ;;
    --reader-password-file) READER_PW_FILE="$2"; shift ;;
    --tls-ca) TLS_CA="$2"; shift ;;
    --tls-cert) TLS_CERT="$2"; shift ;;
    --tls-key) TLS_KEY="$2"; shift ;;
    --retention-days) RETENTION_DAYS="$2"; shift ;;
    *) echo "Unknown parameter: $1"; exit 1 ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

# Log everything to the install log as well as the console.
LOG=/var/log/lm/syslog-graylog-install.log
mkdir -p /var/log/lm /etc/lm-syslog
exec > >(tee -a "$LOG") 2>&1
STEP="start"
log() { echo "$(date -u +%FT%TZ) [syslog-graylog] $*"; logger -t lm-syslog-graylog "$*" 2>/dev/null || true; }
CURLCFG=$(mktemp); chmod 600 "$CURLCFG"
trap 'log "FAILED: $STEP"' ERR
trap 'rm -f "$CURLCFG"' EXIT
log "install starting (LM syslog version $(cat "$(dirname "$0")/VERSION" 2>/dev/null || echo unknown))"

STEP="check arguments"
# Passwords come in 0600 files (written by the LM agent), never on the command
# line, where any local user could read them in the process list. Each file is
# read once and deleted.
[ -s "$ADMIN_PW_FILE" ] && [ -s "$READER_PW_FILE" ] \
  || { log "--admin-password-file and --reader-password-file are required (non-empty files)"; false; }
ADMIN_PW=$(<"$ADMIN_PW_FILE"); READER_PW=$(<"$READER_PW_FILE")
rm -f "$ADMIN_PW_FILE" "$READER_PW_FILE"
for f in "$TLS_CA" "$TLS_CERT" "$TLS_KEY"; do [ -s "$f" ] || { log "TLS file missing: '$f' (--tls-ca/--tls-cert/--tls-key)"; false; }; done
# The API is reached by the cert's name (the hub CA issues DNS-name certs).
CN=$(openssl x509 -in "$TLS_CERT" -noout -subject -nameopt RFC2253 | sed -n 's/.*CN=\([^,]*\).*/\1/p')
[ -n "$CN" ] || { log "could not read CN from $TLS_CERT"; false; }

STEP="check host"
. /etc/os-release
case "$ID:$VERSION_CODENAME" in
  debian:bookworm) MONGO_REPO="https://repo.mongodb.org/apt/debian bookworm/mongodb-org/8.0 main" ;;
  ubuntu:jammy|ubuntu:noble) MONGO_REPO="https://repo.mongodb.org/apt/ubuntu $VERSION_CODENAME/mongodb-org/8.0 multiverse" ;;
  *) log "unsupported OS $ID $VERSION_CODENAME (need Debian 12 or Ubuntu 22.04/24.04)"; false ;;
esac
# MongoDB 5+ needs a CPU with AVX (set the VM CPU type to "host" on Proxmox).
grep -qw avx /proc/cpuinfo || { log "CPU has no AVX: MongoDB will not run (use CPU type 'host')"; false; }
MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
[ "$MEM_MB" -ge 7500 ] || log "WARNING: only ${MEM_MB} MB RAM; 8 GB or more is recommended"
log "host: $PRETTY_NAME, ${MEM_MB} MB RAM, $(nproc) CPU, TLS name $CN"

STEP="install base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q curl gnupg ca-certificates openssl python3 apt-transport-https

STEP="install MongoDB 8.0"
if [ ! -f /etc/apt/sources.list.d/mongodb-org-8.0.list ]; then
  curl -fsSL https://pgp.mongodb.com/server-8.0.asc | gpg --dearmor --yes -o /usr/share/keyrings/mongodb-server-8.0.gpg
  echo "deb [signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg] $MONGO_REPO" > /etc/apt/sources.list.d/mongodb-org-8.0.list
  apt-get update -q
fi
apt-get install -y -q mongodb-org
# MongoDB listens on localhost only (package default); keep it that way.
systemctl enable --now mongod
log "mongod $(mongod --version | awk '/db version/{print $3}') active"

STEP="install OpenSearch 2.19"
sysctl -q -w vm.max_map_count=262144
echo "vm.max_map_count=262144" > /etc/sysctl.d/90-lm-opensearch.conf
if [ ! -f /etc/apt/sources.list.d/opensearch-2.x.list ]; then
  curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch-release.pgp \
    | gpg --dearmor --yes -o /usr/share/keyrings/opensearch-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring.gpg] https://artifacts.opensearch.org/releases/bundle/opensearch/2.x/apt stable main" \
    > /etc/apt/sources.list.d/opensearch-2.x.list
  apt-get update -q
fi
OS_VER=$(apt-cache madison opensearch | awk '{print $3}' | grep '^2\.19\.' | sort -V | tail -1)
[ -n "$OS_VER" ] || { log "no OpenSearch 2.19.x in the repo"; false; }
# The package wants an initial admin password even with security disabled; it is unused.
OPENSEARCH_INITIAL_ADMIN_PASSWORD="$(openssl rand -base64 24)Aa1!" apt-get install -y -q "opensearch=$OS_VER"
apt-mark hold opensearch >/dev/null
cat > /etc/opensearch/opensearch.yml <<'EOF'
# Managed by the LM syslog-graylog installer.
cluster.name: graylog
node.name: lm-graylog
path.data: /var/lib/opensearch
path.logs: /var/log/opensearch
network.host: 127.0.0.1
discovery.type: single-node
action.auto_create_index: false
# Bound to localhost and used only by Graylog on this host.
plugins.security.disabled: true
EOF
# OpenSearch heap: a quarter of RAM, 1-8 GB.
HEAP=$(( MEM_MB / 4 / 1024 )); [ "$HEAP" -ge 1 ] || HEAP=1; [ "$HEAP" -le 8 ] || HEAP=8
mkdir -p /etc/opensearch/jvm.options.d
printf -- '-Xms%sg\n-Xmx%sg\n' "$HEAP" "$HEAP" > /etc/opensearch/jvm.options.d/lm-heap.options
systemctl daemon-reload
systemctl enable opensearch >/dev/null
systemctl restart opensearch
for _ in $(seq 60); do curl -fs http://127.0.0.1:9200/_cluster/health >/dev/null && break; sleep 5; done
curl -fs http://127.0.0.1:9200/_cluster/health >/dev/null || { log "OpenSearch did not answer on 127.0.0.1:9200"; journalctl -u opensearch -n 30 --no-pager; false; }
log "opensearch $OS_VER active (heap ${HEAP} GB)"

STEP="install Graylog 7.0"
if ! dpkg -s graylog-7.0-repository >/dev/null 2>&1; then
  curl -fsSL -o /tmp/graylog-repo.deb https://packages.graylog2.org/repo/packages/graylog-7.0-repository_latest.deb
  dpkg -i /tmp/graylog-repo.deb
  apt-get update -q
fi
apt-get install -y -q graylog-server

STEP="configure Graylog"
CONF=/etc/graylog/server/server.conf
setkey() { if grep -q "^$1 *=" "$CONF"; then sed -i "s|^$1 *=.*|$1 = $2|" "$CONF"; else echo "$1 = $2" >> "$CONF"; fi; }
# Keep the existing secret on a re-run (changing it invalidates stored secrets).
grep -qE '^password_secret *= *.{64,}' "$CONF" || setkey password_secret "$(openssl rand -hex 48)"
setkey root_password_sha2 "$(printf '%s' "$ADMIN_PW" | sha256sum | awk '{print $1}')"
setkey root_timezone UTC
setkey http_bind_address 0.0.0.0:9000
setkey http_publish_uri "https://$CN:9000/"
setkey elasticsearch_hosts http://127.0.0.1:9200
# LM's host/program/text filters are substring matches (*term*); Graylog refuses
# a leading wildcard unless this is on.
setkey allow_leading_wildcard_searches true
# TLS files the graylog user can read (key already PKCS#8 from the hub CA).
install -d -m 750 -o graylog -g graylog /etc/graylog/server/tls
install -m 644 -o graylog -g graylog "$TLS_CA" /etc/graylog/server/tls/ca.pem
cat "$TLS_CERT" "$TLS_CA" > /etc/graylog/server/tls/cert.pem
install -m 600 -o graylog -g graylog "$TLS_KEY" /etc/graylog/server/tls/key.pem
chown graylog:graylog /etc/graylog/server/tls/cert.pem
setkey http_enable_tls true
setkey http_tls_cert_file /etc/graylog/server/tls/cert.pem
setkey http_tls_key_file /etc/graylog/server/tls/key.pem
# Graylog heap: 1-4 GB.
GHEAP=$(( MEM_MB / 8 / 1024 )); [ "$GHEAP" -ge 1 ] || GHEAP=1; [ "$GHEAP" -le 4 ] || GHEAP=4
sed -i "s|-Xms[0-9]*[gm] -Xmx[0-9]*[gm]|-Xms${GHEAP}g -Xmx${GHEAP}g|" /etc/default/graylog-server
systemctl daemon-reload
systemctl enable graylog-server >/dev/null
systemctl restart graylog-server

STEP="wait for the Graylog API"
# Admin credentials go through a private curl config, never the command line.
printf 'user = "admin:%s"\n' "$ADMIN_PW" > "$CURLCFG"
# api METHOD PATH [BODY]: the body goes in on stdin (printf is a shell builtin),
# so passwords in it never show in the process list.
api() { if [ -n "${3:-}" ]; then printf '%s' "$3" | _api "$1" "$2" --data-binary @-; else _api "$1" "$2"; fi; }
_api() { curl -fsS -K "$CURLCFG" --cacert "$TLS_CA" --resolve "$CN:9000:127.0.0.1" \
  -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'X-Requested-By: lm' \
  -X "$1" "https://$CN:9000/api$2" "${@:3}"; }
for _ in $(seq 90); do api GET /system >/dev/null 2>&1 && break; sleep 5; done
GL_VER=$(api GET /system | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])') \
  || { log "Graylog API did not answer on https://$CN:9000/api"; journalctl -u graylog-server -n 40 --no-pager; false; }
log "graylog-server $GL_VER answering on https://$CN:9000"

STEP="create the syslog TLS input (TCP 1514)"
INPUT_ID=$(api GET /system/inputs | python3 -c '
import json, sys
for i in json.load(sys.stdin).get("inputs", []):
    if i.get("title") == "LM syslog (TLS)":
        print(i["id"]); break')
# expand_structured_data stays off: on, Graylog prefixes each field with its SD-ID
# (lm@32473_src_ip); off, it stores src_ip and lm_tenant, the names LM queries.
INPUT_BODY=$(python3 -c 'import json; print(json.dumps({"title": "LM syslog (TLS)", "global": True,
  "type": "org.graylog2.inputs.syslog.tcp.SyslogTCPInput",
  "configuration": {"bind_address": "0.0.0.0", "port": 1514, "tls_enable": True,
    "tls_cert_file": "/etc/graylog/server/tls/cert.pem", "tls_key_file": "/etc/graylog/server/tls/key.pem",
    "tls_key_password": "", "tls_client_auth": "disabled", "expand_structured_data": False,
    "store_full_message": False, "allow_override_date": True, "force_rdns": False,
    "tcp_keepalive": True, "use_null_delimiter": False, "max_message_size": 2097152,
    "recv_buffer_size": 1048576, "number_worker_threads": 2, "timezone": "UTC"}}))')
if [ -z "$INPUT_ID" ]; then
  INPUT_ID=$(api POST /system/inputs "$INPUT_BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  log "created input $INPUT_ID"
else
  api PUT "/system/inputs/$INPUT_ID" "$INPUT_BODY" >/dev/null
  log "updated input $INPUT_ID"
fi
for _ in $(seq 12); do ss -lnt | grep -q ':1514 ' && break; sleep 5; done
ss -lnt | grep -q ':1514 ' || { log "input is not listening on 1514"; api GET "/system/inputstates/$INPUT_ID" || true; false; }

STEP="create the lm-reader user"
READER_ID=$(api GET /users | python3 -c '
import json, sys
for u in json.load(sys.stdin).get("users", []):
    if u.get("username") == "lm-reader":
        print(u["id"]); break')
if [ -z "$READER_ID" ]; then
  api POST /users "$(READER_PW="$READER_PW" python3 -c 'import json, os; print(json.dumps({
    "username": "lm-reader", "password": os.environ["READER_PW"], "email": "lm-reader@localhost",
    "first_name": "LM", "last_name": "Reader", "roles": ["Reader"], "permissions": [],
    "timezone": "UTC", "session_timeout_ms": 3600000}))')" >/dev/null
  READER_ID=$(api GET /users/lm-reader | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  log "created user lm-reader"
else
  api PUT "/users/$READER_ID/password" "$(READER_PW="$READER_PW" python3 -c 'import json, os; print(json.dumps({"password": os.environ["READER_PW"]}))')" >/dev/null
  log "reset lm-reader password"
fi
# Let lm-reader search the "All messages" stream. The share call replaces the
# whole grant list, so read the current grants first and add lm-reader to
# them; other users' access survives a re-run.
STREAM_GRN=grn::::stream:000000000000000000000001
if SHARES=$(api POST "/authz/shares/entities/$STREAM_GRN/prepare" '{}' | READER_ID="$READER_ID" python3 -c '
import json, os, sys
grants = json.load(sys.stdin).get("selected_grantee_capabilities") or {}
grants.setdefault("grn::::user:" + os.environ["READER_ID"], "view")
print(json.dumps({"selected_grantee_capabilities": grants}))') \
   && api POST "/authz/shares/entities/$STREAM_GRN" "$SHARES" >/dev/null; then
  log "lm-reader can view All messages"
else
  log "WARNING: could not share All messages with lm-reader"
fi

STEP="set archive retention ($RETENTION_DAYS days)"
# Best effort: rotate daily and keep RETENTION_DAYS indices in the default
# index set. The API has no "default" alias (GET index_sets/{id} looks up an
# id), so list every index set and take the one flagged default.
RETENTION_APPLIED=false
ISET_DIR=$(mktemp -d)
if api GET "/system/indices/index_sets?skip=0&limit=0&stats=false" > "$ISET_DIR/all.json" \
   && RETENTION_DAYS="$RETENTION_DAYS" python3 - "$ISET_DIR/all.json" > "$ISET_DIR/new.json" <<'PY'
import json, os, sys
s = next(i for i in json.load(open(sys.argv[1]))["index_sets"] if i.get("default"))
s["rotation_strategy_class"] = "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategy"
s["rotation_strategy"] = {"type": "org.graylog2.indexer.rotation.strategies.TimeBasedRotationStrategyConfig",
                          "rotation_period": "P1D", "rotate_empty_index_set": False}
s["retention_strategy_class"] = "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy"
s["retention_strategy"] = {"type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
                           "max_number_of_indices": int(os.environ["RETENTION_DAYS"])}
s.pop("data_tiering", None)
s["use_legacy_rotation"] = True
print(json.dumps(s))
PY
then
  ISET_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$ISET_DIR/new.json")
  if api PUT "/system/indices/index_sets/$ISET_ID" "$(cat "$ISET_DIR/new.json")" >/dev/null; then
    RETENTION_APPLIED=true
    log "retention: daily indices, keep $RETENTION_DAYS (index set $ISET_ID)"
  else
    log "WARNING: could not set retention on index set $ISET_ID; Graylog default kept"
  fi
else
  log "WARNING: could not find the default index set; Graylog default retention kept"
fi
rm -rf "$ISET_DIR"

STEP="install the watchdog"
# systemd restarts a crashed unit; the timer also restarts one whose API stops
# answering (5 failed checks in a row, one a minute, so a slow
# Graylog start is not cut short). Results go to the journal
# (tag lm-graylog-watchdog) and /var/log/lm/syslog-graylog-watchdog.log.
for u in mongod opensearch graylog-server; do
  mkdir -p "/etc/systemd/system/$u.service.d"
  printf '[Service]\nRestart=on-failure\nRestartSec=10\n' > "/etc/systemd/system/$u.service.d/lm-restart.conf"
done
cat > /usr/local/sbin/lm-graylog-watchdog <<EOF
#!/bin/bash
# Managed by the LM syslog-graylog installer. Restarts a unit whose API stopped answering.
STATE=/run/lm-graylog-watchdog; mkdir -p "\$STATE"
LOG=/var/log/lm/syslog-graylog-watchdog.log
check() {  # check <unit> <command...>: count failures, restart on the fifth
  local unit=\$1; shift
  if "\$@" >/dev/null 2>&1; then rm -f "\$STATE/\$unit"; return; fi
  local n=\$(( \$(cat "\$STATE/\$unit" 2>/dev/null || echo 0) + 1 ))
  echo "\$n" > "\$STATE/\$unit"
  if [ "\$n" -ge 5 ]; then
    echo "\$(date -u +%FT%TZ) \$unit not answering (\$n checks), restarting" | tee -a "\$LOG" | logger -t lm-graylog-watchdog
    systemctl restart "\$unit"; rm -f "\$STATE/\$unit"
  fi
}
# Only active units are checked; systemd itself restarts a failed one.
systemctl is-active -q mongod && check mongod timeout 20 mongosh --quiet --eval 'db.runCommand({ping:1}).ok'
systemctl is-active -q opensearch && check opensearch curl -fsS -m 10 http://127.0.0.1:9200/_cluster/health
systemctl is-active -q graylog-server && check graylog-server curl -fsS -m 10 --cacert /etc/graylog/server/tls/ca.pem \\
  --resolve "$CN:9000:127.0.0.1" "https://$CN:9000/api/system/lbstatus"
exit 0
EOF
chmod 755 /usr/local/sbin/lm-graylog-watchdog
cat > /etc/systemd/system/lm-graylog-watchdog.service <<'EOF'
[Unit]
Description=LM syslog archive watchdog
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lm-graylog-watchdog
EOF
cat > /etc/systemd/system/lm-graylog-watchdog.timer <<'EOF'
[Unit]
Description=LM syslog archive watchdog (every minute)
[Timer]
OnBootSec=5min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now lm-graylog-watchdog.timer

STEP="write /etc/lm-syslog/graylog-status.json"
GL_VER="$GL_VER" OS_VER="$OS_VER" INPUT_ID="$INPUT_ID" CN="$CN" RETENTION_DAYS="$RETENTION_DAYS" \
  RETENTION_APPLIED="$RETENTION_APPLIED" python3 - <<'PY'
import json, os, subprocess, time
units = {u: subprocess.run(["systemctl", "is-active", u], capture_output=True, text=True).stdout.strip()
         for u in ("mongod", "opensearch", "graylog-server")}
status = {"installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
          "graylog_version": os.environ["GL_VER"], "opensearch_version": os.environ["OS_VER"],
          "tls_name": os.environ["CN"], "api_port": 9000, "input_port": 1514,
          "input_id": os.environ["INPUT_ID"], "retention_days": int(os.environ["RETENTION_DAYS"]),
          # False when the default index set could not be updated (see the log).
          "retention_applied": os.environ["RETENTION_APPLIED"] == "true",
          "services": units}
with open("/etc/lm-syslog/graylog-status.json", "w") as fh:
    json.dump(status, fh, indent=2)
PY

log "API https://$CN:9000/api, syslog input TCP+TLS 1514, reader lm-reader"
log "OK"
