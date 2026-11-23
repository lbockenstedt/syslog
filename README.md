# LM Syslog

Syslog collection for Lab Manager. Each tenant runs one or more **collectors**
that keep a 24-hour rolling local store, and may add one **archive** (Graylog,
installed by LM) that holds history longer. Day-to-day searching, live tail,
sources, drop rules and settings all happen on LM's **Syslog** page; nobody
needs Graylog's own UI for daily work.

The full design, routes and WebUI are in `lm/docs/syslog.md` (canonical).

## Roles

| Role | Installed by | What it does |
|---|---|---|
| `syslog-collector` | `install_syslog_collector.sh` | rsyslog listens on UDP 514, TCP 514 and TLS 6514 and writes JSON lines to `/var/lib/lm/syslog/<UTC day>/<UTC hour>.jsonl` |
| `syslog` | the agent (module role, type `logging`) | `src/syslog_spoke.py`: answers the hub's `SYSLOG_*` commands, writes drop and archive rsyslog config, keeps the store inside its limits. Loaded automatically after `syslog-collector` |
| `syslog-graylog` | `install_syslog_graylog.sh` | Graylog Open 7.0 + OpenSearch 2.19 (localhost) + MongoDB 8.0. Syslog TCP+TLS input on 1514, HTTPS API on 9000, read-only user `lm-reader` |

Point devices at a collector's IP (UDP/TCP 514, or TLS 6514 with LM's CA).

## How data flows

```
devices --514/6514--> rsyslog (collector) --> drop rules --> hourly JSONL (24 h)
                                                        \--> RFC5424 over TLS --> archive :1514
hub --SYSLOG_QUERY--> spoke --(range inside local data)--> local files
                           \--(older)--> archive query plugin (Graylog API)
```

- Python never handles a message on the receive path; rsyslog does.
- Drop rules run before both outputs, so a dropped message is not stored or
  archived.
- The archive forward queue spills to disk (max 1 GB) and discards new
  messages when full, so an archive outage never blocks the local store.
- Housekeeping every 5 minutes compresses closed hours, deletes hours past
  the retention, and deletes oldest-first above the size cap (default
  2048 MB) or when the disk has under 1 GB free.
- The last applied settings (drop rules, archive target, tenant, limits) are
  kept in `/etc/lm-syslog/config.json` (0600, no passwords), so a collector
  that restarts without its hub keeps dropping and forwarding. A failed
  config check or rsyslog restart puts the previous files back.
  The archive reader password is not on disk: until the hub's next push,
  archive searches report "password not received from the hub yet" and the
  archive status shows reachable as unknown.
- The store records its tenant in `/var/lib/lm/syslog/.tenant` (the
  installer writes it before rsyslog starts listening). Until the hub pushes
  a tenant, that one tags forwarded messages and filters archive searches. Messages stored
  while a collector had no tenant are emptied when its first tenant
  arrives. When a collector is moved to another tenant, the settings are
  saved, then its local messages are emptied, and only then is rsyslog
  switched to the new tenant tag (a failed switch gives the store back to the
  old tenant). Its local messages are emptied before the new tenant can read them (the old tenant keeps them in its
  archive), and a read still running when the move lands returns an error
  (retry) instead of rows that may belong to the new tenant. rsyslog is
  stopped for the purge (UDP messages sent in that moment are lost) and
  started again however the move ends. Until a move the hub asked for has
  applied (it failed, or the spoke has just started), reads and status
  return an error naming the new tenant instead of the old tenant's
  messages; housekeeping retries the move every 5 minutes.

## Swapping the archive

Forwarding is standard RFC5424 syslog over TLS (always: a plain-text archive
or an `http://` API URL is refused) with `[lm@32473 src_ip="…" lm_tenant="…" dev_ts="…"]`
structured data, so any syslog server that accepts TLS can receive it. The header time is the
collector's receive time (the clock the local store uses, so the local/archive
query split lines up); the device's own timestamp is in `dev_ts`. Searching an archive
needs a query plugin in `src/archives/` (`BACKENDS`). A backend without one is
forward-only: queries older than the local data return the local part with
`source: local-partial`. To add a backend, write a class with `search(flt)`
and `status()` (see `src/archives/__init__.py`) and register it in `BACKENDS`.
`search` gets the filters plus `tenant` and should return only messages whose
`lm_tenant` matches it. The spoke never searches without a tenant, and a
plugin should refuse (raise `ArchiveError`) if it gets none.

## Troubleshooting (from the hub)

No shell access is needed:

- **Syslog → Diagnostics** in LM (the `SYSLOG_DIAG` command) shows rsyslog
  state, its config check and journal, the listeners, the rendered drop and
  archive config, store hours and free disk, the forward queue, an archive
  probe (TCP, TLS handshake, API), the installer log and recent errors.
- Spoke log lines (logger names `Syslog*`) reach the hub's Logs view.
- Installers log to `/var/log/lm/syslog-collector-install.log` and
  `/var/log/lm/syslog-graylog-install.log` and end with `OK` or
  `FAILED: <step>`. The Graylog installer also writes
  `/etc/lm-syslog/graylog-status.json`, whose `retention_applied` is false
  (with a `WARNING` line in the install log) when the archive retention
  could not be set on Graylog's default index set.
- Watchdogs: the collector restarts rsyslog when it is not active (logged
  as `syslog watchdog:` in the spoke log). The Graylog host runs
  `lm-graylog-watchdog.timer` every minute: it checks MongoDB, OpenSearch and
  the Graylog API, and restarts a unit after 5 failed checks in a row. It logs
  to `/var/log/lm/syslog-graylog-watchdog.log` and the journal (tag
  `lm-graylog-watchdog`). Diagnostics shows that log when a collector runs on
  the Graylog host; otherwise the archive probe shows whether the API answers.

## Requirements

- Collector: Debian/Ubuntu with rsyslog 8.2106 or newer (Debian 12, Ubuntu
  22.04+), `rsyslog-gnutls`.
- Graylog archive: Debian 12 or Ubuntu 22.04/24.04, a CPU with AVX
  (MongoDB), 8 GB RAM or more recommended.

## Tests

```bash
PYTHONPATH=../lm:../lm/core/src python3 -m pytest -q tests
```
