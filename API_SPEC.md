# Syslog spoke API (module type `logging`)

Commands the hub sends to the `syslog` role. Every reply has
`"status": "SUCCESS"` or `"status": "ERROR"` with a `message`.

## UPDATE_CONFIG / SYSLOG_CONFIG

Merge settings and apply them. Any subset of:

| Key | Meaning |
|---|---|
| `tenant` | tenant slug, sent to the archive as `lm_tenant`; changing it empties the local store first |
| `drop_rules` | list (max 50) of `{field: host\|program\|msg\|severity, op: equals\|contains\|regex\|gte, value, enabled, note}`; severity rules use `gte` and 0-7; `regex` is POSIX ERE as rsyslog runs it (no `\d`, `(?…)`, lazy quantifiers, `[:class:]` names or backslashes inside `[...]`) |
| `retention_hours` | local retention, 1–168 hours (default 24) |
| `max_mb` | local size cap, 64–1048576 MB (default 2048) |
| `archive` | `{backend, host, input_port, tls, api_url, user, password, ca_pem, tls_name}` or `null`; always TLS (`tls: false` is refused; `api_url` must be `https://` with a host that is not a link-local or unspecified IP): the forward checks the CA chain plus `tls_name` (or `host` when it is a DNS name); an IP `host` without `tls_name` is refused, so the name is always checked |

Rules are validated first (a bad rule changes nothing). The rsyslog include
files are rewritten only when they change; `rsyslogd -N1` must accept them or
the old files are restored. Reply: `{applied, restarted, persisted}`. The
apply, the save to disk and a tenant move (purging the previous tenant's
store) are one change: if the settings can't be saved (for example a full
disk) or the store can't be purged, the previous config, rsyslog files and
saved settings are put back, the tenant is not changed, and the reply is
`status: ERROR` with `persisted: false`. The steps run in the order save,
purge, rsyslog, so forwarding never carries a new tenant tag unless the save
and the purge succeeded; if rsyslog then rejects the config, the store and
settings go back to the previous tenant (the purged hours stay purged, as the
hub asked). A tenant move stops rsyslog before the purge and starts it again
however the move ends, so nothing still queued for the previous tenant lands
after the purge (UDP messages sent during the move are lost). Until a tenant
move the hub asked for has applied (a failed push, or the tenant the role was
loaded with before the startup apply), every read and `SYSLOG_STATUS` returns
`status: ERROR` ("collector is moving to tenant …") rather than the previous
tenant's messages; housekeeping retries the move every 5 minutes, and a new
push retries it at once. Out-of-range `retention_hours` or
`max_mb` is refused before anything changes.

## GET_VERSION

`{version}`.

## SYSLOG_STATUS

```
{collector: {active, tenant, oldest_ts, newest_ts, bytes, files, msgs_last_5m,
             disk_free_mb, retention_hours, max_mb},
 archive: {configured, backend, host, reachable, version, error},
 forward: {queue_bytes}}
```

`disk_free_mb` is `null` when free space can't be read; housekeeping then
deletes only by age and size, never for low disk.
`archive.reachable` is `null` (unknown) when it was not checked, for example
when the archive password has not been pushed yet after a restart.

## SYSLOG_QUERY

Request: `{start, end, host, program, severity_max, text, limit (<=5000, default 500), after_ts, use_archive, archive_before}`.
`host`/`program` are case-insensitive substrings, in the local store and the
archive (`host` also matches the
sender IP); `text` matches message, host or program; `after_ts` returns only
newer messages (live tail).

Reply: `{messages: [{ts, host, src_ip, program, severity, facility, msg}],
source: local|archive|local-partial, truncated, oldest_local_ts, error}`,
newest first. A range that starts inside local data is answered locally.
An older one is split at a cut-off: local data from the cut-off to `end`,
then the archive (filtered to this collector's tenant, `lm_tenant`; refused
with `source: local-partial` when the collector has no tenant) for the
time before it, filling what is left of `limit`. The cut-off is
`archive_before` when given (the hub sends the newest oldest-local-message
across the tenant's collectors, so every collector's local part starts at the
same point), else this collector's oldest local message, rounded down to
the millisecond (the archive keeps millisecond times; its part ends 1 ms
before the cut-off, inclusive). A slow archive
therefore never hides recent local messages, and a live tail (`after_ts`)
newer than the cut-off stays local. An archive failure or a forward-only
backend returns the local part as `local-partial` with `error`.
`use_archive: false` skips the archive; the hub sends it to all but one
collector so archive rows are not returned once per collector.

## SYSLOG_SOURCES

Request `{window_s}` (max 3600). Reply `{sources: [{host, src_ip, last_ts, count, by_severity}]}`, busiest first.

## SYSLOG_DROP_PREVIEW

Request `{drop_rules}`. Reply `{scanned, dropped, per_rule}` over the last
hour of local data; each message counts once, against the first matching rule.

## SYSLOG_DIAG

Everything needed to troubleshoot from the hub, with no secrets:
`{version, rsyslog: {active, version, config_check, config_check_rc, journal},
listeners, files: {<drop file>: text, <archive file>: text}, store,
forward_queue: {files, bytes}, archive_probe: {configured, target, tcp_connect,
tls_handshake, api}, settings, installer_log, recent_errors}`.

While a tenant move the hub asked for has not applied, the hub already counts
the collector under the new tenant, so the full view (the old tenant's archive
target, files, journal, store and logs) is withheld and the reply is only
`{version, moving: {to, error, retry}, rsyslog: {active, config_check_rc}}`:
why the move is stuck, without the old tenant's data.
