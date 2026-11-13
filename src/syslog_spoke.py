"""Syslog spoke (module type "logging"): runs on a syslog-collector host.

rsyslog receives and stores messages (see ``store`` and ``rsyslog_conf``);
this spoke answers the hub's SYSLOG_* commands, writes the drop and archive
config rsyslog includes, keeps the local store inside its limits, and
reports everything needed to troubleshoot from the hub (SYSLOG_DIAG).
"""
# Standard library imports.
import asyncio
import glob
import json
import logging
import math
import os
import socket
import ssl
import subprocess
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

# Base spoke (core package when hosted by the agent, flat layout standalone).
try:
    from core.src.base_spoke import BaseSpoke
except ImportError:
    from base_spoke import BaseSpoke

import rsyslog_conf
from archives import ArchiveError, get_backend
from store import LocalStore, SourceTracker

logger = logging.getLogger("SyslogSpoke")

_SENSITIVE = {"password", "admin_password", "reader_password", "secret", "hub_secret", "token"}
DEFAULTS = {"retention_hours": 24, "max_mb": 2048}
# Accepted ranges (the same as the hub's): a zero or negative value would make
# housekeeping delete every closed hour.
_RANGES = {"retention_hours": (1, 168), "max_mb": (64, 1048576)}
# Settings kept on disk so a restart without the hub keeps dropping and forwarding
# (fleet rule 3.4). Secrets are never written: the archive password is only needed
# for queries, which arrive from the hub together with a fresh config push.
_PERSIST_KEYS = ("drop_rules", "retention_hours", "max_mb", "archive", "tenant")
SPOOL_DIR = "/var/spool/rsyslog"
INSTALL_LOGS = "/var/log/lm/syslog-*.log"  # installer and Graylog watchdog logs
_REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Housekeeping cadence (seconds) and the warning thresholds.
TRACK_EVERY_S = 30
HOUSEKEEP_EVERY_S = 300
QUIET_WARN_S = 30 * 60
QUEUE_WARN_BYTES = 256 * 1024 * 1024
# Process-wide, not per instance: a role reload builds a new SyslogSpoke while
# the old one's thread may still be mid-pass, and both drive the same rsyslog
# files and store, so their applies and housekeeping passes must not overlap.
_APPLY_LOCK = threading.Lock()
_HOUSEKEEP_LOCK = threading.Lock()
# Re-entrant: a tenant move holds it across the purge and the tenant commit.
_CLAIM_LOCK = threading.RLock()


class _RecentErrors(logging.Handler):
    """Keep the last 50 WARNING/ERROR lines from the Syslog* loggers for SYSLOG_DIAG."""

    def __init__(self):
        """Start with an empty ring buffer."""
        super().__init__(level=logging.WARNING)
        self.lines: deque = deque(maxlen=50)

    def emit(self, record: logging.LogRecord) -> None:
        """Remember one formatted record."""
        try:
            self.lines.append(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(record.created))}Z "
                              f"{record.levelname} {record.name}: {record.getMessage()}")
        except Exception:  # noqa: BLE001 - logging must never raise
            pass


_RECENT = _RecentErrors()
for _name in ("SyslogSpoke", "SyslogStore"):
    logging.getLogger(_name).addHandler(_RECENT)


def _run(cmd: List[str], timeout: int = 20) -> Dict[str, Any]:
    """Run a command and return {rc, out}; a missing binary or timeout is rc -1."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": (p.stdout + p.stderr).strip()}
    except (OSError, subprocess.SubprocessError) as e:
        return {"rc": -1, "out": f"{type(e).__name__}: {e}"}


def _tail(text: str, n: int) -> str:
    """Return the last n lines of text."""
    return "\n".join(text.splitlines()[-n:])


def _read(path: str) -> Optional[str]:
    """Return a file's text, or None when it does not exist or can't be read."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


class SyslogSpoke(BaseSpoke):
    """Answers SYSLOG_* commands for one collector host."""

    def __init__(self, spoke_id: str, config: Dict[str, Any], store_root: Optional[str] = None,
                 etc_dir: Optional[str] = None):
        """Set up the store reader and source counters; nothing is written yet."""
        super().__init__(spoke_id, config if isinstance(config, dict) else {})
        self.store = LocalStore(store_root or "/var/lib/lm/syslog")
        self.tracker = SourceTracker(self.store)
        self.etc_dir = etc_dir or rsyslog_conf.ETC_DIR
        # A tenant in the role-load config is not taken until it applies in the
        # same transaction as a pushed one (purge, rsyslog, rollback): see
        # startup_apply. Until then the applied (saved or installer) tenant holds.
        incoming = self.config
        self.config = {**self._load_state(), **{k: v for k, v in incoming.items() if k != "tenant"}}
        self._startup = {"tenant": str(incoming["tenant"])} if incoming.get("tenant") else {}
        # The tenant the hub last asked for. While it differs from the applied
        # one the hub already counts this collector as that tenant's, so reads
        # are refused rather than serving the previous tenant's messages.
        self._wanted = str(incoming.get("tenant") or "")
        self._move_error = ""
        self._lock = threading.Lock()
        # One config apply at a time so two pushes can't interleave writes and rollbacks.
        self._apply_lock = _APPLY_LOCK
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._housekeep_lock = _HOUSEKEEP_LOCK
        self._loops_started = False
        self._last_msg_seen = time.time()
        self._quiet_warned = False
        # The tenant of the last config that applied cleanly. Store purges and
        # archive filters use this, never a pushed tenant whose apply is still
        # running and may roll back. Before the hub has pushed one, the tenant
        # the installer recorded for the store.
        self._tenant = self._config_tenant()
        if self._tenant:
            # The applied tenant (saved, or the installer's store owner) is the
            # one a failed move rolls back to, so keep it in the live config.
            self.config["tenant"] = self._tenant
        # Bumped on every tenant change, so a read that overlaps a move can tell.
        self._tenant_gen = 0
        if self._wanted and self._wanted != self._tenant:
            logger.info("syslog: moving from tenant %s to %s at startup; reads wait for the "
                        "settings to apply", self._tenant or "(none)", self._wanted)

    # ---- config ---------------------------------------------------------

    def _setting(self, key: str) -> int:
        """Return a numeric setting from config; the default when missing or out of range."""
        try:
            value = int(self.config.get(key) or DEFAULTS[key])
        except (TypeError, ValueError):
            return DEFAULTS[key]
        low, high = _RANGES[key]
        return value if low <= value <= high else DEFAULTS[key]

    def _paths(self) -> Dict[str, str]:
        """Return the include file paths under this spoke's etc dir."""
        return {"drop": os.path.join(self.etc_dir, "drop.rsyslog"),
                "archive": os.path.join(self.etc_dir, "archive.rsyslog"),
                "ca": os.path.join(self.etc_dir, "archive-ca.pem"),
                "state": os.path.join(self.etc_dir, "config.json")}

    def _load_state(self) -> Dict[str, Any]:
        """Return the last applied settings from disk, or {} when there are none."""
        text = _read(self._paths()["state"])
        if not text:
            return {}
        try:
            data = json.loads(text)
        except ValueError:
            logger.error("syslog state error: %s is not valid JSON; ignoring it", self._paths()["state"])
            return {}
        return {k: data[k] for k in _PERSIST_KEYS if isinstance(data, dict) and k in data}

    def _config_tenant(self) -> str:
        """The tenant this collector serves: the one the hub pushed, else the one
        the installer recorded on the store. The forward tag, status and archive
        searches all use this, so a collector that only has the installer's
        tenant never forwards untagged messages it later can't find."""
        return str(self.config.get("tenant") or "") or self.store.owner()

    def _save_state(self) -> None:
        """Write the applied settings, without secrets, to the state file (0600)."""
        state = {k: self.config[k] for k in _PERSIST_KEYS if k in self.config}
        if isinstance(state.get("archive"), dict):
            state["archive"] = {k: v for k, v in state["archive"].items() if k not in _SENSITIVE}
        path = self._paths()["state"]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1, sort_keys=True)
        os.replace(tmp, path)

    @staticmethod
    def _restore(old: Dict[str, Optional[str]], changed: List[str]) -> str:
        """Put the previous text back into each changed file (remove files that were new).

        Best effort, file by file: returns "" when all were restored, else a note
        naming the files that could not be (each failure is logged)."""
        failed = []
        for p in changed:
            try:
                if old[p] is None:
                    # A new file the failed write never reached has nothing to undo.
                    if os.path.exists(p):
                        os.remove(p)
                else:
                    with open(p, "w", encoding="utf-8") as fh:
                        fh.write(old[p])
            except OSError as e:
                failed.append(os.path.basename(p))
                logger.error("syslog config error: could not restore %s: %s", p, e)
        return f"; could not restore {', '.join(failed)}" if failed else ""

    def startup_apply(self) -> Dict[str, Any]:
        """Apply the loaded settings, with the role-load tenant (a move included)
        as one transaction like a push; just rewrite the files when there is none."""
        return self._merge_and_apply({}, startup=True)

    def _apply_rsyslog(self) -> Dict[str, Any]:
        """Write the drop and archive include files from config; validate and restart
        rsyslog only when a file changed. A failed check or restart restores the old files."""
        # Step 1: validate rules, then render both files.
        rules, err = rsyslog_conf.validate_rules(self.config.get("drop_rules") or [])
        if err:
            return {"status": "ERROR", "message": err}
        archive = self.config.get("archive") or None
        # Also checked on push; a settings file saved by an older version may not pass.
        err = rsyslog_conf.validate_archive(archive) if archive else None
        if err:
            return {"status": "ERROR", "message": err}
        paths = self._paths()
        wanted = {paths["drop"]: rsyslog_conf.render_drop(rules),
                  paths["archive"]: rsyslog_conf.render_archive(archive, self._config_tenant())
                  .replace(rsyslog_conf.ARCHIVE_CA_FILE, paths["ca"])}
        if archive and archive.get("ca_pem"):
            wanted[paths["ca"]] = str(archive["ca_pem"])
        # Step 2: write only what changed, keeping the old text for rollback.
        os.makedirs(self.etc_dir, exist_ok=True)
        old = {p: _read(p) for p in wanted}
        changed = [p for p, text in wanted.items() if old[p] != text]
        if not changed:
            return {"status": "SUCCESS", "restarted": False, "changed": []}
        try:
            for p in changed:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(wanted[p])
        except OSError as e:
            # A half-written set (e.g. disk full) must not be left for the next restart.
            note = self._restore(old, changed)
            logger.error("syslog config error: could not write %s, old files put back%s: %s", p, note, e)
            return {"status": "ERROR", "message": f"could not write {os.path.basename(p)}: {e}{note}"}
        logger.info("syslog config written: %s (drop rules %d enabled, archive %s)",
                    ", ".join(os.path.basename(p) for p in changed),
                    sum(1 for r in rules if r["enabled"]),
                    f"{archive.get('host')}:{archive.get('input_port') or 1514}" if archive else "none")
        # Step 3: check the whole rsyslog config, roll back on failure, else restart.
        check = _run(["rsyslogd", "-N1"])
        if check["rc"] != 0:
            note = self._restore(old, changed)
            logger.error("syslog config error: rsyslogd -N1 rejected the new config, old files "
                         "put back%s: %s", note, _tail(check["out"], 5))
            return {"status": "ERROR", "message": "rsyslog rejected the config: " + _tail(check["out"], 3) + note}
        restart = _run(["systemctl", "restart", "rsyslog"], timeout=60)
        if restart["rc"] != 0:
            # Put the old files back and restart again so collection keeps running.
            note = self._restore(old, changed)
            again = _run(["systemctl", "restart", "rsyslog"], timeout=60)
            logger.error("syslog error: rsyslog restart failed, old files put back%s (restart with "
                         "old files rc=%s): %s", note, again["rc"], _tail(restart["out"], 5))
            return {"status": "ERROR", "message": "rsyslog restart failed: " + _tail(restart["out"], 3) + note}
        logger.info("syslog: rsyslog restarted after config change (config check ok)")
        return {"status": "SUCCESS", "restarted": True,
                "changed": [os.path.basename(p) for p in changed]}

    # ---- BaseSpoke ------------------------------------------------------

    async def get_status(self) -> Dict[str, Any]:
        """Return the same body as SYSLOG_STATUS (heartbeat path), after the same
        claim, so a moved collector never reports the old tenant's store."""
        try:
            gen = await asyncio.to_thread(self._claim_for_read)
        except OSError as e:
            return {"status": "ERROR", "message": str(e)}
        return self._unless_moved(gen, await self._status())

    @staticmethod
    def _mask(data: Any) -> Any:
        """Return a copy of data safe to log: secrets masked, PEMs shortened, nested too."""
        if isinstance(data, list):
            return [SyslogSpoke._mask(v) for v in data]
        if not isinstance(data, dict):
            return data
        out = {}
        for k, v in data.items():
            if k in _SENSITIVE:
                out[k] = "********" if v else ""
            elif k == "ca_pem" and isinstance(v, str):
                out[k] = f"<pem {len(v)} bytes>"
            else:
                out[k] = SyslogSpoke._mask(v)
        return out

    def get_version(self) -> str:
        """Return the repo VERSION file contents ("unknown" when missing)."""
        return (_read(os.path.join(_REPO_DIR, "VERSION")) or "unknown").strip()

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Commands: UPDATE_CONFIG, GET_VERSION, SYSLOG_STATUS, SYSLOG_QUERY,
        SYSLOG_SOURCES, SYSLOG_CONFIG, SYSLOG_DROP_PREVIEW, SYSLOG_DIAG."""
        # Normalise and log the command (queries are frequent: log them at debug).
        cmd = (command_type or "").upper()
        data = data if isinstance(data, dict) else {}
        log = logger.debug if cmd in ("SYSLOG_QUERY", "SYSLOG_STATUS", "SYSLOG_SOURCES") else logger.info
        log("Handling syslog command: %s with data %s", cmd, self._mask(data))
        # Dispatch; any exception becomes an error envelope.
        try:
            res = await self._dispatch(cmd, data)
        except Exception as e:  # noqa: BLE001 - always answer the hub with an envelope
            logger.exception("syslog command %s raised", cmd)
            res = {"status": "ERROR", "message": f"{type(e).__name__}: {e}"}
        # Log the outcome.
        if res.get("status") == "ERROR":
            logger.error("syslog command %s result: error - %s", cmd, res.get("message") or res.get("error"))
        else:
            log("syslog command %s result: success", cmd)
        return res

    async def _dispatch(self, cmd: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Run one normalised command and return its envelope."""
        # Config and version.
        if cmd in ("UPDATE_CONFIG", "SYSLOG_CONFIG"):
            return await self._configure(data, cmd)
        if cmd in ("GET_VERSION", "GET-VERSION"):
            return {"status": "SUCCESS", "version": self.get_version()}
        # Read-only views of the collector, after making sure the store holds
        # only this tenant's messages.
        if cmd in ("SYSLOG_STATUS", "SYSLOG_QUERY", "SYSLOG_SOURCES", "SYSLOG_DROP_PREVIEW"):
            gen = await asyncio.to_thread(self._claim_for_read)
            return self._unless_moved(gen, await self._read(cmd, data))
        if cmd == "SYSLOG_DIAG":
            return await asyncio.to_thread(self._diag_for_caller)
        return {"status": "ERROR", "message": f"unknown command {cmd or '<empty>'}"}

    async def _read(self, cmd: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Run one read-only command (the store is already claimed)."""
        if cmd == "SYSLOG_STATUS":
            return await self._status()
        if cmd == "SYSLOG_QUERY":
            return await self._query(data)
        if cmd == "SYSLOG_SOURCES":
            window = max(60, min(int(data.get("window_s") or 3600), 3600))
            with self._lock:
                rows = self.tracker.listing(window)
            return {"status": "SUCCESS", "sources": rows}
        return await asyncio.to_thread(self._drop_preview, data.get("drop_rules"))

    def _unless_moved(self, gen: int, res: Dict[str, Any]) -> Dict[str, Any]:
        """Return res, or an error when the collector moved to another tenant
        while the read ran: its rows may then belong to the new tenant."""
        if gen != self._tenant_gen:
            logger.warning("syslog: a read overlapped a tenant move; its result was discarded")
            return {"status": "ERROR", "message": "the collector moved to another tenant during this request; retry"}
        return res

    # ---- commands -------------------------------------------------------

    def _claim_for_read(self) -> int:
        """Claim the store for a read (see _claim_store). Raises OSError while a
        tenant move the hub asked for has not applied: the hub already shows this
        collector under the new tenant, and the store still holds the old one's."""
        with _CLAIM_LOCK:
            if self._wanted and self._wanted != self._tenant:
                raise OSError(f"collector is moving to tenant {self._wanted} and its settings have "
                              "not applied yet; see Diagnostics, or push the settings again")
            return self._claim_store()

    def _claim_store(self, tenant: Optional[str] = None) -> int:
        """Purge a previous tenant's local messages (the collector was moved to
        another tenant) before this tenant (default: the committed one) reads
        them, and reset the source counters built from them. Returns the tenant
        generation the caller read under. Raises OSError (old owner kept) when
        the purge fails."""
        with _CLAIM_LOCK:
            if self.store.claim(self._tenant if tenant is None else tenant):
                with self._lock:
                    self.tracker = SourceTracker(self.store)
            return self._tenant_gen

    def _merge_and_apply(self, data: Dict[str, Any], startup: bool = False) -> Dict[str, Any]:
        """Merge data into config and make it live as one change: save it, move
        the store to the tenant, then switch rsyslog. A role-load tenant not
        applied yet goes in under ``data``; with ``startup`` and nothing to
        merge, only the files are rewritten.

        A tenant move stops rsyslog before the purge, so nothing it received
        for the previous tenant (still queued in memory) is written to the
        store after the purge; it is started again however the move ends.

        Forwarding (rsyslog) changes last, so no message is tagged with a new
        tenant unless the save and the store move already succeeded. Any failure
        puts the previous config, saved state, store owner and rsyslog files
        back, so the spoke never runs settings the hub was told failed. Holds the
        apply lock (two pushes can't overwrite each other's rollback) and the
        claim lock (no read claims the store for the other tenant mid-move;
        reads wait at most one rsyslog restart)."""
        with self._apply_lock, _CLAIM_LOCK:
            # A role-load tenant not applied yet goes in first; a push overrides it.
            pending, self._startup = self._startup, {}
            data = {**pending, **data}
            if startup and not data:
                return self._apply_rsyslog()
            if data.get("tenant"):
                self._wanted = str(data["tenant"])
            previous, old_tenant = dict(self.config), self._tenant
            self.config = {**self.config, **data}
            tenant = str(self.config.get("tenant") or "")
            moving = bool(tenant) and tenant != self.store.owner()
            try:
                res = self._apply_steps(previous, old_tenant, tenant, moving)
                # Kept for SYSLOG_DIAG, the one view the new tenant gets mid-move.
                self._move_error = (str(res.get("message")) if res.get("status") == "ERROR"
                                    and self._wanted != self._tenant else "")
                return res
            finally:
                if moving:
                    # Restart collection whether the move worked or was undone
                    # (a no-op when the apply already restarted rsyslog).
                    started = _run(["systemctl", "start", "rsyslog"], 60)
                    if started["rc"] != 0:
                        logger.error("syslog error: rsyslog did not start after the tenant move "
                                     "(the watchdog retries): %s", _tail(started["out"], 3))

    def _apply_steps(self, previous: Dict[str, Any], old_tenant: str, tenant: str,
                     moving: bool) -> Dict[str, Any]:
        """The steps of _merge_and_apply (its locks held, self.config merged)."""
        # Step 1: save the settings.
        try:
            self._save_state()
        except OSError as e:
            return self._undo(previous, f"settings not saved ({e})")
        # Step 2: make the store belong to the tenant (purges a moved store),
        # with rsyslog stopped so its queue is flushed to the files first.
        if moving:
            stopped = _run(["systemctl", "stop", "rsyslog"], 60)
            if stopped["rc"] != 0:
                return self._undo(previous, "rsyslog could not be stopped for the tenant move: "
                                  + _tail(stopped["out"], 3), saved=True)
        try:
            self._claim_store(tenant)
        except OSError as e:
            return self._undo(previous, f"store not moved to tenant {tenant} ({e})", saved=True)
        # Step 3: switch rsyslog (drop rules, archive forward and its tenant tag).
        # A returned ERROR already put the old files back; an exception may
        # have left new ones, so _undo rewrites them from the old config.
        try:
            res = self._apply_rsyslog()
        except Exception as e:  # noqa: BLE001 - undone below like any failed apply
            return self._undo(previous, f"{type(e).__name__}: {e}", saved=True,
                              reclaim=old_tenant, rewrite=True)
        if res.get("status") == "ERROR":
            return self._undo(previous, str(res.get("message")), saved=True, reclaim=old_tenant)
        # Step 4: commit the tenant.
        new = self._config_tenant()
        if new != self._tenant:
            self._tenant, self._tenant_gen = new, self._tenant_gen + 1
        return res

    def _undo(self, previous: Dict[str, Any], why: str, saved: bool = False,
              reclaim: Optional[str] = None, rewrite: bool = False) -> Dict[str, Any]:
        """Put the previous config back: the store owner when it was already
        moved (``reclaim``: the previous tenant), then the rsyslog files when
        ``rewrite`` (an apply that crashed; rendered for the restored owner), and
        the saved state when the new one was already saved. Returns the ERROR
        envelope for ``why``."""
        self.config = previous
        problems = []
        if reclaim is not None:
            try:
                if reclaim:
                    self._claim_store(reclaim)
                else:
                    # claim("") is a no-op, so a failed first assignment would keep
                    # the rejected owner and a retry would skip its purge.
                    self.store.release()
            except OSError as e:
                # Reads stay refused until a later pass finishes the purge.
                problems.append(f"store not given back to {reclaim or 'no tenant'}: {e}")
        if rewrite:
            try:
                back = self._apply_rsyslog()
                if back.get("status") == "ERROR":
                    problems.append(str(back.get("message")))
            except Exception as e:  # noqa: BLE001 - report it, keep the first error first
                problems.append(f"{type(e).__name__}: {e}")
        if saved:
            try:
                self._save_state()
            except OSError as e:
                problems.append(f"previous settings not saved: {e}")
        undone = ("previous settings restored" if not problems
                  else "previous settings could not be put back: " + "; ".join(problems))
        logger.error("syslog config error: %s; %s", why, undone)
        return {"status": "ERROR", "persisted": False, "message": f"{why}; {undone}"}

    async def _configure(self, data: Dict[str, Any], cmd: str) -> Dict[str, Any]:
        """Merge settings into config and apply the rsyslog files (UPDATE_CONFIG, SYSLOG_CONFIG)."""
        # Validate drop rules and the archive before touching config so a bad push changes nothing.
        if "drop_rules" in data:
            _, err = rsyslog_conf.validate_rules(data["drop_rules"])
            if err:
                return {"status": "ERROR", "message": err}
        for key, (low, high) in _RANGES.items():
            if key in data:
                try:
                    ok = low <= int(data[key]) <= high
                except (TypeError, ValueError):
                    ok = False
                if not ok:
                    return {"status": "ERROR", "message": f"{key} must be a whole number from {low} to {high}"}
        if data.get("archive"):
            err = rsyslog_conf.validate_archive(data["archive"])
            if err:
                return {"status": "ERROR", "message": err}
        res = await asyncio.to_thread(self._merge_and_apply, data)
        if res.get("status") == "ERROR":
            return res
        applied = {k: self._mask(data[k]) for k in ("drop_rules", "retention_hours", "max_mb",
                                                     "archive", "tenant") if k in data}
        return {"status": "SUCCESS", "applied": applied, "persisted": True,
                "restarted": res.get("restarted", False), "message": f"{cmd.lower()} applied"}

    async def _status(self) -> Dict[str, Any]:
        """Collector, archive and forward-queue status (SYSLOG_STATUS)."""
        # Local collector state.
        summary = await asyncio.to_thread(self.store.summary)
        active = (await asyncio.to_thread(_run, ["systemctl", "is-active", "rsyslog"], 10))["out"] == "active"
        with self._lock:
            recent = self.tracker.count_since(300)
        # Archive state through its query plugin, if it has one.
        queue = await asyncio.to_thread(self._queue)
        archive = self.config.get("archive") or None
        arch = {"configured": bool(archive), "backend": (archive or {}).get("backend"),
                "host": (archive or {}).get("host"), "reachable": None, "version": "", "error": ""}
        backend = get_backend(archive)
        if backend:
            arch.update(await asyncio.to_thread(backend.status))
        elif archive:
            arch["error"] = "archive backend has no query support (forward only)"
        # One envelope for the WebUI status tiles.
        return {"status": "SUCCESS",
                "collector": {"active": active, "tenant": self._tenant or None,
                              "oldest_ts": summary["oldest_ts"], "newest_ts": summary["newest_ts"],
                              "bytes": summary["bytes"], "files": summary["files"],
                              "msgs_last_5m": recent, "disk_free_mb": summary["disk_free_mb"],
                              "retention_hours": self._setting("retention_hours"),
                              "max_mb": self._setting("max_mb")},
                "archive": arch, "forward": {"queue_bytes": queue["bytes"]}}

    async def _query(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Search local data, and the archive for the part of the range older
        than the local/archive cut-off.

        The cut-off is ``archive_before`` when the hub sends it (the newest
        "oldest local message" across the tenant's collectors, so every
        collector holds local data from it on), else this collector's own
        oldest message. Local covers [cut-off, end], the archive covers
        [start, cut-off), so the parts neither overlap nor leave a gap. Local
        rows come first (they are newer), so a slow or backlogged archive
        never hides recent messages. ``use_archive: false`` (sent by the hub to
        all but one collector) keeps the archive rows from being returned once
        per collector.
        """
        # Normalise the filters.
        now = time.time()
        flt = {k: data.get(k) for k in ("host", "program", "text")}
        flt["start"] = float(data.get("start") or now - 3600)
        flt["end"] = float(data.get("end") or now)
        flt["limit"] = max(1, min(int(data.get("limit") or 500), 5000))
        if data.get("severity_max") is not None:
            flt["severity_max"] = int(data["severity_max"])
        if data.get("after_ts") is not None:
            flt["after_ts"] = float(data["after_ts"])
        oldest = await asyncio.to_thread(self.store.oldest_ts)
        archive = self.config.get("archive") or None
        cut = float(data["archive_before"]) if data.get("archive_before") is not None else oldest
        # Whole milliseconds: the archive keeps millisecond times, so local takes
        # [cut, end] and the archive (inclusive range) ends 1 ms before the cut.
        if cut is not None:
            cut = math.floor(cut * 1000) / 1000
        # Effective start: live tail (after_ts) may start later than start.
        eff_start = max(flt["start"], flt.get("after_ts", flt["start"]))
        # Local only when there is no archive or the range starts after the cut-off.
        if not archive or (cut is not None and eff_start >= cut):
            res = await asyncio.to_thread(self.store.query, flt)
            return {"status": "SUCCESS", **res, "source": "local", "oldest_local_ts": oldest, "error": None}
        # Local part: from the cut-off to the end of the range.
        local = {"messages": [], "truncated": False}
        if cut is not None and flt["end"] >= cut:
            local = await asyncio.to_thread(self.store.query, {**flt, "start": cut})
        room = flt["limit"] - len(local["messages"])
        if room <= 0 or data.get("use_archive") is False:
            return {"status": "SUCCESS", **local, "source": "local", "oldest_local_ts": oldest,
                    "error": None}
        # Archive part: the rest of the limit, from before the cut-off.
        backend = get_backend(archive)
        tenant = rsyslog_conf.archive_tenant(self._tenant)
        error = "archive backend has no query support"
        if not tenant:
            # Fail closed: without a tenant filter the archive could return
            # other tenants' messages.
            error = "archive search refused: collector has no tenant"
            logger.error("syslog archive query refused: no tenant configured")
        elif backend:
            arch_end = flt["end"] if cut is None else min(flt["end"], cut - 0.001)
            try:
                res = await asyncio.to_thread(backend.search, {
                    **flt, "end": arch_end, "limit": room, "tenant": tenant})
                return {"status": "SUCCESS", "messages": local["messages"] + res["messages"],
                        "truncated": bool(local["truncated"] or res.get("truncated")),
                        "source": "archive", "oldest_local_ts": oldest, "error": None}
            except ArchiveError as e:
                error = str(e)
                logger.error("syslog archive query error: %s", error)
        return {"status": "SUCCESS", **local, "source": "local-partial", "oldest_local_ts": oldest,
                "error": error}

    def _drop_preview(self, rules: Any) -> Dict[str, Any]:
        """Count how many of the last hour's messages each rule would drop."""
        clean, err = rsyslog_conf.validate_rules(rules or [])
        if err:
            return {"status": "ERROR", "message": err}
        per_rule = [0] * len(clean)
        scanned = dropped = 0
        for msg in self.store.scan_recent(3600):
            scanned += 1
            # rsyslog stops at the first matching rule; count it against that rule.
            for i, rule in enumerate(clean):
                if rule["enabled"] and rsyslog_conf.rule_matches(rule, msg):
                    per_rule[i] += 1
                    dropped += 1
                    break
        return {"status": "SUCCESS", "scanned": scanned, "dropped": dropped, "per_rule": per_rule}

    def _queue(self) -> Dict[str, int]:
        """Return the archive forward queue's spool file count and bytes."""
        files = glob.glob(os.path.join(SPOOL_DIR, "lm_archive*"))
        total = 0
        for f in files:
            try:
                total += os.path.getsize(f)
            except OSError:
                pass
        return {"files": len(files), "bytes": total}

    def _probe_archive(self) -> Dict[str, Any]:
        """Check the archive end to end: TCP connect, TLS handshake, then its API."""
        archive = self.config.get("archive") or None
        if not archive or not archive.get("host"):
            return {"configured": False}
        host, port = str(archive["host"]), int(archive.get("input_port") or 1514)
        out: Dict[str, Any] = {"configured": True, "target": f"{host}:{port}"}
        # TCP connect to the forward port.
        try:
            sock = socket.create_connection((host, port), timeout=5)
            out["tcp_connect"] = "ok"
        except OSError as e:
            out["tcp_connect"] = f"error: {e}"
            out["tls_handshake"] = "not tried (no TCP connection)"
            sock = None
        # TLS handshake with the same CA the forwarder uses.
        if sock:
            try:
                # Same checks as the forwarder: the chain, plus the name when one is known.
                peer = rsyslog_conf.archive_peer_name(archive)
                ctx = ssl.create_default_context(cadata=archive.get("ca_pem") or None)
                ctx.check_hostname = bool(peer)
                with ctx.wrap_socket(sock, server_hostname=peer or host) as tls:
                    out["tls_handshake"] = f"ok ({tls.version()})"
            except (OSError, ssl.SSLError, ValueError) as e:
                # ValueError: a malformed CA PEM, reported here instead of failing DIAG.
                sock.close()
                out["tls_handshake"] = f"error: {e}"
        # API status through the query plugin.
        backend = get_backend(archive)
        out["api"] = backend.status() if backend else {"error": "no query plugin for backend "
                                                                f"{archive.get('backend')!r}"}
        return out

    def _diag_for_caller(self) -> Dict[str, Any]:
        """SYSLOG_DIAG. While a tenant move the hub asked for has not applied, the
        hub already counts this collector under the new tenant, so the full view
        (old tenant's archive target, files, journal, store, logs) is withheld
        like every other read; only what the new tenant needs to see why the move
        is stuck is returned: the move error and the rsyslog service state."""
        with _CLAIM_LOCK:
            pending = self._wanted and self._wanted != self._tenant
            wanted, error = self._wanted, self._move_error
        if not pending:
            return self._diag()
        active = _run(["systemctl", "is-active", "rsyslog"], 10)["out"]
        check = _run(["rsyslogd", "-N1"])
        return {"status": "SUCCESS", "version": self.get_version(),
                "moving": {"to": wanted, "error": error or "the startup apply has not run yet",
                           "retry": "housekeeping retries every 5 minutes; a push retries at once"},
                "rsyslog": {"active": active, "config_check_rc": check["rc"]}}

    def _diag(self) -> Dict[str, Any]:
        """Everything needed to troubleshoot this collector from the hub (no secrets)."""
        # rsyslog service, config check, journal and listeners.
        paths = self._paths()
        active = _run(["systemctl", "is-active", "rsyslog"], 10)["out"]
        version = _run(["rsyslogd", "-v"], 10)["out"].splitlines()[:1]
        check = _run(["rsyslogd", "-N1"])
        journal = _run(["journalctl", "-u", "rsyslog", "-n", "100", "--no-pager"])
        listen = _run(["ss", "-lntup"], 10)["out"].splitlines()
        # Installer logs (OK/FAILED markers) and the Graylog watchdog log.
        installer = []
        for path in sorted(glob.glob(INSTALL_LOGS)):
            installer.append(f"== {path}\n" + _tail(_read(path) or "", 100))
        # Store, queue, archive probe and settings; secrets are never included.
        summary = self.store.summary()
        return {"status": "SUCCESS", "version": self.get_version(),
                "rsyslog": {"active": active, "version": version[0] if version else "",
                            "config_check": _tail(check["out"], 30), "config_check_rc": check["rc"],
                            "journal": journal["out"]},
                "listeners": [ln for ln in listen if ":514 " in ln or ":6514 " in ln],
                "files": {paths["drop"]: _read(paths["drop"]), paths["archive"]: _read(paths["archive"])},
                "store": summary, "forward_queue": self._queue(),
                "archive_probe": self._probe_archive(),
                "settings": {"tenant": self._tenant or None,
                             "retention_hours": self._setting("retention_hours"),
                             "max_mb": self._setting("max_mb"),
                             "drop_rules": len(self.config.get("drop_rules") or [])},
                "installer_log": "\n".join(installer),
                "recent_errors": list(_RECENT.lines)}

    # ---- background -----------------------------------------------------

    def start_background_loops(self) -> None:
        """Start the housekeeping thread, which first applies the saved config.

        Called by the agent when it hosts the role and by the standalone
        control plane. Everything runs in the thread, because the agent calls
        this from its event loop and the apply may restart rsyslog.
        """
        if self._loops_started:
            return
        self._loops_started = True
        # A fresh event per thread, so an old thread still finishing a slow
        # step after a reload can't miss its stop and run beside the new one.
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._housekeeping_loop, args=(self._stop,),
                                        name="syslog-housekeeping", daemon=True)
        self._thread.start()
        logger.info("syslog background loops started (store %s)", self.store.root)

    def stop_background_loops(self) -> None:
        """Stop the housekeeping thread (the agent calls this on role unload or reload).

        Does not wait: the agent calls it on its event loop, and the thread
        exits on its own at its next check of the event."""
        self._stop.set()
        self._thread = None
        self._loops_started = False
        logger.info("syslog background loops stopped")

    def _housekeeping_loop(self, stop: threading.Event) -> None:
        """Apply the saved config, then refresh source counters, run retention and
        watch rsyslog until stopped."""
        # Startup apply: keep running on the last good files if it fails.
        try:
            res = self.startup_apply()
            if res.get("status") == "ERROR":
                logger.error("syslog startup config error: %s", res.get("message"))
        except Exception as e:  # noqa: BLE001
            logger.error("syslog startup config error: %s", e)
        # Housekeeping until stop_background_loops sets the event.
        last_housekeep = 0.0
        while not stop.is_set():
            try:
                due = time.time() - last_housekeep >= HOUSEKEEP_EVERY_S
                self.housekeeping_tick(run_retention=due)
                if due:
                    last_housekeep = time.time()
            except Exception as e:  # noqa: BLE001 - the loop must survive any one failure
                logger.error("syslog housekeeping error: %s", e)
            stop.wait(TRACK_EVERY_S)

    def _retry_move(self) -> None:
        """Retry a tenant move the hub asked for that has not applied (reads are
        refused until it does), so a collector heals once the disk or rsyslog
        recovers without waiting for another push."""
        wanted = self._wanted
        if not wanted or wanted == self._tenant:
            return
        logger.info("syslog: retrying the move to tenant %s", wanted)
        res = self._merge_and_apply({"tenant": wanted})
        if res.get("status") != "ERROR":
            logger.info("syslog: collector moved to tenant %s", wanted)

    def _watch_rsyslog(self) -> None:
        """Restart rsyslog when it is not running (the collector's watchdog).

        Skipped while a config apply holds the lock, since that may be
        restarting rsyslog itself.
        """
        if not self._apply_lock.acquire(blocking=False):
            return
        try:
            state = _run(["systemctl", "is-active", "rsyslog"], 10)["out"]
            if state == "active":
                return
            res = _run(["systemctl", "restart", "rsyslog"], 60)
            logger.error("syslog watchdog: rsyslog was %s, restarted (rc=%s) %s", state or "unknown",
                         res["rc"], _tail(res["out"], 3))
        finally:
            self._apply_lock.release()

    def housekeeping_tick(self, run_retention: bool, now: Optional[float] = None) -> None:
        """One housekeeping pass (split out so tests can drive it). Serialised,
        so an old thread finishing a pass after a reload can't overlap the new one."""
        with self._housekeep_lock:
            self._housekeeping_pass(run_retention, now)

    def _housekeeping_pass(self, run_retention: bool, now: Optional[float]) -> None:
        """The body of housekeeping_tick."""
        now = now or time.time()
        self._claim_store()
        # Source counters and the "no messages" warning.
        with self._lock:
            read = self.tracker.refresh(now)
        if read:
            self._last_msg_seen, self._quiet_warned = now, False
        elif now - self._last_msg_seen > QUIET_WARN_S and not self._quiet_warned:
            logger.warning("syslog: no messages received for %d minutes",
                           int((now - self._last_msg_seen) // 60))
            self._quiet_warned = True
        # Archive queue growth means the archive is not taking messages.
        queue = self._queue()
        if queue["bytes"] > QUEUE_WARN_BYTES:
            logger.warning("syslog: archive forward queue is %d MB (archive unreachable or slow)",
                           queue["bytes"] // (1024 * 1024))
        if not run_retention:
            return
        self._retry_move()
        self._watch_rsyslog()
        # Retention: compress closed hours, then delete by age, size cap and free space.
        # Under the claim lock: a gzip that overlapped a tenant purge could put the
        # old tenant's hour back (as .gz) after the purge emptied it.
        with _CLAIM_LOCK:
            res = self.store.housekeep(self._setting("retention_hours"), self._setting("max_mb"), now=now)
        if res["gzipped"] or res["deleted"]:
            logger.info("syslog retention: %d hour file(s) compressed, %d deleted, %d MB freed",
                        res["gzipped"], res["deleted"], res["freed_bytes"] // (1024 * 1024))
        if res["size_cap_hit"]:
            logger.warning("syslog retention: size cap %d MB reached, oldest data deleted early",
                           self._setting("max_mb"))
        if res["low_disk_hit"]:
            logger.warning("syslog retention: disk nearly full, oldest data deleted early")
