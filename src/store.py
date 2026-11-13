"""Local syslog store: hourly JSON Lines files written by rsyslog.

rsyslog writes one line per message to ``<root>/YYYY-MM-DD/HH.jsonl`` (UTC,
keyed by receive time). This module only reads those files, compresses closed
hours, enforces retention and the size cap, and keeps per-source counters.
Python never handles a message on the receive path.
"""
# Standard library imports.
import gzip
import json
import logging
import os
import re
import shutil
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger("SyslogStore")

DEFAULT_ROOT = "/var/lib/lm/syslog"
# A query stops scanning after this many seconds and reports "truncated".
QUERY_TIME_BUDGET_S = 20.0
# Hours are compressed only after rsyslog has closed them (omfile closeTimeout is 10 min).
CLOSE_GRACE_S = 15 * 60
MAX_LIMIT = 5000
_HOUR_FILE = re.compile(r"^(\d{2})\.jsonl(\.gz)?$")
_DAY_DIR = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def hour_start(ts: float) -> int:
    """Return the epoch second at the start of the UTC hour containing ts."""
    return int(ts) - int(ts) % 3600


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one stored line into a message dict, or None when it is damaged."""
    # A partly written last line or a bad byte must not break a query.
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    # rsyslog writes seconds and the fraction separately; join them.
    try:
        ts = float(f"{int(rec.get('ts', 0))}.{rec.get('frac') or 0}")
    except (TypeError, ValueError):
        return None
    return {"ts": ts, "host": rec.get("host") or "", "src_ip": rec.get("src_ip") or "",
            "program": rec.get("program") or "", "severity": _int(rec.get("sev"), 7),
            "facility": _int(rec.get("fac"), 1), "msg": rec.get("msg") or ""}


def _int(value: Any, default: int) -> int:
    """Return value as an int, or default when it is not a number."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def matches(msg: Dict[str, Any], flt: Dict[str, Any]) -> bool:
    """Return True when a message passes the query filters.

    host and program match case-insensitively as substrings; text matches the
    message, host or program; severity_max keeps that level and more severe.
    """
    # Time window (after_ts is the live-tail cursor, strictly newer).
    if msg["ts"] < flt.get("start", 0) or msg["ts"] > flt.get("end", float("inf")):
        return False
    if flt.get("after_ts") is not None and msg["ts"] <= flt["after_ts"]:
        return False
    # Severity, then the text filters.
    if flt.get("severity_max") is not None and msg["severity"] > flt["severity_max"]:
        return False
    for key in ("host", "program"):
        want = (flt.get(key) or "").lower()
        if want and want not in msg[key].lower() and not (key == "host" and want in msg["src_ip"]):
            return False
    text = (flt.get("text") or "").lower()
    if text and text not in msg["msg"].lower() and text not in msg["host"].lower() \
            and text not in msg["program"].lower():
        return False
    return True


class LocalStore:
    """Read side of the rsyslog-written hourly files under ``root``."""

    def __init__(self, root: str = DEFAULT_ROOT):
        """Remember the store root; nothing is read until asked."""
        self.root = root

    # ---- file discovery -------------------------------------------------

    def hour_files(self) -> List[Dict[str, Any]]:
        """Return every stored hour, oldest first: {hour (epoch), path, bytes, gz}."""
        out = []
        if not os.path.isdir(self.root):
            return out
        # Walk day directories, then hour files inside them.
        for day in os.listdir(self.root):
            if not _DAY_DIR.match(day):
                continue
            day_dir = os.path.join(self.root, day)
            for name in os.listdir(day_dir):
                m = _HOUR_FILE.match(name)
                if not m:
                    continue
                path = os.path.join(day_dir, name)
                try:
                    hour = int(datetime.strptime(f"{day} {m.group(1)}", "%Y-%m-%d %H")
                               .replace(tzinfo=timezone.utc).timestamp())
                    size = os.path.getsize(path)
                except (ValueError, OSError):
                    continue
                out.append({"hour": hour, "path": path, "bytes": size, "gz": bool(m.group(2))})
        out.sort(key=lambda f: (f["hour"], f["gz"]))
        return out

    def oldest_ts(self) -> Optional[float]:
        """Return the timestamp of the oldest stored message, or None when empty."""
        for f in self.hour_files():
            for line in self._lines(f["path"]):
                msg = parse_line(line)
                if msg:
                    return msg["ts"]
        return None

    def newest_ts(self) -> Optional[float]:
        """Return the timestamp of the newest stored message, or None when empty."""
        for f in reversed(self.hour_files()):
            last = None
            # A plain file can be large: read only its last 64 KB.
            lines = self._tail_lines(f["path"]) if not f["gz"] else self._lines(f["path"])
            for line in lines:
                msg = parse_line(line)
                if msg:
                    last = msg["ts"]
            if last is not None:
                return last
        return None

    @staticmethod
    def _tail_lines(path: str, size: int = 65536) -> List[str]:
        """Return the complete lines in the last ``size`` bytes of a plain file."""
        try:
            with open(path, "rb") as fh:
                fh.seek(max(0, os.path.getsize(path) - size))
                data = fh.read().decode("utf-8", "replace")
        except OSError:
            return []
        # The first line may be cut by the seek; skip it unless we read the whole file.
        lines = data.splitlines()
        return lines[1:] if os.path.getsize(path) > size else lines

    @staticmethod
    def _lines(path: str) -> Iterator[str]:
        """Yield the lines of a plain or gzipped hour file; a vanished file yields nothing."""
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
                yield from fh
        except (OSError, EOFError):
            return

    # ---- queries --------------------------------------------------------

    def query(self, flt: Dict[str, Any]) -> Dict[str, Any]:
        """Return matching messages newest first, at most ``limit``.

        Files are read newest hour first and stop once the limit is reached,
        so memory stays bounded by ``limit``. A query that runs past the time
        budget returns what it has with ``truncated`` set.
        """
        # Normalise the limit and the time window.
        limit = max(1, min(int(flt.get("limit") or 500), MAX_LIMIT))
        start, end = float(flt.get("start") or 0), float(flt.get("end") or time.time())
        flt = {**flt, "start": start, "end": end}
        deadline = time.monotonic() + QUERY_TIME_BUDGET_S
        out: List[Dict[str, Any]] = []
        truncated = False
        # Cheap pre-filter on the raw line before JSON parsing. Skipped for text
        # that rsyslog escapes in JSON (quotes, slashes, control chars), where the
        # raw line would not contain it as typed; the full match below still runs.
        needle = (flt.get("text") or "").lower()
        if any(c in needle for c in '"\\/') or not needle.isprintable():
            needle = ""
        # Newest hour first; within an hour keep the newest matches.
        for f in reversed(self.hour_files()):
            if f["hour"] + 3600 <= start or f["hour"] > end:
                continue
            keep: deque = deque(maxlen=limit - len(out))
            for line in self._lines(f["path"]):
                if needle and needle not in line.lower():
                    continue
                msg = parse_line(line)
                if msg and matches(msg, flt):
                    keep.append(msg)
                if time.monotonic() > deadline:
                    truncated = True
                    break
            out.extend(reversed(keep))
            if len(out) >= limit or truncated:
                truncated = truncated or len(out) >= limit
                break
        out.sort(key=lambda m: m["ts"], reverse=True)
        return {"messages": out[:limit], "truncated": truncated}

    def scan_recent(self, seconds: int = 3600) -> Iterator[Dict[str, Any]]:
        """Yield every message from the last ``seconds`` (used by drop-rule preview)."""
        since = time.time() - seconds
        for f in self.hour_files():
            if f["hour"] + 3600 <= since:
                continue
            for line in self._lines(f["path"]):
                msg = parse_line(line)
                if msg and msg["ts"] >= since:
                    yield msg

    # ---- housekeeping ---------------------------------------------------

    def owner(self) -> str:
        """Return the tenant recorded in ``<root>/.tenant`` ("" when none)."""
        try:
            with open(os.path.join(self.root, ".tenant"), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""

    def release(self) -> None:
        """Forget the owner (remove ``.tenant``), so the next claim purges again.

        Used to undo a first tenant assignment that failed later on: the store
        goes back to having no owner. Raises OSError when the marker can't be removed."""
        try:
            os.remove(os.path.join(self.root, ".tenant"))
        except FileNotFoundError:
            pass

    def claim(self, tenant: str) -> bool:
        """Make the store belong to ``tenant``; return True when messages that
        were not this tenant's were removed. An empty ``tenant`` changes nothing. Raises OSError, leaving the old
        owner in place, when any of those files can't be removed.

        The owner is kept in ``<root>/.tenant`` (the installer writes it when it
        knows the tenant). Every hour file is emptied before a new owner is
        recorded: after a move to another tenant (the old tenant keeps its
        messages in the archive under its own lm_tenant), and also when a store
        with no owner gets its first tenant, because messages received while the
        collector had no tenant can't be attributed to anyone.
        """
        marker = os.path.join(self.root, ".tenant")
        owner = self.owner()
        # No tenant known yet (fresh install, or settings not pushed yet): change
        # nothing; the store keeps the owner the installer recorded.
        if owner == tenant or not tenant:
            return False
        # Step 1: empty the old tenant's hours. The open hour is truncated, not
        # deleted, because rsyslog keeps writing to it (append mode).
        purged = bool(owner) or bool(tenant and self.hour_files())
        if purged:
            removed, failed = 0, 0
            for f in self.hour_files():
                try:
                    if f["gz"]:
                        os.remove(f["path"])
                    else:
                        open(f["path"], "w", encoding="utf-8").close()
                    removed += 1
                except OSError as e:
                    failed += 1
                    logger.error("syslog store: error removing %s: %s", f["path"], e)
            # Any file left over still holds the old tenant's messages: keep the old
            # owner and raise, so every read is refused and the next claim retries.
            if failed:
                raise OSError(f"store still belongs to tenant {owner}: could not remove "
                              f"{failed} of its hour files (will retry)")
            logger.warning("syslog store: tenant changed from %s to %s; removed %d hour files",
                           owner or "<none>", tenant, removed)
        # Step 2: record the new owner (atomic replace).
        os.makedirs(self.root, exist_ok=True)
        tmp = marker + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(tenant)
        os.replace(tmp, marker)
        return purged

    def housekeep(self, retention_hours: int, max_mb: int, min_free_mb: int = 1024,
                  now: Optional[float] = None) -> Dict[str, Any]:
        """Compress closed hours, then delete hours past retention, over the size
        cap, or while the disk is below ``min_free_mb``. Oldest goes first.
        Returns counts for logging."""
        now = now or time.time()
        result = {"gzipped": 0, "deleted": 0, "freed_bytes": 0, "size_cap_hit": False,
                  "low_disk_hit": False}
        # Step 1: gzip every hour that closed more than the grace period ago.
        for f in self.hour_files():
            if not f["gz"] and f["hour"] + 3600 + CLOSE_GRACE_S < now:
                if self._gzip(f["path"]):
                    result["gzipped"] += 1
        # Step 2: delete by age, then by size cap, then by free space.
        files = self.hour_files()
        cutoff = hour_start(now) - int(retention_hours) * 3600
        total = sum(f["bytes"] for f in files)
        current = hour_start(now)
        for f in files:
            too_old = f["hour"] < cutoff
            too_big = total > int(max_mb) * 1024 * 1024
            free = self.disk_free_mb()
            low_disk = free is not None and free < min_free_mb
            # Never delete the hour rsyslog is writing now.
            if f["hour"] >= current or not (too_old or too_big or low_disk):
                continue
            try:
                os.remove(f["path"])
            except OSError as e:
                logger.error("syslog store: error deleting %s: %s", f["path"], e)
                continue
            total -= f["bytes"]
            result["deleted"] += 1
            result["freed_bytes"] += f["bytes"]
            result["size_cap_hit"] |= too_big and not too_old
            result["low_disk_hit"] |= low_disk and not too_old
        self._remove_empty_days()
        return result

    def _gzip(self, path: str) -> bool:
        """Compress one hour file in place; keep the original if anything fails."""
        tmp = path + ".gz.tmp"
        try:
            with open(path, "rb") as src, gzip.open(tmp, "wb", compresslevel=6) as dst:
                shutil.copyfileobj(src, dst)
            os.replace(tmp, path + ".gz")
        except OSError as e:
            logger.error("syslog store: error compressing %s: %s", path, e)
            try:
                os.remove(tmp)
            except OSError:
                pass
            return False
        # Step 2: drop the original. If that fails, drop the copy instead, so the
        # hour is never stored twice (a query would return its messages twice).
        try:
            os.remove(path)
            return True
        except OSError as e:
            logger.error("syslog store: error removing %s after compressing it: %s", path, e)
            try:
                os.remove(path + ".gz")
            except OSError:
                pass
            return False

    def _remove_empty_days(self) -> None:
        """Remove day directories left empty by deletion."""
        if not os.path.isdir(self.root):
            return
        for day in os.listdir(self.root):
            path = os.path.join(self.root, day)
            if _DAY_DIR.match(day) and os.path.isdir(path) and not os.listdir(path):
                try:
                    os.rmdir(path)
                except OSError:
                    pass

    def disk_free_mb(self) -> Optional[int]:
        """Return free megabytes on the store's filesystem, or None when it can't
        be read (unknown is not "no space": it must not trigger deletion)."""
        try:
            return int(shutil.disk_usage(self.root if os.path.isdir(self.root) else "/").free
                       // (1024 * 1024))
        except OSError as e:
            logger.error("syslog store: error reading free disk space: %s", e)
            return None

    def summary(self) -> Dict[str, Any]:
        """Return size and age facts for status and diagnostics."""
        files = self.hour_files()
        return {"dir": self.root, "files": len(files),
                "bytes": sum(f["bytes"] for f in files),
                "oldest_ts": self.oldest_ts(), "newest_ts": self.newest_ts(),
                "disk_free_mb": self.disk_free_mb(),
                "hours": [{"hour": f["hour"], "bytes": f["bytes"], "gz": f["gz"]}
                          for f in files[-48:]]}


class SourceTracker:
    """Per-source counters fed by tailing the current hour file.

    Each refresh reads only bytes added since the last one, so the cost is
    proportional to new traffic, not to the store size.
    """

    def __init__(self, store: LocalStore, window_s: int = 3600):
        """Start with no counters; ``refresh`` fills them."""
        self.store = store
        self.window_s = window_s
        self._offsets: Dict[str, int] = {}
        # host -> {"src_ip", "last_ts", "minutes": {minute_epoch: {sev: n}}}
        self.sources: Dict[str, Dict[str, Any]] = {}

    def refresh(self, now: Optional[float] = None) -> int:
        """Read new lines from the open (uncompressed) hour files; return lines read."""
        now = now or time.time()
        read = 0
        live = [f for f in self.store.hour_files()
                if not f["gz"] and f["hour"] + 3600 > now - self.window_s]
        # Forget offsets of files that are gone or compressed.
        self._offsets = {p: o for p, o in self._offsets.items() if any(f["path"] == p for f in live)}
        for f in live:
            read += self._read_new(f["path"])
        self._expire(now)
        return read

    def _read_new(self, path: str) -> int:
        """Count the lines appended to path since the last call."""
        count = 0
        try:
            with open(path, "rb") as fh:
                fh.seek(self._offsets.get(path, 0))
                for raw in fh:
                    # Leave a partly written last line for next time.
                    if not raw.endswith(b"\n"):
                        break
                    self._offsets[path] = self._offsets.get(path, 0) + len(raw)
                    msg = parse_line(raw.decode("utf-8", "replace"))
                    if msg:
                        self._add(msg)
                        count += 1
        except OSError:
            pass
        return count

    def _add(self, msg: Dict[str, Any]) -> None:
        """Add one message to its source's per-minute counters."""
        key = msg["host"] or msg["src_ip"] or "unknown"
        src = self.sources.setdefault(key, {"src_ip": msg["src_ip"], "last_ts": 0.0, "minutes": {}})
        src["src_ip"] = msg["src_ip"] or src["src_ip"]
        src["last_ts"] = max(src["last_ts"], msg["ts"])
        minute = int(msg["ts"]) - int(msg["ts"]) % 60
        bucket = src["minutes"].setdefault(minute, {})
        sev = str(msg["severity"])
        bucket[sev] = bucket.get(sev, 0) + 1

    def _expire(self, now: float) -> None:
        """Drop minute buckets older than the window, and sources with none left."""
        floor = now - self.window_s
        for key in list(self.sources):
            src = self.sources[key]
            src["minutes"] = {m: b for m, b in src["minutes"].items() if m >= floor - 60}
            if not src["minutes"] and src["last_ts"] < floor:
                del self.sources[key]

    def listing(self, window_s: int = 3600, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Return one row per source seen in the window, busiest first."""
        now = now or time.time()
        rows = []
        for host, src in self.sources.items():
            by_sev: Dict[str, int] = {}
            for minute, bucket in src["minutes"].items():
                if minute >= now - window_s - 60:
                    for sev, n in bucket.items():
                        by_sev[sev] = by_sev.get(sev, 0) + n
            rows.append({"host": host, "src_ip": src["src_ip"], "last_ts": src["last_ts"],
                         "count": sum(by_sev.values()), "by_severity": by_sev})
        rows.sort(key=lambda r: r["count"], reverse=True)
        return rows

    def count_since(self, seconds: int, now: Optional[float] = None) -> int:
        """Return how many messages arrived in the last ``seconds``."""
        floor = (now or time.time()) - seconds
        return sum(n for src in self.sources.values()
                   for minute, bucket in src["minutes"].items() if minute >= floor - 59
                   for n in bucket.values())
