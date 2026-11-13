"""Local store: query order and filters, damaged lines, retention, source counters."""
import gzip
import json
import os
import time
from datetime import datetime, timezone

from store import LocalStore, SourceTracker

NOW = 1_800_000_000 - 1_800_000_000 % 3600 + 1800  # half past an hour


def _path(root, ts, gz=False):
    """Return the hour file path rsyslog would use for ts."""
    d = datetime.fromtimestamp(ts, tz=timezone.utc)
    return os.path.join(root, d.strftime("%Y-%m-%d"), d.strftime("%H") + ".jsonl" + (".gz" if gz else ""))


def _write(root, msgs, gz=False, extra=""):
    """Write messages to their hour files the way the rsyslog template does."""
    by_file = {}
    for m in msgs:
        line = json.dumps({"ts": int(m["ts"]), "frac": "500000", "host": m.get("host", "sw1"),
                           "src_ip": m.get("src_ip", "10.0.0.1"), "program": m.get("program", "kernel"),
                           "sev": m.get("sev", 6), "fac": 1, "msg": m.get("msg", "hello")})
        by_file.setdefault(_path(root, m["ts"], gz), []).append(line)
    for path, lines in by_file.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = "\n".join(lines) + "\n" + extra
        if gz:
            with gzip.open(path, "wt") as fh:
                fh.write(data)
        else:
            with open(path, "w") as fh:
                fh.write(data)


def test_query_newest_first_across_hours_with_limit(tmp_path):
    """Newest hour is read first and the limit keeps the newest matches."""
    root = str(tmp_path)
    _write(root, [{"ts": NOW - 7200 + i} for i in range(5)], gz=True)
    _write(root, [{"ts": NOW - 10 + i} for i in range(5)])
    res = LocalStore(root).query({"start": NOW - 9000, "end": NOW + 10, "limit": 7})
    ts = [int(m["ts"]) for m in res["messages"]]
    assert ts == [NOW - 6, NOW - 7, NOW - 8, NOW - 9, NOW - 10, NOW - 7196, NOW - 7197]
    assert res["truncated"] is True
    assert res["messages"][0]["ts"] == NOW - 6 + 0.5


def test_query_filters_and_damaged_lines(tmp_path):
    """Host, severity, text and after_ts filters; a broken line is skipped."""
    root = str(tmp_path)
    _write(root, [{"ts": NOW - 30, "host": "core-sw", "sev": 3, "msg": "Link DOWN on 1/1/1"},
                  {"ts": NOW - 20, "host": "core-sw", "sev": 6, "msg": "link down noise"},
                  {"ts": NOW - 10, "host": "fw1", "sev": 2, "msg": "link down"}],
           extra='{"ts": 17, "host": "cut')
    store = LocalStore(root)
    base = {"start": NOW - 100, "end": NOW}
    got = store.query({**base, "host": "CORE", "severity_max": 4, "text": "link down"})["messages"]
    assert [m["msg"] for m in got] == ["Link DOWN on 1/1/1"]
    assert len(store.query({**base, "after_ts": NOW - 20.5})["messages"]) == 2
    # The source IP also matches the host filter.
    assert len(store.query({**base, "host": "10.0.0.1"})["messages"]) == 3



def test_query_text_with_quotes_matches(tmp_path):
    """Text that is escaped in the JSON line (quotes) still matches the message."""
    root = str(tmp_path)
    _write(root, [{"ts": NOW - 5, "msg": 'login "bob" denied'}])
    got = LocalStore(root).query({"start": NOW - 100, "end": NOW, "text": '"bob"'})["messages"]
    assert [m["msg"] for m in got] == ['login "bob" denied']


def test_housekeep_gzips_deletes_old_and_keeps_current(tmp_path):
    """Closed hours are compressed, hours past retention deleted, the current hour kept."""
    root = str(tmp_path)
    _write(root, [{"ts": NOW - 30 * 3600}, {"ts": NOW - 2 * 3600}, {"ts": NOW - 60}])
    store = LocalStore(root)
    res = store.housekeep(retention_hours=24, max_mb=1000, min_free_mb=0, now=NOW)
    files = store.hour_files()
    assert res["deleted"] == 1 and res["gzipped"] >= 1
    assert [f["gz"] for f in files] == [True, False]
    assert store.query({"start": 0, "end": NOW})["messages"][-1]["ts"] == NOW - 2 * 3600 + 0.5


def test_gzip_never_leaves_an_hour_stored_twice(tmp_path, monkeypatch):
    """If the original can't be removed after compressing, the copy is dropped,
    so the hour's messages are returned once, not twice."""
    import store as store_mod
    root = str(tmp_path)
    _write(root, [{"ts": NOW - 2 * 3600}, {"ts": NOW - 60}])
    real_remove = os.remove

    def stuck_remove(path):
        """Refuse to remove the plain hour file, as a failing disk would."""
        if path.endswith(".jsonl"):
            raise OSError("Device or resource busy")
        real_remove(path)
    monkeypatch.setattr(store_mod.os, "remove", stuck_remove)
    store = LocalStore(root)
    store.housekeep(retention_hours=24, max_mb=1000, min_free_mb=0, now=NOW)
    monkeypatch.setattr(store_mod.os, "remove", real_remove)
    assert len(store.query({"start": 0, "end": NOW})["messages"]) == 2


def test_housekeep_size_cap_deletes_oldest_first(tmp_path):
    """Over the size cap, the oldest hour goes even inside retention."""
    root = str(tmp_path)
    # Random text, so compression can't shrink it under the cap.
    _write(root, [{"ts": NOW - 3 * 3600, "msg": os.urandom(700_000).hex()},
                  {"ts": NOW - 2 * 3600, "msg": os.urandom(700_000).hex()}, {"ts": NOW - 60}])
    store = LocalStore(root)
    res = store.housekeep(retention_hours=24, max_mb=1, min_free_mb=0, now=NOW)
    assert res["size_cap_hit"] is True
    assert [f["hour"] for f in store.hour_files()] == [NOW - 2 * 3600 - 1800, NOW - 1800]


def test_unknown_free_space_deletes_nothing(tmp_path, monkeypatch):
    """A failed free-space read is "unknown", not "disk full": no closed hour
    inside retention and the size cap is deleted for it."""
    import store as store_mod
    root = str(tmp_path)
    _write(root, [{"ts": NOW - 3 * 3600}, {"ts": NOW - 2 * 3600}, {"ts": NOW - 60}])

    def broken(path):
        """The filesystem can't be queried."""
        raise OSError("stale file handle")
    monkeypatch.setattr(store_mod.shutil, "disk_usage", broken)
    store = LocalStore(root)
    assert store.disk_free_mb() is None
    res = store.housekeep(retention_hours=24, max_mb=1000, min_free_mb=1024, now=NOW)
    assert res["deleted"] == 0 and res["low_disk_hit"] is False
    assert len(store.hour_files()) == 3


def test_source_tracker_reads_only_new_complete_lines(tmp_path):
    """Counters grow with appended lines; a half-written line waits for its newline."""
    root = str(tmp_path)
    now = time.time()
    _write(root, [{"ts": now - 5, "host": "ap1", "sev": 4}])
    tracker = SourceTracker(LocalStore(root))
    assert tracker.refresh(now) == 1
    path = _path(root, now - 5)
    with open(path, "a") as fh:
        fh.write(json.dumps({"ts": int(now - 1), "frac": "0", "host": "ap1", "src_ip": "10.0.0.1",
                             "program": "x", "sev": 4, "fac": 1, "msg": "m"}))
    assert tracker.refresh(now) == 0
    with open(path, "a") as fh:
        fh.write("\n")
    assert tracker.refresh(now) == 1
    row = tracker.listing(3600, now)[0]
    assert row["host"] == "ap1" and row["count"] == 2 and row["by_severity"] == {"4": 2}
    assert tracker.count_since(300, now) == 2
