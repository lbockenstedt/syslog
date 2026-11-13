"""Spoke: query routing local/archive/local-partial, config rollback, masking, diag secrecy."""
import asyncio
import json
import os

import archives
import syslog_spoke
from archives import ArchiveError
from syslog_spoke import SyslogSpoke
from test_store import NOW, _write

ARCHIVE = {"backend": "graylog", "host": "10.9.9.9", "input_port": 1514, "user": "lm-reader",
           "password": "s3cret-reader", "api_url": "https://10.9.9.9:9000/api", "ca_pem": "PEM",
           "tls_name": "syslog-graylog-acme"}


def _spoke(tmp_path, owner=None, **cfg):
    """Build a spoke over a temp store and etc dir. ``owner`` records the store's
    tenant first, as the installer does (default: the config's tenant, if the
    store has no owner yet); pass "" to leave the store unowned."""
    root = tmp_path / "store"
    marker = root / ".tenant"
    owner = cfg.get("tenant", "") if owner is None else owner
    if owner and not marker.exists():
        os.makedirs(str(root), exist_ok=True)
        marker.write_text(owner)
    return SyslogSpoke("sp1", dict(cfg), store_root=str(root), etc_dir=str(tmp_path / "etc"))


def _cmd(spoke, cmd, data):
    """Run one command synchronously."""
    return asyncio.run(spoke.handle_command(cmd, data))


class _FakeArchive:
    """Archive plugin stand-in recording searches."""
    fail = None
    calls = []

    def __init__(self, archive):
        """Keep nothing."""

    def search(self, flt):
        """Return one archived message or raise."""
        _FakeArchive.calls.append(flt)
        if _FakeArchive.fail:
            raise ArchiveError(_FakeArchive.fail)
        return {"messages": [{"ts": 1.0, "host": "old", "src_ip": "", "program": "", "severity": 6,
                              "facility": 1, "msg": "archived"}], "truncated": False}

    def status(self):
        """Always reachable."""
        return {"reachable": True, "version": "7.0.0", "error": ""}


def test_query_routing(tmp_path, monkeypatch):
    """Inside local data -> local; older -> archive; archive failure or no plugin -> local-partial."""
    monkeypatch.setitem(archives.BACKENDS, "graylog", _FakeArchive)
    _FakeArchive.fail, _FakeArchive.calls = None, []
    _write(str(tmp_path / "store"), [{"ts": NOW - 100}, {"ts": NOW - 50}])
    spoke = _spoke(tmp_path, archive=ARCHIVE, tenant='ac"me')
    oldest = NOW - 100 + 0.5
    # Range starts inside local data.
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": oldest, "end": NOW})
    assert res["source"] == "local" and len(res["messages"]) == 2 and res["oldest_local_ts"] == oldest
    # Older than local data: local rows first, the archive fills the rest of
    # the limit for the time before local data, filtered to this tenant.
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW, "limit": 10})
    assert res["source"] == "archive"
    assert [m["msg"] for m in res["messages"]] == ["hello", "hello", "archived"]
    call = _FakeArchive.calls[-1]
    assert call["limit"] == 8 and call["end"] < oldest and call["tenant"] == "acme"
    # Local rows fill the limit: the archive is not asked.
    n = len(_FakeArchive.calls)
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW, "limit": 2})
    assert res["source"] == "local" and len(res["messages"]) == 2 and len(_FakeArchive.calls) == n
    # use_archive false (hub, all but one collector): local only.
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW, "use_archive": False})
    assert res["source"] == "local" and len(_FakeArchive.calls) == n
    # Hub cut-off (newest oldest across collectors): local only from it on,
    # the archive only before it, so collectors neither overlap nor leave gaps.
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW, "archive_before": NOW - 60})
    assert [m["msg"] for m in res["messages"]] == ["hello", "archived"]
    assert _FakeArchive.calls[-1]["end"] < NOW - 60
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW, "archive_before": NOW - 60,
                                       "use_archive": False})
    assert res["source"] == "local" and len(res["messages"]) == 1
    # Live tail newer than the cut-off never asks the archive.
    n = len(_FakeArchive.calls)
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW, "after_ts": NOW - 75})
    assert res["source"] == "local" and len(_FakeArchive.calls) == n
    # Archive failure falls back to local with the error.
    _FakeArchive.fail = "Graylog /search/messages: HTTP 500"
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW})
    assert res["source"] == "local-partial" and "HTTP 500" in res["error"] and len(res["messages"]) == 2
    # A backend with no query plugin is forward-only.
    spoke.config["archive"] = {**ARCHIVE, "backend": "syslog"}
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW})
    assert res["source"] == "local-partial" and "no query support" in res["error"]
    # No archive at all: local, no error.
    spoke.config["archive"] = None
    assert _cmd(spoke, "SYSLOG_QUERY", {"start": 0, "end": NOW})["source"] == "local"


def test_config_rollback_when_rsyslog_rejects(tmp_path, monkeypatch):
    """A config rsyslogd -N1 rejects is undone on disk and in memory."""
    calls = []

    def fake_run(cmd, timeout=20):
        calls.append(cmd)
        return {"rc": 1 if cmd[:2] == ["rsyslogd", "-N1"] else 0, "out": "error on line 3"}
    monkeypatch.setattr(syslog_spoke, "_run", fake_run)
    spoke = _spoke(tmp_path, tenant="acme")
    etc = tmp_path / "etc"
    os.makedirs(etc)
    (etc / "drop.rsyslog").write_text("OLD\n")
    res = _cmd(spoke, "SYSLOG_CONFIG", {"drop_rules": [{"field": "host", "op": "equals", "value": "x"}]})
    assert res["status"] == "ERROR" and "rejected" in res["message"]
    assert (etc / "drop.rsyslog").read_text() == "OLD\n"
    assert not (etc / "archive.rsyslog").exists()
    assert "drop_rules" not in spoke.config
    assert ["systemctl", "restart", "rsyslog"] not in calls


def test_config_restarts_only_on_change(tmp_path, monkeypatch):
    """The first apply restarts rsyslog; the same settings again do not."""
    calls = []
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: calls.append(cmd) or {"rc": 0, "out": ""})
    spoke = _spoke(tmp_path, tenant="acme")
    rules = [{"field": "severity", "op": "gte", "value": 7}]
    assert _cmd(spoke, "SYSLOG_CONFIG", {"drop_rules": rules, "archive": ARCHIVE})["restarted"] is True
    assert (tmp_path / "etc" / "archive-ca.pem").read_text() == "PEM"
    assert _cmd(spoke, "UPDATE_CONFIG", {"drop_rules": rules})["restarted"] is False
    assert calls.count(["systemctl", "restart", "rsyslog"]) == 1
    # A bad rule is refused before anything is written.
    res = _cmd(spoke, "SYSLOG_CONFIG", {"drop_rules": [{"field": "msg", "op": "regex", "value": "("}]})
    assert res["status"] == "ERROR" and spoke.config["drop_rules"] == rules


def test_mask_and_diag_never_carry_secrets(tmp_path, monkeypatch):
    """Passwords are masked in logs (nested too) and absent from SYSLOG_DIAG."""
    masked = SyslogSpoke._mask({"archive": ARCHIVE, "list": [{"admin_password": "x"}]})
    assert masked["archive"]["password"] == "********" and masked["list"][0]["admin_password"] == "********"
    assert masked["archive"]["ca_pem"] == "<pem 3 bytes>"
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    monkeypatch.setitem(archives.BACKENDS, "graylog", _FakeArchive)
    spoke = _spoke(tmp_path, archive={**ARCHIVE, "host": "127.0.0.1", "input_port": 1})
    diag = _cmd(spoke, "SYSLOG_DIAG", {})
    assert diag["status"] == "SUCCESS" and "error" in diag["archive_probe"]["tcp_connect"]
    assert "s3cret-reader" not in json.dumps(diag)


def test_drop_preview_counts_first_matching_rule(tmp_path):
    """Each message counts once, against the first rule that drops it."""
    import time
    now = time.time()
    _write(str(tmp_path / "store"), [{"ts": now - 10, "sev": 7, "msg": "debug cron"},
                                     {"ts": now - 5, "sev": 3, "msg": "cron failed"},
                                     {"ts": now - 1, "sev": 6, "msg": "ok"}])
    res = _cmd(_spoke(tmp_path), "SYSLOG_DROP_PREVIEW", {"drop_rules": [
        {"field": "severity", "op": "gte", "value": 7},
        {"field": "msg", "op": "contains", "value": "cron"}]})
    assert (res["scanned"], res["dropped"], res["per_rule"]) == (3, 2, [1, 1])


def test_restart_failure_restores_old_files(tmp_path, monkeypatch):
    """A failed rsyslog restart puts the previous include files back and restarts again."""
    calls = []

    def fake_run(cmd, timeout=20):
        """The first restart fails; everything else succeeds."""
        calls.append(cmd)
        restarts = [c for c in calls if c[:2] == ["systemctl", "restart"]]
        return {"rc": 1 if len(restarts) == 1 and cmd[:2] == ["systemctl", "restart"] else 0, "out": "boom"}
    monkeypatch.setattr(syslog_spoke, "_run", fake_run)
    spoke = _spoke(tmp_path)
    drop = spoke._paths()["drop"]
    os.makedirs(spoke.etc_dir)
    with open(drop, "w") as fh:
        fh.write("OLD")
    res = _cmd(spoke, "SYSLOG_CONFIG", {"drop_rules": [{"field": "program", "op": "equals", "value": "x"}]})
    assert res["status"] == "ERROR" and "restart failed" in res["message"]
    assert open(drop).read() == "OLD"
    assert sum(1 for c in calls if c[:2] == ["systemctl", "restart"]) == 2
    assert spoke.config.get("drop_rules") is None


def test_applied_config_survives_restart_without_secrets(tmp_path, monkeypatch):
    """Settings are saved after a good apply and reloaded by a new spoke with no config;
    the archive password is never written to disk."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    rules = [{"field": "program", "op": "equals", "value": "noisy"}]
    res = _cmd(_spoke(tmp_path), "SYSLOG_CONFIG", {"drop_rules": rules, "archive": ARCHIVE, "tenant": "acme"})
    assert res["status"] == "SUCCESS"
    state_file = os.path.join(str(tmp_path / "etc"), "config.json")
    assert "s3cret-reader" not in open(state_file).read()
    assert oct(os.stat(state_file).st_mode & 0o777) == "0o600"
    # A restart: the agent loads the role with no config.
    again = _spoke(tmp_path)
    assert again.config["tenant"] == "acme" and again.config["archive"]["host"] == "10.9.9.9"
    assert again.config["drop_rules"][0]["value"] == "noisy"
    before = open(again._paths()["archive"]).read()
    again.startup_apply()
    assert open(again._paths()["archive"]).read() == before


def test_config_not_saved_is_rolled_back(tmp_path, monkeypatch):
    """A push that reaches rsyslog but can't be saved is undone as a whole:
    old config, old rsyslog files, old tenant and the old tenant's store."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, owner="acme", tenant="acme")
    spoke.startup_apply()
    drop_before = open(spoke._paths()["drop"]).read()

    def disk_full():
        """Stand in for a save that hits a full disk."""
        raise OSError("No space left on device")
    monkeypatch.setattr(spoke, "_save_state", disk_full)
    rule = {"field": "host", "op": "equals", "value": "noisy", "enabled": True}
    res = _cmd(spoke, "SYSLOG_CONFIG", {"drop_rules": [rule], "tenant": "other"})
    assert res["status"] == "ERROR" and res["persisted"] is False
    assert "not saved" in res["message"] and "previous settings restored" in res["message"]
    assert spoke._tenant == "acme" and not spoke.config.get("drop_rules")
    assert open(spoke._paths()["drop"]).read() == drop_before
    assert open(str(tmp_path / "store" / ".tenant")).read() == "acme"
    # The hub now counts the collector as "other": acme's messages are not served.
    query = {"start": NOW - 3600, "end": NOW}
    refused = _cmd(spoke, "SYSLOG_QUERY", query)
    assert refused["status"] == "ERROR" and "moving to tenant other" in refused["message"]
    monkeypatch.undo()
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "acme"})["status"] == "SUCCESS"
    assert len(_cmd(spoke, "SYSLOG_QUERY", query)["messages"]) == 1
    ok = _cmd(_spoke(tmp_path, owner="acme"), "SYSLOG_CONFIG", {"retention_hours": 12, "tenant": "acme"})
    assert ok["status"] == "SUCCESS" and ok["persisted"] is True


def test_background_loops_start_off_the_caller_and_stop(tmp_path, monkeypatch):
    """start returns at once (the apply runs in the thread); stop ends the thread
    so a role reload does not leave a second housekeeping loop running."""
    import threading
    started = threading.Event()
    release = threading.Event()

    def slow_apply():
        """Stand in for an apply that restarts rsyslog."""
        started.set()
        release.wait(5)
        return {"status": "SUCCESS"}
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": "active"})
    spoke = _spoke(tmp_path)
    monkeypatch.setattr(spoke, "startup_apply", slow_apply)
    spoke.start_background_loops()
    assert started.wait(2) and spoke._thread.is_alive()
    release.set()
    thread = spoke._thread
    spoke.stop_background_loops()
    thread.join(2)
    assert not thread.is_alive() and spoke._loops_started is False
    # A restart gets its own stop event; stopping again ends the new thread.
    spoke.start_background_loops()
    second = spoke._thread
    spoke.stop_background_loops()
    second.join(2)
    assert not second.is_alive()


def test_watchdog_restarts_rsyslog_when_not_active(tmp_path, monkeypatch):
    """The retention pass restarts rsyslog when systemd says it is not active."""
    calls = []

    def fake_run(cmd, timeout=20):
        """rsyslog reports failed."""
        calls.append(cmd)
        return {"rc": 0, "out": "failed" if cmd[1] == "is-active" else ""}
    monkeypatch.setattr(syslog_spoke, "_run", fake_run)
    _spoke(tmp_path).housekeeping_tick(run_retention=True)
    assert ["systemctl", "restart", "rsyslog"] in calls


def test_archive_query_refused_without_tenant(tmp_path, monkeypatch):
    """A collector with no tenant never searches the shared archive."""
    monkeypatch.setitem(archives.BACKENDS, "graylog", _FakeArchive)
    _FakeArchive.fail, _FakeArchive.calls = None, []
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, archive=ARCHIVE)
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400 * 3, "end": NOW})
    assert res["source"] == "local-partial" and "no tenant" in res["error"]
    assert _FakeArchive.calls == [] and len(res["messages"]) == 1


def test_config_restored_when_render_raises(tmp_path, monkeypatch):
    """A push whose rendering raises leaves the previous in-memory config."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    spoke = _spoke(tmp_path)
    before = dict(spoke.config)
    res = _cmd(spoke, "SYSLOG_CONFIG", {"archive": {**ARCHIVE, "input_port": "bad"}})
    assert res["status"] == "ERROR" and spoke.config == before


def test_moving_collector_to_another_tenant_purges_local_messages(tmp_path, monkeypatch):
    """The new tenant never reads the old tenant's local messages."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    query = {"start": NOW - 3600, "end": NOW}
    # Messages stored while the collector had no tenant go to nobody.
    spoke = _spoke(tmp_path, owner="", tenant="acme")
    spoke.startup_apply()
    assert _cmd(spoke, "SYSLOG_QUERY", query)["messages"] == []
    # The owner (as the installer records it) keeps its own messages.
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    assert len(_cmd(spoke, "SYSLOG_QUERY", query)["messages"]) == 1
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex"})["status"] == "SUCCESS"
    assert _cmd(spoke, "SYSLOG_QUERY", query)["messages"] == []
    # A restarted spoke given a new tenant at start-up refuses reads until the
    # startup apply moves it, then the old tenant's messages are gone.
    _write(str(tmp_path / "store"), [{"ts": NOW - 40}])
    again = _spoke(tmp_path, tenant="initech")
    assert _cmd(again, "SYSLOG_QUERY", query)["status"] == "ERROR"
    assert again.startup_apply()["status"] == "SUCCESS"
    assert _cmd(again, "SYSLOG_QUERY", query)["messages"] == []
    # The heartbeat status is gated the same way: no counts from the previous tenant.
    _write(str(tmp_path / "store"), [{"ts": NOW - 30}])
    moved = _spoke(tmp_path, tenant="umbrella")
    assert asyncio.run(moved.get_status())["status"] == "ERROR"
    moved.startup_apply()
    assert asyncio.run(moved.get_status())["collector"]["oldest_ts"] is None


def test_store_kept_until_the_hub_pushes_the_tenant(tmp_path, monkeypatch):
    """A fresh install (installer recorded the tenant, no settings pushed yet)
    keeps collecting: an empty spoke tenant never empties the store."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": "active"})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    fresh = _spoke(tmp_path, owner="acme")
    fresh.housekeeping_tick(run_retention=True)
    asyncio.run(fresh.get_status())
    assert open(str(tmp_path / "store" / ".tenant")).read() == "acme"
    query = {"start": NOW - 3600, "end": NOW}
    assert len(_cmd(fresh, "SYSLOG_QUERY", query)["messages"]) == 1
    assert _cmd(fresh, "SYSLOG_CONFIG", {"tenant": "acme"})["status"] == "SUCCESS"
    assert len(_cmd(fresh, "SYSLOG_QUERY", query)["messages"]) == 1


def test_plain_text_archive_is_refused(tmp_path, monkeypatch):
    """A push asking for a plain-text forward changes nothing."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    spoke = _spoke(tmp_path, tenant="acme")
    res = _cmd(spoke, "SYSLOG_CONFIG", {"archive": {**ARCHIVE, "tls": False}})
    assert res["status"] == "ERROR" and "TLS" in res["message"]
    assert not spoke.config.get("archive")


def test_failed_tenant_move_is_rolled_back(tmp_path, monkeypatch):
    """A tenant move whose store purge fails changes nothing: old tenant, old
    rsyslog files, old saved settings, and the old tenant can still read."""
    import store as store_mod
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, tenant="acme")
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "acme"})["status"] == "SUCCESS"
    archive_before = open(spoke._paths()["archive"]).read()
    state_before = open(spoke._paths()["state"]).read()

    def purge_fails(self, tenant):
        """Stand in for a purge that hits a read-only disk."""
        raise OSError("Read-only file system")
    monkeypatch.setattr(store_mod.LocalStore, "claim", purge_fails)
    res = _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex", "archive": ARCHIVE})
    assert res["status"] == "ERROR" and res["persisted"] is False
    assert "globex" in res["message"] and "previous settings restored" in res["message"]
    assert spoke._tenant == "acme" and spoke.config.get("tenant") == "acme"
    assert open(spoke._paths()["archive"]).read() == archive_before
    assert open(spoke._paths()["state"]).read() == state_before
    # The hub counts the collector as globex now: acme's messages are refused.
    assert _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 3600, "end": NOW})["status"] == "ERROR"
    monkeypatch.undo()
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "acme"})["status"] == "SUCCESS"
    assert len(_cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 3600, "end": NOW})["messages"]) == 1


def test_read_overlapping_a_tenant_move_is_discarded(tmp_path, monkeypatch):
    """A query that claimed the store for acme, then saw the collector move to
    globex before it finished, returns an error, never rows read after the move."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, tenant="acme")
    real_query = spoke.store.query

    def move_mid_read(*a, **kw):
        """Move the collector while this read is in progress."""
        assert spoke._merge_and_apply({"tenant": "globex"})["status"] != "ERROR"
        return real_query(*a, **kw)
    monkeypatch.setattr(spoke.store, "query", move_mid_read)
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 3600, "end": NOW})
    assert res["status"] == "ERROR" and "moved to another tenant" in res["message"]
    assert "messages" not in res and spoke._tenant == "globex"


def test_gzip_cannot_bring_back_a_purged_hour(tmp_path, monkeypatch):
    """A tenant move that lands while housekeeping compresses an old hour waits
    for it, so the old tenant's hour is never put back (as .gz) after the purge."""
    import glob
    import threading
    import store as store_mod
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    root = str(tmp_path / "store")
    _write(root, [{"ts": NOW - 7200, "msg": "acme secret"}])
    spoke = _spoke(tmp_path, tenant="acme")
    real_copy = store_mod.shutil.copyfileobj
    mover = threading.Thread(target=spoke._merge_and_apply, args=({"tenant": "globex"},))

    def copy_while_moving(src, dst, *a):
        """Start the move mid-copy and give it time to run if nothing stops it."""
        mover.start()
        mover.join(timeout=0.5)
        return real_copy(src, dst, *a)
    monkeypatch.setattr(store_mod.shutil, "copyfileobj", copy_while_moving)
    spoke.housekeeping_tick(run_retention=True, now=NOW)
    mover.join(timeout=5)
    assert spoke._tenant == "globex"
    for path in glob.glob(os.path.join(root, "*", "*.jsonl*")):
        assert os.path.getsize(path) == 0 or not path.endswith(".gz"), path
    query = {"start": NOW - 3 * 3600, "end": NOW}
    monkeypatch.setattr(store_mod.shutil, "copyfileobj", real_copy)
    assert _cmd(spoke, "SYSLOG_QUERY", query)["messages"] == []


def test_out_of_range_retention_and_size_are_refused(tmp_path, monkeypatch):
    """Zero or negative retention/size would delete every closed hour: refuse
    them on push, and ignore them if they are already in the saved settings."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    spoke = _spoke(tmp_path, tenant="acme")
    for bad in ({"retention_hours": -1}, {"retention_hours": 0}, {"max_mb": -5},
                {"max_mb": "lots"}, {"retention_hours": 10_000}):
        res = _cmd(spoke, "SYSLOG_CONFIG", bad)
        assert res["status"] == "ERROR" and "must be a whole number" in res["message"]
    assert spoke._setting("retention_hours") == 24 and spoke._setting("max_mb") == 2048
    assert _spoke(tmp_path, tenant="acme", retention_hours=-1)._setting("retention_hours") == 24
    assert _cmd(spoke, "SYSLOG_CONFIG", {"retention_hours": 12})["status"] == "SUCCESS"
    assert spoke._setting("retention_hours") == 12


def test_failed_purge_keeps_old_owner_and_refuses_reads(tmp_path, monkeypatch):
    """If an old tenant's hour file can't be emptied, the store keeps its old owner,
    reads are refused, and the next claim retries the purge."""
    import builtins
    import store as store_mod
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    query = {"start": NOW - 3600, "end": NOW}
    assert len(_cmd(_spoke(tmp_path, tenant="acme"), "SYSLOG_QUERY", query)["messages"]) == 1

    def stuck_open(path, mode="r", *a, **kw):
        """Fail to truncate hour files, as a read-only or failing disk would."""
        if "w" in mode and str(path).endswith(".jsonl"):
            raise OSError("Read-only file system")
        return builtins.open(path, mode, *a, **kw)
    monkeypatch.setattr(store_mod, "open", stuck_open, raising=False)
    moved = _spoke(tmp_path, tenant="globex")
    assert moved.startup_apply()["status"] == "ERROR"
    res = _cmd(moved, "SYSLOG_QUERY", query)
    assert res["status"] == "ERROR" and "globex" in res["message"]
    assert open(str(tmp_path / "store" / ".tenant")).read() == "acme"
    # Once the disk recovers, the next housekeeping pass retries the move.
    monkeypatch.undo()
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": "active"})
    moved.housekeeping_tick(run_retention=True)
    res = _cmd(moved, "SYSLOG_QUERY", query)
    assert res["status"] == "SUCCESS" and res["messages"] == []


def test_locks_are_shared_across_role_reloads(tmp_path):
    """An old instance still finishing a pass blocks the reloaded one."""
    old, new = _spoke(tmp_path), _spoke(tmp_path)
    assert old._apply_lock is new._apply_lock and old._housekeep_lock is new._housekeep_lock


def test_failed_apply_after_a_move_gives_the_store_back(tmp_path, monkeypatch):
    """rsyslog switches last: when it rejects a tenant move, the store, the saved
    settings and the tenant all go back to the old tenant, and reads still work."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, archive=ARCHIVE, tenant="acme")
    query = {"start": NOW - 3600, "end": NOW}
    assert len(_cmd(spoke, "SYSLOG_QUERY", query)["messages"]) == 1
    archive_file = spoke._paths()["archive"]
    before = open(archive_file).read() if os.path.exists(archive_file) else None
    seen = []

    def rejecting(cmd, timeout=20):
        """rsyslog's config check rejects the config; record the store owner then."""
        if cmd[0] != "rsyslogd":
            return {"rc": 0, "out": ""}
        seen.append(spoke.store.owner())
        return {"rc": 1, "out": "bad"}
    monkeypatch.setattr(syslog_spoke, "_run", rejecting)
    res = _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex"})
    assert res["status"] == "ERROR" and "rsyslog" in res["message"]
    # The store was already moved when rsyslog was switched, and is given back.
    assert seen[0] == "globex" and spoke.store.owner() == "acme" and spoke._tenant == "acme"
    assert spoke.config["tenant"] == "acme"
    saved = json.load(open(spoke._paths()["state"]))
    assert saved["tenant"] == "acme"
    if before is not None:
        assert open(archive_file).read() == before
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    # The hub counts the collector as globex: reads are refused until the move applies.
    assert _cmd(spoke, "SYSLOG_QUERY", query)["status"] == "ERROR"
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex"})["status"] == "SUCCESS"
    assert _cmd(spoke, "SYSLOG_QUERY", query)["messages"] == []


def test_failed_first_assignment_leaves_the_store_unowned(tmp_path, monkeypatch):
    """A first tenant whose rsyslog apply fails is not left as the store owner, so
    the retry purges the messages received while the collector had no tenant."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 1, "out": "bad"})
    spoke = _spoke(tmp_path)
    assert spoke.store.owner() == ""
    res = _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "acme", "drop_rules": [
        {"field": "msg", "op": "contains", "value": "x", "enabled": True}]})
    assert res["status"] == "ERROR" and spoke.store.owner() == "" and spoke._tenant == ""
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "acme"})["status"] == "SUCCESS"
    query = {"start": NOW - 3600, "end": NOW}
    assert _cmd(spoke, "SYSLOG_QUERY", query)["messages"] == []


def test_installer_tenant_tags_the_forward(tmp_path, monkeypatch):
    """With only the installer's tenant (no tenant pushed yet), forwarded messages
    carry that tenant, the same one archive searches filter on and status shows."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    spoke = _spoke(tmp_path, owner="acme")
    assert _cmd(spoke, "SYSLOG_CONFIG", {"archive": ARCHIVE})["status"] == "SUCCESS"
    assert 'set $.lm_tenant = "acme";' in open(spoke._paths()["archive"]).read()
    assert _cmd(spoke, "SYSLOG_STATUS", {})["collector"]["tenant"] == "acme"


def test_crashed_apply_rewrites_the_old_files(tmp_path, monkeypatch):
    """An exception mid-apply (files may be half new) rewrites them from the old config."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    spoke = _spoke(tmp_path, tenant="acme")
    assert _cmd(spoke, "SYSLOG_CONFIG", {"drop_rules": []})["status"] == "SUCCESS"
    drop = spoke._paths()["drop"]
    before = open(drop).read()
    calls = []

    def crashing(cmd, timeout=20):
        """The first rsyslog check crashes after the new files were written."""
        calls.append(cmd)
        if len(calls) == 1:
            raise RuntimeError("boom")
        return {"rc": 0, "out": ""}
    monkeypatch.setattr(syslog_spoke, "_run", crashing)
    res = _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex", "drop_rules": [
        {"field": "msg", "op": "contains", "value": "x", "enabled": True}]})
    assert res["status"] == "ERROR" and "boom" in res["message"]
    assert open(drop).read() == before and spoke.store.owner() == "acme"


def test_write_error_restores_files(tmp_path, monkeypatch):
    """A write that fails part-way leaves the previous include files."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    spoke = _spoke(tmp_path)
    assert _cmd(spoke, "SYSLOG_CONFIG", {"drop_rules": []})["status"] == "SUCCESS"
    drop = os.path.join(spoke.etc_dir, "drop.rsyslog")
    before = open(drop).read()
    real_open = open

    def flaky(path, mode="r", *a, **kw):
        if "w" in mode and str(path).endswith("archive.rsyslog"):
            raise OSError("disk full")
        return real_open(path, mode, *a, **kw)
    monkeypatch.setattr("builtins.open", flaky)
    res = _cmd(spoke, "SYSLOG_CONFIG", {"archive": ARCHIVE, "tenant": "acme", "drop_rules": [
        {"field": "msg", "op": "contains", "value": "x", "enabled": True}]})
    monkeypatch.setattr("builtins.open", real_open)
    assert res["status"] == "ERROR" and open(drop).read() == before
    # The real cause, plus the file that could not be put back (the disk is still
    # failing), not a crash on the never-written new CA file.
    assert res["message"].startswith("could not write archive.rsyslog: disk full; could not restore archive.rsyslog")
    assert not os.path.exists(spoke._paths()["ca"])


def test_cutoff_is_whole_milliseconds(tmp_path, monkeypatch):
    """Local starts at the cut-off rounded down to the ms; the archive (ms
    precision, inclusive) ends exactly 1 ms before it: no gap, no overlap."""
    from archives.graylog import _iso
    monkeypatch.setitem(archives.BACKENDS, "graylog", _FakeArchive)
    _FakeArchive.fail, _FakeArchive.calls = None, []
    _write(str(tmp_path / "store"), [{"ts": NOW - 50, "msg": "same ms as cut"}])
    spoke = _spoke(tmp_path, archive=ARCHIVE, tenant="acme")
    msg_ts = int(NOW - 50) + 0.5          # the store keeps microseconds
    cut = msg_ts + 0.0004                 # same millisecond, just after it
    res = _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 86400, "end": NOW, "archive_before": cut})
    # The archive holds that message at msg's whole ms, which it no longer
    # searches, so local must return it.
    assert "same ms as cut" in [m["msg"] for m in res["messages"]]
    assert _iso(_FakeArchive.calls[-1]["end"]) == _iso(msg_ts - 0.001)
    assert _iso(1794564000.123) == "2026-11-13T10:00:00.123Z"


def test_tenant_move_stops_rsyslog_around_the_purge(tmp_path, monkeypatch):
    """rsyslog is stopped before the old tenant's store is purged (so nothing it
    still queues lands after the purge) and started again, even when the move fails."""
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, tenant="acme", archive=ARCHIVE)
    calls = []

    def recording(cmd, timeout=20):
        """Record systemctl stop/start with the store owner at that moment."""
        if cmd[:2] == ["systemctl", "stop"] or cmd[:2] == ["systemctl", "start"]:
            calls.append((cmd[1], spoke.store.owner()))
        return {"rc": 0, "out": ""}
    monkeypatch.setattr(syslog_spoke, "_run", recording)
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex"})["status"] == "SUCCESS"
    assert calls[0] == ("stop", "acme") and calls[-1] == ("start", "globex")
    # A move rsyslog rejects still restarts collection, for the old tenant.
    calls.clear()

    def rejecting(cmd, timeout=20):
        """Reject the rsyslog config check; record stop/start otherwise."""
        if cmd[0] == "rsyslogd":
            return {"rc": 1, "out": "bad"}
        return recording(cmd, timeout)
    monkeypatch.setattr(syslog_spoke, "_run", rejecting)
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "initech"})["status"] == "ERROR"
    assert calls[0] == ("stop", "globex") and calls[-1] == ("start", "globex")


def test_push_before_startup_apply_carries_the_role_load_tenant(tmp_path, monkeypatch):
    """A push that arrives before the startup apply also applies the tenant the
    role was loaded with, so it is moved as one transaction, not left pending."""
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, owner="acme", tenant="globex")
    assert spoke._tenant == "acme"
    assert _cmd(spoke, "SYSLOG_CONFIG", {"retention_hours": 12})["status"] == "SUCCESS"
    assert spoke._tenant == "globex" and spoke.store.owner() == "globex"
    assert _cmd(spoke, "SYSLOG_QUERY", {"start": NOW - 3600, "end": NOW})["messages"] == []


def test_diag_mid_move_withholds_the_old_tenants_details(tmp_path, monkeypatch):
    """After a failed move the hub counts the collector as the new tenant, so
    SYSLOG_DIAG shows why the move is stuck, not the old tenant's archive,
    files, store or logs; once the move applies the full view returns."""
    import store as store_mod
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    _write(str(tmp_path / "store"), [{"ts": NOW - 50}])
    spoke = _spoke(tmp_path, tenant="acme", archive=ARCHIVE)

    def purge_fails(self, tenant):
        """Stand in for a purge that hits a read-only disk."""
        raise OSError("Read-only file system")
    monkeypatch.setattr(store_mod.LocalStore, "claim", purge_fails)
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex"})["status"] == "ERROR"
    diag = _cmd(spoke, "SYSLOG_DIAG", {})
    assert diag["moving"]["to"] == "globex" and "Read-only" in diag["moving"]["error"]
    assert not {"files", "store", "settings", "archive_probe", "installer_log",
                "recent_errors"} & set(diag)
    monkeypatch.undo()
    monkeypatch.setattr(syslog_spoke, "_run", lambda cmd, timeout=20: {"rc": 0, "out": ""})
    assert _cmd(spoke, "SYSLOG_CONFIG", {"tenant": "globex"})["status"] == "SUCCESS"
    full = _cmd(spoke, "SYSLOG_DIAG", {})
    assert "moving" not in full and full["settings"]["tenant"] == "globex"
