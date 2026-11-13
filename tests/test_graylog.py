"""Graylog plugin: query building, request shape, response parsing, failures."""
import json

import httpx
import pytest

from archives import ArchiveError, get_backend
from archives.graylog import GraylogArchive, build_query

ARCHIVE = {"backend": "graylog", "api_url": "https://10.9.9.9:9000/api/", "user": "lm-reader",
           "password": "pw", "tls_name": "syslog-graylog-acme"}


def _with(monkeypatch, handler):
    """Route the plugin's HTTP calls to handler."""
    monkeypatch.setattr(GraylogArchive, "_client", lambda self: httpx.Client(
        transport=httpx.MockTransport(handler), auth=self.auth, headers={"X-Requested-By": "lm"}))


def test_build_query_escapes_user_terms():
    """Lucene specials in user input are escaped; severity becomes a range."""
    q = build_query({"host": "sw:1", "program": "a*b", "text": 'say "hi"', "severity_max": 3})
    assert q == ('(source:*sw\\:1* OR src_ip:*sw\\:1*) AND application_name:/.*[aA]\\*[bB].*/ AND '
                 '(message:"say\\ \\"hi\\"" OR source:*say\\ \\"hi\\"* OR '
                 'application_name:/.*[sS][aA][yY]\\ \\"[hH][iI]\\".*/) AND level:[0 TO 3]')
    # One word is a substring match like the local store ("fail" finds "failed").
    # Case is ignored like the local store: message and source are indexed
    # lower-cased; application_name (stored as sent) gets a case-blind regex,
    # so "lldp" also finds a program logged as "Lldp".
    assert build_query({"text": "Fail"}) == ("(message:*fail* OR source:*fail* OR "
                                             "application_name:/.*[fF][aA][iI][lL].*/)")
    assert build_query({"program": "lldp"}) == "application_name:/.*[lL][lL][dD][pP].*/"
    # A slash can't end the regex early.
    assert build_query({"program": "a/b"}) == "application_name:/.*[aA]\\/[bB].*/"
    assert build_query({"host": "SW1-CORE"}) == "(source:*sw1\\-core* OR src_ip:*SW1\\-CORE*)"
    assert build_query({}) == "*"
    # The tenant filter keeps other tenants' forwarded messages out.
    assert build_query({"tenant": "acme"}) == 'lm_tenant:"acme"'


def test_search_request_and_parsing(monkeypatch):
    """POST /search/messages with an absolute range; rows map to the LM message shape."""
    seen = {}

    def handler(request):
        seen["url"], seen["body"] = str(request.url), json.loads(request.content)
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, json={
            "schema": [{"field": f} for f in ("timestamp", "source", "src_ip", "application_name",
                                              "level", "facility_num", "message")],
            "datarows": [["2026-11-13T10:00:01.250Z", "sw1", "10.0.0.1", "lldp", 4, 3, "neighbor lost"],
                         ["2026-11-13T10:00:00.000Z", "sw1", "10.0.0.1", "lldp", 6, 3, "older"]]})
    _with(monkeypatch, handler)
    res = get_backend(ARCHIVE).search({"start": 0, "end": 1_800_000_000, "limit": 2, "after_ts": 1_794_564_000.5, "tenant": "acme"})
    assert seen["url"] == "https://10.9.9.9:9000/api/search/messages"
    assert seen["sni"] == "syslog-graylog-acme"
    assert seen["body"]["timerange"]["type"] == "absolute" and seen["body"]["size"] == 2
    assert seen["body"]["sort_order"] == "desc"
    assert res["messages"] == [{"ts": 1_794_564_001.25, "host": "sw1", "src_ip": "10.0.0.1", "program": "lldp",
                                "severity": 4, "facility": 3, "msg": "neighbor lost"}]
    assert res["truncated"] is True


@pytest.mark.parametrize("resp,text", [(httpx.Response(401), "login refused"),
                                       (httpx.Response(500, text="boom"), "HTTP 500: boom"),
                                       (httpx.Response(200, text="<html>"), "not JSON")])
def test_failures_raise_archive_error(monkeypatch, resp, text):
    """Bad status or a non-JSON body is an ArchiveError, and status() reports it."""
    _with(monkeypatch, lambda request: resp)
    with pytest.raises(ArchiveError, match=text):
        GraylogArchive(ARCHIVE).search({"start": 0, "end": 1, "tenant": "acme"})
    st = GraylogArchive(ARCHIVE).status()
    assert st["reachable"] is False and text in st["error"]


def test_bad_ca_is_an_archive_error_not_a_crash():
    """A broken CA PEM makes status() report the error instead of raising."""
    res = GraylogArchive({"api_url": "https://gl:9000/api", "password": "pw", "ca_pem": "not a pem"}).status()
    assert res["reachable"] is False and "CA" in res["error"]


def test_search_without_tenant_is_refused(monkeypatch):
    """No tenant filter means no search at all: the archive may hold other tenants."""
    _with(monkeypatch, lambda request: pytest.fail("archive was called"))
    with pytest.raises(ArchiveError, match="no tenant"):
        GraylogArchive(ARCHIVE).search({"start": 0, "end": 1})


def test_plain_http_api_is_refused(monkeypatch):
    """The reader password is never sent over plain HTTP."""
    _with(monkeypatch, lambda request: pytest.fail("archive was called"))
    with pytest.raises(ArchiveError, match="https"):
        GraylogArchive({**ARCHIVE, "api_url": "http://gl:9000/api"}).search(
            {"start": 0, "end": 1, "tenant": "acme"})


def test_link_local_api_is_refused(monkeypatch):
    """A saved config pointing at cloud metadata never gets the reader password."""
    _with(monkeypatch, lambda request: pytest.fail("archive was called"))
    with pytest.raises(ArchiveError, match="link-local"):
        GraylogArchive({**ARCHIVE, "api_url": "https://169.254.169.254/api"}).search(
            {"start": 0, "end": 1, "tenant": "acme"})


def test_missing_password_is_not_a_login_refusal(monkeypatch):
    """After a restart the password is absent until the hub pushes it; no call is made."""
    _with(monkeypatch, lambda request: pytest.fail("archive was called"))
    with pytest.raises(ArchiveError, match="not received from the hub"):
        GraylogArchive({**ARCHIVE, "password": ""}).search({"start": 0, "end": 1, "tenant": "acme"})
    assert GraylogArchive({**ARCHIVE, "password": ""}).status()["reachable"] is None
