"""Graylog query plugin (Graylog Open 7.0 Search Scripting API).

Search: ``POST /api/search/messages`` with a Lucene query and an absolute
time range, sorted newest first. Status: ``GET /api/system``. Both use the
read-only ``lm-reader`` account LM created at install time, and verify the
server certificate against the archive CA (by ``tls_name`` when the API URL is an IP).
"""
# Standard library imports.
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

# Third-party imports.
import httpx

from .base import ArchiveError, api_url_ok, tls_verify

_FIELDS = ["timestamp", "source", "src_ip", "application_name", "level", "facility_num",
           "message"]
# Lucene specials plus the space, so a multi-word term stays one term.
_LUCENE_SPECIAL = re.compile(r'([+\-!(){}\[\]^"~*?:\\/&| ])')
_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
# Graylog's syslog input stores the facility as a name unless facility_num is kept.
_DEFAULT_FACILITY = 1


def _iso(ts: float) -> str:
    """Return an epoch time as the ISO-8601 UTC string Graylog expects."""
    # Whole milliseconds first, so float error (x.122999…) can't shift a bound by 1 ms.
    ms = round(ts * 1000)
    return datetime.fromtimestamp(ms // 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + f".{ms % 1000:03d}Z"


def _epoch(value: Any) -> float:
    """Parse a Graylog timestamp (ISO-8601) into epoch seconds; 0 when unparseable."""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _escape(term: str) -> str:
    """Escape Lucene special characters in a user term."""
    return _LUCENE_SPECIAL.sub(r"\\\1", term.strip())


def _any_case(field: str, term: str) -> str:
    """Case-insensitive substring match on a keyword field (stored as sent,
    matched case-sensitively), like the local store: a Lucene regex with a
    [xX] class for each letter and every other character escaped."""
    out = []
    for c in term.strip():
        lo, up = c.lower(), c.upper()
        if len(lo) == 1 and len(up) == 1 and lo != up:
            out.append(f"[{lo}{up}]")
        else:
            out.append(c if c.isalnum() else "\\" + c)
    return f"{field}:/.*{''.join(out)}.*/"


def build_query(flt: Dict[str, Any]) -> str:
    """Turn the LM query filters into a Lucene query string.

    host and program are substring matches (wildcards); text matches the
    message, host or program, the same as the local store: a single word is a
    substring (wildcard) match, so "fail" finds "failed" in both places; words
    with spaces match as a phrase in the message, since the archive indexes
    the message word by word; severity_max keeps
    that level and more severe; tenant keeps only messages LM forwarded for
    that tenant (lm_tenant).
    """
    # Wildcard terms skip the analyzer. Graylog indexes message and source
    # lower-cased, so those terms are lower-cased; application_name is a
    # keyword field kept as sent, so it is matched by a case-blind regex.
    parts: List[str] = []
    if flt.get("host"):
        h = _escape(flt["host"])
        parts.append(f"(source:*{h.lower()}* OR src_ip:*{h}*)")
    if flt.get("program"):
        parts.append(_any_case("application_name", flt["program"]))
    if flt.get("text"):
        t = _escape(flt["text"])
        msg = f'"{t}"' if any(c.isspace() for c in flt["text"].strip()) else f"*{t.lower()}*"
        parts.append(f'(message:{msg} OR source:*{t.lower()}* OR {_any_case("application_name", flt["text"])})')
    if flt.get("severity_max") is not None:
        parts.append(f"level:[0 TO {int(flt['severity_max'])}]")
    # Only this tenant's messages, in case the archive also holds others.
    if flt.get("tenant"):
        parts.append(f'lm_tenant:"{_escape(flt["tenant"])}"')
    return " AND ".join(parts) or "*"


class GraylogArchive:
    """Query a Graylog server as the LM read-only user."""

    def __init__(self, archive: Dict[str, Any]):
        """Keep the connection facts; no call is made until asked."""
        self.api_url = str(archive.get("api_url") or "").rstrip("/")
        self.auth = (str(archive.get("user") or ""), str(archive.get("password") or ""))
        # LM's CA issues certs for a name, not an IP: check the cert against
        # tls_name while connecting to the IP in api_url.
        self.tls_name = str(archive.get("tls_name") or "")
        self.archive = archive

    def _client(self) -> httpx.Client:
        """Return an httpx client with the archive CA and LM's request header."""
        return httpx.Client(verify=tls_verify(self.archive), timeout=_TIMEOUT, auth=self.auth,
                            headers={"Accept": "application/json", "X-Requested-By": "lm"})

    def _call(self, method: str, path: str, **kw) -> Dict[str, Any]:
        """Make one API call and return the JSON body; raise ArchiveError on any failure."""
        if not self.api_url:
            raise ArchiveError("archive has no api_url")
        # The reader password rides on every call: only to a safe https URL.
        if not api_url_ok(self.api_url):
            raise ArchiveError("archive api_url must be an https URL with a host (not link-local)")
        # The password is never saved on disk, so after a restart it is missing
        # until the hub's next push: say so instead of a misleading login refusal.
        if not self.auth[1]:
            raise ArchiveError("archive password not received from the hub yet "
                               "(it is not saved on disk; the next settings push brings it)")
        try:
            with self._client() as client:
                ext = {"sni_hostname": self.tls_name} if self.tls_name else None
                resp = client.request(method, self.api_url + path, extensions=ext, **kw)
        except httpx.HTTPError as e:
            raise ArchiveError(f"Graylog {path}: {type(e).__name__}: {e}") from e
        # Check the status, then that the body is JSON.
        if resp.status_code in (401, 403):
            raise ArchiveError(f"Graylog {path}: HTTP {resp.status_code} (lm-reader login refused)")
        if resp.status_code >= 400:
            raise ArchiveError(f"Graylog {path}: HTTP {resp.status_code}: {resp.text[:200]}")
        try:
            body = resp.json()
        except ValueError as e:
            raise ArchiveError(f"Graylog {path}: response is not JSON") from e
        if not isinstance(body, dict):
            raise ArchiveError(f"Graylog {path}: unexpected response")
        return body

    def search(self, flt: Dict[str, Any]) -> Dict[str, Any]:
        """Run one search and return messages newest first in the LM shape."""
        # Fail closed: the archive may hold other tenants, so never search it
        # without the tenant filter.
        if not flt.get("tenant"):
            raise ArchiveError("archive search refused: collector has no tenant")
        limit = int(flt.get("limit") or 500)
        start = float(flt.get("start") or 0)
        if flt.get("after_ts") is not None:
            start = max(start, float(flt["after_ts"]))
        body = {"query": build_query(flt), "fields": _FIELDS, "from": 0, "size": limit,
                "timerange": {"type": "absolute", "from": _iso(start), "to": _iso(float(flt["end"]))},
                "sort": "timestamp", "sort_order": "desc"}
        data = self._call("POST", "/search/messages", json=body)
        # The response is a schema (column names) plus rows of values.
        cols = [c.get("field") for c in data.get("schema") or [] if isinstance(c, dict)]
        rows = data.get("datarows") or []
        out = []
        for row in rows:
            rec = dict(zip(cols, row)) if isinstance(row, list) else {}
            ts = _epoch(rec.get("timestamp"))
            if flt.get("after_ts") is not None and ts <= float(flt["after_ts"]):
                continue
            out.append({"ts": ts, "host": rec.get("source") or "", "src_ip": rec.get("src_ip") or "",
                        "program": rec.get("application_name") or "",
                        "severity": _num(rec.get("level"), 7),
                        "facility": _num(rec.get("facility_num"), _DEFAULT_FACILITY),
                        "msg": rec.get("message") or ""})
        return {"messages": out, "truncated": len(rows) >= limit}

    def status(self) -> Dict[str, Any]:
        """Return whether the API answers and its version; never raises.

        Without the password (not yet pushed after a restart) reachability is
        unknown (None), not False: no call is made.
        """
        if not self.auth[1]:
            return {"reachable": None, "version": "",
                    "error": "archive password not received from the hub yet"}
        try:
            info = self._call("GET", "/system")
        except ArchiveError as e:
            return {"reachable": False, "version": "", "error": str(e)}
        return {"reachable": True, "version": str(info.get("version") or ""), "error": ""}


def _num(value: Any, default: int) -> int:
    """Return value as an int, or default."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
