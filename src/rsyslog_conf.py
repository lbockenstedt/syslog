"""Render the rsyslog include files the collector's ruleset loads.

``40-lm-syslog.conf`` (written once by the installer) defines the listeners
and the ``lm_syslog`` ruleset. That ruleset includes two files this module
renders from hub settings:

- ``drop.rsyslog``: one ``stop`` statement per enabled drop rule. It runs
  before both the local file and the archive forward, so a dropped message is
  dropped everywhere.
- ``archive.rsyslog``: an ``omfwd`` action sending RFC5424 syslog over TCP
  (TLS when asked) to the archive, using the ``lm_fwd`` template from
  ``40-lm-syslog.conf``. Only a comment when no archive is connected.

Forwarding is plain syslog, so any syslog server can be the archive.
"""
# Standard library imports.
import re
from typing import Any, Dict, List, Optional, Tuple

from archives.base import api_url_ok

ETC_DIR = "/etc/lm-syslog"
DROP_FILE = ETC_DIR + "/drop.rsyslog"
ARCHIVE_FILE = ETC_DIR + "/archive.rsyslog"
ARCHIVE_CA_FILE = ETC_DIR + "/archive-ca.pem"
SYSTEM_CA_FILE = "/etc/ssl/certs/ca-certificates.crt"
MAX_RULES = 50
# Rule field -> rsyslog property.
_FIELDS = {"host": "$hostname", "program": "$programname", "msg": "$msg",
           "severity": "$syslogseverity"}
_TEXT_OPS = ("equals", "contains", "regex")
_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _ere_error(pattern: str) -> Optional[str]:
    """Return why pattern is outside the regex subset both engines read alike, or None.

    rsyslog's re_match uses POSIX ERE, while the drop preview uses Python re.
    Syntax the two read differently would preview one way and drop another
    (\\d is a digit in Python but a literal d in ERE), so it is refused:
    backslash-letter escapes, (?...) groups, lazy quantifiers, backslashes
    inside [...], and POSIX [:class:] names.
    """
    i, in_class = 0, False
    while i < len(pattern):
        c, nxt = pattern[i], pattern[i + 1:i + 2]
        if in_class:
            if c == "\\":
                return "a backslash inside [...] means different things in rsyslog and the preview"
            if c == "[" and nxt == ":":
                return "[:class:] names are not supported; list the characters, e.g. [0-9] or [ ]"
            # A ] right after [ or [^ is a literal, not the end of the class.
            if c == "]" and pattern[i - 1] != "[" and pattern[i - 2:i] != "[^":
                in_class = False
        elif c == "\\":
            if nxt.isalnum():
                return f"\\{nxt} is not POSIX ERE; use a class such as [0-9]"
            i += 2
            continue
        elif c == "[":
            in_class = True
        elif c == "(" and nxt == "?":
            return "(?...) groups and flags are not POSIX ERE"
        elif c in "*+?}" and nxt == "?":
            return "lazy quantifiers (*? +? ?? {}?) are not POSIX ERE"
        i += 1
    return None


def validate_rules(rules: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Return (clean rules, error). Error is None when every rule is valid.

    Rules: field host|program|msg with op equals|contains|regex and a string
    value, or field severity with op gte and a value 0..7.
    """
    if rules is None:
        return [], None
    if not isinstance(rules, list):
        return [], "drop_rules must be a list"
    if len(rules) > MAX_RULES:
        return [], f"at most {MAX_RULES} drop rules"
    clean = []
    for i, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            return [], f"rule {i}: must be an object"
        field, op, value = rule.get("field"), rule.get("op"), rule.get("value")
        if field not in _FIELDS:
            return [], f"rule {i}: field must be one of {', '.join(_FIELDS)}"
        # Severity rules compare numbers; the rest compare text.
        if field == "severity":
            if op != "gte" or not isinstance(value, int) or isinstance(value, bool) \
                    or not 0 <= value <= 7:
                return [], f"rule {i}: severity rules use op 'gte' and a value 0-7"
        else:
            if op not in _TEXT_OPS or not isinstance(value, str) or not value.strip():
                return [], f"rule {i}: op must be one of {', '.join(_TEXT_OPS)} with a non-empty value"
            if op == "regex":
                ere = _ere_error(value)
                if ere:
                    return [], f"rule {i}: {ere}"
                try:
                    re.compile(value)
                except re.error as e:
                    return [], f"rule {i}: invalid regex: {e}"
        clean.append({"field": field, "op": op, "value": value,
                      "enabled": rule.get("enabled", True) is not False,
                      "note": str(rule.get("note") or "")[:200]})
    return clean, None


def rule_matches(rule: Dict[str, Any], msg: Dict[str, Any]) -> bool:
    """Python twin of the rendered rsyslog test, used by the drop preview."""
    if rule["field"] == "severity":
        return msg["severity"] >= rule["value"]
    have = str(msg.get(rule["field"]) or "")
    if rule["op"] == "equals":
        return have == rule["value"]
    if rule["op"] == "contains":
        return rule["value"].lower() in have.lower()
    return re.search(rule["value"], have) is not None


def _quote(value: str) -> str:
    """Return value as an rsyslog string literal (backslash and quote escaped)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_drop(rules: List[Dict[str, Any]]) -> str:
    """Render enabled rules as RainerScript ``stop`` statements."""
    lines = ["# Managed by LM (Syslog -> Drop Rules). Edits here are overwritten."]
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        prop = _FIELDS[rule["field"]]
        if rule["field"] == "severity":
            test = f"{prop} >= {int(rule['value'])}"
        elif rule["op"] == "equals":
            test = f"{prop} == {_quote(rule['value'])}"
        elif rule["op"] == "contains":
            test = f"{prop} contains_i {_quote(rule['value'])}"
        else:
            test = f"re_match({prop}, {_quote(rule['value'])})"
        lines.append(f"if {test} then stop")
    return "\n".join(lines) + "\n"


def archive_tenant(tenant: Optional[str]) -> str:
    """The tenant value stamped on forwarded messages (lm_tenant), with the
    characters that would break the rsyslog string or SD element removed.
    Archive searches filter on this same value."""
    return re.sub(r'["\\\]]', "", tenant or "")


def archive_peer_name(archive: Dict[str, Any]) -> str:
    """Return the name the archive certificate must carry: tls_name, else the host
    when it is a DNS name. Empty for a bare IP with no tls_name, which
    validate_archive refuses (LM's CA puts only DNS names in certificates)."""
    name = str(archive.get("tls_name") or "").strip()
    host = str(archive.get("host") or "").strip()
    if name:
        return name
    return "" if _IPV4.match(host) or ":" in host else host


def validate_archive(archive: Dict[str, Any]) -> Optional[str]:
    """Return why an archive record can't be used, or None. Traffic to the
    archive is always encrypted (fleet rule 5.4): the forward uses TLS and any
    API URL (which carries the reader password) is HTTPS."""
    if archive.get("tls", True) is False:
        return "archive forwarding must use TLS (plain-text syslog is not allowed)"
    api_url = str(archive.get("api_url") or "")
    if api_url and not api_url_ok(api_url):
        return "archive api_url must be an https URL with a host (not link-local)"
    # Checking only the CA chain would let any cert from the same CA stand in
    # for the archive, so the forward always checks a name.
    if archive.get("host") and not archive_peer_name(archive):
        return "archive host is an IP address: set tls_name to the name in its certificate"
    return None


def render_archive(archive: Optional[Dict[str, Any]], tenant: str) -> str:
    """Render the archive forward action, or a comment when there is no archive.

    The queue is in memory spilling to disk, capped at 1 GB. When it is full
    new messages are discarded instead of blocking, so an archive outage never
    stops the local store.
    """
    header = "# Managed by LM (Syslog -> Settings -> Archive). Edits here are overwritten.\n"
    if not archive or not archive.get("host"):
        return header + "# No archive connected.\n"
    host = str(archive["host"])
    port = int(archive.get("input_port") or 1514)
    # Always TLS (validate_archive refuses anything else). It checks the archive
    # certificate against its CA (LM's hub CA for an LM-installed archive, else
    # the given CA or the system bundle) and the name in it, so another cert
    # from the same CA can't stand in for the archive.
    ca = ARCHIVE_CA_FILE if archive.get("ca_pem") else SYSTEM_CA_FILE
    peer = archive_peer_name(archive)
    if not peer:
        raise ValueError(validate_archive(archive))
    tls_params = (' StreamDriver="gtls" StreamDriverMode="1"'
                  f' StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers={_quote(peer)}'
                  f' StreamDriver.CAFile={_quote(ca)}')
    # The forward template (defined in 40-lm-syslog.conf, since templates can't
    # live inside a ruleset) reads the tenant from this variable.
    sd_tenant = archive_tenant(tenant)
    return (header + f'set $.lm_tenant = {_quote(sd_tenant)};\n'
            f'action(type="omfwd" name="lm_archive" target={_quote(host)} port="{port}" protocol="tcp"'
            f' TCP_Framing="octet-counted" template="lm_fwd"{tls_params}'
            ' queue.type="LinkedList" queue.filename="lm_archive" queue.spoolDirectory="/var/spool/rsyslog"'
            ' queue.maxDiskSpace="1g" queue.size="200000" queue.timeoutEnqueue="0"'
            ' queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="10")\n')
