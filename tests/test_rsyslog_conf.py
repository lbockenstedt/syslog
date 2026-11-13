"""Drop-rule validation and rendering, and the archive forward action."""
from rsyslog_conf import render_archive, render_drop, rule_matches, validate_archive, validate_rules


def test_validate_rejects_bad_rules():
    """Bad regex, wrong severity op, unknown field and too many rules are refused."""
    assert "invalid regex" in validate_rules([{"field": "msg", "op": "regex", "value": "("}])[1]
    assert "severity" in validate_rules([{"field": "severity", "op": "equals", "value": 3}])[1]
    assert "field" in validate_rules([{"field": "facility", "op": "equals", "value": "x"}])[1]
    assert "at most" in validate_rules([{"field": "host", "op": "equals", "value": "a"}] * 51)[1]
    clean, err = validate_rules([{"field": "severity", "op": "gte", "value": 7, "enabled": False}])
    assert err is None and clean[0]["enabled"] is False


def test_render_drop_escapes_and_skips_disabled():
    """Quotes and backslashes can't break out of the rsyslog string; disabled rules vanish."""
    rules, _ = validate_rules([
        {"field": "msg", "op": "contains", "value": 'a"b\\c'},
        {"field": "host", "op": "equals", "value": "sw1", "enabled": False},
        {"field": "program", "op": "regex", "value": "^cron"},
        {"field": "severity", "op": "gte", "value": 7}])
    text = render_drop(rules)
    assert 'if $msg contains_i "a\\"b\\\\c" then stop' in text
    assert "sw1" not in text
    assert 'if re_match($programname, "^cron") then stop' in text
    assert "if $syslogseverity >= 7 then stop" in text


def test_rule_matches_mirrors_rendered_ops():
    """The preview's Python test agrees with the rendered operators."""
    msg = {"host": "SW1", "program": "cron", "msg": "Hello World", "severity": 7}
    assert rule_matches({"field": "msg", "op": "contains", "value": "world"}, msg)
    assert not rule_matches({"field": "host", "op": "equals", "value": "sw1"}, msg)
    assert rule_matches({"field": "severity", "op": "gte", "value": 6}, msg)


def test_render_archive_none_and_tls():
    """No archive renders no action; a TLS archive uses the given CA and never blocks the store."""
    assert "action(" not in render_archive(None, "acme")
    text = render_archive({"host": "10.1.1.5", "input_port": 1514, "ca_pem": "PEM",
                           "tls_name": "syslog-graylog-acme"}, 'ac"me]')
    assert 'set $.lm_tenant = "acme";' in text
    assert 'target="10.1.1.5" port="1514"' in text
    assert 'StreamDriver.CAFile="/etc/lm-syslog/archive-ca.pem"' in text
    assert 'queue.timeoutEnqueue="0"' in text
    # The name is always checked, so another cert from the same CA is refused.
    assert 'StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="syslog-graylog-acme"' in text
    assert 'StreamDriverPermittedPeers="gl.example"' in render_archive({"host": "gl.example"}, "t")
    # Plain-text archive traffic is refused (fleet rule 5.4: always encrypted).
    assert "TLS" in validate_archive({"host": "h", "tls": False})
    assert "https" in validate_archive({"host": "h", "api_url": "http://h:9000/api"})
    assert validate_archive({"host": "h", "api_url": "https://h:9000/api"}) is None
    # An IP with no tls_name would check only the CA chain: refused.
    assert "tls_name" in validate_archive({"host": "10.1.1.5"})
    assert "tls_name" in validate_archive({"host": "fd00::5"})
    assert validate_archive({"host": "10.1.1.5", "tls_name": "gl.example"}) is None


def test_regex_rules_limited_to_what_rsyslog_and_preview_agree_on():
    """Python-only regex syntax is refused (rsyslog's ERE reads \\d as a literal d);
    plain ERE, escaped specials and literal ] at the start of a class are accepted."""
    def err(value):
        """Return the validation error for one regex rule."""
        return validate_rules([{"field": "msg", "op": "regex", "value": value}])[1]
    for bad in (r"link \d+ down", "(?i)link", "a+?", r"[\.]", "[[:space:]]"):
        assert err(bad), bad
    for good in ("link [0-9]+ down", r"\.\*", "[]a]x", "foo|bar$", r"a\\d"):
        assert err(good) is None, good


def test_api_url_must_be_a_safe_https_host():
    """The reader password only goes to an https URL with a real, non-link-local host."""
    for bad in ("http://h:9000/api", "https:///api", "https://169.254.169.254/api",
                "https://[fe80::1]/api", "https://0.0.0.0:9000/api"):
        assert "api_url" in validate_archive({"host": "h", "api_url": bad}), bad
    for good in ("https://graylog.lab:9000/api", "https://10.1.2.3:9000/api",
                 "HTTPS://h:9000/api"):
        assert validate_archive({"host": "h", "api_url": good}) is None, good
