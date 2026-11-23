"""Shared pieces for archive query plugins."""
# Standard library imports.
import ipaddress
import ssl
from typing import Any, Dict, Optional
from urllib.parse import urlsplit


class ArchiveError(Exception):
    """An archive query or status call failed; the text is safe to show and log."""


def tls_verify(archive: Dict[str, Any]) -> Any:
    """Return the ``verify`` value for httpx: an SSL context trusting the archive CA,
    or True for the system store.

    The CA PEM arrives in the pushed config and is loaded in memory, so no file
    is written. Certificate checks are never turned off. A bad PEM raises
    ArchiveError so callers keep their never-raise and fallback promises.
    """
    pem: Optional[str] = archive.get("ca_pem")
    if not pem:
        return True
    try:
        return ssl.create_default_context(cadata=str(pem))
    except (ssl.SSLError, ValueError) as e:
        raise ArchiveError(f"archive CA is not a valid PEM certificate: {e}") from e


def api_url_ok(url: str) -> bool:
    """True if ``url`` is an https URL the collector may send the reader password to.

    The same check the hub runs when the archive is saved
    (lm core/src/syslog_archive.py ``_archive_api_url_ok``), repeated here so a
    bad push can't send the password elsewhere. Not the fleet's
    ``safe_external_url``: only this collector calls the URL, inside the
    tenant network, so a private or loopback Graylog is the normal case (as
    for NetBox or TrueNAS instance URLs). Link-local and unspecified addresses
    (cloud metadata, 0.0.0.0) are refused.
    """
    # Scheme and host.
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        return False
    # Refuse link-local / unspecified IP literals; names are allowed.
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        return True
    return not (ip.is_link_local or ip.is_unspecified)
