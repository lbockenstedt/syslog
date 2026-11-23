"""Archive query plugins, keyed by the archive record's ``backend`` name.

Forwarding to an archive is standard RFC5424 syslog over TLS (see
``rsyslog_conf``), so any syslog server that accepts TLS can be the archive.
A plugin's API calls must use HTTPS: they carry the reader password. Searching it needs a plugin here. A
backend with no plugin is forward-only: queries older than the local window
return the local part with ``source: local-partial``.

A plugin is a class built with the archive dict that provides:

- ``search(flt) -> {"messages": [...], "truncated": bool}`` (newest first,
  same message shape as the local store), raising ``ArchiveError`` on failure.
  ``flt`` carries the query filters plus ``tenant``; return only messages
  whose ``lm_tenant`` matches it, and raise ``ArchiveError`` when ``tenant``
  is empty (fail closed);
- ``status() -> {"reachable": bool, "version": str, "error": str}``.
"""
# Standard library imports.
from typing import Any, Dict, Optional

from .base import ArchiveError
from .graylog import GraylogArchive

BACKENDS = {"graylog": GraylogArchive}


def get_backend(archive: Optional[Dict[str, Any]]):
    """Return a plugin instance for the archive, or None when it has no query plugin."""
    if not archive:
        return None
    cls = BACKENDS.get(str(archive.get("backend") or "").lower())
    return cls(archive) if cls else None


__all__ = ["ArchiveError", "BACKENDS", "get_backend"]
