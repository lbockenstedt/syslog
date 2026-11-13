"""Entry point and control plane for the standalone Syslog (logging) spoke.

Normally the generic agent hosts the ``syslog`` role; this file runs the same
spoke as its own service when needed. It registers under module type
"logging" and starts the spoke's own background loops.
"""
# Dependency self-heal: must run before third-party imports (see truenas/control_plane.py).
import os as _os
try:
    try:
        from core.src.dep_guard import ensure_requirements as _ensure_requirements
    except ImportError:
        from dep_guard import ensure_requirements as _ensure_requirements
    _ensure_requirements(_os.path.join(
        _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "requirements.txt"))
except Exception:
    pass

# Standard library imports.
import argparse
import asyncio
import logging
from typing import Any, Dict

# Base control plane (core package or flat layout) and the Syslog spoke.
try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane
from syslog_spoke import SyslogSpoke

# Shared logging setup, with a basic fallback when it is not installed.
try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        def configure_logging(default_level=logging.INFO, **_):
            """Fallback logging: basicConfig with the standard format."""
            logging.basicConfig(level=default_level, force=True,
                                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
configure_logging()
logger = logging.getLogger("SyslogControlPlane")


class SyslogControlPlane(BaseControlPlane):
    """Control plane for the Syslog (logging) module."""

    def get_service_name(self) -> str:
        """Return the systemd service name for this spoke."""
        return "lm-syslog"

    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None,
                 hub_url: str = None, config: Dict[str, Any] = None):
        """Store the config, start the base control plane and set the module type."""
        self.config = config or {}
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.module_type = "logging"

    async def run_hub_mode(self):
        """Register the Syslog spoke, start its loops and run the hub connection loop."""
        logger.info("Starting Syslog module in HUB MODE -> %s", self.hub_url)
        spoke = SyslogSpoke(self.spoke_id, self.config)
        self.register_module("logging", spoke)
        spoke.start_background_loops()
        await self.run()


if __name__ == "__main__":
    # Command-line options.
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True, help="Spoke ID")
    parser.add_argument("--secret", default=None,
                        help="Authentication secret (required; or set SPOKE_SECRET)")
    parser.add_argument("--hub-secret", nargs='?', default="", const="",
                        help="Hub authentication secret for mutual auth")
    parser.add_argument("--hub", required=True, help="Hub WebSocket URL")
    args = parser.parse_args()
    secret = args.secret or _os.getenv("SPOKE_SECRET")
    if not secret:
        parser.error("authentication secret required: pass --secret or set SPOKE_SECRET")
    # Build the control plane and run it until stopped or interrupted.
    cp = SyslogControlPlane(args.id, secret, args.hub_secret, args.hub)
    try:
        asyncio.run(cp.run_hub_mode())
    except KeyboardInterrupt:
        pass
