"""
Safety module — RedOps will NEVER attack a target not in the configured allowlist.
This is enforced at every entry point, not just the API layer.
"""
from app.config import settings
from functools import wraps
import logging

log = logging.getLogger("redops.safety")


class TargetNotAllowedError(Exception):
    """Raised when a target IP is outside the configured allowlist."""
    def __init__(self, host: str):
        super().__init__(
            f"Target '{host}' is not in TARGET_ALLOWLIST. "
            "RedOps refuses to attack unallowlisted targets."
        )
        self.host = host


def require_allowed_target(host: str):
    """
    Hard check. Call this before any network operation against a target.
    Raises TargetNotAllowedError if the host is not in the allowlist.
    """
    if not settings.is_target_allowed(host):
        log.critical("SAFETY BLOCK: attempted attack on non-allowlisted target %s", host)
        raise TargetNotAllowedError(host)
    log.debug("Safety check passed for target: %s", host)


def safe_target(func):
    """
    Decorator for attack module functions.
    Expects first argument to be `host: str`.
    """
    @wraps(func)
    async def wrapper(host: str, *args, **kwargs):
        require_allowed_target(host)
        return await func(host, *args, **kwargs)
    return wrapper