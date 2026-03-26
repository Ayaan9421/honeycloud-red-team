"""
app/config.py
─────────────
Single source of truth for all RedOps settings.
Reads from .env file in the project root (same folder as main.py).

Priority order (highest → lowest):
  1. Real environment variables  (export TARGET_ALLOWLIST=...)
  2. .env file                   (TARGET_ALLOWLIST=... in .env)
  3. Defaults below              (fallback if neither of the above exist)
"""
import ipaddress
import logging
import os
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("redops.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",           # ignore unknown keys in .env
    )

    app_env:    str = "development"
    secret_key: str = "dev-secret-change-me"

    # ── Database ──────────────────────────────────────────────
    database_url: str = "sqlite+aiosqlite:///./redops.db"

    # ── Redis ─────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Safety allowlist ──────────────────────────────────────
    # Comma-separated IPs and/or CIDR ranges.
    # RedOps will REFUSE to attack anything not in this list.
    # Override via TARGET_ALLOWLIST in .env or environment variable.
    target_allowlist: str = (
        "127.0.0.1,"
        "172.20.0.0/24,"
        "192.168.0.0/16,"
        "10.0.0.0/8,"
        "136.112.225.237"
    )

    # ── Honeypot defaults ─────────────────────────────────────
    mock_honeypot_host:      str = "127.0.0.1"
    mock_honeypot_ssh_port:  int = 2222
    mock_honeypot_http_port: int = 8080

    # ── Campaign limits ───────────────────────────────────────
    default_dwell_min_sec:    int = 5
    default_dwell_max_sec:    int = 15
    max_concurrent_campaigns: int = 3

    # ─────────────────────────────────────────────────────────
    def model_post_init(self, __context):
        """Log where config came from so you can always debug allowlist issues."""
        env_path = os.path.abspath(".env")
        env_exists = os.path.exists(env_path)
        log.info("━━ RedOps Config ━━")
        log.info("  .env path:    %s  (%s)", env_path, "FOUND" if env_exists else "NOT FOUND — using defaults")
        log.info("  app_env:      %s", self.app_env)
        log.info("  allowlist:    %s", self.target_allowlist)
        log.info("  honeypot:     %s:%d", self.mock_honeypot_host, self.mock_honeypot_ssh_port)
        log.info("  database:     %s", self.database_url)
        log.info("  redis:        %s", self.redis_url)

    # ─────────────────────────────────────────────────────────
    def is_target_allowed(self, host: str) -> bool:
        """
        Hard safety check — call this before ANY network operation against a target.
        Returns True only if host is explicitly in the allowlist.
        Empty allowlist = allow all (dev/test mode only — logs a warning).
        """
        stripped = self.target_allowlist.strip().strip(",")
        if not stripped:
            log.warning("SAFETY: target_allowlist is EMPTY — allowing all targets (dev mode)")
            return True

        try:
            target = ipaddress.ip_address(host)
        except ValueError:
            log.warning("SAFETY BLOCK: '%s' is not a valid IP address", host)
            return False

        for entry in stripped.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                if "/" in entry:
                    if target in ipaddress.ip_network(entry, strict=False):
                        return True
                else:
                    if target == ipaddress.ip_address(entry):
                        return True
            except ValueError:
                log.debug("Skipping invalid allowlist entry: %r", entry)
                continue

        log.warning("SAFETY BLOCK: '%s' is not in TARGET_ALLOWLIST", host)
        return False

    def allowlist_entries(self) -> list[str]:
        """Return allowlist as a clean list (for display in /api/health)."""
        return [
            e.strip() for e in self.target_allowlist.split(",")
            if e.strip()
        ]


settings = Settings()