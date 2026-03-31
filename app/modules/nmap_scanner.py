"""
nmap_scanner.py
───────────────
Real nmap integration with fully dynamic, config-driven profiles.

NOTHING is hardcoded here:
  • Scan profiles are loaded from  campaigns/nmap_profiles.yaml  at runtime.
  • If that file does not exist it is auto-generated with sensible defaults
    so the system self-bootstraps on first run.
  • Profiles can be added, edited, or removed by editing the YAML — no code change needed.
  • The fallback TCP scanner (used when the nmap binary is absent) also
    derives its port list from whatever ports the active profile declares,
    so even the fallback path is config-driven.
  • The /api/tools/scan/profiles endpoint reflects the live YAML state.

Install:
    pip install python-nmap
    # Windows: download nmap installer from https://nmap.org/download.html
    # Linux:   sudo apt-get install nmap
    # macOS:   brew install nmap
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import yaml  # already in requirements (pyyaml)

from app.modules.attack_modules import ActionResult
from app.core.safety import safe_target

log = logging.getLogger("redops.nmap")

# ── Config file location ────────────────────────────────────────────────────
PROFILES_FILE = Path("campaigns") / "nmap_profiles.yaml"

# ── Default profile YAML written on first run ────────────────────────────────
_DEFAULT_PROFILES_YAML = """\
# nmap_profiles.yaml
# ──────────────────
# Defines all nmap scan profiles used by HoneyCloud campaigns.
# Edit this file to add, remove, or tweak profiles — no code change needed.
#
# Fields per profile:
#   args          : raw nmap argument string passed to PortScanner.scan()
#   description   : human-readable label shown in the API
#   needs_root    : whether the scan requires root/admin privileges
#   ports         : port list/range string passed to nmap -p  (can be omitted
#                   to let the args string control ports itself)
#   timeout_sec   : max seconds to wait before giving up (default 120)
#
# Supported port string formats (identical to nmap -p syntax):
#   "22,80,443"          — discrete ports
#   "1-1024"             — range
#   "22,80,8000-8100"    — mixed
#   ""  or omit field    — let nmap args decide (e.g. --top-ports 100)

profiles:

  stealth:
    args: "-sS -sV --version-intensity 2 -T2 -n --open"
    description: "SYN stealth scan — low noise, minimal footprint. Needs Npcap/root."
    needs_root: true
    ports: "21,22,23,25,53,80,110,143,443,445,993,995,2222,2223,3306,3389,5432,6379,8080,8443,9090"
    timeout_sec: 180

  standard:
    args: "-sT -sV --version-intensity 3 -T3 -n --open"
    description: "TCP connect scan — reliable on Windows without Npcap."
    needs_root: false
    ports: "21,22,23,25,53,80,110,143,443,445,993,995,2222,2223,3306,3389,5432,6379,8080,8443,9090"
    timeout_sec: 120

  aggressive:
    args: "-sT -sV -sC -O --version-intensity 5 -T4 -n --open"
    description: "Full scan — OS detection, NSE scripts, banner grab, version."
    needs_root: false
    ports: "1-65535"
    timeout_sec: 300

  honeypot:
    args: "-sT -sV --version-intensity 4 -T3 -n --open"
    description: "Honeypot-focused — ports that deception systems typically expose."
    needs_root: false
    ports: "21,22,23,80,443,2222,2223,8080,8443,9090,3306,5432,6379"
    timeout_sec: 60

  quick:
    args: "-sT --top-ports 100 -T4 -n --open"
    description: "Fast top-100 port sweep — good for initial recon."
    needs_root: false
    ports: ""
    timeout_sec: 30

  udp:
    args: "-sU -sV --version-intensity 2 -T3 --open"
    description: "UDP service discovery — DNS, SNMP, NTP, TFTP."
    needs_root: true
    ports: "53,67,68,69,123,161,162,500,514,1900,5353"
    timeout_sec: 180

  os_detect:
    args: "-sT -O --osscan-guess -T3 -n"
    description: "OS fingerprinting with aggressive guess — identifies honeypot OS stack."
    needs_root: false
    ports: "22,80,443,2222"
    timeout_sec: 90
"""


# ── Profile loader ───────────────────────────────────────────────────────────

def _ensure_profiles_file() -> None:
    """Write the default YAML if the file does not exist yet."""
    PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not PROFILES_FILE.exists():
        PROFILES_FILE.write_text(_DEFAULT_PROFILES_YAML, encoding="utf-8")
        log.info("Created default nmap_profiles.yaml at %s", PROFILES_FILE)


def load_profiles() -> dict[str, dict]:
    """
    Load scan profiles from the YAML file.
    Returns a plain dict keyed by profile name.
    Creates the file with defaults if it doesn't exist.
    Gracefully returns an empty dict on parse error (logs the problem).
    """
    _ensure_profiles_file()
    try:
        data = yaml.safe_load(PROFILES_FILE.read_text(encoding="utf-8")) or {}
        profiles = data.get("profiles", {})
        if not isinstance(profiles, dict) or not profiles:
            log.error(
                "nmap_profiles.yaml has no 'profiles' section or is empty — "
                "delete the file so it can be regenerated."
            )
            return {}
        log.debug("Loaded %d nmap profiles from %s", len(profiles), PROFILES_FILE)
        return profiles
    except yaml.YAMLError as exc:
        log.error("Failed to parse %s: %s", PROFILES_FILE, exc)
        return {}


def get_profile(name: str) -> dict:
    """
    Return a single profile dict, falling back to 'standard' then to a
    safe inline default so the system never crashes due to a missing profile.
    """
    profiles = load_profiles()
    if name in profiles:
        return profiles[name]
    log.warning("Profile '%s' not found in %s — falling back to 'standard'", name, PROFILES_FILE)
    if "standard" in profiles:
        return profiles["standard"]
    # Last-resort inline default (never hardcoded ports — minimal args only)
    return {
        "args":        "-sT -T3 -n",
        "description": "Emergency fallback — edit nmap_profiles.yaml",
        "needs_root":  False,
        "ports":       "",
        "timeout_sec": 120,
    }


def get_available_profiles() -> list[dict]:
    """
    Returns profile metadata for the /api/tools/scan/profiles endpoint.
    Reads live from YAML every call so the API always reflects the current file.
    """
    profiles = load_profiles()
    return [
        {
            "name":        name,
            "description": cfg.get("description", ""),
            "needs_root":  cfg.get("needs_root", False),
            "nmap_args":   cfg.get("args", ""),
            "ports":       cfg.get("ports", "<nmap default>") or "<nmap default>",
            "timeout_sec": cfg.get("timeout_sec", 120),
        }
        for name, cfg in profiles.items()
    ]


# ── Result structures ────────────────────────────────────────────────────────

@dataclass
class PortInfo:
    port:     int
    protocol: str          # tcp / udp
    state:    str          # open / closed / filtered
    service:  str = ""     # ssh, http, ...
    product:  str = ""     # OpenSSH, Apache, ...
    version:  str = ""     # 7.9p1, 2.4.41, ...
    extra:    str = ""
    cpe:      str = ""


@dataclass
class HostInfo:
    ip:          str
    hostname:    str             = ""
    state:       str             = "unknown"
    os_match:    str             = ""
    os_accuracy: int             = 0
    ports:       list[PortInfo]  = field(default_factory=list)


@dataclass
class NmapScanResult:
    target:        str
    profile:       str
    scan_args:     str
    ports_arg:     str           # actual -p value used
    started_at:    str
    elapsed_s:     float
    hosts:         list[HostInfo] = field(default_factory=list)
    raw_command:   str            = ""
    nmap_version:  str            = ""
    error:         Optional[str]  = None
    fallback_used: bool           = False

    # ── Convenience helpers used by the scorer and orchestrator ──────────────

    @property
    def open_ports(self) -> list[int]:
        ports: list[int] = []
        for h in self.hosts:
            for p in h.ports:
                if p.state == "open":
                    ports.append(p.port)
        return sorted(set(ports))

    @property
    def services(self) -> dict[int, str]:
        """port → service name mapping."""
        svc: dict[int, str] = {}
        for h in self.hosts:
            for p in h.ports:
                if p.state == "open":
                    svc[p.port] = p.service or "unknown"
        return svc

    @property
    def has_honeypot_ports(self) -> bool:
        """
        True if ports associated with common Cowrie/honeypot deployments appear open.
        The port set comes from the live YAML so operators can update it without code changes.
        """
        profiles = load_profiles()
        honeypot_cfg = profiles.get("honeypot", {})
        raw = honeypot_cfg.get("ports", "")
        honeypot_port_set = _parse_ports(raw) if raw else {2222, 2223}
        return bool(set(self.open_ports) & honeypot_port_set)

    def to_json(self) -> str:
        d = asdict(self)
        # Inject computed properties so the API/scorer can use them without re-instantiating
        d["open_ports"]         = self.open_ports
        d["services"]           = {str(k): v for k, v in self.services.items()}
        d["has_honeypot_ports"] = self.has_honeypot_ports
        return json.dumps(d, default=str, indent=2)


# ── Port string parsing ──────────────────────────────────────────────────────

def _parse_ports(port_str: str) -> set[int]:
    """
    Parse a nmap-style port string into a Python set of ints.
    Supports: "22,80,443"  "1-1024"  "22,80,8000-8100"
    """
    result: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            try:
                result.update(range(int(lo_s), int(hi_s) + 1))
            except ValueError:
                log.warning("Invalid port range '%s' in profile — skipping", part)
        else:
            try:
                result.add(int(part))
            except ValueError:
                log.warning("Invalid port '%s' in profile — skipping", part)
    return result


# ── Core nmap runner ─────────────────────────────────────────────────────────

def _nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _parse_nmap_result(nm, target: str) -> list[HostInfo]:
    """Convert python-nmap PortScanner output into HostInfo list."""
    hosts: list[HostInfo] = []
    for host_ip in nm.all_hosts():
        hd = nm[host_ip]
        hi = HostInfo(
            ip=host_ip,
            hostname=hd.hostname() or "",
            state=hd.state(),
        )
        # OS detection (only with -O flag)
        try:
            os_matches = hd.get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                hi.os_match    = best.get("name", "")
                hi.os_accuracy = int(best.get("accuracy", 0))
        except Exception:
            pass

        for proto in hd.all_protocols():
            for port_num, port_data in hd[proto].items():
                hi.ports.append(PortInfo(
                    port=int(port_num),
                    protocol=proto,
                    state=port_data.get("state", ""),
                    service=port_data.get("name", ""),
                    product=port_data.get("product", ""),
                    version=port_data.get("version", ""),
                    extra=port_data.get("extrainfo", ""),
                    cpe=(" ".join(port_data.get("cpe", "").split())
                         if port_data.get("cpe") else ""),
                ))
        hi.ports.sort(key=lambda p: p.port)
        hosts.append(hi)
    return hosts


def _run_nmap_sync(target: str, profile_name: str, custom_ports: Optional[str]) -> NmapScanResult:
    """
    Synchronous nmap execution — runs inside a thread-pool executor so the
    async event loop is never blocked.

    Profile args and port list both come from load_profiles() so they always
    reflect the current nmap_profiles.yaml content.
    """
    import nmap as nmap_lib  # deferred import — startup survives missing package

    cfg        = get_profile(profile_name)
    args       = cfg.get("args", "-sT -T3 -n --open")
    timeout    = int(cfg.get("timeout_sec", 120))

    # Port list: custom_ports (from API caller) > profile ports > empty (nmap decides)
    ports_arg  = custom_ports or cfg.get("ports", "") or ""

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0         = time.perf_counter()
    nm         = nmap_lib.PortScanner()
    raw_cmd    = ""

    try:
        log.info(
            "nmap: starting profile='%s' target=%s ports='%s' args='%s'",
            profile_name, target, ports_arg or "<nmap default>", args,
        )
        scan_kwargs: dict = {"hosts": target, "arguments": args}
        if ports_arg:
            scan_kwargs["ports"] = ports_arg
        nm.scan(**scan_kwargs)
        raw_cmd = nm.command_line()
        log.info("nmap: command → %s", raw_cmd)

    except nmap_lib.PortScannerError as exc:
        elapsed = time.perf_counter() - t0
        log.error("nmap PortScannerError: %s", exc)
        return NmapScanResult(
            target=target, profile=profile_name, scan_args=args,
            ports_arg=ports_arg, started_at=started_at,
            elapsed_s=round(elapsed, 2), error=str(exc), raw_command=raw_cmd,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        log.error("nmap unexpected error: %s", exc)
        return NmapScanResult(
            target=target, profile=profile_name, scan_args=args,
            ports_arg=ports_arg, started_at=started_at,
            elapsed_s=round(elapsed, 2), error=str(exc), raw_command=raw_cmd,
        )

    elapsed      = time.perf_counter() - t0
    hosts        = _parse_nmap_result(nm, target)
    nmap_version = ""
    try:
        v = nm.nmap_version()
        nmap_version = ".".join(str(x) for x in v) if isinstance(v, tuple) else str(v)
    except Exception:
        pass

    result = NmapScanResult(
        target=target, profile=profile_name, scan_args=args,
        ports_arg=ports_arg, started_at=started_at,
        elapsed_s=round(elapsed, 2), hosts=hosts,
        raw_command=raw_cmd, nmap_version=nmap_version,
    )
    log.info(
        "nmap: done — hosts=%d open_ports=%s elapsed=%.1fs",
        len(hosts), result.open_ports, elapsed,
    )
    return result


# ── Fallback scanner (no nmap binary) ───────────────────────────────────────

async def _fallback_scan(
    target: str,
    profile_name: str,
    custom_ports: Optional[str],
) -> NmapScanResult:
    """
    Pure-Python async TCP connect scan used when nmap is not installed.
    Derives the port list from the YAML profile so it stays consistent.
    """
    from app.modules.attack_modules import port_scan as _port_scan

    cfg       = get_profile(profile_name)
    raw_ports = custom_ports or cfg.get("ports", "") or ""

    # Parse port string → list[int]
    if raw_ports:
        port_list = sorted(_parse_ports(raw_ports))
    else:
        # No port spec: scan a broad but reasonable default pulled from
        # the 'standard' profile (or fall back to common ports)
        std_ports = load_profiles().get("standard", {}).get("ports", "")
        port_list = sorted(_parse_ports(std_ports)) if std_ports else [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 2222, 2223, 3306, 3389, 5432, 6379, 8080, 8443, 9090,
        ]

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0         = time.perf_counter()

    log.warning(
        "nmap binary absent — using async TCP fallback for %s (%d ports)",
        target, len(port_list),
    )
    action = await _port_scan(target, ports=port_list)
    elapsed = time.perf_counter() - t0

    # Parse "open ports: [22, 80, ...]" out of the detail string
    open_ports: list[int] = []
    try:
        import ast
        raw = action.detail.split("open ports: ")[1]
        open_ports = ast.literal_eval(raw)
    except Exception:
        pass

    hi = HostInfo(ip=target, state="up")
    for p in open_ports:
        hi.ports.append(PortInfo(port=p, protocol="tcp", state="open"))

    return NmapScanResult(
        target=target, profile="fallback",
        scan_args="async-tcp-connect",
        ports_arg=",".join(str(p) for p in port_list),
        started_at=started_at,
        elapsed_s=round(elapsed, 2),
        hosts=[hi] if open_ports else [],
        fallback_used=True,
    )


# ── Public entry point ───────────────────────────────────────────────────────

@safe_target
async def run_nmap_scan(
    host:         str,
    profile:      str           = "standard",
    custom_ports: Optional[str] = None,
) -> ActionResult:
    """
    Main entry point called by the orchestrator stage pipeline and the
    /api/tools router.

    Returns ActionResult where:
      .success  = True when at least one open port was found
      .detail   = JSON-serialised NmapScanResult (includes open_ports,
                  services, has_honeypot_ports as top-level keys)
      .detected = False (detection inference is done by CampaignScorer)
    """
    # Validate profile name — reject unknown names early
    known = set(load_profiles().keys())
    if profile not in known:
        log.warning("Unknown profile '%s', falling back to 'standard'", profile)
        profile = "standard" if "standard" in known else (next(iter(known)) if known else profile)

    loop = asyncio.get_event_loop()

    if _nmap_available():
        try:
            result: NmapScanResult = await loop.run_in_executor(
                None, _run_nmap_sync, host, profile, custom_ports
            )
        except Exception as exc:
            log.exception("nmap executor error")
            result = NmapScanResult(
                target=host, profile=profile, scan_args="",
                ports_arg=custom_ports or "",
                started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                elapsed_s=0.0, error=str(exc),
            )
    else:
        result = await _fallback_scan(host, profile, custom_ports)

    success = bool(result.open_ports) and result.error is None
    return ActionResult(
        action="nmap_scan",
        success=success,
        detail=result.to_json(),
        latency_ms=result.elapsed_s * 1000,
    )