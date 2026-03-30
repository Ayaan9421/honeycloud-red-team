"""
Playbook Loader
───────────────
Loads YAML campaign playbooks from the /campaigns directory.
Each playbook defines the stage sequence, dwell times, abort conditions,
and credential sets for the campaign.

Changes in this version:
  • StageConfig gains optional nmap_profile field.
  • All built-in playbooks now include nmap_scan stage after fingerprint.
  • nmap_profile varies by playbook: aggressive for default, stealth for stealth_apt.
"""
import logging
import yaml
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

log = logging.getLogger("redops.playbooks")

PLAYBOOKS_DIR = Path("campaigns")


# ── Stage config ───────────────────────────────────────────
@dataclass
class StageConfig:
    name:         str
    enabled:      bool  = True
    dwell_min:    float = 2.0
    dwell_max:    float = 8.0
    max_attempts: int   = 10
    nmap_profile: str   = "standard"   # used only by nmap_scan stage


# ── Full playbook ──────────────────────────────────────────
@dataclass
class Playbook:
    name:        str
    description: str
    stages:      List[StageConfig] = field(default_factory=list)
    credentials: dict = field(default_factory=dict)
    abort_on_detection: bool = False


# ── Built-in playbooks ─────────────────────────────────────
DEFAULT_PLAYBOOK = Playbook(
    name="default_apt",
    description="Full 7-stage APT simulation — fingerprint + nmap through exfil.",
    stages=[
        StageConfig("fingerprint", dwell_min=1.0, dwell_max=2.0),
        StageConfig("nmap_scan",   dwell_min=2.0, dwell_max=4.0,  nmap_profile="honeypot"),
        StageConfig("banner_grab", dwell_min=1.0, dwell_max=2.0),
        StageConfig("ssh_brute",   dwell_min=3.0, dwell_max=8.0,  max_attempts=8),
        StageConfig("ssh_exec",    dwell_min=2.0, dwell_max=5.0),
        StageConfig("exfil",       dwell_min=1.0, dwell_max=3.0),
    ],
    credentials={
        "root":  ["root", "toor", "password", "123456"],
        "admin": ["admin", "admin123", "password"],
        "pi":    ["raspberry", "pi"],
    },
    abort_on_detection=False,
)

STEALTH_PLAYBOOK = Playbook(
    name="stealth_apt",
    description="Slow, patient campaign — stealth nmap + maximum dwell times.",
    stages=[
        StageConfig("fingerprint", dwell_min=5.0,  dwell_max=15.0),
        StageConfig("nmap_scan",   dwell_min=10.0, dwell_max=30.0, nmap_profile="stealth"),
        StageConfig("banner_grab", dwell_min=5.0,  dwell_max=10.0),
        StageConfig("ssh_brute",   dwell_min=30.0, dwell_max=90.0, max_attempts=5),
        StageConfig("ssh_exec",    dwell_min=15.0, dwell_max=40.0),
        StageConfig("exfil",       dwell_min=10.0, dwell_max=20.0),
    ],
    credentials={
        "root":  ["root", "toor"],
        "admin": ["admin"],
    },
    abort_on_detection=False,
)

AGGRESSIVE_PLAYBOOK = Playbook(
    name="aggressive_apt",
    description="Fast aggressive campaign — full nmap OS + script scan, rapid brute.",
    stages=[
        StageConfig("fingerprint", dwell_min=0.5, dwell_max=1.0),
        StageConfig("nmap_scan",   dwell_min=1.0, dwell_max=2.0,  nmap_profile="aggressive"),
        StageConfig("banner_grab", dwell_min=0.5, dwell_max=1.0),
        StageConfig("ssh_brute",   dwell_min=1.0, dwell_max=3.0,  max_attempts=15),
        StageConfig("ssh_exec",    dwell_min=1.0, dwell_max=2.0),
        StageConfig("exfil",       dwell_min=0.5, dwell_max=1.0),
    ],
    credentials={
        "root":  ["root", "toor", "password", "123456", "admin"],
        "admin": ["admin", "admin123", "password", "1234"],
        "pi":    ["raspberry", "pi"],
        "user":  ["user", "password"],
    },
    abort_on_detection=False,
)

FINGERPRINT_ONLY_PLAYBOOK = Playbook(
    name="fingerprint_only",
    description="Only runs fingerprint + nmap — non-invasive recon.",
    stages=[
        StageConfig("fingerprint", dwell_min=0.5, dwell_max=1.0),
        StageConfig("nmap_scan",   dwell_min=0.5, dwell_max=1.0, nmap_profile="honeypot"),
    ],
    abort_on_detection=False,
)

NMAP_ONLY_PLAYBOOK = Playbook(
    name="nmap_only",
    description="Pure nmap scan — no SSH interaction. Safe recon playbook.",
    stages=[
        StageConfig("nmap_scan", dwell_min=0.5, dwell_max=1.0, nmap_profile="aggressive"),
    ],
    abort_on_detection=False,
)

_BUILTIN: dict[str, Playbook] = {
    "default_apt":      DEFAULT_PLAYBOOK,
    "stealth_apt":      STEALTH_PLAYBOOK,
    "aggressive_apt":   AGGRESSIVE_PLAYBOOK,
    "fingerprint_only": FINGERPRINT_ONLY_PLAYBOOK,
    "nmap_only":        NMAP_ONLY_PLAYBOOK,
}


def load_playbook(name: str) -> Playbook:
    if name in _BUILTIN:
        log.debug("Using built-in playbook: %s", name)
        return _BUILTIN[name]

    yaml_path = PLAYBOOKS_DIR / f"{name}.yaml"
    if yaml_path.exists():
        try:
            return _load_yaml(yaml_path)
        except Exception as e:
            log.error("Failed to parse playbook YAML %s: %s", yaml_path, e)

    log.warning("Playbook '%s' not found — using default_apt", name)
    return DEFAULT_PLAYBOOK


def list_playbooks() -> List[dict]:
    available = []
    for name, pb in _BUILTIN.items():
        available.append({
            "name":        name,
            "description": pb.description,
            "stages":      [s.name for s in pb.stages],
            "stage_count": len(pb.stages),
            "source":      "builtin",
        })
    if PLAYBOOKS_DIR.exists():
        for yaml_file in PLAYBOOKS_DIR.glob("*.yaml"):
            pb_name = yaml_file.stem
            if pb_name not in _BUILTIN:
                available.append({
                    "name":        pb_name,
                    "description": f"Custom playbook from {yaml_file.name}",
                    "stages":      [],
                    "stage_count": "?",
                    "source":      "yaml",
                })
    return available


def _load_yaml(path: Path) -> Playbook:
    with open(path) as f:
        data = yaml.safe_load(f)

    stages = [
        StageConfig(
            name=s["name"],
            enabled=s.get("enabled", True),
            dwell_min=s.get("dwell_min", 2.0),
            dwell_max=s.get("dwell_max", 8.0),
            max_attempts=s.get("max_attempts", 10),
            nmap_profile=s.get("nmap_profile", "standard"),
        )
        for s in data.get("stages", [])
    ]

    return Playbook(
        name=data["name"],
        description=data.get("description", ""),
        stages=stages,
        credentials=data.get("credentials", {}),
        abort_on_detection=data.get("abort_on_detection", False),
    )