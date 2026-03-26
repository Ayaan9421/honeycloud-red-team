"""
Playbook Loader
───────────────
Loads YAML campaign playbooks from the /campaigns directory.
Each playbook defines the stage sequence, dwell times, abort conditions,
and credential sets for the campaign.

Default playbook is always available without a file (built-in).
"""
import os
import yaml
import logging
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

log = logging.getLogger("redops.playbooks")

PLAYBOOKS_DIR = Path("campaigns")

# ── Stage config ───────────────────────────────────────────
@dataclass
class StageConfig:
    name:       str
    enabled:    bool  = True
    dwell_min:  float = 2.0    # seconds before next stage
    dwell_max:  float = 8.0
    max_attempts: int = 10     # for brute-force stages


# ── Full playbook ──────────────────────────────────────────
@dataclass
class Playbook:
    name:        str
    description: str
    stages:      List[StageConfig] = field(default_factory=list)
    credentials: dict = field(default_factory=dict)   # {username: [passwords]}
    abort_on_detection: bool = False   # stop campaign if honeypot detected early


# ── Built-in default playbook ──────────────────────────────
DEFAULT_PLAYBOOK = Playbook(
    name="default_apt",
    description="Full 6-stage APT simulation — fingerprint through exfil.",
    stages=[
        StageConfig("fingerprint", dwell_min=1.0, dwell_max=2.0),
        StageConfig("port_scan",   dwell_min=1.5, dwell_max=3.0),
        StageConfig("banner_grab", dwell_min=1.0, dwell_max=2.0),
        StageConfig("ssh_brute",   dwell_min=3.0, dwell_max=8.0, max_attempts=8),
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
    description="Slow, patient campaign with extra dwell time — hardest to detect.",
    stages=[
        StageConfig("fingerprint", dwell_min=5.0,  dwell_max=15.0),
        StageConfig("port_scan",   dwell_min=10.0, dwell_max=30.0),
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

FINGERPRINT_ONLY_PLAYBOOK = Playbook(
    name="fingerprint_only",
    description="Only runs the fingerprint stage — non-invasive recon.",
    stages=[
        StageConfig("fingerprint", dwell_min=0.5, dwell_max=1.0),
    ],
    abort_on_detection=False,
)

_BUILTIN: dict[str, Playbook] = {
    "default_apt":      DEFAULT_PLAYBOOK,
    "stealth_apt":      STEALTH_PLAYBOOK,
    "fingerprint_only": FINGERPRINT_ONLY_PLAYBOOK,
}


def load_playbook(name: str) -> Playbook:
    """
    Load a playbook by name.
    Checks built-ins first, then looks for a YAML file in /campaigns.
    """
    # Check built-ins
    if name in _BUILTIN:
        log.debug("Using built-in playbook: %s", name)
        return _BUILTIN[name]

    # Try YAML file
    yaml_path = PLAYBOOKS_DIR / f"{name}.yaml"
    if yaml_path.exists():
        try:
            return _load_yaml(yaml_path)
        except Exception as e:
            log.error("Failed to parse playbook YAML %s: %s", yaml_path, e)

    log.warning("Playbook '%s' not found — using default_apt", name)
    return DEFAULT_PLAYBOOK


def list_playbooks() -> List[dict]:
    """List all available playbooks (built-ins + YAML files)."""
    available = []

    for name, pb in _BUILTIN.items():
        available.append({
            "name":        name,
            "description": pb.description,
            "stages":      len(pb.stages),
            "source":      "builtin",
        })

    if PLAYBOOKS_DIR.exists():
        for yaml_file in PLAYBOOKS_DIR.glob("*.yaml"):
            pb_name = yaml_file.stem
            if pb_name not in _BUILTIN:
                available.append({
                    "name":        pb_name,
                    "description": f"Custom playbook from {yaml_file.name}",
                    "stages":      "?",
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
