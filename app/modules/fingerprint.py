"""
Fingerprinting Engine
─────────────────────
Collects signals that indicate whether a target is a honeypot or a real system.
Four signal channels feed a Random Forest classifier.

Signals:
  1. banner_score       — SSH/HTTP banner similarity to known honeypot strings
  2. timing_score       — response-time distribution anomalies
  3. filesystem_score   — /proc /dev probing via SSH command execution
  4. protocol_depth     — how far SSH/protocol negotiation progresses
"""
import asyncio
import json
import re
import socket
import time
import logging
from dataclasses import dataclass, asdict
from typing import Optional

import paramiko

from app.core.safety import require_allowed_target
from app.ml.fingerprint_model import FingerprintClassifier

log = logging.getLogger("redops.fingerprint")

# ── Known honeypot banner fragments ───────────────────────
HONEYPOT_BANNER_SIGNATURES = [
    r"SSH-2\.0-OpenSSH_6\.0p1",   # Classic Cowrie default
    r"SSH-2\.0-OpenSSH_5\.",       # Old version Cowrie uses
    r"SSH-2\.0-libssh",            # Kippo / some Cowrie builds
    r"SSH-2\.0-OpenSSH_7\.4",      # Common Cowrie 2.x default
    "cowrie",
    "kippo",
    "honeypot",
    "dionaea",
]

# Commands that reveal fake filesystems
PROBE_COMMANDS = [
    ("uname -a",               "Linux"),        # Real kernels have build strings
    ("cat /proc/version",      "gcc"),           # Real /proc/version has gcc info
    ("ls /proc/net/",          "tcp"),           # Real systems have many entries
    ("ls /dev/ | wc -l",       ""),              # Honeypots often have <10 devices
    ("echo $((1+1))",          "2"),             # Arithmetic should work everywhere
]


@dataclass
class FingerprintSignals:
    banner_score:          float = 0.0
    timing_score:          float = 0.0
    filesystem_score:      float = 0.0
    protocol_depth_score:  float = 0.0
    raw_banner:            str   = ""
    timing_samples:        list  = None
    fs_anomalies:          int   = 0

    def __post_init__(self):
        if self.timing_samples is None:
            self.timing_samples = []


async def score_banner(host: str, port: int, timeout: float = 5.0) -> tuple[float, str]:
    """
    Connect raw TCP, grab banner, score against known honeypot signatures.
    Returns (score 0-1, raw_banner).
    """
    try:
        loop = asyncio.get_event_loop()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        banner_str = banner.decode("utf-8", errors="replace").strip()
    except Exception as e:
        log.debug("Banner grab failed: %s", e)
        return 0.0, ""

    matches = sum(
        1 for sig in HONEYPOT_BANNER_SIGNATURES
        if re.search(sig, banner_str, re.IGNORECASE)
    )
    score = min(1.0, matches / 2)  # 2+ matches → confidence 1.0
    log.debug("Banner: %r  score=%.2f", banner_str[:80], score)
    return score, banner_str


async def score_timing(host: str, port: int, samples: int = 6) -> tuple[float, list]:
    """
    Measure response-time jitter.
    Honeypots (especially Cowrie) have unusually consistent response times
    because they're synchronous Python processes with no real I/O load.
    Real systems have natural variance from kernel scheduling.
    """
    times = []
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            await asyncio.wait_for(reader.read(128), timeout=3.0)
            writer.close()
            await writer.wait_closed()
            times.append(time.perf_counter() - t0)
        except Exception:
            pass
        await asyncio.sleep(0.3)

    if len(times) < 3:
        return 0.0, times

    mean = sum(times) / len(times)
    variance = sum((t - mean) ** 2 for t in times) / len(times)
    std_dev = variance ** 0.5
    cv = std_dev / mean if mean > 0 else 0  # coefficient of variation

    # Low CV (< 0.15) → suspiciously consistent → honeypot signal
    score = max(0.0, 1.0 - (cv / 0.15)) if cv < 0.15 else 0.0
    log.debug("Timing CV=%.4f  score=%.2f", cv, score)
    return round(score, 4), times


async def score_filesystem(
    host: str, port: int,
    username: str = "root", password: str = "root",
    timeout: float = 10.0,
) -> tuple[float, int]:
    """
    Login (intentionally weak creds — honeypot will accept them),
    run probe commands, count anomalies in output.
    Returns (score, anomaly_count).
    """
    anomalies = 0
    total_probes = len(PROBE_COMMANDS)

    def _ssh_probe():
        nonlocal anomalies
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=timeout, banner_timeout=timeout,
                allow_agent=False, look_for_keys=False,
            )
            for cmd, expected_fragment in PROBE_COMMANDS:
                try:
                    _, stdout, _ = client.exec_command(cmd, timeout=5)
                    output = stdout.read(1024).decode("utf-8", errors="replace")
                    if expected_fragment and expected_fragment not in output:
                        anomalies += 1
                        log.debug("FS anomaly: cmd=%r expected=%r got=%r", cmd, expected_fragment, output[:60])
                except Exception as e:
                    log.debug("FS probe cmd failed: %s", e)
                    anomalies += 1
        except paramiko.AuthenticationException:
            # Real system rejected creds — that's actually a honeypot signal too
            # (Cowrie accepts almost everything; real systems reject root/root)
            anomalies += 1
        except Exception as e:
            log.debug("SSH connect failed: %s", e)
        finally:
            client.close()
        return anomalies

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _ssh_probe)
    except Exception as e:
        log.debug("Filesystem probe error: %s", e)

    score = anomalies / total_probes if total_probes > 0 else 0.0
    log.debug("Filesystem anomalies=%d/%d  score=%.2f", anomalies, total_probes, score)
    return round(score, 4), anomalies


async def score_protocol_depth(host: str, port: int, timeout: float = 8.0) -> float:
    """
    Push SSH negotiation deeper than normal clients go.
    Real OpenSSH handles all subsystems; Cowrie fails silently on uncommon ones.
    """
    depth_score = 0.0

    def _deep_probe():
        nonlocal depth_score
        transport = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=timeout)
            depth_score += 0.2  # got through handshake

            # Try auth to measure response
            try:
                transport.auth_password("root", "root", fallback=False)
                depth_score += 0.3  # accepted weak creds → likely honeypot
            except paramiko.AuthenticationException:
                pass  # real system — no extra score

            # Attempt sftp subsystem
            try:
                transport.open_sftp_client()
                depth_score += 0.2
            except Exception:
                pass

        except Exception as e:
            log.debug("Protocol depth probe error: %s", e)
        finally:
            if transport:
                transport.close()
        return depth_score

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _deep_probe)
    except Exception:
        pass

    log.debug("Protocol depth score=%.2f", depth_score)
    return round(min(1.0, depth_score), 4)


async def run_fingerprint(host: str, port: int = 22) -> dict:
    """
    Full fingerprint pipeline. Returns a dict ready for DB storage + API response.
    """
    require_allowed_target(host)
    log.info("Starting fingerprint: %s:%d", host, port)

    # Run all signal collectors concurrently
    banner_task   = asyncio.create_task(score_banner(host, port))
    timing_task   = asyncio.create_task(score_timing(host, port))
    fs_task       = asyncio.create_task(score_filesystem(host, port))
    proto_task    = asyncio.create_task(score_protocol_depth(host, port))

    (banner_score, raw_banner), (timing_score, timing_samples), \
    (fs_score, fs_anomalies), proto_score = await asyncio.gather(
        banner_task, timing_task, fs_task, proto_task
    )

    signals = FingerprintSignals(
        banner_score=banner_score,
        timing_score=timing_score,
        filesystem_score=fs_score,
        protocol_depth_score=proto_score,
        raw_banner=raw_banner,
        timing_samples=timing_samples,
        fs_anomalies=fs_anomalies,
    )

    # ML classification
    classifier = FingerprintClassifier.load()
    features   = [banner_score, timing_score, fs_score, proto_score]
    confidence = classifier.predict(features)
    is_honeypot = confidence >= 0.6

    if confidence >= 0.75:
        verdict = "HONEYPOT"
    elif confidence >= 0.45:
        verdict = "UNCERTAIN"
    else:
        verdict = "REAL"

    result = {
        "target_host":           host,
        "target_port":           port,
        "banner_score":          banner_score,
        "timing_score":          timing_score,
        "filesystem_score":      fs_score,
        "protocol_depth_score":  proto_score,
        "honeypot_confidence":   confidence,
        "is_honeypot":           is_honeypot,
        "verdict":               verdict,
        "raw_features_json":     json.dumps(asdict(signals)),
    }
    log.info("Fingerprint result: %s | confidence=%.2f | verdict=%s", host, confidence, verdict)
    return result