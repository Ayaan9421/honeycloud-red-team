"""
Fingerprinting Engine  (v2)
────────────────────────────
Collects 4 independent signals that indicate whether a target SSH service
is a honeypot (Cowrie / Kippo / similar) or a real OpenSSH system.

Signal pipeline:
  1. banner_score       — raw TCP banner similarity to known honeypot strings
  2. timing_score       — response-time CV anomaly (honeypots are too consistent)
  3. filesystem_score   — /proc /dev probing via SSH + auth-acceptance signal
  4. protocol_depth     — how deep SSH negotiation goes (weak creds, SFTP, etc.)

Key fixes in v2:
  • THE ROOT BUG: paramiko auth_password(fallback=False) raises
    SSHException("No existing session") after Cowrie accepts the password
    but then sends an "unimplemented" (type 3) packet. This is NOT an auth
    failure — Cowrie DID accept the credentials. We now catch SSHException
    separately from AuthenticationException so Cowrie auth acceptance is
    correctly detected.
  • Filesystem probe tries multiple credential pairs instead of just root/root.
  • Cowrie-specific filesystem tells: /dev device count < 15, /proc/net sparse.
  • Protocol depth probe properly handles the SSHException from Cowrie's
    "unimplemented" response and still awards the honeypot signal.
  • Timing now measures full banner-delivery latency (more discriminating).
  • All probes explicitly use the port passed in (supports port 2222 etc.).
"""
import asyncio
import json
import re
import socket
import time
import logging
from dataclasses import dataclass, asdict, field
from typing import Tuple, List

import paramiko

from app.core.safety import require_allowed_target
from app.ml.fingerprint_model import FingerprintClassifier

log = logging.getLogger("redops.fingerprint")

# ── Honeypot banner signatures ─────────────────────────────
# Each entry: (regex, score)  — score applied when the pattern matches
HONEYPOT_BANNER_SIGNATURES: List[Tuple[str, float]] = [
    (r"SSH-2\.0-OpenSSH_6\.0p1",  0.85),   # Cowrie classic default
    (r"SSH-2\.0-OpenSSH_5\.",      0.75),   # Older Cowrie / Kippo
    (r"SSH-2\.0-OpenSSH_7\.4",     0.65),   # Cowrie 2.x default
    (r"SSH-2\.0-libssh",           0.75),   # Kippo / some Cowrie builds
    (r"SSH-2\.0-OpenSSH_8\.0p1",   0.35),   # Some custom Cowrie configs
    (r"cowrie",                    1.00),
    (r"kippo",                     1.00),
    (r"honeypot",                  1.00),
    (r"dionaea",                   1.00),
    (r"glutton",                   1.00),
]

# Real modern OpenSSH — penalise if matched
REAL_SSH_PATTERNS = [
    r"SSH-2\.0-OpenSSH_[89]\.",
    r"SSH-2\.0-OpenSSH_7\.[5-9]",
]

# (command, fragment_expected_in_real_output)
# Cowrie returns canned/incomplete output for these
PROBE_COMMANDS = [
    ("uname -a",                                 "Linux"),
    ("cat /proc/version",                        "gcc"),
    ("ls /proc/net/ 2>/dev/null | wc -l",        ""),   # checked numerically below
    ("ls /dev/ 2>/dev/null | wc -l",             ""),   # checked numerically below
    ("echo $((2*7))",                             "14"),
    ("cat /etc/os-release 2>/dev/null | head -1","NAME"),
]

# Credential pairs to try — Cowrie accepts most of these
CRED_PAIRS = [
    ("root",  "root"),
    ("root",  "123456"),
    ("admin", "admin"),
    ("root",  "toor"),
    ("root",  "password"),
    ("pi",    "raspberry"),
    ("user",  "user"),
]


@dataclass
class FingerprintSignals:
    banner_score:          float = 0.0
    timing_score:          float = 0.0
    filesystem_score:      float = 0.0
    protocol_depth_score:  float = 0.0
    raw_banner:            str   = ""
    timing_samples:        list  = field(default_factory=list)
    fs_anomalies:          int   = 0
    auth_accepted:         bool  = False
    cowrie_tells:          int   = 0


# ── Signal 1: Banner ───────────────────────────────────────

async def score_banner(host: str, port: int, timeout: float = 6.0) -> Tuple[float, str]:
    """
    Raw TCP connect, read SSH banner, score against honeypot signatures.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner_bytes = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        banner_str = banner_bytes.decode("utf-8", errors="replace").strip()
    except Exception as e:
        log.debug("Banner grab failed %s:%d — %s", host, port, e)
        return 0.0, ""

    log.debug("Raw banner from %s:%d — %r", host, port, banner_str[:80])

    score = 0.0
    for pattern, weight in HONEYPOT_BANNER_SIGNATURES:
        if re.search(pattern, banner_str, re.IGNORECASE):
            score = max(score, weight)
            log.debug("Banner matched %r → score=%.2f", pattern, weight)

    # Penalise for modern real OpenSSH banners
    for pattern in REAL_SSH_PATTERNS:
        if re.search(pattern, banner_str, re.IGNORECASE):
            score = max(0.0, score - 0.3)
            log.debug("Real SSH pattern matched — reducing banner score")
            break

    return round(min(1.0, score), 4), banner_str


# ── Signal 2: Timing ───────────────────────────────────────

async def score_timing(host: str, port: int, samples: int = 8) -> Tuple[float, list]:
    """
    Measures SSH banner delivery latency across multiple connections.
    Cowrie (synchronous Python, no real I/O) has very low response-time
    variance (CV < 0.08). Real SSH has much higher variance.
    """
    times = []
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=4.0
            )
            await asyncio.wait_for(reader.read(128), timeout=4.0)
            elapsed = time.perf_counter() - t0
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            times.append(elapsed)
        except Exception:
            pass
        await asyncio.sleep(0.4)

    if len(times) < 3:
        log.debug("Timing: not enough samples (%d) — skipping", len(times))
        return 0.0, times

    mean = sum(times) / len(times)
    var  = sum((t - mean) ** 2 for t in times) / len(times)
    std  = var ** 0.5
    cv   = std / mean if mean > 0 else 1.0

    # Empirical thresholds from internet-scale SSH fingerprinting research:
    # Cowrie CV typically < 0.08; real SSH typically > 0.18
    if cv < 0.08:
        score = 1.0
    elif cv < 0.18:
        score = 1.0 - ((cv - 0.08) / (0.18 - 0.08))
    else:
        score = 0.0

    log.debug(
        "Timing: mean=%.3fs cv=%.4f score=%.2f (n=%d)",
        mean, cv, score, len(times)
    )
    return round(score, 4), times


# ── Signal 3: Filesystem / SSH probe ──────────────────────

async def score_filesystem(
    host: str, port: int,
    timeout: float = 15.0,
) -> Tuple[float, int]:
    """
    Tries multiple credential pairs (Cowrie accepts most).
    On successful login: runs probe commands and counts filesystem anomalies.
    On all-rejected: small real-system signal.

    KEY FIX: paramiko raises SSHException("No existing session") — NOT
    AuthenticationException — when Cowrie accepts the password but then
    sends an "unimplemented" type-3 packet in response to the next step.
    We treat SSHException after a connect attempt as auth-accepted.
    """
    anomalies     = 0
    auth_accepted = False
    cowrie_tells  = 0

    def _ssh_probe() -> Tuple[int, bool, int]:
        nonlocal anomalies, auth_accepted, cowrie_tells

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connected = False
        for username, password in CRED_PAIRS:
            try:
                client.connect(
                    host, port=port,
                    username=username, password=password,
                    timeout=timeout, banner_timeout=timeout,
                    allow_agent=False, look_for_keys=False,
                )
                auth_accepted = True
                connected = True
                log.debug("FS: SSH auth accepted %s@%s cred=%r", username, host, password)
                break
            except paramiko.AuthenticationException:
                log.debug("FS: SSH auth rejected %s@%s cred=%r", username, host, password)
                continue
            except paramiko.SSHException as e:
                # Cowrie accepts the password then sends an "unimplemented"
                # packet (type 3) which paramiko surfaces as SSHException.
                # This is auth ACCEPTANCE, not rejection.
                log.debug("FS: SSHException (likely Cowrie type-3 unimplemented): %s", e)
                auth_accepted = True
                connected = True
                break
            except Exception as e:
                log.debug("FS: connect error: %s", e)
                break

        if not connected:
            log.debug("FS: all credentials rejected for %s:%d", host, port)
            client.close()
            return 1, False, 0   # mild real-system signal

        # Run probe commands
        for cmd, expected_fragment in PROBE_COMMANDS:
            try:
                _, stdout, _ = client.exec_command(cmd, timeout=8)
                output = stdout.read(2048).decode("utf-8", errors="replace").strip()
                log.debug("FS [%s] → %r", cmd, output[:60])

                if expected_fragment and expected_fragment not in output:
                    anomalies += 1
                    log.debug("FS anomaly: expected %r not found", expected_fragment)
                    continue

                # Numeric Cowrie tells
                if "wc -l" in cmd:
                    try:
                        count = int(output.strip())
                        if "/dev/" in cmd and count < 15:
                            cowrie_tells += 1
                            log.debug("FS Cowrie tell: /dev count=%d (< 15)", count)
                        elif "/proc/net/" in cmd and count < 5:
                            cowrie_tells += 1
                            log.debug("FS Cowrie tell: /proc/net count=%d (< 5)", count)
                    except ValueError:
                        anomalies += 1

            except Exception as e:
                log.debug("FS probe cmd failed: %s", e)
                anomalies += 1

        client.close()
        return anomalies, auth_accepted, cowrie_tells

    loop = asyncio.get_event_loop()
    try:
        anomalies, auth_accepted, cowrie_tells = await loop.run_in_executor(
            None, _ssh_probe
        )
    except Exception as e:
        log.debug("FS executor error: %s", e)

    total_probes = len(PROBE_COMMANDS)
    if auth_accepted:
        base  = anomalies / total_probes if total_probes > 0 else 0.0
        bonus = min(0.30, cowrie_tells * 0.15)
        score = min(1.0, base + bonus)
    else:
        score = 0.10   # all creds rejected — mild real-system signal

    log.debug(
        "FS: auth=%s anomalies=%d/%d cowrie_tells=%d score=%.2f",
        auth_accepted, anomalies, total_probes, cowrie_tells, score
    )
    return round(score, 4), anomalies


# ── Signal 4: Protocol depth ───────────────────────────────

async def score_protocol_depth(host: str, port: int, timeout: float = 12.0) -> float:
    """
    Pushes SSH negotiation beyond normal client behaviour.
    Scores based on:
      +0.15 — completed SSH handshake
      +0.40 — weak creds accepted OR SSHException after auth (Cowrie type-3)
      +0.20 — SFTP subsystem opened
      +0.15 — suspiciously small / listing (Cowrie fake FS)

    KEY FIX: auth_password(fallback=False) raises SSHException on Cowrie
    after password acceptance due to the "unimplemented" type-3 packet.
    We catch that separately and still award the honeypot signal.
    """
    depth_score = 0.0

    def _deep_probe() -> float:
        nonlocal depth_score
        transport = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            transport = paramiko.Transport(sock)
            transport.start_client(timeout=timeout)
            depth_score += 0.15   # completed handshake
            log.debug("Proto: handshake complete (+0.15)")

            # Attempt weak-credential auth
            auth_ok = False
            for username, password in [("root", "root"), ("admin", "admin"), ("pi", "raspberry")]:
                try:
                    transport.auth_password(username, password, fallback=False)
                    auth_ok = True
                    depth_score += 0.40
                    log.debug("Proto: weak creds accepted %s/%s (+0.40)", username, password)
                    break
                except paramiko.AuthenticationException:
                    log.debug("Proto: auth rejected %s/%s", username, password)
                    continue
                except paramiko.SSHException as e:
                    # Cowrie accepted password then sent type-3 "unimplemented"
                    # paramiko raises SSHException here — this IS acceptance
                    auth_ok = True
                    depth_score += 0.40
                    log.debug("Proto: SSHException after auth (Cowrie type-3) (+0.40): %s", e)
                    break
                except Exception as e:
                    log.debug("Proto: auth attempt error: %s", e)
                    break

            # Try SFTP
            if auth_ok:
                try:
                    sftp = transport.open_sftp_client()
                    depth_score += 0.20
                    log.debug("Proto: SFTP opened (+0.20)")
                    try:
                        entries = sftp.listdir("/")
                        if entries and len(entries) < 10:
                            depth_score += 0.15
                            log.debug(
                                "Proto: suspicious / listing (%d entries) (+0.15)",
                                len(entries)
                            )
                    except Exception:
                        pass
                    sftp.close()
                except Exception as e:
                    log.debug("Proto: SFTP failed: %s", e)

        except Exception as e:
            log.debug("Proto: outer probe error: %s", e)
        finally:
            if transport:
                try:
                    transport.close()
                except Exception:
                    pass
        return depth_score

    loop = asyncio.get_event_loop()
    try:
        depth_score = await loop.run_in_executor(None, _deep_probe)
    except Exception as e:
        log.debug("Proto: executor error: %s", e)

    final = round(min(1.0, depth_score), 4)
    log.debug("Proto: final score=%.2f", final)
    return final


# ── Main pipeline ──────────────────────────────────────────

async def run_fingerprint(host: str, port: int = 22) -> dict:
    """
    Full fingerprint pipeline. Runs all 4 signal collectors concurrently.
    Returns a dict ready for DB storage + API response.
    """
    require_allowed_target(host)
    log.info("Starting fingerprint: %s:%d", host, port)

    banner_task = asyncio.create_task(score_banner(host, port))
    timing_task = asyncio.create_task(score_timing(host, port))
    fs_task     = asyncio.create_task(score_filesystem(host, port))
    proto_task  = asyncio.create_task(score_protocol_depth(host, port))

    (banner_score, raw_banner), \
    (timing_score, timing_samples), \
    (fs_score,     fs_anomalies), \
    proto_score = await asyncio.gather(
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

    classifier  = FingerprintClassifier.load()
    features    = [banner_score, timing_score, fs_score, proto_score]
    confidence  = classifier.predict(features)
    is_honeypot = confidence >= 0.55

    if confidence >= 0.70:
        verdict = "HONEYPOT"
    elif confidence >= 0.40:
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
        "honeypot_confidence":   round(confidence, 4),
        "is_honeypot":           is_honeypot,
        "verdict":               verdict,
        "raw_features_json":     json.dumps(asdict(signals)),
    }
    log.info(
        "Fingerprint: %s:%d | banner=%.2f timing=%.2f fs=%.2f proto=%.2f "
        "→ confidence=%.2f verdict=%s",
        host, port,
        banner_score, timing_score, fs_score, proto_score,
        confidence, verdict
    )
    return result