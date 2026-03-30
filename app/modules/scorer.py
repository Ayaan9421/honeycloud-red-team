"""
Campaign Scorer
───────────────
Accumulates per-stage results during a campaign run and
computes the four primary metrics + composite Deception Score.

Changes in this version:
  • _infer_detection handles nmap_scan stage — if port 2222 or 2223 found
    open, it's a honeypot port exposure (detected). Also checks for
    fallback_used flag to distinguish real vs simulated nmap.
  • nmap_scan result is parsed as JSON for richer detection inference.
"""
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from app.modules.attack_modules import ActionResult

log = logging.getLogger("redops.scorer")


@dataclass
class StageRecord:
    stage_name:  str
    success:     bool
    detected:    bool  = False
    elapsed_ms:  float = 0.0


class CampaignScorer:

    def __init__(self):
        self._fingerprint_confidence: float = 0.0
        self._stages: list[StageRecord]     = []
        self._campaign_start_ms: float      = time.perf_counter() * 1000
        self._first_detection_ms: Optional[float] = None

    def record_fingerprint(self, confidence: float):
        self._fingerprint_confidence = confidence

    def record_stage(self, stage_name: str, result: ActionResult, elapsed_ms: float):
        detected = self._infer_detection(stage_name, result)

        if detected and self._first_detection_ms is None:
            self._first_detection_ms = (
                (time.perf_counter() * 1000) - self._campaign_start_ms
            )

        self._stages.append(StageRecord(
            stage_name=stage_name,
            success=result.success,
            detected=detected,
            elapsed_ms=elapsed_ms,
        ))
        log.debug("Stage %s: success=%s detected=%s", stage_name, result.success, detected)

    def _infer_detection(self, stage: str, result: ActionResult) -> bool:
        detail = (result.detail or "").lower()

        # ── Fingerprint ────────────────────────────────────────
        if stage == "fingerprint":
            try:
                fp_data = json.loads(result.detail or "{}")
                verdict = fp_data.get("verdict", "").upper()
                if verdict in ("HONEYPOT", "UNCERTAIN"):
                    return True
                if fp_data.get("honeypot_confidence", 0.0) >= 0.40:
                    return True
            except (json.JSONDecodeError, AttributeError):
                pass
            return False

        # ── Nmap scan ──────────────────────────────────────────
        # Detection = the scan reached the honeypot and found its ports.
        # We consider it "detected by honeypot" if honeypot ports (2222/2223)
        # are open, or if any port is open (Cowrie logs every SYN).
        if stage == "nmap_scan":
            try:
                nmap_data = json.loads(result.detail or "{}")
                open_ports = nmap_data.get("open_ports", [])
                # Honeypot-specific ports
                if set(open_ports) & {2222, 2223}:
                    return True
                # Any successful scan against Cowrie is logged by Cowrie
                if result.success and open_ports:
                    return True
                # Fallback scan also triggers detection if it found ports
                if nmap_data.get("fallback_used") and open_ports:
                    return True
            except (json.JSONDecodeError, AttributeError):
                # If we can't parse, treat success as detected
                return result.success
            return False

        # ── Banner grab ────────────────────────────────────────
        if stage == "banner_grab":
            honeypot_banners = ["cowrie", "kippo", "openssh_6.0p1", "openssh_5.", "openssh_7.4", "libssh"]
            if any(sig in detail for sig in honeypot_banners):
                return True
            return result.success

        # ── Port scan ──────────────────────────────────────────
        if stage == "port_scan":
            if "2222" in detail:
                return True
            return False

        # ── SSH brute force ────────────────────────────────────
        if stage == "ssh_brute":
            if result.success:
                return True
            if "tried=" in detail:
                try:
                    n_tried = int(detail.split("tried=")[1].split()[0])
                    if n_tried > 0:
                        return True
                except (ValueError, IndexError):
                    pass
            return False

        # ── SSH exec + exfil ───────────────────────────────────
        if stage in ("ssh_exec", "exfil"):
            if result.success:
                return True
            if "channel closed" in detail or "authentication failed" in detail:
                return True
            return False

        return False

    def compute(self) -> dict:
        total = len(self._stages)
        if total == 0:
            return self._empty_scores()

        detected_count     = sum(1 for s in self._stages if s.detected)
        detection_coverage = detected_count / total
        evasion_rate       = 1.0 - detection_coverage

        detection_latency = (
            self._first_detection_ms / 1000
            if self._first_detection_ms is not None
            else None
        )

        # Kill chain depth = number of stages completed BEFORE first detection
        kill_chain_depth = 0
        for s in self._stages:
            if s.detected:
                break
            kill_chain_depth += 1

        # Deception Score: (1 - fingerprint_confidence) × detection_coverage
        deception_score = (1.0 - self._fingerprint_confidence) * detection_coverage

        scores = {
            "fingerprint_score":  round(self._fingerprint_confidence, 4),
            "evasion_rate":       round(evasion_rate, 4),
            "detection_latency":  round(detection_latency, 2) if detection_latency else None,
            "kill_chain_depth":   kill_chain_depth,
            "deception_score":    round(deception_score, 4),
            "stages_total":       total,
            "stages_detected":    detected_count,
            "stage_breakdown":    [
                {
                    "stage":    s.stage_name,
                    "success":  s.success,
                    "detected": s.detected,
                }
                for s in self._stages
            ],
            "recommendations": self._generate_recommendations(
                evasion_rate, self._fingerprint_confidence, kill_chain_depth
            ),
        }
        log.info("Campaign scores: %s", scores)
        return scores

    def _empty_scores(self) -> dict:
        return {
            "fingerprint_score": 0.0, "evasion_rate": 0.0,
            "detection_latency": None, "kill_chain_depth": 0,
            "deception_score": 0.0, "stages_total": 0,
            "stages_detected": 0, "stage_breakdown": [],
            "recommendations": [],
        }

    def _generate_recommendations(
        self, evasion_rate: float, fp_confidence: float, kill_chain_depth: int
    ) -> list[str]:
        recs = []

        if fp_confidence > 0.70:
            recs.append(
                f"Honeypot fingerprint confidence is {fp_confidence:.0%} — "
                f"rotate SSH banner and randomise response timing."
            )
        elif fp_confidence > 0.40:
            recs.append(
                f"Honeypot partially fingerprintable ({fp_confidence:.0%}) — "
                f"consider tuning banner string and enabling timing jitter in Cowrie config."
            )

        if evasion_rate > 0.30:
            recs.append(
                f"High evasion rate ({evasion_rate:.0%}) — "
                f"tighten detection thresholds in HoneyCloud ML pipeline."
            )

        if kill_chain_depth >= 4:
            recs.append(
                f"Attacker reached stage {kill_chain_depth} before first detection — "
                f"add earlier-stage alerting (port scan / nmap / banner grab alerts)."
            )
        elif kill_chain_depth >= 2:
            recs.append(
                f"Attacker reached stage {kill_chain_depth} before detection — "
                f"consider enabling faster alert triggers for scan activity."
            )

        if evasion_rate < 0.10 and fp_confidence < 0.40:
            recs.append(
                "Excellent deception — honeypot was not fingerprintable and "
                "detected all attack stages. Current configuration is strong."
            )

        if not recs:
            recs.append(
                "Campaign completed with moderate scores. "
                "Review per-stage logs for fine-grained tuning opportunities."
            )

        return recs