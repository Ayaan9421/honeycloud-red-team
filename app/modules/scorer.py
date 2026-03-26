"""
Campaign Scorer
───────────────
Accumulates per-stage results during a campaign run and
computes the four primary metrics + composite Deception Score.

Deception Score = (1 - fingerprint_confidence) × detection_coverage
"""
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
    detected:    bool   = False   # True if honeypot caught this stage
    elapsed_ms:  float  = 0.0
    first_detect_ms: Optional[float] = None


class CampaignScorer:
    def __init__(self):
        self._fingerprint_confidence: float = 0.0
        self._stages: list[StageRecord] = []
        self._campaign_start_ms: float = time.perf_counter() * 1000
        self._first_detection_ms: Optional[float] = None

    def record_fingerprint(self, confidence: float):
        """Store the honeypot fingerprint confidence from the fingerprint stage."""
        self._fingerprint_confidence = confidence

    def record_stage(self, stage_name: str, result: ActionResult, elapsed_ms: float):
        """
        Record a completed stage.
        'detected' is currently heuristic — in a full integration, HoneyCloud's
        alert feed would confirm detection in real-time.
        """
        # Heuristic: if the honeypot banner gave us a canned response,
        # we assume it detected us. Real integration: poll HoneyCloud API.
        detected = self._infer_detection(stage_name, result)

        if detected and self._first_detection_ms is None:
            self._first_detection_ms = (time.perf_counter() * 1000) - self._campaign_start_ms

        rec = StageRecord(
            stage_name=stage_name,
            success=result.success,
            detected=detected,
            elapsed_ms=elapsed_ms,
        )
        self._stages.append(rec)
        log.debug("Stage %s: success=%s detected=%s", stage_name, result.success, detected)

    def _infer_detection(self, stage: str, result: ActionResult) -> bool:
        """
        Heuristic detection inference.
        Replace with real HoneyCloud alert API polling for production.
        """
        detail = (result.detail or "").lower()
        # If we got a login but the shell output looks canned → detected
        if stage == "ssh_exec" and result.success:
            canned_signs = ["honeypot", "fake", "simulation"]
            if any(s in detail for s in canned_signs):
                return True
        # Banner contained known honeypot signature → fingerprint detected us
        if stage == "banner_grab":
            honeypot_banners = ["cowrie", "kippo", "openssh_6.0p1"]
            if any(s in detail for s in honeypot_banners):
                return True
        # High-severity stages on Cowrie always get logged — assume detected
        if stage in ("ssh_brute", "exfil"):
            return result.success  # if we succeeded, Cowrie logged it
        return False

    def compute(self) -> dict:
        """Compute all campaign metrics and return as a dict."""
        total = len(self._stages)
        if total == 0:
            return self._empty_scores()

        detected_count  = sum(1 for s in self._stages if s.detected)
        detection_coverage = detected_count / total  # fraction detected by honeypot

        # Evasion rate = % of stages NOT detected by honeypot
        evasion_rate = 1.0 - detection_coverage

        # Detection latency in seconds (None if never detected)
        detection_latency = (
            self._first_detection_ms / 1000
            if self._first_detection_ms is not None
            else None
        )

        # Kill chain depth = how many stages completed before first detection
        kill_chain_depth = 0
        for s in self._stages:
            if s.detected:
                break
            kill_chain_depth += 1

        # Deception Score: high when attacker couldn't fingerprint the honeypot
        # AND when the honeypot still caught the attack
        deception_score = (1.0 - self._fingerprint_confidence) * detection_coverage

        scores = {
            "fingerprint_score":   round(self._fingerprint_confidence, 4),
            "evasion_rate":        round(evasion_rate, 4),
            "detection_latency":   round(detection_latency, 2) if detection_latency else None,
            "kill_chain_depth":    kill_chain_depth,
            "deception_score":     round(deception_score, 4),
            "stages_total":        total,
            "stages_detected":     detected_count,
            "recommendations":     self._generate_recommendations(
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
            "stages_detected": 0, "recommendations": [],
        }

    def _generate_recommendations(
        self, evasion_rate: float, fp_confidence: float, kill_chain_depth: int
    ) -> list[str]:
        recs = []
        if evasion_rate > 0.3:
            recs.append(f"High evasion rate ({evasion_rate:.0%}) — tighten detection thresholds in HoneyCloud ML pipeline")
        if fp_confidence > 0.7:
            recs.append(f"Honeypot fingerprint confidence is {fp_confidence:.0%} — rotate SSH banner and randomize response timing")
        if kill_chain_depth >= 3:
            recs.append(f"Attacker reached stage {kill_chain_depth} before detection — add earlier-stage alerting rules")
        if evasion_rate < 0.1 and fp_confidence < 0.4:
            recs.append("Excellent deception — honeypot was undetected and caught all attacks. Keep current configuration.")
        if not recs:
            recs.append("Review per-stage logs for fine-grained tuning opportunities.")
        return recs