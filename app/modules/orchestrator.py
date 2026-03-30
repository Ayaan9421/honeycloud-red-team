"""
Campaign Orchestrator
─────────────────────
Executes a multi-stage APT campaign as a FastAPI BackgroundTask.

KEY: Creates its OWN AsyncSession — never uses the request-scoped one.
FastAPI closes request sessions when the HTTP response returns, which is
before the background task finishes. This version is safe.

run_campaign(campaign_id) — the only public entry point.

Changes in this version:
  • Added nmap_scan stage handler — uses real nmap via nmap_scanner module.
  • scorer.record_stage handles nmap_scan with port-based detection inference.
"""
import asyncio
import json
import logging
import time
from datetime import datetime

from sqlalchemy import select

from app.db.sessions import AsyncSessionLocal
from app.db.models import Campaign, CampaignStage, AttackEvent, CampaignStatus, SeverityLevel
from app.modules import fingerprint as fp_module
from app.modules import attack_modules as atk
from app.modules.nmap_scanner import run_nmap_scan
from app.core.redis_client import publish_event
from app.core.safety import require_allowed_target, TargetNotAllowedError
from app.modules.scorer import CampaignScorer

log = logging.getLogger("redops.orchestrator")

STAGE_SEV = {
    "fingerprint": SeverityLevel.LOW,
    "port_scan":   SeverityLevel.LOW,
    "nmap_scan":   SeverityLevel.LOW,
    "banner_grab": SeverityLevel.LOW,
    "ssh_brute":   SeverityLevel.HIGH,
    "ssh_exec":    SeverityLevel.CRITICAL,
    "exfil":       SeverityLevel.CRITICAL,
}

STAGE_ORDER = ["fingerprint", "nmap_scan", "port_scan", "banner_grab", "ssh_brute", "ssh_exec", "exfil"]


async def _pub(campaign_id: str, event_type: str, data: dict):
    try:
        await publish_event(campaign_id, {
            "type":        event_type,
            "campaign_id": campaign_id,
            "ts":          datetime.utcnow().isoformat(),
            "data":        data,
        })
    except Exception as e:
        log.warning("Redis publish failed (non-fatal): %s", e)


async def run_campaign(campaign_id: str):
    """Entry point for BackgroundTasks. Creates its own DB session."""
    async with AsyncSessionLocal() as db:
        await _execute(campaign_id, db)


async def _execute(campaign_id: str, db):
    # ── Load campaign ──────────────────────────────────────────
    result = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    campaign = result.scalar_one_or_none()
    if not campaign:
        log.error("Orchestrator: campaign %s not found in DB", campaign_id)
        return

    # ── Safety re-check ────────────────────────────────────────
    try:
        require_allowed_target(campaign.target_host)
    except TargetNotAllowedError as e:
        log.critical("Orchestrator SAFETY BLOCK: %s", e)
        campaign.status = CampaignStatus.ABORTED
        await db.commit()
        return

    # ── Load playbook ──────────────────────────────────────────
    from app.modules.playbooks import load_playbook
    playbook = load_playbook(campaign.playbook_name)
    playbook_stage_names = [s.name for s in playbook.stages if s.enabled]

    log.info(
        "[%s] Starting campaign → target=%s:%d  playbook=%s  stages=%s",
        campaign_id[:8], campaign.target_host, campaign.target_port,
        campaign.playbook_name, playbook_stage_names
    )

    # ── Mark running ───────────────────────────────────────────
    campaign.status     = CampaignStatus.RUNNING
    campaign.started_at = datetime.utcnow()
    await db.commit()

    await _pub(campaign_id, "campaign_start", {
        "name":    campaign.name,
        "target":  f"{campaign.target_host}:{campaign.target_port}",
        "stages":  playbook_stage_names,
    })

    host       = campaign.target_host
    port       = campaign.target_port
    scorer     = CampaignScorer()
    login_cred = None

    for order, stage_name in enumerate(playbook_stage_names):
        # ── Fetch or create stage record ───────────────────────
        sq = await db.execute(
            select(CampaignStage).where(
                CampaignStage.campaign_id == campaign_id,
                CampaignStage.stage_name  == stage_name,
            )
        )
        stage_rec = sq.scalar_one_or_none()
        if not stage_rec:
            stage_rec = CampaignStage(
                campaign_id=campaign_id,
                stage_name=stage_name,
                stage_order=order,
            )
            db.add(stage_rec)
            await db.flush()

        stage_rec.status     = "running"
        stage_rec.started_at = datetime.utcnow()
        await db.commit()

        await _pub(campaign_id, "stage_start", {
            "stage": stage_name,
            "order": order,
            "total": len(playbook_stage_names),
        })
        log.info(
            "[%s] Stage %d/%d: %s",
            campaign_id[:8], order + 1, len(playbook_stage_names), stage_name
        )

        t0            = time.perf_counter()
        action_result = None

        # ── Run the stage ──────────────────────────────────────
        try:
            if stage_name == "fingerprint":
                fp = await fp_module.run_fingerprint(host, port)
                action_result = atk.ActionResult(
                    action="fingerprint",
                    success=True,
                    detail=json.dumps({
                        k: v for k, v in fp.items() if k != "raw_features_json"
                    }),
                )
                scorer.record_fingerprint(fp.get("honeypot_confidence", 0.0))

            elif stage_name == "nmap_scan":
                # Real nmap scan — use playbook profile if defined,
                # fallback to "honeypot" profile for campaign context
                pb_stage = next((s for s in playbook.stages if s.name == "nmap_scan"), None)
                nmap_profile = getattr(pb_stage, "nmap_profile", "honeypot") if pb_stage else "honeypot"
                action_result = await run_nmap_scan(host, profile=nmap_profile)

                # Publish enriched nmap summary
                try:
                    nmap_data = json.loads(action_result.detail)
                    await _pub(campaign_id, "nmap_result", {
                        "open_ports":         nmap_data.get("open_ports", []) if hasattr(nmap_data, "get") else [],
                        "has_honeypot_ports": nmap_data.get("has_honeypot_ports", False) if hasattr(nmap_data, "get") else False,
                        "elapsed_s":          nmap_data.get("elapsed_s", 0),
                        "fallback_used":      nmap_data.get("fallback_used", False),
                    })
                except Exception:
                    pass

            elif stage_name == "port_scan":
                action_result = await atk.port_scan(host)

            elif stage_name == "banner_grab":
                action_result = await atk.banner_grab(host, port)

            elif stage_name == "ssh_brute":
                pb_stage = next((s for s in playbook.stages if s.name == "ssh_brute"), None)
                action_result = await atk.ssh_brute_force(
                    host, port,
                    max_attempts=pb_stage.max_attempts if pb_stage else 8,
                    dwell_min=pb_stage.dwell_min if pb_stage else 3.0,
                    dwell_max=pb_stage.dwell_max if pb_stage else 8.0,
                )
                if action_result.success and "cred=" in action_result.detail:
                    for part in action_result.detail.split():
                        if part.startswith("cred=") and ":" in part:
                            cred_str = part.split("=", 1)[1]
                            login_cred = cred_str.split(":", 1)
                            log.info("[%s] SSH cred discovered: %s", campaign_id[:8], login_cred[0])
                            break

            elif stage_name == "ssh_exec":
                u, p = login_cred if login_cred else ["root", "root"]
                action_result = await atk.ssh_exec_commands(host, port, u, p)

            elif stage_name == "exfil":
                u, p = login_cred if login_cred else ["root", "root"]
                action_result = await atk.simulate_exfil(host, port, u, p)

            else:
                log.warning("[%s] Unknown stage '%s' — skipping", campaign_id[:8], stage_name)
                action_result = atk.ActionResult(
                    action=stage_name, success=False,
                    detail=f"Unknown stage: {stage_name}"
                )

        except Exception as exc:
            log.exception("[%s] Stage '%s' raised an exception", campaign_id[:8], stage_name)
            action_result = atk.ActionResult(
                action=stage_name, success=False, detail=f"exception: {exc}"
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000
        scorer.record_stage(stage_name, action_result, elapsed_ms)

        # ── Persist stage result ───────────────────────────────
        stage_rec.status       = "done"
        stage_rec.completed_at = datetime.utcnow()
        stage_rec.result_json  = (action_result.detail or "")[:2000]

        db.add(AttackEvent(
            campaign_id=campaign_id,
            stage=stage_name,
            action=action_result.action,
            detail=(action_result.detail or "")[:1000],
            success=action_result.success,
            detected=action_result.detected,
            severity=STAGE_SEV.get(stage_name, SeverityLevel.INFO),
        ))
        await db.commit()

        await _pub(campaign_id, "stage_done", {
            "stage":      stage_name,
            "success":    action_result.success,
            "detected":   action_result.detected,
            "detail":     (action_result.detail or "")[:300],
            "elapsed_ms": round(elapsed_ms, 1),
        })

        # Dwell between stages
        if order < len(playbook_stage_names) - 1:
            pb_stage = next((s for s in playbook.stages if s.name == stage_name), None)
            dwell = pb_stage.dwell_min if pb_stage else 2.0
            log.info("[%s] Dwell %.1fs before next stage", campaign_id[:8], dwell)
            await asyncio.sleep(dwell)

    # ── Compute final scores ───────────────────────────────────
    scores = scorer.compute()

    campaign.status            = CampaignStatus.COMPLETED
    campaign.completed_at      = datetime.utcnow()
    campaign.fingerprint_score = scores["fingerprint_score"]
    campaign.evasion_rate      = scores["evasion_rate"]
    campaign.detection_latency = scores["detection_latency"]
    campaign.kill_chain_depth  = scores["kill_chain_depth"]
    campaign.deception_score   = scores["deception_score"]
    campaign.report_json       = json.dumps(scores)
    await db.commit()

    await _pub(campaign_id, "campaign_done", scores)
    log.info(
        "[%s] ✓ Campaign complete — deception=%.2f  evasion=%.0f%%  depth=%d",
        campaign_id[:8],
        scores["deception_score"],
        scores["evasion_rate"] * 100,
        scores["kill_chain_depth"],
    )