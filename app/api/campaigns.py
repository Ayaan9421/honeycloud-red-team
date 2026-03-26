"""
Campaign API Router
────────────────────
POST   /api/campaigns              — create + launch
GET    /api/campaigns              — list all (filterable by status)
GET    /api/campaigns/{id}         — single campaign + stages
GET    /api/campaigns/{id}/events  — all attack events
GET    /api/campaigns/{id}/report  — full scored report + recommendations
DELETE /api/campaigns/{id}         — abort running campaign

KEY FIX: All queries use selectinload(Campaign.stages) so the stages
relationship is eagerly loaded inside the async session — never lazily
accessed during Pydantic serialization (which triggers MissingGreenlet).
"""
import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.sessions import get_db
from app.db.models import Campaign, CampaignStage, AttackEvent, CampaignStatus
from app.schemas.campaign import (
    CampaignCreate, CampaignOut, AttackEventOut, CampaignReport
)
from app.modules.orchestrator import run_campaign
from app.config import settings

log = logging.getLogger("redops.api.campaigns")
router = APIRouter(prefix="/api/campaigns", tags=["Campaigns"])


def _campaign_query():
    """Base query that always eagerly loads the stages relationship."""
    return select(Campaign).options(selectinload(Campaign.stages))


@router.post("", response_model=CampaignOut, status_code=201)
async def create_campaign(
    payload: CampaignCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create and immediately launch an APT campaign against the target."""

    # ── Safety check ──────────────────────────────────────────
    if not settings.is_target_allowed(payload.target_host):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Target '{payload.target_host}' is not in TARGET_ALLOWLIST. "
                f"Add it to your .env: TARGET_ALLOWLIST=...,{payload.target_host}"
            )
        )

    # ── Concurrency cap ───────────────────────────────────────
    running_q = await db.execute(
        select(Campaign).where(Campaign.status == CampaignStatus.RUNNING)
    )
    if len(running_q.scalars().all()) >= settings.max_concurrent_campaigns:
        raise HTTPException(
            status_code=429,
            detail=f"Max {settings.max_concurrent_campaigns} concurrent campaigns reached."
        )

    # ── Create campaign record ────────────────────────────────
    campaign = Campaign(
        name=payload.name,
        target_host=payload.target_host,
        target_port=payload.target_port,
        playbook_name=payload.playbook_name,
        status=CampaignStatus.PENDING,
    )
    db.add(campaign)
    await db.flush()  # assigns campaign.id without committing

    # ── Create stage records ──────────────────────────────────
    stage_names = ["fingerprint", "port_scan", "banner_grab", "ssh_brute", "ssh_exec", "exfil"]
    for i, name in enumerate(stage_names):
        db.add(CampaignStage(
            campaign_id=campaign.id,
            stage_name=name,
            stage_order=i,
            status="pending",
        ))

    await db.commit()

    # Re-fetch with stages eagerly loaded so Pydantic can serialize it
    result = await db.execute(
        _campaign_query().where(Campaign.id == campaign.id)
    )
    campaign = result.scalar_one()

    # ── Launch as background task ─────────────────────────────
    # DO NOT pass `db` — the request-scoped session closes when this
    # HTTP response returns, before the background task finishes.
    # The orchestrator opens its own AsyncSessionLocal().
    background_tasks.add_task(run_campaign, campaign.id)

    log.info(
        "Campaign %s created → target=%s:%d  playbook=%s",
        campaign.id[:8], payload.target_host, payload.target_port, payload.playbook_name
    )
    return campaign


@router.get("", response_model=List[CampaignOut])
async def list_campaigns(
    limit: int = Query(20, le=100),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = _campaign_query().order_by(Campaign.created_at.desc()).limit(limit)
    if status:
        try:
            q = q.where(Campaign.status == CampaignStatus(status))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status '{status}'. "
                       f"Valid: pending, running, paused, completed, aborted"
            )
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{campaign_id}", response_model=CampaignOut)
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        _campaign_query().where(Campaign.id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")
    return campaign


@router.get("/{campaign_id}/events", response_model=List[AttackEventOut])
async def get_events(campaign_id: str, db: AsyncSession = Depends(get_db)):
    # Verify campaign exists
    exists = await db.execute(select(Campaign).where(Campaign.id == campaign_id))
    if not exists.scalar_one_or_none():
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")

    result = await db.execute(
        select(AttackEvent)
        .where(AttackEvent.campaign_id == campaign_id)
        .order_by(AttackEvent.timestamp)
    )
    return result.scalars().all()


@router.get("/{campaign_id}/report", response_model=CampaignReport)
async def get_report(campaign_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        _campaign_query().where(Campaign.id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")
    if campaign.status not in (CampaignStatus.COMPLETED, CampaignStatus.ABORTED):
        raise HTTPException(
            status_code=409,
            detail=(
                f"Campaign is '{campaign.status.value}' — report available after completion. "
                f"Poll GET /api/campaigns/{campaign_id} to check status."
            )
        )

    ev_result = await db.execute(
        select(AttackEvent)
        .where(AttackEvent.campaign_id == campaign_id)
        .order_by(AttackEvent.timestamp)
    )
    events = ev_result.scalars().all()

    recs = []
    if campaign.report_json:
        try:
            recs = json.loads(campaign.report_json).get("recommendations", [])
        except Exception:
            pass

    ds = campaign.deception_score or 0.0
    if ds >= 0.8:
        summary = "Excellent — honeypot was invisible and caught all attacks."
    elif ds >= 0.5:
        summary = "Moderate — some stages evaded or honeypot was partially fingerprinted."
    else:
        summary = "Poor — attacker fingerprinted the honeypot or evaded detection."

    return CampaignReport(
        campaign_id=campaign.id,
        name=campaign.name,
        target_host=campaign.target_host,
        status=campaign.status.value,
        fingerprint_score=campaign.fingerprint_score,
        evasion_rate=campaign.evasion_rate,
        detection_latency=campaign.detection_latency,
        kill_chain_depth=campaign.kill_chain_depth,
        deception_score=campaign.deception_score,
        events=[AttackEventOut.model_validate(e) for e in events],
        recommendations=recs,
        summary=summary,
    )


@router.delete("/{campaign_id}", status_code=204)
async def abort_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail=f"Campaign '{campaign_id}' not found")
    if campaign.status not in (CampaignStatus.PENDING, CampaignStatus.RUNNING):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot abort campaign in '{campaign.status.value}' state."
        )
    campaign.status = CampaignStatus.ABORTED
    await db.commit()
    log.info("Campaign %s aborted", campaign_id[:8])