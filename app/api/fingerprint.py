"""
Fingerprint API Router
───────────────────────
POST /api/fingerprint          — run isolated fingerprint scan
GET  /api/fingerprint/history  — past fingerprint results from DB
"""
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.db.sessions import get_db
from app.db.models import FingerprintResult
from app.schemas.campaign import FingerprintRequest, FingerprintOut
from app.modules.fingerprint import run_fingerprint
from app.core.safety import TargetNotAllowedError

log = logging.getLogger("redops.api.fingerprint")
router = APIRouter(prefix="/api/fingerprint", tags=["Fingerprint"])


@router.post("", response_model=FingerprintOut)
async def api_fingerprint(
    req: FingerprintRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Run a full fingerprint pipeline against a target.
    Returns verdict: HONEYPOT | UNCERTAIN | REAL
    """
    try:
        result = await run_fingerprint(req.host, req.port)
    except TargetNotAllowedError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        log.error("Fingerprint error: %s", e)
        raise HTTPException(status_code=500, detail=f"Fingerprint failed: {e}")

    # Persist to DB
    fp_record = FingerprintResult(
        target_host=result["target_host"],
        target_port=result["target_port"],
        banner_score=result["banner_score"],
        timing_score=result["timing_score"],
        filesystem_score=result["filesystem_score"],
        protocol_depth_score=result["protocol_depth_score"],
        honeypot_confidence=result["honeypot_confidence"],
        is_honeypot=result["is_honeypot"],
        raw_features_json=result.get("raw_features_json"),
    )
    db.add(fp_record)
    await db.commit()

    log.info(
        "Fingerprint complete: %s → %s (confidence=%.2f)",
        req.host, result["verdict"], result["honeypot_confidence"]
    )
    return result


@router.get("/history", response_model=List[FingerprintOut])
async def fingerprint_history(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
):
    """Return the last N fingerprint scan results."""
    result = await db.execute(
        select(FingerprintResult)
        .order_by(desc(FingerprintResult.scanned_at))
        .limit(limit)
    )
    rows = result.scalars().all()

    # Map DB model to schema — add verdict field
    out = []
    for r in rows:
        conf = r.honeypot_confidence or 0.0
        if conf >= 0.75:
            verdict = "HONEYPOT"
        elif conf >= 0.45:
            verdict = "UNCERTAIN"
        else:
            verdict = "REAL"
        out.append(FingerprintOut(
            target_host=r.target_host,
            target_port=r.target_port,
            banner_score=r.banner_score,
            timing_score=r.timing_score,
            filesystem_score=r.filesystem_score,
            protocol_depth_score=r.protocol_depth_score,
            honeypot_confidence=r.honeypot_confidence,
            is_honeypot=r.is_honeypot,
            verdict=verdict,
        ))
    return out