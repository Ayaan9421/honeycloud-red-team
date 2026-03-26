"""
ML API Router
──────────────
GET  /api/ml/forecast/{campaign_id}  — Bi-LSTM next move + anomaly score
POST /api/ml/retrain                 — retrain RF classifier on accumulated data
GET  /api/ml/status                  — which models are loaded
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.sessions import get_db
from app.db.models import AttackEvent, FingerprintResult
from app.ml.defender_inference import predict_threat, load_models, _models_loaded
from app.ml.fingerprint_model import FingerprintClassifier

log = logging.getLogger("redops.api.ml")
router = APIRouter(prefix="/api/ml", tags=["ML / Intelligence"])


# ── Forecast ───────────────────────────────────────────────
@router.get("/forecast/{campaign_id}")
async def get_forecast(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Run Bi-LSTM inference on the last 5 events of a campaign.
    Returns: forecasted next move, confidence %, anomaly score, model used.
    """
    result = await db.execute(
        select(AttackEvent)
        .where(AttackEvent.campaign_id == campaign_id)
        .order_by(AttackEvent.timestamp.asc())
    )
    events = result.scalars().all()

    if not events:
        raise HTTPException(
            status_code=404,
            detail="No events found for this campaign yet."
        )

    recent = events[-5:]
    forecast = predict_threat(recent)
    return {
        "campaign_id": campaign_id,
        "events_used": len(recent),
        **forecast,
    }


# ── Model status ───────────────────────────────────────────
@router.get("/status")
async def model_status():
    """Returns which ML models are currently loaded in memory."""
    import os
    from pathlib import Path

    MODEL_DIR = Path("app/ml/models")
    models = {
        "bilstm":           (MODEL_DIR / "bilstm_model.keras").exists(),
        "isolation_forest": (MODEL_DIR / "isolation_forest.pkl").exists(),
        "random_forest":    (MODEL_DIR / "random_forest.pkl").exists(),
        "xgboost":          (MODEL_DIR / "xgboost_classifier.pkl").exists(),
        "fingerprint_rf":   Path("models/fingerprint_rf.pkl").exists(),
    }

    return {
        "models_on_disk": models,
        "inference_ready": _models_loaded,
        "fingerprint_classifier": "rf_trained" if Path("models/fingerprint_rf.pkl").exists() else "heuristic",
    }


# ── Retrain fingerprint RF ──────────────────────────────────
class RetrainRequest(BaseModel):
    label_honeypot_ids: List[str] = []   # fingerprint result IDs to label as honeypot
    label_real_ids:     List[str] = []   # fingerprint result IDs to label as real


@router.post("/retrain")
async def retrain_fingerprint(
    req: RetrainRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Retrain the Random Forest fingerprint classifier using labeled scan results.
    Provide lists of FingerprintResult IDs labelled as honeypot or real.
    """
    all_ids = req.label_honeypot_ids + req.label_real_ids
    if len(all_ids) < 10:
        raise HTTPException(
            status_code=400,
            detail=f"Need at least 10 labeled samples to retrain. Got {len(all_ids)}."
        )

    result = await db.execute(
        select(FingerprintResult).where(FingerprintResult.id.in_(all_ids))
    )
    records = {r.id: r for r in result.scalars().all()}

    X, y = [], []
    for rid in req.label_honeypot_ids:
        if rid in records:
            r = records[rid]
            X.append([
                r.banner_score or 0.0,
                r.timing_score or 0.0,
                r.filesystem_score or 0.0,
                r.protocol_depth_score or 0.0,
            ])
            y.append(1)
    for rid in req.label_real_ids:
        if rid in records:
            r = records[rid]
            X.append([
                r.banner_score or 0.0,
                r.timing_score or 0.0,
                r.filesystem_score or 0.0,
                r.protocol_depth_score or 0.0,
            ])
            y.append(0)

    if len(X) < 10:
        raise HTTPException(
            status_code=400,
            detail=f"Only {len(X)} valid records found after DB lookup. Need ≥10."
        )

    log.info("Retraining RF with %d samples (%d honeypot, %d real)",
             len(X), y.count(1), y.count(0))
    FingerprintClassifier.retrain(X, y)

    return {
        "status": "retrained",
        "samples": len(X),
        "honeypot_labels": y.count(1),
        "real_labels": y.count(0),
    }