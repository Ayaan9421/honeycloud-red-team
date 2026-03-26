"""
Health Check Router
────────────────────
GET /api/health  — liveness + readiness check
"""
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.db.sessions import get_db
from app.core.redis_client import get_redis
from app.config import settings

router = APIRouter(prefix="/api", tags=["Health"])


@router.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    """Liveness + readiness probe. Returns status of DB and Redis."""
    db_ok    = False
    redis_ok = False
    db_err   = None
    redis_err = None

    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_err = str(e)

    try:
        r = await get_redis()
        await r.ping()
        redis_ok = True
    except Exception as e:
        redis_err = str(e)

    overall = "ok" if (db_ok and redis_ok) else "degraded"

    return {
        "status":    overall,
        "timestamp": datetime.utcnow().isoformat(),
        "env":       settings.app_env,
        "database":  {"connected": db_ok, "error": db_err},
        "redis":     {"connected": redis_ok, "error": redis_err},
        "allowlist": settings.target_allowlist,
    }