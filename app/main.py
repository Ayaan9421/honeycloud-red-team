"""
RedOps API — main.py
─────────────────────
FastAPI application entry point.
Registers all routers, WebSocket live feed, and lifespan hooks.

Run:
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
"""
import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.db.sessions import init_db
from app.core.redis_client import close_redis, subscribe_campaign
from app.ml.fingerprint_model import seed_synthetic_training_data
from app.ml.defender_inference import load_models

# ── Routers ────────────────────────────────────────────────
from app.api.campaigns   import router as campaigns_router
from app.api.fingerprint import router as fingerprint_router
from app.api.ml          import router as ml_router
from app.api.health      import router as health_router
from app.api.tools import router as tools_router
from app.api.exploits import router as exploits_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("redops")


# ── Lifespan ───────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("━━ RedOps starting up ━━")

    log.info("[1/3] Initialising database...")
    await init_db()

    log.info("[2/3] Seeding fingerprint ML model...")
    seed_synthetic_training_data()

    log.info("[3/3] Loading defender inference models...")
    load_models()

    log.info("━━ RedOps ready ━━  http://0.0.0.0:8000/docs")
    yield

    log.info("━━ RedOps shutting down ━━")
    await close_redis()


# ── App ────────────────────────────────────────────────────
app = FastAPI(
    title="RedOps — Adversarial Honeypot Framework",
    description=(
        "Automated red team engine that fingerprints honeypots, "
        "runs multi-stage APT campaigns, and feeds results back to harden defences."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register routers ───────────────────────────────────────
app.include_router(health_router)
app.include_router(fingerprint_router)
app.include_router(campaigns_router)
app.include_router(tools_router)
app.include_router(exploits_router)
app.include_router(ml_router)

# ── Playbooks listing (lightweight, no router needed) ──────
@app.get("/api/playbooks", tags=["Campaigns"])
async def list_playbooks():
    """List all available campaign playbooks (built-ins + custom YAML)."""
    from app.modules.playbooks import list_playbooks as _list
    return {"playbooks": _list()}


# ── WebSocket live campaign feed ───────────────────────────
@app.websocket("/api/ws/campaigns/{campaign_id}")
async def websocket_campaign_feed(websocket: WebSocket, campaign_id: str):
    """
    Real-time campaign event stream via Redis Pub/Sub.
    Connect from the frontend or test_attack.py to watch stages execute live.

    Message types:
        campaign_start  — campaign kicked off
        stage_start     — a new stage began
        stage_done      — stage completed (includes success, detail, elapsed_ms)
        campaign_done   — all stages complete, includes final scores
    """
    await websocket.accept()
    log.info("WebSocket connected: campaign=%s", campaign_id[:8])

    pubsub = await subscribe_campaign(campaign_id)

    try:
        while True:
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=1.0
            )
            if message and message.get("data"):
                try:
                    payload = json.loads(message["data"])
                    await websocket.send_json(payload)

                    # Close the WS once campaign is done
                    if payload.get("type") == "campaign_done":
                        log.info("Campaign %s done — closing WS", campaign_id[:8])
                        break
                except (json.JSONDecodeError, Exception) as e:
                    log.warning("WS message parse error: %s", e)
            else:
                # Keep-alive ping so the connection doesn't time out
                await asyncio.sleep(0.4)

    except WebSocketDisconnect:
        log.info("WebSocket client disconnected: campaign=%s", campaign_id[:8])
    except Exception as e:
        log.error("WebSocket error (campaign=%s): %s", campaign_id[:8], e)
    finally:
        try:
            await pubsub.unsubscribe(f"campaign:{campaign_id}:events")
        except Exception:
            pass
        log.debug("WebSocket cleaned up: campaign=%s", campaign_id[:8])


# ── Root ───────────────────────────────────────────────────
@app.get("/", tags=["Root"])
async def root():
    return {
        "name":    "RedOps",
        "version": "1.0.0",
        "docs":    "/docs",
        "health":  "/api/health",
        "status":  "operational",
    }