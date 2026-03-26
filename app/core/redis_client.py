import json
import redis.asyncio as aioredis
from app.config import settings

_redis: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def close_redis():
    global _redis
    if _redis:
        await _redis.close()
        _redis = None


# ── Campaign state helpers ─────────────────────────────────

async def set_campaign_state(campaign_id: str, state: dict, ttl: int = 86400):
    r = await get_redis()
    await r.setex(f"campaign:{campaign_id}:state", ttl, json.dumps(state))


async def get_campaign_state(campaign_id: str) -> dict | None:
    r = await get_redis()
    raw = await r.get(f"campaign:{campaign_id}:state")
    return json.loads(raw) if raw else None


async def delete_campaign_state(campaign_id: str):
    r = await get_redis()
    await r.delete(f"campaign:{campaign_id}:state")


# ── Pub/Sub for WebSocket live feed ───────────────────────

async def publish_event(campaign_id: str, event: dict):
    r = await get_redis()
    await r.publish(f"campaign:{campaign_id}:events", json.dumps(event))


async def subscribe_campaign(campaign_id: str):
    r = await get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(f"campaign:{campaign_id}:events")
    return pubsub