"""
Tools API Router
────────────────
Exposes real attack tool integration (nmap) as first-class API endpoints.

Endpoints:
  POST   /api/tools/scan              — launch a scan job (async, returns job_id)
  GET    /api/tools/scan/{job_id}     — poll job status + results
  GET    /api/tools/scan/profiles     — list profiles live from nmap_profiles.yaml
  GET    /api/tools/scan              — list all past jobs
  DELETE /api/tools/scan/{job_id}     — remove a completed job from memory
  POST   /api/tools/compare           — run scan against multiple targets and diff

Profiles are NOT hardcoded here — they are read live from
campaigns/nmap_profiles.yaml on every request to /profiles.
"""
import asyncio
import json
import logging
import shutil
import uuid
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from app.modules.nmap_scanner import (
    run_nmap_scan,
    get_available_profiles,
    load_profiles,
    NmapScanResult,
)
from app.core.safety import require_allowed_target, TargetNotAllowedError

log = logging.getLogger("redops.api.tools")
router = APIRouter(prefix="/api/tools", tags=["Tools"])

# ── In-process job store ─────────────────────────────────────────────────────
_JOBS: dict[str, dict] = {}


# ── Request / response schemas ────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:       str           = Field(..., description="IP or hostname to scan")
    profile:      str           = Field("standard", description="Profile name from nmap_profiles.yaml")
    custom_ports: Optional[str] = Field(None, description="Override port list, nmap syntax: '22,80,443,8000-8100'")
    notes:        Optional[str] = Field(None, description="Optional label for this job")


class CompareRequest(BaseModel):
    targets:      List[str]     = Field(..., description="List of IPs / hostnames to scan and compare")
    profile:      str           = Field("honeypot", description="Profile to use for all targets")
    custom_ports: Optional[str] = Field(None)


class ScanJobOut(BaseModel):
    job_id:      str
    target:      str
    profile:     str
    status:      str                    # pending | running | done | error
    created_at:  str
    started_at:  Optional[str]  = None
    finished_at: Optional[str]  = None
    elapsed_s:   Optional[float] = None
    notes:       Optional[str]  = None
    result:      Optional[dict] = None  # NmapScanResult as dict, once done
    error:       Optional[str]  = None


# ── Background task ──────────────────────────────────────────────────────────

async def _run_scan_job(
    job_id: str,
    target: str,
    profile: str,
    custom_ports: Optional[str],
) -> None:
    """Runs as a BackgroundTask — updates _JOBS in place."""
    _JOBS[job_id]["status"]     = "running"
    _JOBS[job_id]["started_at"] = datetime.utcnow().isoformat()

    try:
        action = await run_nmap_scan(target, profile=profile, custom_ports=custom_ports)

        try:
            result_dict = json.loads(action.detail)
        except Exception:
            result_dict = {"raw": action.detail}

        _JOBS[job_id].update({
            "status":      "done",
            "finished_at": datetime.utcnow().isoformat(),
            "elapsed_s":   result_dict.get("elapsed_s"),
            "result":      result_dict,
            "error":       result_dict.get("error"),
        })
        log.info("Scan job %s done — success=%s", job_id, action.success)

    except TargetNotAllowedError as exc:
        _JOBS[job_id].update({
            "status":      "error",
            "finished_at": datetime.utcnow().isoformat(),
            "error":       f"Safety block: {exc}",
        })
    except Exception as exc:
        log.exception("Scan job %s failed", job_id)
        _JOBS[job_id].update({
            "status":      "error",
            "finished_at": datetime.utcnow().isoformat(),
            "error":       str(exc),
        })


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/scan/profiles")
async def list_profiles():
    """
    List all available nmap scan profiles.
    Profiles are read live from campaigns/nmap_profiles.yaml —
    edit that file to add or tune profiles without restarting.
    """
    profiles = get_available_profiles()   # reads YAML on every call
    return {
        "profiles":        profiles,
        "profile_count":   len(profiles),
        "profile_names":   [p["name"] for p in profiles],
        "nmap_available":  shutil.which("nmap") is not None,
        "profiles_source": "campaigns/nmap_profiles.yaml",
    }


@router.post("/scan", response_model=ScanJobOut, status_code=202)
async def launch_scan(
    payload: ScanRequest,
    background_tasks: BackgroundTasks,
):
    """
    Launch an nmap scan as a background job.
    Returns immediately with a job_id.
    Poll GET /api/tools/scan/{job_id} for status and results.

    Profile names are validated against the live nmap_profiles.yaml.
    """
    # Validate profile name against live YAML
    known = set(load_profiles().keys())
    if payload.profile not in known:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unknown profile '{payload.profile}'. "
                f"Available: {sorted(known)}. "
                f"Edit campaigns/nmap_profiles.yaml to add new profiles."
            ),
        )

    # Safety check
    try:
        require_allowed_target(payload.target)
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    job_id = str(uuid.uuid4())
    now    = datetime.utcnow().isoformat()

    _JOBS[job_id] = {
        "job_id":      job_id,
        "target":      payload.target,
        "profile":     payload.profile,
        "status":      "pending",
        "created_at":  now,
        "started_at":  None,
        "finished_at": None,
        "elapsed_s":   None,
        "notes":       payload.notes,
        "result":      None,
        "error":       None,
    }

    background_tasks.add_task(
        _run_scan_job, job_id, payload.target, payload.profile, payload.custom_ports
    )

    log.info(
        "Scan job %s queued — target=%s profile=%s",
        job_id, payload.target, payload.profile,
    )
    return _JOBS[job_id]


@router.get("/scan", response_model=List[ScanJobOut])
async def list_scans(
    limit:  int           = Query(20, le=100),
    status: Optional[str] = Query(None, description="pending | running | done | error"),
):
    """List all scan jobs, newest first."""
    jobs = sorted(_JOBS.values(), key=lambda j: j["created_at"], reverse=True)
    if status:
        jobs = [j for j in jobs if j["status"] == status]
    return jobs[:limit]


@router.get("/scan/{job_id}", response_model=ScanJobOut)
async def get_scan(job_id: str):
    """Poll a scan job for its current status and results."""
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found")
    return job


@router.delete("/scan/{job_id}", status_code=204)
async def delete_scan(job_id: str):
    """Remove a completed scan job from the in-memory store."""
    if job_id not in _JOBS:
        raise HTTPException(status_code=404, detail=f"Scan job '{job_id}' not found")
    if _JOBS[job_id]["status"] == "running":
        raise HTTPException(status_code=409, detail="Cannot delete a running scan")
    del _JOBS[job_id]


@router.post("/compare")
async def compare_targets(
    payload: CompareRequest,
):
    """
    Scan multiple targets with the same profile and return a port-level diff.

    Runs all scans concurrently (blocks until all complete).
    Useful for: 'Are these two honeypot configs equally detectable?'
    """
    if len(payload.targets) > 5:
        raise HTTPException(status_code=400, detail="Maximum 5 targets per comparison")

    # Validate profile
    known = set(load_profiles().keys())
    if payload.profile not in known:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown profile '{payload.profile}'. Available: {sorted(known)}",
        )

    for t in payload.targets:
        try:
            require_allowed_target(t)
        except TargetNotAllowedError as exc:
            raise HTTPException(status_code=403, detail=str(exc))

    # Run all scans concurrently
    results = await asyncio.gather(
        *[run_nmap_scan(t, profile=payload.profile, custom_ports=payload.custom_ports)
          for t in payload.targets],
        return_exceptions=True,
    )

    comparison = []
    for target, res in zip(payload.targets, results):
        if isinstance(res, Exception):
            comparison.append({
                "target":              target,
                "error":               str(res),
                "open_ports":          [],
                "services":            {},
                "has_honeypot_ports":  False,
            })
            continue

        try:
            r_dict = json.loads(res.detail)  # type: ignore[union-attr]
        except Exception:
            comparison.append({"target": target, "raw": getattr(res, "detail", str(res))})
            continue

        comparison.append({
            "target":             target,
            "open_ports":         r_dict.get("open_ports", []),
            "port_count":         len(r_dict.get("open_ports", [])),
            "services":           r_dict.get("services", {}),
            "honeypot_score": r_dict.get("honeypot_score"),
            "honeypot_indicators": r_dict.get("honeypot_indicators"),
            "os_match":           (r_dict.get("hosts") or [{}])[0].get("os_match", ""),
            "elapsed_s":          r_dict.get("elapsed_s"),
            "fallback_used":      r_dict.get("fallback_used", False),
            "error":              r_dict.get("error"),
        })

    # Port diff matrix
    all_ports: set[int] = set()
    for c in comparison:
        all_ports.update(c.get("open_ports") or [])

    port_diff = {
        str(port): {
            c["target"]: port in (c.get("open_ports") or [])
            for c in comparison
            if "open_ports" in c
        }
        for port in sorted(all_ports)
    }

    return {
        "profile":    payload.profile,
        "targets":    comparison,
        "port_diff":  port_diff,
        "summary": {
            "total_unique_ports":  len(all_ports),
            "honeypot_detections": sum(1 for c in comparison if (c.get("honeypot_score") or 0) > 0.6),
            "targets_with_errors": sum(1 for c in comparison if c.get("error")),
        },
    }