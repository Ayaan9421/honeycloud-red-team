from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.db.models import CampaignStatus


class CampaignCreate(BaseModel):
    name:          str  = Field(..., example="APT-Sim-001")
    target_host:   str  = Field(..., example="172.20.0.10")
    target_port:   int  = Field(22, example=2222)
    playbook_name: str  = Field("default_apt", example="default_apt")


class CampaignStageOut(BaseModel):
    id:           str
    stage_name:   str
    stage_order:  int
    status:       str
    detected:     bool
    started_at:   Optional[datetime]
    completed_at: Optional[datetime]
    result_json:  Optional[str]

    class Config:
        from_attributes = True


class CampaignOut(BaseModel):
    id:                  str
    name:                str
    target_host:         str
    target_port:         int
    status:              CampaignStatus
    playbook_name:       str
    created_at:          datetime
    started_at:          Optional[datetime]
    completed_at:        Optional[datetime]
    fingerprint_score:   Optional[float]
    evasion_rate:        Optional[float]
    detection_latency:   Optional[float]
    kill_chain_depth:    Optional[int]
    deception_score:     Optional[float]
    stages:              List[CampaignStageOut] = []

    class Config:
        from_attributes = True


class AttackEventOut(BaseModel):
    id:          str
    timestamp:   datetime
    stage:       str
    action:      str
    detail:      Optional[str]
    success:     bool
    detected:    bool
    severity:    str

    class Config:
        from_attributes = True


class FingerprintRequest(BaseModel):
    host: str = Field(..., example="172.20.0.10")
    port: int = Field(22, example=2222)


class FingerprintOut(BaseModel):
    target_host:          str
    target_port:          int
    banner_score:         Optional[float]
    timing_score:         Optional[float]
    filesystem_score:     Optional[float]
    protocol_depth_score: Optional[float]
    honeypot_confidence:  Optional[float]
    is_honeypot:          Optional[bool]
    verdict:              str  # "HONEYPOT" | "REAL" | "UNCERTAIN"

    class Config:
        from_attributes = True


class CampaignReport(BaseModel):
    campaign_id:       str
    name:              str
    target_host:       str
    status:            str
    fingerprint_score: Optional[float]
    evasion_rate:      Optional[float]
    detection_latency: Optional[float]
    kill_chain_depth:  Optional[int]
    deception_score:   Optional[float]
    events:            List[AttackEventOut]
    recommendations:   List[str]
    summary:           str


# WebSocket live event pushed to connected clients
class WSEvent(BaseModel):
    type:        str   # "stage_start" | "stage_done" | "event" | "campaign_done"
    campaign_id: str
    data:        Dict[str, Any]