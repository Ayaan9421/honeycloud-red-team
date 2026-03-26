from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Enum, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime
import enum
import uuid

Base = declarative_base()


def new_id() -> str:
    return str(uuid.uuid4())


class CampaignStatus(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    ABORTED   = "aborted"


class SeverityLevel(str, enum.Enum):
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Campaign(Base):
    __tablename__ = "campaigns"

    id             = Column(String, primary_key=True, default=new_id)
    name           = Column(String, nullable=False)
    target_host    = Column(String, nullable=False)
    target_port    = Column(Integer, default=22)
    status         = Column(Enum(CampaignStatus), default=CampaignStatus.PENDING)
    playbook_name  = Column(String, nullable=False)

    # Timing
    created_at     = Column(DateTime, default=datetime.utcnow)
    started_at     = Column(DateTime, nullable=True)
    completed_at   = Column(DateTime, nullable=True)

    # Results
    fingerprint_score   = Column(Float, nullable=True)   # 0-1, honeypot confidence
    evasion_rate        = Column(Float, nullable=True)   # % stages not detected
    detection_latency   = Column(Float, nullable=True)   # seconds
    kill_chain_depth    = Column(Integer, nullable=True) # stages completed
    deception_score     = Column(Float, nullable=True)   # composite

    # Raw report JSON
    report_json    = Column(Text, nullable=True)

    stages  = relationship("CampaignStage", back_populates="campaign", cascade="all, delete-orphan")
    events  = relationship("AttackEvent",   back_populates="campaign", cascade="all, delete-orphan")


class CampaignStage(Base):
    __tablename__ = "campaign_stages"

    id           = Column(String, primary_key=True, default=new_id)
    campaign_id  = Column(String, ForeignKey("campaigns.id"), nullable=False)
    stage_name   = Column(String, nullable=False)   # e.g. "fingerprint", "ssh_brute"
    stage_order  = Column(Integer, nullable=False)
    status       = Column(String, default="pending") # pending / running / done / skipped
    started_at   = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    result_json  = Column(Text, nullable=True)
    detected     = Column(Boolean, default=False)   # was this stage caught by the honeypot?

    campaign = relationship("Campaign", back_populates="stages")


class AttackEvent(Base):
    __tablename__ = "attack_events"

    id           = Column(String, primary_key=True, default=new_id)
    campaign_id  = Column(String, ForeignKey("campaigns.id"), nullable=False)
    timestamp    = Column(DateTime, default=datetime.utcnow)
    stage        = Column(String, nullable=False)
    action       = Column(String, nullable=False)   # e.g. "ssh_connect", "send_password"
    detail       = Column(Text, nullable=True)
    success      = Column(Boolean, default=False)
    detected     = Column(Boolean, default=False)
    severity     = Column(Enum(SeverityLevel), default=SeverityLevel.INFO)

    campaign = relationship("Campaign", back_populates="events")


class FingerprintResult(Base):
    __tablename__ = "fingerprint_results"

    id                  = Column(String, primary_key=True, default=new_id)
    campaign_id         = Column(String, ForeignKey("campaigns.id"), nullable=True)
    target_host         = Column(String, nullable=False)
    target_port         = Column(Integer, default=22)
    scanned_at          = Column(DateTime, default=datetime.utcnow)

    # Raw signal values
    banner_score        = Column(Float, nullable=True)   # 0-1 Cowrie similarity
    timing_score        = Column(Float, nullable=True)   # response timing anomaly
    filesystem_score    = Column(Float, nullable=True)   # /proc /dev probing
    protocol_depth_score= Column(Float, nullable=True)  # how deep SSH negotiation goes

    # Composite ML output
    honeypot_confidence = Column(Float, nullable=True)   # final RF prediction
    is_honeypot         = Column(Boolean, nullable=True) # threshold: > 0.6
    raw_features_json   = Column(Text, nullable=True)