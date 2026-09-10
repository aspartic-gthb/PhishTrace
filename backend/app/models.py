from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy.sql import func
from .database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, index=True)
    domain = Column(String, index=True)
    risk_score = Column(Float)
    risk_level = Column(String)  # SAFE, SUSPICIOUS, HIGH_RISK
    explanation = Column(String)
    
    # Forensic Fields
    sender = Column(String, default="unknown")
    subject = Column(String, default="unknown")
    spf_status = Column(String, default="UNKNOWN")
    dkim_status = Column(String, default="UNKNOWN")
    dmarc_status = Column(String, default="UNKNOWN")
    origin_ip = Column(String, default="unknown")
    received_chain = Column(String, default="[]") # JSON string
    auth_results = Column(String, default="UNKNOWN")
    
    # New Context-Aware Fusion Fields
    trust_score = Column(Float, default=0.0)
    category = Column(String, default="UNKNOWN")
    
    # WHOIS Fields
    domain_age_days = Column(Integer, default=-1)
    whois_registrar = Column(String, default="UNKNOWN")
    
    # Extended Forensic & Geolocation Intelligence Fields
    reply_to = Column(String, default="unknown")
    return_path = Column(String, default="unknown")
    message_id = Column(String, default="unknown")
    origin_country = Column(String, default="unknown")
    origin_city = Column(String, default="unknown")
    origin_isp = Column(String, default="unknown")
    origin_asn = Column(String, default="unknown")
    geo_mismatch = Column(Integer, default=0) # 0=Aligned, 1=Mismatch
    geo_mismatch_reason = Column(String, default="")
    forensic_hash = Column(String, default="")
    evidence_data = Column(String, default="{}") # Full structured JSON forensic record
    attachments_info = Column(String, default="[]") # JSON list of parsed attachment objects
    
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

class BlockedDomain(Base):
    __tablename__ = "blocked_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class AllowedDomain(Base):
    __tablename__ = "allowed_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class GlobalSettings(Base):
    __tablename__ = "global_settings"

    id = Column(Integer, primary_key=True, index=True)
    retention_days = Column(Integer, default=30)
    pii_masking_enabled = Column(Integer, default=1) # 0=False, 1=True (using int for SQLite bool compatibility safety)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class EncryptionMetadata(Base):
    """
    Simulates Key Management Service (KMS) metadata.
    In a real scenario, this would track versions of keys used for column-level encryption.
    """
    __tablename__ = "encryption_keys"

    id = Column(String, primary_key=True, index=True) # UUID
    key_version = Column(Integer, autoincrement=True, unique=True)
    algorithm = Column(String, default="AES-256-GCM")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="ACTIVE") # ACTIVE, ROTATED

class UserAPIKey(Base):
    """
    Stores encrypted API keys for external integrations
    Examples: Gemini API, Email services, Slack webhooks, etc.
    """
    __tablename__ = "user_api_keys"

    id = Column(Integer, primary_key=True, index=True)
    service_name = Column(String, index=True)  # e.g., "gemini", "sendgrid", "slack"
    encrypted_key = Column(String)  # Encrypted API key
    key_version_id = Column(String)  # References encryption_keys.id
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    is_active = Column(Integer, default=1)  # 0=disabled, 1=enabled

