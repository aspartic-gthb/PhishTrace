from pydantic import BaseModel, Field
from typing import List
from enum import Enum

class ActionTaken(str, Enum):
    BLOCKED = "BLOCKED"
    WARNED = "WARNED"
    IGNORED = "IGNORED"

class RiskEvent(BaseModel):
    domain_hash: str = Field(..., description="SHA-256 hash of the domain")
    timestamp: int = Field(..., description="Unix timestamp (rounded)")
    risk_bucket: int = Field(..., ge=0, le=10, description="Risk score bucket (0-10)")
    labels: List[str] = Field(default_factory=list, description="Detected patterns")
    action_taken: ActionTaken
