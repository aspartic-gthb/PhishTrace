from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from enum import Enum
import uuid

class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"

class AnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="Text content to analyze")
    url: Optional[str] = Field(None, description="Source URL for context (will be hashed)")
    page_title: Optional[str] = Field(None, description="Page Title for Impersonation Check")
    dom_hash: Optional[str] = Field(None, description="Hash of DOM structure/signature")
    local_hour: Optional[int] = Field(None, ge=0, le=23, description="Client local hour 0-23")
    day_of_week: Optional[int] = Field(None, ge=0, le=6, description="Client day 0=Mon, 6=Sun")

class FeatureContribution(BaseModel):
    word: str
    weight: float

class LabelAnalysis(BaseModel):
    probability: float
    top_features: List[FeatureContribution] = Field(default_factory=list)

class AnalysisResponse(BaseModel):
    max_risk_score: float = Field(..., ge=0, le=1)
    risk_level: RiskLevel
    detections: Dict[str, LabelAnalysis]
    explanation: Optional[str] = "Analysis completed successfully."
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_version: str = "1.0.0"
