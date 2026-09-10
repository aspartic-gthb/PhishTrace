from pydantic import BaseModel
from typing import List, Dict

class DailyCount(BaseModel):
    date: str
    count: int

class GlobalStatsResponse(BaseModel):
    total_scans: int
    threats_blocked: int
    common_patterns: Dict[str, int]
    recent_trend: List[DailyCount]
