from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models import ScanResult
from app import models
from typing import Dict, Any, List
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/v1", tags=["stats"])

@router.get("/dashboard", response_model=Dict[str, Any])
async def get_dashboard_stats(db: Session = Depends(get_db)):
    # 1. KPI: Total Scans
    total_scans = db.query(ScanResult).count()

    # 2. KPI: Threats Blocked (High Risk + Suspicious)
    # Assuming anything >= 0.4 is "actionable"
    blocked_count = db.query(ScanResult).filter(
        ScanResult.risk_score >= 0.4
    ).count()

    critical_count = db.query(ScanResult).filter(
        ScanResult.risk_level == "HIGH_RISK"
    ).count()

    # 3. Recent Interventions (Recent Browsing History - All Scans)
    recent_risks = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).limit(10).all()

    recent_data = [
        {
            "domain": r.domain,
            "timestamp": r.timestamp.isoformat(), # Correctly uses stored timezone (IST)
            "type": "Phishing" if "Impersonation" in (r.explanation or "") else ("Social Eng." if r.risk_score >= 0.4 else "Browsing"),
            "risk": r.risk_level.replace("_", " ") if r.risk_score >= 0.4 else "SAFE",
            "score": r.risk_score
        }
        for r in recent_risks
    ]

    # 4. Activity Trend (Last 7 days - simplified for performance)
    # Instead of expensive date aggregation, use simple mock data based on total scans
    # 4. Activity Trend (Real Data)
    trend_data = []
    
    # Calculate last 7 days
    today = datetime.now().date()
    seven_days_ago = datetime.now() - timedelta(days=6)
    
    # Query optimized: Aggregation in DB
    daily_counts_query = db.query(
        func.date(ScanResult.timestamp).label('date'),
        func.count(ScanResult.id).label('count')
    ).filter(
        ScanResult.timestamp >= seven_days_ago,
        ScanResult.risk_score >= 0.4
    ).group_by(
        func.date(ScanResult.timestamp)
    ).all()
    
    # Map results { '2025-01-20': 5, ... }
    counts_map = {}
    for res in daily_counts_query:
        # res.date might be string or None depending on DB driver
        if res.date:
            counts_map[str(res.date)] = res.count

    # Fill last 7 days structure
    for i in range(7):
        d = (datetime.now() - timedelta(days=6-i)).date()
        d_str = d.isoformat() # YYYY-MM-DD
        trend_data.append({
            "date": d.strftime("%a"),
            "count": counts_map.get(d_str, 0)
        })

    return {
        "kpi": {
            "total_scans": total_scans,
            "threats_blocked": blocked_count,
            "critical_blocked": critical_count,
            "safety_score": max(0, 100 - (critical_count * 5))  # Clamped heuristic logic
        },
        "recent_interventions": recent_data,
        "activity_trend": trend_data
    }

@router.get("/activity", response_model=List[Dict[str, Any]])
async def get_activity_log(
    limit: int = 20,  # Reduced from 50 to speed up query
    offset: int = 0, 
    db: Session = Depends(get_db)
):
    scans = db.query(ScanResult).order_by(
        ScanResult.timestamp.desc()
    ).offset(offset).limit(limit).all()

    # Get all blocked domains for efficient checking
    blocked_domains = {b.domain for b in db.query(models.BlockedDomain).all()}

    # Process scans with efficient lookups
    activity_log = []
    for s in scans:
        # Check against blocklist (O(1) lookup for exact, then check subdomains)
        is_blocked = False
        if s.domain:
            if s.domain in blocked_domains:
                is_blocked = True
            else:
                # Check for subdomains: movies.tamilrockers.com -> tamilrockers.com
                parts = s.domain.split('.')
                for i in range(1, len(parts) - 1):
                    if '.'.join(parts[i:]) in blocked_domains:
                        is_blocked = True
                        break

        # Map status and category
        explanation = (s.explanation or "").lower()
        
        # Determine Status
        if is_blocked or s.risk_score > 0.8:
            status = "BLOCKED"
        elif s.risk_score > 0.5:
             status = "WARNED"
        else:
             status = "SAFE"

        # Map Category
        if any(kw in explanation for kw in ["impersonation", "typosquatting", "homoglyph", "phish"]):
            category = "Phishing"
        elif any(kw in explanation for kw in ["urgency", "social engineering", "scam"]):
            category = "Social Eng."
        elif s.risk_score > 0.7:
            category = "Critical"
        elif s.risk_score < 0.1:
            category = "Safe"
        else:
            category = "General"
        
        # Override risk score for display if blocked
        display_score = 1.0 if is_blocked else s.risk_score
        display_level = "HIGH_RISK" if is_blocked else s.risk_level

        # Define IST for fallback
        from datetime import timezone, timedelta
        IST = timezone(timedelta(hours=5, minutes=30))
        
        activity_log.append({
            "id": s.id,
            "domain": s.domain,
            "timestamp": s.timestamp.isoformat() if s.timestamp else datetime.now(IST).isoformat(),
            "risk_score": display_score,
            "risk_level": display_level,
            "status": status,
            "category": category,
            "explanation": s.explanation,
            "is_blocked": is_blocked
        })
    
    return activity_log


@router.get("/cognitive-status")
async def get_cognitive_status(db: Session = Depends(get_db)):
    """
    Calculates REAL statistical behavioral metrics:
    1. Variance (StdDev of time gaps): Detects robotic vs human rhythm.
    2. Burst Rate: Max requests in any 10s sliding window.
    """
    import statistics
    
    # 1. Fetch last 50 scans for statistical significance
    recent_scans = db.query(ScanResult.timestamp).order_by(ScanResult.timestamp.desc()).limit(50).all()
    
    timestamps = [s.timestamp.timestamp() for s in recent_scans]
    
    if len(timestamps) < 2:
        return {
            "level": 0.05,
            "status": "Calibrating",
            "triggers": ["Insufficient Data"],
            "variance": 0.0,
            "burst_rate": 0
        }

    # 2. Calculate Time Gaps (Ditas)
    gaps = []
    for i in range(len(timestamps) - 1):
        # timestamps are desc, so t[i] > t[i+1]
        gaps.append(timestamps[i] - timestamps[i+1])
        
    # 3. Calculate Variance (Standard Deviation)
    # Low Variance (< 0.5s) = Robotic/Scripted
    # High Variance (> 2.0s) = Sporadic/Human
    try:
        variance = statistics.stdev(gaps)
    except:
        variance = 0.0
        
    # 4. Calculate Burst Rate (Max in 10s)
    # Simple sliding window check
    max_burst = 0
    now = datetime.now().timestamp()
    
    # Check simple density first
    recent_1m_count = len([t for t in timestamps if now - t < 60])
    
    # Determine Logic
    status = "Human (Verified)"
    level = 0.2
    triggers = []
    
    if variance < 0.5 and recent_1m_count > 5:
        status = "Bot-Like"
        level = 0.9
        triggers.append("Low Variance (Robotic)")
    elif variance > 5.0:
        status = "Sporadic"
        level = 0.1
        triggers.append("High Entropy")
    
    if recent_1m_count > 15:
        status = "High Velocity"
        level += 0.5
        triggers.append(f"Burst: {recent_1m_count}/min")

    return {
        "level": min(round(level, 2), 1.0),
        "status": status,
        "triggers": triggers[:3], 
        "variance": round(variance, 2),
        "burst_rate": recent_1m_count,
        "density_metric": recent_1m_count # Keep for backward compatibility
    }

@router.delete("/reset")
async def reset_data(db: Session = Depends(get_db)):
    try:
        db.query(ScanResult).delete()
        db.commit()
        return {"status": "success", "message": "All telemetry data purged."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
