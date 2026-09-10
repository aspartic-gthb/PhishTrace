from sqlalchemy.orm import Session
from app.database import get_db
from app.database import get_db
from app import models
from app.models import ScanResult
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from app.schemas.analysis import AnalysisRequest, AnalysisResponse, RiskLevel
from app.services.inference import get_inference_service, InferenceService
from app.services.temporal import analyze_temporal_risk
from app.services.impersonation import analyze_impersonation
import hashlib
import uuid

print("LOADING ANALYSIS MODULE FROM backend/app/routes/analysis.py")
router = APIRouter(prefix="/api/v1", tags=["analysis"])

def get_risk_level(score: float) -> RiskLevel:
    if score >= 0.7:
        return RiskLevel.HIGH_RISK
    elif score >= 0.4:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.SAFE

from pydantic import BaseModel

class BlockRequest(BaseModel):
    domain: str

@router.post("/block")
async def block_domain(request: BlockRequest, db: Session = Depends(get_db)):
    try:
        # Check if already blocked
        exists = db.query(models.BlockedDomain).filter(models.BlockedDomain.domain == request.domain).first()
        if not exists:
            blocked = models.BlockedDomain(domain=request.domain)
            db.add(blocked)
            db.commit()
            return {"status": "success", "message": f"Domain {request.domain} blocked permanently."}
        return {"status": "skipped", "message": "Domain already blocked."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/unblock")
async def unblock_domain(request: BlockRequest, db: Session = Depends(get_db)):
    try:
        blocked = db.query(models.BlockedDomain).filter(models.BlockedDomain.domain == request.domain).first()
        if blocked:
            db.delete(blocked)
            db.commit()
            return {"status": "success", "message": f"Domain {request.domain} unblocked."}
        return {"status": "skipped", "message": "Domain not found in blocklist."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/blocklist")
async def get_blocklist(db: Session = Depends(get_db)):
    """Get all permanently blocked domains"""
    try:
        blocked_domains = db.query(models.BlockedDomain).all()
        return {
            "status": "success",
            "count": len(blocked_domains),
            "domains": [{"domain": bd.domain, "blocked_at": bd.created_at.isoformat() if hasattr(bd, 'created_at') else None} for bd in blocked_domains]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_message(
    request: AnalysisRequest, 
    service: InferenceService = Depends(get_inference_service),
    db: Session = Depends(get_db)
):
    try:
        # 0. BLOCKLIST CHECK (Overriding everything)
        if request.url:
            try:
                parsed = urlparse(request.url)
                domain = parsed.netloc
                if domain:
                    # Check for exact match or subdomain match
                    # We query all blocked domains to check (optimized in prod with specific queries, but fine here)
                    blocked_list = db.query(models.BlockedDomain).all()
                    for blocked_entry in blocked_list:
                         if domain == blocked_entry.domain or domain.endswith("." + blocked_entry.domain):
                             return AnalysisResponse(
                                max_risk_score=1.0,
                                risk_level=RiskLevel.HIGH_RISK,
                                detections={},
                                explanation=f"Access denied. '{blocked_entry.domain}' is in your permanent blocklist.",
                                request_id=str(uuid.uuid4())
                            )
            except:
                pass

        # Note: We do NOT persist request.text or request.url
        results = service.analyze_text(request.text)
        
        # Temporal Analysis
        temporal_multiplier, temporal_warning = analyze_temporal_risk(
            request.local_hour, 
            request.day_of_week, 
            results["max_risk_score"]
        )
        
        max_score = min(results["max_risk_score"] * temporal_multiplier, 1.0)
        risk_lvl = get_risk_level(max_score)
        
        # Simple rule-based explanation
        explanation = f"Content analysis indicates {risk_lvl.value.lower().replace('_', ' ')} behavior."
        if max_score > 0.6:
            explanation += " High urgency or authority patterns detected."
            
        if temporal_warning:
            explanation += f" {temporal_warning}"

        # Impersonation Analysis (Module 3)
        imp_risk_add, imp_warning = analyze_impersonation(request.page_title, request.url)
        max_score = min(max_score + imp_risk_add, 1.0)
        
        # If impersonation detected, force High Risk
        if imp_risk_add > 0:
             risk_lvl = RiskLevel.HIGH_RISK
             explanation = imp_warning # Override explanation with the most critical finding
        else:
             risk_lvl = get_risk_level(max_score)

        # PERSISTENCE: Save result to DB
        # Extract domain safely
        domain = "unknown"
        if request.url:
            try:
                parsed = urlparse(request.url)
                domain = parsed.netloc or request.url[:50]
            except:
                pass

        new_scan = ScanResult(
            url=request.url,
            domain=domain,
            risk_score=max_score,
            risk_level=risk_lvl.name,
            explanation=explanation
        )
        db.add(new_scan)
        db.commit()

        return AnalysisResponse(
            max_risk_score=max_score,
            risk_level=risk_lvl,
            detections=results["detections"],
            explanation=explanation,
            request_id=str(uuid.uuid4())
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
