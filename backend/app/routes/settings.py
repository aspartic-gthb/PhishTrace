from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models
from pydantic import BaseModel
from datetime import datetime, timedelta

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

class SettingsSchema(BaseModel):
    retention_days: int
    pii_masking_enabled: bool

@router.get("", response_model=SettingsSchema)
async def get_settings(db: Session = Depends(get_db)):
    settings = db.query(models.GlobalSettings).first()
    if not settings:
        # Initialize defaults
        settings = models.GlobalSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    
    return {
        "retention_days": settings.retention_days,
        "pii_masking_enabled": bool(settings.pii_masking_enabled)
    }

@router.post("")
async def update_settings(payload: SettingsSchema, db: Session = Depends(get_db)):
    settings = db.query(models.GlobalSettings).first()
    if not settings:
        settings = models.GlobalSettings()
        db.add(settings)
    
    settings.retention_days = payload.retention_days
    settings.pii_masking_enabled = 1 if payload.pii_masking_enabled else 0
    db.commit()
    
    return {"status": "success", "message": "Settings updated"}

@router.delete("/purge-old")
async def purge_old_data(db: Session = Depends(get_db)):
    """
    Manually trigger retention policy cleanup
    """
    settings = db.query(models.GlobalSettings).first()
    days = settings.retention_days if settings else 30
    
    cutoff_date = datetime.now() - timedelta(days=days)
    
    try:
        deleted = db.query(models.ScanResult).filter(
            models.ScanResult.timestamp < cutoff_date
        ).delete()
        db.commit()
        return {"status": "success", "deleted_count": deleted, "policy_days": days}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/rotate-keys")
async def rotate_encryption_keys(db: Session = Depends(get_db)):
    """
    Rotates the encryption key.
    1. Mark current ACTIVE key as ROTATED.
    2. Generate new UUID key as ACTIVE.
    """
    import uuid
    
    try:
        # 1. Archive old keys
        db.query(models.EncryptionMetadata).filter(
            models.EncryptionMetadata.status == "ACTIVE"
        ).update({"status": "ROTATED"})
        
        # 2. Create new key
        new_key_id = str(uuid.uuid4())
        new_key = models.EncryptionMetadata(
            id=new_key_id,
            status="ACTIVE"
        )
        db.add(new_key)
        db.commit()
        
        return {
            "status": "success", 
            "message": "Master Key Rotated Successfully",
            "new_key_id": new_key_id,
            "algorithm": "AES-256-GCM"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
