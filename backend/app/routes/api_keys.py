"""
API Key Management Routes
Handles encrypted storage of API keys for external integrations
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models
from app.services.encryption import EncryptionService
from pydantic import BaseModel
from typing import List, Optional
import uuid

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])

# Initialize encryption service
encryption_service = EncryptionService()

class APIKeyCreate(BaseModel):
    service_name: str
    api_key: str

class APIKeyResponse(BaseModel):
    id: int
    service_name: str
    masked_key: str  # Show only last 4 characters
    created_at: str
    is_active: bool

@router.post("/", response_model=APIKeyResponse)
async def store_api_key(payload: APIKeyCreate, db: Session = Depends(get_db)):
    """
    Store an encrypted API key
    
    Example services: gemini, sendgrid, slack, twilio
    """
    try:
        # Get or create active encryption key
        active_key = db.query(models.EncryptionMetadata).filter(
            models.EncryptionMetadata.status == "ACTIVE"
        ).first()
        
        if not active_key:
            # Create first encryption key
            key_id = str(uuid.uuid4())
            active_key = models.EncryptionMetadata(
                id=key_id,
                status="ACTIVE"
            )
            db.add(active_key)
            db.commit()
            print(f"🔑 Created first encryption key: {key_id}")
        
        # Encrypt the API key
        encrypted_key = encryption_service.encrypt(payload.api_key)
        
        # Check if key for this service already exists
        existing = db.query(models.UserAPIKey).filter(
            models.UserAPIKey.service_name == payload.service_name
        ).first()
        
        if existing:
            # Update existing
            existing.encrypted_key = encrypted_key
            existing.key_version_id = active_key.id
            existing.is_active = 1
            db.commit()
            db.refresh(existing)
            api_key_record = existing
            print(f"🔄 Updated API key for: {payload.service_name}")
        else:
            # Create new
            api_key_record = models.UserAPIKey(
                service_name=payload.service_name,
                encrypted_key=encrypted_key,
                key_version_id=active_key.id
            )
            db.add(api_key_record)
            db.commit()
            db.refresh(api_key_record)
            print(f"✅ Stored encrypted API key for: {payload.service_name}")
        
        # Return masked key (show only last 4 chars)
        masked = f"{'*' * (len(payload.api_key) - 4)}{payload.api_key[-4:]}"
        
        return {
            "id": api_key_record.id,
            "service_name": api_key_record.service_name,
            "masked_key": masked,
            "created_at": api_key_record.created_at.isoformat(),
            "is_active": bool(api_key_record.is_active)
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to store API key: {str(e)}")

@router.get("/", response_model=List[APIKeyResponse])
async def list_api_keys(db: Session = Depends(get_db)):
    """
    List all stored API keys (encrypted, showing only masked versions)
    """
    keys = db.query(models.UserAPIKey).all()
    
    result = []
    for key in keys:
        # Decrypt to get length for masking
        try:
            decrypted = encryption_service.decrypt(key.encrypted_key)
            if len(decrypted) > 4:
                masked = f"{'*' * (len(decrypted) - 4)}{decrypted[-4:]}"
            else:
                masked = "*" * len(decrypted)
        except:
            masked = "****[ENCRYPTED]"
        
        result.append({
            "id": key.id,
            "service_name": key.service_name,
            "masked_key": masked,
            "created_at": key.created_at.isoformat(),
            "is_active": bool(key.is_active)
        })
    
    return result

@router.get("/{service_name}/decrypt")
async def get_decrypted_key(service_name: str, db: Session = Depends(get_db)):
    """
    Retrieve and decrypt an API key (use with caution!)
    In production, this would require authentication
    """
    key_record = db.query(models.UserAPIKey).filter(
        models.UserAPIKey.service_name == service_name,
        models.UserAPIKey.is_active == 1
    ).first()
    
    if not key_record:
        raise HTTPException(status_code=404, detail=f"No active API key found for {service_name}")
    
    try:
        decrypted_key = encryption_service.decrypt(key_record.encrypted_key)
        return {
            "service_name": service_name,
            "api_key": decrypted_key,
            "key_version": key_record.key_version_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

@router.delete("/{service_name}")
async def delete_api_key(service_name: str, db: Session = Depends(get_db)):
    """
    Delete an API key
    """
    deleted = db.query(models.UserAPIKey).filter(
        models.UserAPIKey.service_name == service_name
    ).delete()
    
    db.commit()
    
    if deleted == 0:
        raise HTTPException(status_code=404, detail=f"No API key found for {service_name}")
    
    return {"status": "success", "message": f"Deleted API key for {service_name}"}

@router.post("/rotate-all")
async def rotate_all_keys(db: Session = Depends(get_db)):
    """
    Rotate encryption key and re-encrypt all API keys
    """
    try:
        # Get all encrypted keys
        all_keys = db.query(models.UserAPIKey).all()
        
        if not all_keys:
            return {"status": "success", "message": "No keys to rotate"}
        
        # Decrypt all with current key
        decrypted_keys = []
        for key in all_keys:
            decrypted = encryption_service.decrypt(key.encrypted_key)
            decrypted_keys.append((key, decrypted))
        
        # Rotate encryption key
        new_key_id = str(uuid.uuid4())
        
        # Mark old keys as ROTATED
        db.query(models.EncryptionMetadata).filter(
            models.EncryptionMetadata.status == "ACTIVE"
        ).update({"status": "ROTATED"})
        
        # Create new encryption key
        new_key = models.EncryptionMetadata(
            id=new_key_id,
            status="ACTIVE"
        )
        db.add(new_key)
        
        # Re-encrypt all keys with new key
        encryption_service._get_or_create_key()  # Reload key
        
        for key_record, decrypted in decrypted_keys:
            new_encrypted = encryption_service.encrypt(decrypted)
            key_record.encrypted_key = new_encrypted
            key_record.key_version_id = new_key_id
        
        db.commit()
        
        return {
            "status": "success",
            "message": f"Rotated encryption key and re-encrypted {len(all_keys)} API keys",
            "new_key_id": new_key_id,
            "keys_rotated": len(all_keys)
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Key rotation failed: {str(e)}")
