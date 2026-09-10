from app.database import SessionLocal, engine
from app import models
from datetime import datetime, timedelta
import random

# Init DB
models.Base.metadata.create_all(bind=engine)
db = SessionLocal()

print("Seeding database...")

# Clear existing (optional, but good for clean slate)
# db.query(models.ScanResult).delete()

# Helper for time
def time_ago(mins):
    return datetime.utcnow() - timedelta(minutes=mins)

# Sample Data
samples = [
    {"url": "https://accounts.google.com", "domain": "accounts.google.com", "risk": 0.0, "level": "SAFE", "expl": "Safe Platform detected"},
    {"url": "http://secure-login-update-bank-acc.com", "domain": "secure-login-update-bank-acc.com", "risk": 0.95, "level": "HIGH_RISK", "expl": "Detected as Phishing"},
    {"url": "https://github.com", "domain": "github.com", "risk": 0.0, "level": "SAFE", "expl": "Safe Platform detected"},
    {"url": "http://verify-paypal-limit.net", "domain": "verify-paypal-limit.net", "risk": 0.88, "level": "HIGH_RISK", "expl": "Detected as Phishing"},
    {"url": "https://stackoverflow.com", "domain": "stackoverflow.com", "risk": 0.0, "level": "SAFE", "expl": "Safe Platform detected"},
    {"url": "https://www.youtube.com", "domain": "www.youtube.com", "risk": 0.0, "level": "SAFE", "expl": "Safe Platform detected"},
    {"url": "http://netflix-payment-failed.tk", "domain": "netflix-payment-failed.tk", "risk": 0.92, "level": "HIGH_RISK", "expl": "Detected as Phishing"},
    {"url": "https://react.dev", "domain": "react.dev", "risk": 0.0, "level": "SAFE", "expl": "Safe Platform detected"},
    {"url": "http://amazon-support-case-821.com", "domain": "amazon-support-case-821.com", "risk": 0.75, "level": "HIGH_RISK", "expl": "Detected as Social Eng."},
    {"url": "https://dashboard.stripe.com", "domain": "dashboard.stripe.com", "risk": 0.0, "level": "SAFE", "expl": "Safe Platform detected"},
    {"url": "http://urgent-verify-irs.gov.us.com", "domain": "urgent-verify-irs.gov.us.com", "risk": 0.98, "level": "HIGH_RISK", "expl": "Detected as Phishing (Impersonation)"},
]

# Generate ~30 entries
for i in range(30):
    sample = random.choice(samples)
    
    # Add random variation
    time_offset = random.randint(1, 1000)
    risk_variance = random.uniform(-0.05, 0.05) if sample['risk'] > 0 else 0
    final_risk = max(0.0, min(1.0, sample['risk'] + risk_variance))
    
    scan = models.ScanResult(
        url=sample['url'],
        domain=sample['domain'],
        risk_score=final_risk,
        risk_level=sample['level'],
        explanation=sample['expl'],
        timestamp=time_ago(time_offset)
    )
    db.add(scan)

db.commit()
db.close()
print("✅ Database seeded with 30 initial history items.")
