from sqlalchemy.orm import Session
from app.models import ScanResult
from app.database import SessionLocal
import random
import time
import threading
from datetime import datetime, timedelta

def generate_shadow_telemetry():
    """
    Background worker that generates realistic 'Shadow Telemetry' 
    to keep the dashboard alive with fresh data.
    """
    print("Shadow Telemetry Generator: Starting...")
    
    categories = ["Phishing", "Social Eng.", "Safe", "Critical", "Behavioral Drift"]
    domains = ["bank-security-verify.it", "workforce-sync.com", "google-security-update.net", "fin-portal-auth.co", "identity-nexus.io"]
    explanations = [
        "High urgency patterns detected in incoming SMTP stream.",
        "Anonymized signal mismatch on decentralized mesh node.",
        "Structural DNA collision in DOM verification layer.",
        "Temporal pressure detected in workspace identity context.",
        "Nominal pattern match on verified service signature."
    ]

    while True:
        try:
            db: Session = SessionLocal()
            
            # Generate 1-3 random events every 30-60 seconds
            num_events = random.randint(1, 3)
            for _ in range(num_events):
                risk_score = random.uniform(0.05, 0.95)
                risk_level = "SAFE"
                if risk_score > 0.7: risk_level = "HIGH_RISK"
                elif risk_score > 0.4: risk_level = "SUSPICIOUS"

                new_scan = ScanResult(
                    url=f"https://{random.choice(domains)}/auth/identity",
                    domain=random.choice(domains),
                    risk_score=risk_score,
                    risk_level=risk_level,
                    explanation=f"[Local Behavior] {random.choice(explanations)}",
                    timestamp=datetime.now()
                )
                db.add(new_scan)
            
            db.commit()
            db.close()
            
            # Wait for next pulse
            time.sleep(random.randint(15, 30))
            
        except Exception as e:
            print(f"Shadow Telemetry Generator Error: {e}")
            time.sleep(10)

def start_telemetry_engine():
    # Disabled to allow real user data only
    print("Shadow Telemetry Generator: Disabled by user request.")
    pass
