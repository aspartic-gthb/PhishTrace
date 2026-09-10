import sys, os
sys.path.append('backend')
sys.path.append('.')

from app.database import SessionLocal, engine
from app import models
from app.services.forensic_report import compute_evidence_hash
from datetime import datetime, timedelta, timezone
import json

IST = timezone(timedelta(hours=5, minutes=30))
models.Base.metadata.create_all(bind=engine)
db = SessionLocal()

print("Seeding realistic Email Forensics and Threat Detection records...")

sample_emails = [
    {
        "subject": "CRITICAL: Immediate Executive Wire Transfer Required - Q3 Acquisition [PHONE_REDACTED]",
        "sender": "John Harrison <ceo@chase.com>",
        "domain": "chase.com",
        "reply_to": "exec-finance@bulletproof-smtp.ru",
        "return_path": "bounce@bulletproof-smtp.ru",
        "message_id": "<20260910.8841.chase-corp@bulletproof-smtp.ru>",
        "risk_score": 0.96,
        "risk_level": "CRITICAL",
        "category": "BUSINESS_EMAIL_COMPROMISE",
        "explanation": "Executive impersonation wire diversion attack; Claimed sender domain chase.com failed SPF/DMARC; Earliest relay located in Moscow, Russia via Tor Exit network (PII Masked)",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "origin_ip": "185.220.101.5",
        "origin_country": "Russia",
        "origin_city": "Moscow",
        "origin_isp": "Tor Exit Router Network",
        "origin_asn": "AS208323",
        "geo_mismatch": 1,
        "geo_mismatch_reason": "Origin Mismatch: Email claims to be from JPMorgan Chase (United States), but earliest SMTP relay IP is geolocated in Moscow, Russia (ISP: Tor Exit Router Network).",
        "domain_age_days": 10500,
        "whois_registrar": "CSC Corporate Domains, Inc.",
        "trust_score": 0.0,
        "received_chain": ["185.220.101.5", "194.26.29.1"],
        "signals": {"urgency": 0.95, "fear": 0.88, "authority": 0.98, "impersonation": 0.96},
        "attachments": [
            {
                "filename": "Emergency_Wire_Transfer_Instructions.pdf.exe",
                "extension": ".exe",
                "is_dangerous": True,
                "is_double_extension": True,
                "danger_category": "DOUBLE_EXTENSION_SPOOF",
                "risk_score": 0.99
            }
        ],
        "mins_ago": 5
    },
    {
        "subject": "Security Alert: Verify Your Account Credentials Within 24 Hours",
        "sender": "PayPal Fraud Desk <security-alert@paypal-update-desk.xyz>",
        "domain": "paypal-update-desk.xyz",
        "reply_to": "security-alert@paypal-update-desk.xyz",
        "return_path": "bounce@paypal-update-desk.xyz",
        "message_id": "<PAYPAL-SEC-991283@paypal-update-desk.xyz>",
        "risk_score": 0.91,
        "risk_level": "CRITICAL",
        "category": "CREDENTIAL_HARVESTING",
        "explanation": "Lookalike typosquatting domain targeting PayPal; Registered 4 days ago with high-risk TLD (.xyz); Urgency cues and credential lure detected (PII Masked)",
        "spf_status": "PASS",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "origin_ip": "194.26.29.1",
        "origin_country": "Russia",
        "origin_city": "Saint Petersburg",
        "origin_isp": "Selectel Network Ltd",
        "origin_asn": "AS49505",
        "geo_mismatch": 1,
        "geo_mismatch_reason": "Threat Infrastructure: Origin IP is identified as a bulletproof hosting cluster (Saint Petersburg, Russia).",
        "domain_age_days": 4,
        "whois_registrar": "NameCheap, Inc.",
        "trust_score": 12.0,
        "received_chain": ["194.26.29.1"],
        "signals": {"urgency": 0.92, "fear": 0.89, "authority": 0.84, "impersonation": 0.94},
        "mins_ago": 18
    },
    {
        "subject": "Urgent: Fee Payment Diversion Notification [EMAIL_REDACTED]",
        "sender": "Dr. K. N. Subramanya <principal@rvce.edu.in>",
        "domain": "rvce.edu.in",
        "reply_to": "admissions-rvce@mobile-gateway.ng",
        "return_path": "daemon@mobile-gateway.ng",
        "message_id": "<RVCE-ADM-44120@mobile-gateway.ng>",
        "risk_score": 0.89,
        "risk_level": "CRITICAL",
        "category": "PAYMENT_DIVERSION_FRAUD",
        "explanation": "Educational institutional impersonation of RVCE; Origin IP in Lagos, Nigeria mismatches expected Indian academic infrastructure; Divergent Reply-To address (PII Masked)",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "origin_ip": "102.89.23.10",
        "origin_country": "Nigeria",
        "origin_city": "Lagos",
        "origin_isp": "MTN Nigeria Broadband",
        "origin_asn": "AS29465",
        "geo_mismatch": 1,
        "geo_mismatch_reason": "High Risk Origin: Domain 'rvce.edu.in' (.in) sent from suspicious geographical origin (Lagos, Nigeria via MTN Nigeria Broadband).",
        "domain_age_days": 5200,
        "whois_registrar": "National Internet Exchange of India (NIXI)",
        "trust_score": 8.0,
        "received_chain": ["102.89.23.10"],
        "signals": {"urgency": 0.87, "fear": 0.65, "authority": 0.94, "impersonation": 0.95},
        "mins_ago": 42
    },
    {
        "subject": "Your Receipt for Order #PP-8492041",
        "sender": "service@paypal.com",
        "domain": "paypal.com",
        "reply_to": "service@paypal.com",
        "return_path": "service@paypal.com",
        "message_id": "<8492041.pp@mx.paypal.com>",
        "risk_score": 0.04,
        "risk_level": "SAFE",
        "category": "TRANSACTIONAL",
        "explanation": "Authentic transactional receipt; Strict SPF/DKIM/DMARC alignment verified across PayPal enterprise mail relay in California, USA",
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "origin_ip": "142.250.100.1",
        "origin_country": "United States",
        "origin_city": "Mountain View",
        "origin_isp": "Google LLC",
        "origin_asn": "AS15169",
        "geo_mismatch": 0,
        "geo_mismatch_reason": "",
        "domain_age_days": 9400,
        "whois_registrar": "MarkMonitor, Inc.",
        "trust_score": 98.0,
        "received_chain": ["142.250.100.1"],
        "signals": {"urgency": 0.05, "fear": 0.02, "authority": 0.12, "impersonation": 0.04},
        "mins_ago": 75
    },
    {
        "subject": "Faculty Syndicate Meeting: Academic Curriculum Review",
        "sender": "Academic Dean <dean@rvce.edu.in>",
        "domain": "rvce.edu.in",
        "reply_to": "dean@rvce.edu.in",
        "return_path": "dean@rvce.edu.in",
        "message_id": "<academic-sync-2026@rvce.edu.in>",
        "risk_score": 0.02,
        "risk_level": "SAFE",
        "category": "INTERNAL_COMMUNICATION",
        "explanation": "Authentic internal communication; Verified institutional domain rvce.edu.in via authorized Google Workspace mail exchange",
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "origin_ip": "142.250.100.1",
        "origin_country": "United States",
        "origin_city": "Mountain View",
        "origin_isp": "Google LLC",
        "origin_asn": "AS15169",
        "geo_mismatch": 0,
        "geo_mismatch_reason": "",
        "domain_age_days": 5200,
        "whois_registrar": "National Internet Exchange of India (NIXI)",
        "trust_score": 99.0,
        "received_chain": ["142.250.100.1"],
        "signals": {"urgency": 0.08, "fear": 0.01, "authority": 0.25, "impersonation": 0.02},
        "mins_ago": 110
    }
]

for item in sample_emails:
    scan_time = datetime.now() - timedelta(minutes=item["mins_ago"])
    
    evidence = {
        "subject": item["subject"],
        "sender": item["sender"],
        "message_id": item["message_id"],
        "origin_ip": item["origin_ip"],
        "timestamp": scan_time.isoformat(),
        "risk_score": item["risk_score"]
    }
    evidence_hash = compute_evidence_hash(evidence)

    hop_details = []
    for i, ip in enumerate(item["received_chain"]):
        hop_details.append({
            "hop_index": i + 1,
            "ip": ip,
            "from_host": f"node-{i+1}.mail-relay.net",
            "by_host": "mx.google.com" if i == len(item["received_chain"])-1 else f"node-{i+2}.mail-relay.net",
            "protocol": "ESMTPS",
            "is_private": False,
            "timestamp": scan_time.strftime("%a, %d %b %Y %H:%M:%S +0530")
        })

    full_evidence = {
        "hop_details": hop_details,
        "signals": item["signals"],
        "auth_summary": {
            "spf": item["spf_status"],
            "dkim": item["dkim_status"],
            "dmarc": item["dmarc_status"]
        }
    }

    scan = models.ScanResult(
        url=f"Subject: {item['subject']}\nFrom: {item['sender']}",
        domain=item["domain"],
        risk_score=item["risk_score"],
        risk_level=item["risk_level"],
        explanation=item["explanation"],
        timestamp=scan_time,
        sender=item["sender"],
        subject=item["subject"],
        spf_status=item["spf_status"],
        dkim_status=item["dkim_status"],
        dmarc_status=item["dmarc_status"],
        origin_ip=item["origin_ip"],
        received_chain=json.dumps(item["received_chain"]),
        auth_results=f"spf={item['spf_status'].lower()} dkim={item['dkim_status'].lower()} dmarc={item['dmarc_status'].lower()}",
        trust_score=item["trust_score"],
        category=item["category"],
        domain_age_days=item["domain_age_days"],
        whois_registrar=item["whois_registrar"],
        reply_to=item["reply_to"],
        return_path=item["return_path"],
        message_id=item["message_id"],
        origin_country=item["origin_country"],
        origin_city=item["origin_city"],
        origin_isp=item["origin_isp"],
        origin_asn=item["origin_asn"],
        geo_mismatch=item["geo_mismatch"],
        geo_mismatch_reason=item["geo_mismatch_reason"],
        forensic_hash=evidence_hash,
        evidence_data=json.dumps(full_evidence),
        attachments_info=json.dumps(item.get("attachments", []))
    )
    db.add(scan)

db.commit()
db.close()
print("✅ Seeded 5 high-fidelity forensic threat records successfully!")
