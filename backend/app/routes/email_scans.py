"""
Real-time Email Scans & Forensic Intelligence API
Provides live feed of email threat scans, deep forensic reports,
evidence hash verification, and PDF export for the SOC Analyst Dashboard.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Response, UploadFile, File
from fastapi.responses import Response, JSONResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app import models
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import os
import io

from app.services.forensic_report import build_structured_forensic_report, generate_forensic_pdf, compute_evidence_hash
from app.services.email_forensics import parse_raw_email_headers
from app.services.ip_geolocation import geolocate_ip, evaluate_origin_mismatch
from app.services.dns_analysis import analyze_sender_domain_dns
from app.services.email_risk import fuse_email_risk_scores

router = APIRouter(prefix="/api/v1/email-scans", tags=["email-scans"])

def format_scan_entry(scan: models.ScanResult) -> Dict[str, Any]:
    """Helper to convert ScanResult ORM object into rich dictionary"""
    subject = scan.subject if scan.subject and scan.subject != "unknown" else ""
    sender = scan.sender if scan.sender and scan.sender != "unknown" else ""
    
    if not subject and not sender and scan.url:
        lines = scan.url.split('\n')
        for line in lines:
            if line.startswith("Subject:"):
                subject = line.replace("Subject:", "").strip()
            elif line.startswith("From:"):
                sender = line.replace("From:", "").strip()

    # Parse received chain JSON if available
    received_chain = []
    try:
        if scan.received_chain:
            received_chain = json.loads(scan.received_chain)
    except Exception:
        received_chain = []

    # Parse full evidence snapshot if saved
    evidence = {}
    try:
        if getattr(scan, "evidence_data", None):
            evidence = json.loads(scan.evidence_data)
    except Exception:
        evidence = {}

    # Parse attachments
    attachments = []
    try:
        if getattr(scan, "attachments_info", None):
            attachments = json.loads(scan.attachments_info)
        elif evidence and "attachments" in evidence:
            attachments = evidence["attachments"]
    except Exception:
        attachments = []

    return {
        "id": scan.id,
        "subject": subject or "Confidential Subject",
        "sender": sender or "unknown@domain.com",
        "sender_domain": scan.domain or (sender.split("@")[-1] if "@" in sender else "unknown"),
        "risk_score": scan.risk_score or 0.0,
        "risk_level": scan.risk_level or "SAFE",
        "explanation": scan.explanation or "",
        "timestamp": scan.timestamp.isoformat() if scan.timestamp else datetime.now().isoformat(),
        # Authentication
        "spf_status": getattr(scan, "spf_status", "UNKNOWN") or "UNKNOWN",
        "dkim_status": getattr(scan, "dkim_status", "UNKNOWN") or "UNKNOWN",
        "dmarc_status": getattr(scan, "dmarc_status", "UNKNOWN") or "UNKNOWN",
        "auth_results": getattr(scan, "auth_results", "UNKNOWN") or "UNKNOWN",
        "trust_score": getattr(scan, "trust_score", 0.0) or 0.0,
        "category": getattr(scan, "category", "UNKNOWN") or "UNKNOWN",
        # Sender Domain Intel
        "domain_age_days": getattr(scan, "domain_age_days", -1),
        "whois_registrar": getattr(scan, "whois_registrar", "UNKNOWN") or "UNKNOWN",
        # Extended Forensics & Geolocation
        "reply_to": getattr(scan, "reply_to", "unknown") or "unknown",
        "return_path": getattr(scan, "return_path", "unknown") or "unknown",
        "message_id": getattr(scan, "message_id", "unknown") or "unknown",
        "origin_ip": getattr(scan, "origin_ip", "unknown") or "unknown",
        "origin_country": getattr(scan, "origin_country", "Unknown") or "Unknown",
        "origin_city": getattr(scan, "origin_city", "Unknown") or "Unknown",
        "origin_isp": getattr(scan, "origin_isp", "Unknown") or "Unknown",
        "origin_asn": getattr(scan, "origin_asn", "N/A") or "N/A",
        "origin_latitude": (evidence.get("geo_intel", {}) or {}).get("lat") or (evidence.get("geolocation", {}) or {}).get("lat") or 0.0,
        "origin_longitude": (evidence.get("geo_intel", {}) or {}).get("lon") or (evidence.get("geolocation", {}) or {}).get("lon") or 0.0,
        "geo_mismatch": bool(getattr(scan, "geo_mismatch", 0)),
        "geo_mismatch_reason": getattr(scan, "geo_mismatch_reason", "") or "",
        "received_chain": received_chain,
        "forensic_hash": getattr(scan, "forensic_hash", "") or "",
        "attachments": attachments,
        "evidence_data": evidence
    }

@router.get("/recent", response_model=List[Dict[str, Any]])
async def get_recent_email_scans(limit: int = 20, db: Session = Depends(get_db)):
    """
    Get recent email scans for real-time display in the Analyst Dashboard.
    """
    try:
        # Fetch scans ordered by newest first
        scans = db.query(models.ScanResult).order_by(
            models.ScanResult.timestamp.desc()
        ).limit(limit * 2).all()
        
        result = []
        for scan in scans:
            is_email = (
                (scan.subject and scan.subject != "unknown") or 
                (scan.sender and scan.sender != "unknown") or
                ("Subject:" in (scan.url or "")) or 
                ("From:" in (scan.url or ""))
            )
            
            if is_email:
                result.append(format_scan_entry(scan))
                if len(result) >= limit:
                    break
        
        return result
        
    except Exception as e:
        print(f"Error fetching email scans: {e}")
        return []

@router.get("/stats")
async def get_email_scan_stats(db: Session = Depends(get_db)):
    """
    Get comprehensive SOC statistics about scanned emails.
    """
    try:
        one_day_ago = datetime.now() - timedelta(days=1)
        
        total_scans = db.query(models.ScanResult).count()
        if total_scans == 0:
            return {
                "total_scans": 0,
                "high_risk": 0,
                "suspicious": 0,
                "safe_emails": 0,
                "total_emails_scanned_24h": 0,
                "phishing_detected_24h": 0,
                "safe_emails_24h": 0,
                "detection_rate": 0.0,
                "geo_mismatches_flagged": 0,
                "auth_failures": 0
            }

        phishing_detected = db.query(models.ScanResult).filter(
            models.ScanResult.risk_score >= 0.70
        ).count()

        suspicious = db.query(models.ScanResult).filter(
            models.ScanResult.risk_score >= 0.40,
            models.ScanResult.risk_score < 0.70
        ).count()

        safe = max(total_scans - phishing_detected - suspicious, 0)
        
        geo_mismatches = db.query(models.ScanResult).filter(
            models.ScanResult.geo_mismatch == 1
        ).count()

        auth_fails = db.query(models.ScanResult).filter(
            (models.ScanResult.spf_status == "FAIL") | 
            (models.ScanResult.dmarc_status == "FAIL")
        ).count()

        return {
            "total_scans": total_scans,
            "high_risk": phishing_detected,
            "suspicious": suspicious,
            "safe_emails": safe,
            "total_emails_scanned_24h": total_scans,
            "phishing_detected_24h": phishing_detected,
            "safe_emails_24h": safe,
            "detection_rate": round((phishing_detected / total_scans * 100), 1) if total_scans > 0 else 0.0,
            "geo_mismatches_flagged": geo_mismatches,
            "auth_failures": auth_fails
        }
        
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return {
            "total_scans": 0,
            "high_risk": 0,
            "suspicious": 0,
            "safe_emails": 0,
            "total_emails_scanned_24h": 0,
            "phishing_detected_24h": 0,
            "safe_emails_24h": 0,
            "detection_rate": 0.0
        }

@router.get("/campaigns")
async def get_email_campaigns(db: Session = Depends(get_db)):
    """
    Searchable Case Management & Threat Campaign Clustering.
    Groups related fraudulent emails by shared infrastructure, origin IP,
    Reply-To aliases, or lookalike domain targets into cohesive campaigns.
    """
    scans = db.query(models.ScanResult).filter(
        (models.ScanResult.risk_score >= 0.40) | (models.ScanResult.geo_mismatch == 1)
    ).order_by(models.ScanResult.timestamp.desc()).all()

    clusters = {}

    for scan in scans:
        entry = format_scan_entry(scan)
        origin_ip = entry.get("origin_ip", "unknown")
        reply_to = entry.get("reply_to", "unknown")
        domain = entry.get("sender_domain", "unknown")

        cluster_key = ""
        cluster_name = ""
        actor_desc = ""

        if "185.220.101" in origin_ip or "194.26.29" in origin_ip or "bulletproof-smtp.ru" in reply_to:
            cluster_key = "CAMP-RU-TOR-01"
            cluster_name = "Operation StealWire (Russian Tor / Bulletproof Cluster)"
            actor_desc = "Eastern European Cybercrime Syndicate utilizing Tor exit routing & bulletproof relays for executive wire fraud."
        elif "102.89." in origin_ip or "mobile-gateway.ng" in reply_to or ".ng" in reply_to:
            cluster_key = "CAMP-NG-FEE-02"
            cluster_name = "Operation IvoryLure (Institutional Fee Diversion)"
            actor_desc = "West African financial fraud ring targeting academic and institutional tuition fee collection."
        elif ".xyz" in domain or ".top" in domain or "paypal" in domain or "chase" in domain:
            cluster_key = f"CAMP-SPOOF-{domain.replace('.', '-')}"
            cluster_name = f"Operation MirrorBrand ({domain} Typo-Squatting)"
            actor_desc = f"Domain spoofing campaign hosting credential harvesting portals targeting {domain} users."
        else:
            cluster_key = f"CAMP-MISC-{entry.get('origin_country', 'UNKNOWN')}"
            cluster_name = f"Campaign Cluster ({entry.get('origin_country', 'Global')})"
            actor_desc = f"Anomalous sender infrastructure originating from {entry.get('origin_country', 'Unknown')}."

        if cluster_key not in clusters:
            clusters[cluster_key] = {
                "campaign_id": cluster_key,
                "name": cluster_name,
                "threat_actor_profile": actor_desc,
                "severity": "CRITICAL" if entry["risk_score"] >= 0.75 else "HIGH",
                "target_brands": set(),
                "origin_countries": set(),
                "origin_ips": set(),
                "reply_to_aliases": set(),
                "incident_count": 0,
                "incidents": [],
                "first_seen": entry["timestamp"],
                "last_seen": entry["timestamp"]
            }

        c = clusters[cluster_key]
        c["incident_count"] += 1
        c["incidents"].append(entry)
        if entry.get("sender_domain"): c["target_brands"].add(entry["sender_domain"])
        if entry.get("origin_country"): c["origin_countries"].add(entry["origin_country"])
        if entry.get("origin_ip") and entry["origin_ip"] != "unknown": c["origin_ips"].add(entry["origin_ip"])
        if entry.get("reply_to") and entry["reply_to"] != "unknown": c["reply_to_aliases"].add(entry["reply_to"])
        if entry["timestamp"] < c["first_seen"]: c["first_seen"] = entry["timestamp"]
        if entry["timestamp"] > c["last_seen"]: c["last_seen"] = entry["timestamp"]

    results = []
    for c in clusters.values():
        results.append({
            "campaign_id": c["campaign_id"],
            "name": c["name"],
            "threat_actor_profile": c["threat_actor_profile"],
            "severity": c["severity"],
            "target_brands": list(c["target_brands"]),
            "origin_countries": list(c["origin_countries"]),
            "origin_ips": list(c["origin_ips"]),
            "reply_to_aliases": list(c["reply_to_aliases"]),
            "incident_count": c["incident_count"],
            "incidents": c["incidents"],
            "first_seen": c["first_seen"],
            "last_seen": c["last_seen"]
        })

    return sorted(results, key=lambda x: x["incident_count"], reverse=True)

@router.get("/{scan_id}")
async def get_email_scan_by_id(scan_id: int, db: Session = Depends(get_db)):
    """
    Get detailed forensic information for a single scan.
    """
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Email scan record not found")
    return format_scan_entry(scan)

@router.get("/{scan_id}/forensic-report")
async def get_forensic_report(scan_id: int, db: Session = Depends(get_db)):
    """
    Generate and return a structured JSON forensic incident report
    with cryptographic evidence hash.
    """
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Email scan record not found")
    
    entry = format_scan_entry(scan)
    report = build_structured_forensic_report(entry)
    return report

@router.get("/{scan_id}/forensic-report/pdf")
async def get_forensic_report_pdf(scan_id: int, db: Session = Depends(get_db)):
    """
    Generate and return a downloadable, print-ready PDF forensic report.
    """
    scan = db.query(models.ScanResult).filter(models.ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Email scan record not found")
    
    entry = format_scan_entry(scan)
    report = build_structured_forensic_report(entry)
    pdf_bytes = generate_forensic_pdf(report)
    
    filename = f"forensic_report_incident_{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )

@router.post("/analyze")
async def analyze_raw_email(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Direct forensic analysis endpoint for raw email MIME or headers.
    Enables instant testing, demonstration, and SIEM ingestion.
    """
    eml_input = payload.get("eml_content") or payload.get("raw_headers", "")
    raw_headers = payload.get("raw_headers") or eml_input
    text = payload.get("text", "")
    subject_input = payload.get("subject", "")
    sender_domain_input = payload.get("sender_domain", "")

    # 1. Parse Headers & EML MIME structure
    extracted_attachments = []
    if eml_input and ("\n\n" in eml_input or "\r\n\r\n" in eml_input):
        try:
            import email
            from email import policy
            from app.services.email_forensics import assess_filename
            msg = email.message_from_string(eml_input, policy=policy.default)
            if not subject_input and msg.get("Subject"):
                subject_input = str(msg.get("Subject"))
            if not sender_domain_input and msg.get("From"):
                sender_domain_input = str(msg.get("From"))
            if not text:
                body_part = msg.get_body(preferencelist=('plain', 'html'))
                if body_part:
                    text = body_part.get_content()
                else:
                    text = msg.get_payload() if isinstance(msg.get_payload(), str) else ""
            
            for part in msg.iter_attachments():
                fn = part.get_filename()
                if fn:
                    assessed = assess_filename(fn, part.get_content_type() or "")
                    extracted_attachments.append(assessed)
        except Exception as e:
            print(f"EML parsing notice: {e}")

    parsed_hdr = parse_raw_email_headers(raw_headers)
    subject = parsed_hdr.get("subject") if parsed_hdr.get("subject") != "unknown" else (subject_input or "Direct .EML Scan")
    from_sender = parsed_hdr.get("from") if parsed_hdr.get("from") != "unknown" else (sender_domain_input or "unknown@domain")
    from_domain = parsed_hdr.get("from_domain") or (from_sender.split("@")[-1].replace(">", "").strip() if "@" in from_sender else "unknown")

    # 2. IP Geolocation on Earliest Relay IP
    origin_ip = parsed_hdr.get("origin_ip", "unknown")
    geo_info = geolocate_ip(origin_ip)
    mismatch_info = evaluate_origin_mismatch(from_domain, geo_info)

    # 3. DNS & Domain Intelligence
    dns_info = analyze_sender_domain_dns(from_domain)

    # 4. Social Engineering / ML Scoring
    # Simple rule-based/ML simulation for direct test payloads
    text_lower = (text + " " + subject).lower()
    urgency_val = 0.9 if any(k in text_lower for k in ["urgent", "immediately", "24 hours", "asap", "suspend", "action required"]) else 0.1
    fear_val = 0.9 if any(k in text_lower for k in ["unauthorized", "legal", "lawsuit", "locked", "compromised", "police", "subpoena"]) else 0.1
    authority_val = 0.85 if any(k in text_lower for k in ["ceo", "executive", "director", "administrator", "it support", "internal revenue", "hr"]) else 0.1
    impersonation_val = 0.9 if (mismatch_info.get("mismatch") or parsed_hdr.get("reply_to_mismatch") or dns_info.get("is_lookalike")) else 0.15

    ml_signals = {
        "urgency": urgency_val,
        "fear": fear_val,
        "authority": authority_val,
        "impersonation": impersonation_val
    }

    # 5. Risk Fusion
    fused = fuse_email_risk_scores(
        ml_content_score=max(urgency_val, fear_val, authority_val),
        ml_signals=ml_signals,
        auth_summary=parsed_hdr,
        dns_summary=dns_info,
        impersonation_score=impersonation_val,
        origin_mismatch=mismatch_info,
        email_context={
            "subject": subject,
            "text": text,
            "sender_domain": from_domain
        }
    )

    # 6. Evidence Hash
    evidence_dict = {
        "subject": subject,
        "sender": from_sender,
        "message_id": parsed_hdr.get("message_id"),
        "origin_ip": origin_ip,
        "timestamp": datetime.now().isoformat(),
        "risk_score": fused["final_email_score"]
    }
    evidence_hash = compute_evidence_hash(evidence_dict)

    # 7. Persist to DB with PII masking
    final_text = text
    import re
    # Mask emails and phones
    final_text = re.sub(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', '[EMAIL_REDACTED]', final_text)
    final_text = re.sub(r'\b\d{10}\b', '[PHONE_REDACTED]', final_text)

    db_scan = models.ScanResult(
        url=final_text[:500],
        domain=from_domain,
        risk_score=fused["final_email_score"],
        risk_level=fused["risk_level"],
        explanation="; ".join(fused.get("factors", [])) + " [PII Masked]",
        timestamp=datetime.now(),
        sender=from_sender,
        subject=subject,
        spf_status=parsed_hdr.get("spf_status", "UNKNOWN"),
        dkim_status=parsed_hdr.get("dkim_status", "UNKNOWN"),
        dmarc_status=parsed_hdr.get("dmarc_status", "UNKNOWN"),
        origin_ip=origin_ip,
        received_chain=json.dumps(parsed_hdr.get("received_chain", [])),
        auth_results=parsed_hdr.get("auth_results", "UNKNOWN"),
        trust_score=fused.get("trust_score", 0.0),
        category=fused.get("category", "UNKNOWN"),
        domain_age_days=dns_info.get("domain_age_days", -1),
        whois_registrar=dns_info.get("whois_registrar", "UNKNOWN"),
        reply_to=parsed_hdr.get("reply_to", "unknown"),
        return_path=parsed_hdr.get("return_path", "unknown"),
        message_id=parsed_hdr.get("message_id", "unknown"),
        origin_country=geo_info.get("country", "Unknown"),
        origin_city=geo_info.get("city", "Unknown"),
        origin_isp=geo_info.get("isp", "Unknown"),
        origin_asn=geo_info.get("asn", "N/A"),
        geo_mismatch=1 if mismatch_info.get("mismatch") else 0,
        geo_mismatch_reason=mismatch_info.get("reason", ""),
        forensic_hash=evidence_hash,
        evidence_data=json.dumps({**parsed_hdr, "attachments": extracted_attachments})
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    return format_scan_entry(db_scan)


@router.post("/evaluate-dataset")
async def evaluate_dataset_endpoint(
    payload: Optional[Dict[str, Any]] = None
):
    """
    Evaluates a dataset provided via JSON (csv_content or dataset_path) or defaults to data/processed/train.csv.
    Returns metrics (accuracy, precision, recall, f1, threat distributions, vector averages).
    """
    import io
    import pandas as pd
    import numpy as np
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    import joblib

    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    dataset_name = "train.csv (Built-in)"

    # Determine dataset
    if payload and payload.get("csv_content"):
        try:
            df = pd.read_csv(io.StringIO(payload["csv_content"]))
            dataset_name = payload.get("filename", "Uploaded Dataset")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse CSV content: {str(e)}")
    elif payload and payload.get("dataset_path"):
        target_path = os.path.abspath(payload["dataset_path"])
        if not os.path.exists(target_path):
            raise HTTPException(status_code=404, detail=f"Dataset path '{target_path}' not found")
        if target_path.endswith(".json"):
            df = pd.read_json(target_path)
        else:
            df = pd.read_csv(target_path)
        dataset_name = os.path.basename(target_path)
    else:
        train_path = os.path.join(project_root, "data", "processed", "train.csv")
        if not os.path.exists(train_path):
            raise HTTPException(status_code=404, detail="Default dataset train.csv not found")
        df = pd.read_csv(train_path)
        dataset_name = "train.csv (Built-in 1,345 samples)"

    # Detect text column
    candidates = ["text", "cleaned_text", "body", "email_body", "content", "message", "subject_body", "Email Text"]
    text_col = None
    for c in candidates:
        if c in df.columns:
            text_col = c
            break
    if not text_col:
        for col in df.columns:
            if df[col].dtype == object:
                text_col = col
                break
    if not text_col:
        raise HTTPException(status_code=400, detail="No suitable text column found in dataset")

    # Load model
    vec_path = os.path.join(project_root, "models", "vectorizer_v6.joblib")
    model_path = os.path.join(project_root, "models", "model_v6.joblib")
    if not os.path.exists(vec_path) or not os.path.exists(model_path):
        vec_path = os.path.join(project_root, "models", "vectorizer_baseline.joblib")
        model_path = os.path.join(project_root, "models", "model_baseline.joblib")

    vectorizer = joblib.load(vec_path)
    model = joblib.load(model_path)

    texts = df[text_col].fillna("").astype(str).tolist()
    X = vectorizer.transform(texts)
    preds = model.predict(X)
    probs_list = model.predict_proba(X)

    if isinstance(probs_list, list):
        urgency_prob = probs_list[0][:, 1]
        authority_prob = probs_list[1][:, 1]
        fear_prob = probs_list[2][:, 1]
        impersonation_prob = probs_list[3][:, 1]
    else:
        urgency_prob = probs_list[:, 0]
        authority_prob = probs_list[:, 1]
        fear_prob = probs_list[:, 2]
        impersonation_prob = probs_list[:, 3]

    composite_risk = np.maximum.reduce([urgency_prob, authority_prob, fear_prob, impersonation_prob])

    critical_count = int(np.sum(composite_risk >= 0.70))
    suspicious_count = int(np.sum((composite_risk >= 0.40) & (composite_risk < 0.70)))
    safe_count = int(np.sum(composite_risk < 0.40))

    labels = ["urgency", "authority", "fear", "impersonation"]
    metrics = {}
    if all(col in df.columns for col in labels):
        for i, label in enumerate(labels):
            y_true = df[label].astype(int)
            y_pred = preds[:, i]
            acc = float(accuracy_score(y_true, y_pred))
            prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
            metrics[label] = {
                "accuracy": round(acc * 100, 2),
                "precision": round(float(prec) * 100, 2),
                "recall": round(float(rec) * 100, 2),
                "f1_score": round(float(f1) * 100, 2)
            }
    elif "label" in df.columns or "is_phishing" in df.columns:
        gt_col = "label" if "label" in df.columns else "is_phishing"
        y_true = df[gt_col].astype(int)
        binary_preds = (composite_risk >= 0.50).astype(int)
        acc = float(accuracy_score(y_true, binary_preds))
        prec, rec, f1, _ = precision_recall_fscore_support(y_true, binary_preds, average="binary", zero_division=0)
        metrics["overall"] = {
            "accuracy": round(acc * 100, 2),
            "precision": round(float(prec) * 100, 2),
            "recall": round(float(rec) * 100, 2),
            "f1_score": round(float(f1) * 100, 2)
        }

    # Sample preview
    sample_preview = []
    for idx in range(min(5, len(df))):
        sample_preview.append({
            "text": texts[idx][:120] + ("..." if len(texts[idx]) > 120 else ""),
            "risk_score": round(float(composite_risk[idx]), 3),
            "risk_level": "CRITICAL" if composite_risk[idx] >= 0.7 else ("SUSPICIOUS" if composite_risk[idx] >= 0.4 else "SAFE"),
            "urgency": round(float(urgency_prob[idx]), 2),
            "authority": round(float(authority_prob[idx]), 2),
            "fear": round(float(fear_prob[idx]), 2),
            "impersonation": round(float(impersonation_prob[idx]), 2),
        })

    return {
        "dataset_name": dataset_name,
        "total_samples": len(df),
        "critical_count": critical_count,
        "suspicious_count": suspicious_count,
        "safe_count": safe_count,
        "avg_urgency": round(float(urgency_prob.mean() * 100), 1),
        "avg_authority": round(float(authority_prob.mean() * 100), 1),
        "avg_fear": round(float(fear_prob.mean() * 100), 1),
        "avg_impersonation": round(float(impersonation_prob.mean() * 100), 1),
        "metrics": metrics,
        "sample_preview": sample_preview
    }

