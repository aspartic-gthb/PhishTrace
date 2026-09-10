from typing import Dict, Any, List
import re

def categorize_intent(subject: str, text: str) -> str:
    """
    Lightweight intent classifier to tag emails based on content.
    """
    subject_lower = (subject or "").lower()
    text_lower = (text or "").lower()
    combined = subject_lower + " " + text_lower

    if any(w in combined for w in ['wire transfer', 'payroll', 'gift card', 'executive', 'ceo', 'urgent request']):
        return "BUSINESS_EMAIL_COMPROMISE"
    if any(w in combined for w in ['receipt', 'invoice', 'payment received', 'order confirmation', 'transaction', 'billing']):
        return "TRANSACTIONAL"
    if any(w in combined for w in ['login', 'password', 'verify account', '2fa', 'verification code', 'sign in', 'unauthorized access']):
        return "CREDENTIAL_HARVESTING"
    if any(w in combined for w in ['shipped', 'delivery', 'tracking', 'package']):
        return "DELIVERY"
    if any(w in combined for w in ['discount', 'offer', 'sale', 'save', 'cashback', 'promotional', 'free']):
        return "PROMOTIONAL"
    
    return "GENERAL_COMMUNICATION"

def fuse_email_risk_scores(
    ml_content_score: float,
    ml_signals: Dict[str, float],
    auth_summary: Dict[str, Any],
    dns_summary: Dict[str, Any],
    links_info: List[Dict[str, Any]] = None,
    impersonation_score: float = 0.0,
    origin_mismatch: Dict[str, Any] = None,
    email_context: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Context-Aware Forensic Risk Fusion Engine.
    Fuses:
    1. Social Engineering Signals (Urgency, Fear, Authority Pressure, Impersonation)
    2. Authentication & Protocol Security (SPF, DKIM, DKIM Alignment, DMARC, Reply-To)
    3. Sender Domain Intelligence (Domain Age, Registrar, MX Sanity, Lookalike Detection)
    4. Origin Geolocation & Relay Path Mismatch Anomaly
    """
    if links_info is None:
        links_info = []
    if origin_mismatch is None:
        origin_mismatch = {}
    if email_context is None:
        email_context = {}
        
    subject = email_context.get("subject", "unknown")
    text = email_context.get("text", "")
    is_whitelisted = email_context.get("is_whitelisted", False)
    
    if is_whitelisted and not origin_mismatch.get("mismatch", False):
        return {
            "final_email_score": 0.0,
            "risk_level": "SAFE",
            "threat_classification": "Whitelisted & Authenticated Sender",
            "trust_score": 100.0,
            "category": "KNOWN_SAFE",
            "weights": { "base_risk": 0.0, "trust_deduction": 1.0, "context_adj": 0.0 },
            "factors": ["+ Verified authentic sender infrastructure"]
        }

    category = categorize_intent(subject, text)
    factors = []

    # --- 1. BASE THREAT RISK (Social Engineering & Impersonation) ---
    t_urgency = ml_signals.get("urgency", 0.0)
    t_fear = ml_signals.get("fear", 0.0)
    t_authority = ml_signals.get("authority", 0.0)
    
    T_score = ml_content_score
    P_score = impersonation_score or ml_signals.get("impersonation", 0.0)
    
    # Behavioral Social Engineering index
    social_engineering_index = (0.35 * t_urgency) + (0.35 * t_fear) + (0.30 * t_authority)
    if social_engineering_index > 0.5:
        factors.append(f"- Social Engineering Patterns detected (Urgency: {t_urgency:.2f}, Fear: {t_fear:.2f}, Authority: {t_authority:.2f})")

    # Link & Domain Analysis
    L_score = 0.0
    domain_mismatch_found = False
    sender_domain = (email_context.get("sender_domain", "") or "").lower()
    
    for link in links_info:
        dest_domain = link.get("domain", "").lower()
        if dest_domain and sender_domain and dest_domain != sender_domain:
            if not dest_domain.endswith(f".{sender_domain}") and not sender_domain.endswith(f".{dest_domain}"):
                domain_mismatch_found = True
                L_score += 0.5
        if link.get("is_ip", False):
            L_score += 0.8
            
    L_score = min(L_score, 1.0)
    if domain_mismatch_found:
        factors.append("- In-email hyperlink destination deviates from sender domain")

    # Base Threat Composition
    base_risk = (0.25 * T_score) + (0.25 * P_score) + (0.20 * social_engineering_index) + (0.30 * L_score)

    # --- 2. AUTHENTICATION & SENDER ANOMALIES ---
    spf = auth_summary.get("spf_status", "NONE")
    dkim = auth_summary.get("dkim_status", "NONE")
    dmarc = auth_summary.get("dmarc_status", "NONE")
    dkim_aligned = auth_summary.get("dkim_aligned", True)
    reply_to_mismatch = auth_summary.get("reply_to_mismatch", False)
    
    auth_trust = 0.0
    if "PASS" in spf: 
        auth_trust += 0.33
        factors.append("+ SPF PASS")
    elif "FAIL" in spf: 
        factors.append("- SPF FAIL (Unauthorized sending IP)")
    
    if "PASS" in dkim and dkim_aligned: 
        auth_trust += 0.33
        factors.append("+ DKIM PASS (Signature aligned)")
    elif not dkim_aligned and auth_summary.get("dkim_domain") != "unknown":
        factors.append(f"- DKIM Misaligned: Signed by '{auth_summary.get('dkim_domain')}' instead of sender")
    elif "FAIL" in dkim: 
        factors.append("- DKIM FAIL (Cryptographic signature invalid)")
        
    if "PASS" in dmarc: 
        auth_trust += 0.34
        factors.append("+ DMARC PASS")
    elif "FAIL" in dmarc: 
        factors.append("- DMARC FAIL (Policy violation)")

    if reply_to_mismatch:
        factors.append(f"- Reply-To Address Anomaly: Directs responses to '{auth_summary.get('reply_to')}'")

    # --- 3. DOMAIN INTELLIGENCE ---
    dns_trust = 0.0
    if dns_summary.get("has_mx", False):
        dns_trust += 0.5
    else:
        factors.append("- Domain lacks MX Records")
        
    if dns_summary.get("has_spf", False) or dns_summary.get("has_dmarc", False):
        dns_trust += 0.5

    domain_age_penalty = 0.0
    if dns_summary.get("is_fresh_domain", False):
        domain_age_penalty = 0.40
        factors.append(f"- High Risk: Domain registered very recently ({dns_summary.get('domain_age', 'New')})")
    elif dns_summary.get("domain_age_days", -1) > 365:
        factors.append("+ Domain is well-established (> 1 year)")

    if dns_summary.get("is_lookalike", False):
        domain_age_penalty += 0.40
        factors.append(f"- Suspicious Lookalike Domain: {dns_summary.get('lookalike_reason', '')}")

    # --- 4. ORIGIN GEOLOCATION MISMATCH ANOMALY ---
    geo_penalty = 0.0
    if origin_mismatch.get("mismatch", False):
        geo_penalty = 0.45
        factors.append(f"- GEOLOCATION ANOMALY: {origin_mismatch.get('reason', '')}")

    # --- 5. SUSPICIOUS ATTACHMENT ANALYSIS ---
    attachment_penalty = 0.0
    attachments = auth_summary.get("attachments", [])
    for att in attachments:
        if att.get("is_double_extension"):
            attachment_penalty = max(attachment_penalty, 0.95)
            factors.append(f"- CRITICAL ATTACHMENT: Double extension lure detected '{att.get('filename')}'")
        elif att.get("is_dangerous"):
            attachment_penalty = max(attachment_penalty, att.get("risk_score", 0.8))
            factors.append(f"- DANGEROUS ATTACHMENT: High-risk file type '{att.get('filename')}' ({att.get('danger_category')})")

    # --- 6. COMPREHENSIVE FUSION ---
    overall_trust = (0.50 * auth_trust) + (0.50 * dns_trust)
    
    # Calculate unified score
    final_score = base_risk - (0.25 * overall_trust) + (0.50 * domain_age_penalty) + (0.50 * geo_penalty) + (0.60 * attachment_penalty)
    if reply_to_mismatch:
        final_score += 0.20

    # Safety Floors for Critical Indicator Combinations
    if attachment_penalty >= 0.90:
        final_score = max(final_score, 0.94)

    if origin_mismatch.get("mismatch", False) and ("FAIL" in spf or "FAIL" in dmarc):
        final_score = max(final_score, 0.88)
        factors.append("- CRITICAL: Sender origin mismatch paired with email authentication failure")

    if dns_summary.get("is_lookalike", False) or dns_summary.get("is_fresh_domain", False):
        if "FAIL" in dmarc or not dkim_aligned:
            final_score = max(final_score, 0.85)

    if P_score > 0.75 and (reply_to_mismatch or not dkim_aligned):
        final_score = max(final_score, 0.86)

    final_score = round(min(max(final_score, 0.0), 1.0), 4)
    trust_score_out = round(overall_trust * 100, 1)

    # Classification
    if final_score >= 0.70:
        risk_level = "CRITICAL" if final_score >= 0.85 else "HIGH_RISK"
        classification = f"Fraudulent Threat ({category.replace('_', ' ').title()})"
    elif final_score >= 0.40:
        risk_level = "SUSPICIOUS"
        classification = "Suspicious Email Characteristics"
    else:
        risk_level = "SAFE"
        classification = "Legitimate / Nominal Risk"

    if not factors:
        factors.append("Standard email communication patterns")

    return {
        "final_email_score": final_score,
        "trust_score": trust_score_out,
        "category": category,
        "risk_level": risk_level,
        "threat_classification": classification,
        "weights": { 
            "base_risk": round(base_risk, 2), 
            "trust_deduction": round(overall_trust, 2), 
            "geo_penalty": round(geo_penalty, 2),
            "domain_penalty": round(domain_age_penalty, 2)
        },
        "factors": factors
    }
