import re
import email
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from typing import Dict, Any, List, Optional

try:
    import dkim
    HAS_DKIMPY = True
except ImportError:
    HAS_DKIMPY = False

def parse_received_header(header_value: str) -> Dict[str, Any]:
    """
    Parses a single RFC 5321/5322 Received header into structured hop components.
    Example header:
      from mail.attacker.org (unknown [185.220.101.5]) by mx.google.com with ESMTPS id xyz; Wed, 10 Sep 2026 14:20:00 -0700
    """
    cleaned = " ".join(header_value.replace("\r", " ").replace("\n", " ").split())
    
    # Extract IP address
    ip_match = re.search(r'\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]', cleaned)
    if not ip_match:
        ip_match = re.search(r'\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b', cleaned)
    hop_ip = ip_match.group(1) if ip_match else "unknown"

    # Extract 'from' host
    from_match = re.search(r'\bfrom\s+([^\s()]+)', cleaned, re.IGNORECASE)
    from_host = from_match.group(1) if from_match else "unknown"

    # Extract 'by' host
    by_match = re.search(r'\bby\s+([^\s()]+)', cleaned, re.IGNORECASE)
    by_host = by_match.group(1) if by_match else "unknown"

    # Extract protocol / with
    with_match = re.search(r'\bwith\s+([^\s;]+)', cleaned, re.IGNORECASE)
    protocol = with_match.group(1) if with_match else "SMTP"

    # Extract timestamp (after semicolon)
    timestamp = ""
    if ";" in cleaned:
        timestamp = cleaned.split(";")[-1].strip()

    is_private_ip = False
    if hop_ip != "unknown":
        if (hop_ip.startswith("127.") or 
            hop_ip.startswith("10.") or 
            hop_ip.startswith("192.168.") or 
            hop_ip.startswith("172.16.") or
            hop_ip.startswith("172.17.") or
            hop_ip.startswith("172.18.") or
            hop_ip.startswith("172.19.") or
            hop_ip.startswith("172.20.") or
            hop_ip.startswith("172.21.") or
            hop_ip.startswith("172.22.") or
            hop_ip.startswith("172.23.") or
            hop_ip.startswith("172.24.") or
            hop_ip.startswith("172.25.") or
            hop_ip.startswith("172.26.") or
            hop_ip.startswith("172.27.") or
            hop_ip.startswith("172.28.") or
            hop_ip.startswith("172.29.") or
            hop_ip.startswith("172.30.") or
            hop_ip.startswith("172.31.")):
            is_private_ip = True

    return {
        "from_host": from_host,
        "by_host": by_host,
        "ip": hop_ip,
        "is_private": is_private_ip,
        "protocol": protocol,
        "timestamp": timestamp,
        "raw": cleaned[:200]
    }

def extract_domain(email_address: str) -> str:
    """Safely extracts domain from an email string like 'Name <user@domain.com>'"""
    _, addr = parseaddr(email_address)
    if "@" in addr:
        return addr.split("@")[-1].strip().lower()
    return ""

def parse_raw_email_headers(raw_header_text: str) -> Dict[str, Any]:
    """
    Parses raw email header text to extract key authentication fields,
    Received IP chain, Return-Path, Message-ID, Reply-To, SPF/DKIM/DMARC status,
    and checks for Reply-To / DKIM alignment anomalies.
    """
    if not raw_header_text or not isinstance(raw_header_text, str):
        return {
            "from": "unknown",
            "to": "unknown",
            "subject": "unknown",
            "return_path": "unknown",
            "message_id": "unknown",
            "reply_to": "unknown",
            "date": "unknown",
            "spf_status": "NONE",
            "dkim_status": "NONE",
            "dmarc_status": "NONE",
            "dkim_domain": "unknown",
            "dkim_aligned": True,
            "reply_to_mismatch": False,
            "origin_ip": "unknown",
            "received_chain": [],
            "hop_details": [],
            "auth_results": "No headers provided"
        }

    # Parse headers using standard library
    msg = Parser(policy=policy.default).parsestr(raw_header_text)

    sender_from = msg.get("From", "unknown")
    recipient_to = msg.get("To", "unknown")
    subject = msg.get("Subject", "unknown")
    return_path = msg.get("Return-Path", "unknown")
    message_id = msg.get("Message-ID", "unknown")
    reply_to = msg.get("Reply-To", "unknown")
    date_header = msg.get("Date", "unknown")
    auth_results = msg.get("Authentication-Results", "")

    from_domain = extract_domain(str(sender_from))
    reply_to_domain = extract_domain(str(reply_to))

    # 1. Parse SPF / DKIM / DMARC from Authentication-Results header
    spf_status = "NONE"
    dkim_status = "NONE"
    dmarc_status = "NONE"

    auth_lower = auth_results.lower() if auth_results else ""
    
    # SPF match
    if "spf=pass" in auth_lower:
        spf_status = "PASS"
    elif "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
        spf_status = "FAIL"
    elif "spf=neutral" in auth_lower or "spf=none" in auth_lower:
        spf_status = "NEUTRAL"

    # DKIM header status match
    if "dkim=pass" in auth_lower:
        dkim_status = "PASS"
    elif "dkim=fail" in auth_lower:
        dkim_status = "FAIL"

    # DMARC match
    if "dmarc=pass" in auth_lower:
        dmarc_status = "PASS"
    elif "dmarc=fail" in auth_lower:
        dmarc_status = "FAIL"

    # Fallback check for Received-SPF header
    received_spf = msg.get("Received-SPF", "").lower()
    if spf_status == "NONE" and received_spf:
        if "pass" in received_spf:
            spf_status = "PASS"
        elif "fail" in received_spf:
            spf_status = "FAIL"

    # 2. Extract DKIM signature header tags (d= and s=) for alignment
    dkim_header = msg.get("DKIM-Signature", "")
    dkim_domain = "unknown"
    dkim_aligned = True
    if dkim_header:
        d_match = re.search(r'\bd=([a-zA-Z0-9.\-_]+)', str(dkim_header))
        if d_match:
            dkim_domain = d_match.group(1).lower()
            if from_domain and dkim_domain:
                if not (from_domain == dkim_domain or from_domain.endswith("." + dkim_domain) or dkim_domain.endswith("." + from_domain)):
                    dkim_aligned = False

    # 3. Check Reply-To vs From address mismatch
    reply_to_mismatch = False
    if reply_to != "unknown" and reply_to_domain and from_domain:
        if reply_to_domain != from_domain and not reply_to_domain.endswith("." + from_domain):
            reply_to_mismatch = True

    # 4. Extract Received Chain with Hop Details
    received_headers = msg.get_all("Received") or []
    hop_details = []
    received_chain = []
    origin_ip = "unknown"

    for i, r_hdr in enumerate(received_headers):
        hop_info = parse_received_header(str(r_hdr))
        hop_info["hop_index"] = i + 1
        hop_details.append(hop_info)
        if hop_info["ip"] != "unknown" and not hop_info["is_private"]:
            received_chain.append(hop_info["ip"])

    if received_chain:
        # The earliest public IP in Received chain (last hop chronologically in RFC 5321)
        origin_ip = received_chain[-1]

    # 5. Extract & Analyze Attachments
    attachments = extract_attachment_metadata(msg, raw_header_text)
    has_suspicious_attachments = any(a.get("is_dangerous") for a in attachments)
    attachment_risk = 0.0
    if attachments:
        attachment_risk = max(a.get("risk_score", 0.0) for a in attachments)

    # 6. Optional Cryptographic DKIM Verification (If raw email bytes available)
    crypto_dkim_verified = False
    if HAS_DKIMPY and raw_header_text:
        try:
            raw_bytes = raw_header_text.encode('utf-8', errors='ignore')
            if b"\r\n\r\n" in raw_bytes or b"\n\n" in raw_bytes:
                crypto_dkim_verified = dkim.verify(raw_bytes)
                if crypto_dkim_verified:
                    dkim_status = "PASS (VERIFIED)"
        except Exception:
            crypto_dkim_verified = False

    return {
        "from": str(sender_from),
        "from_domain": from_domain,
        "to": str(recipient_to),
        "subject": str(subject),
        "return_path": str(return_path),
        "message_id": str(message_id),
        "reply_to": str(reply_to),
        "reply_to_mismatch": reply_to_mismatch,
        "date": str(date_header),
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "dkim_domain": dkim_domain,
        "dkim_aligned": dkim_aligned,
        "origin_ip": origin_ip,
        "received_chain": received_chain,
        "hop_details": hop_details,
        "auth_results": str(auth_results) if auth_results else "Header parsed",
        "attachments": attachments,
        "has_suspicious_attachments": has_suspicious_attachments,
        "attachment_risk_score": attachment_risk
    }

DANGEROUS_EXTENSIONS = {
    ".exe": ("EXECUTABLE_BINARY", 0.98),
    ".scr": ("SCREENSAVER_EXECUTABLE", 0.98),
    ".bat": ("BATCH_SCRIPT", 0.95),
    ".cmd": ("COMMAND_SCRIPT", 0.95),
    ".vbs": ("VBSCRIPT_DROPPER", 0.98),
    ".js": ("JAVASCRIPT_DROPPER", 0.90),
    ".ps1": ("POWERSHELL_SCRIPT", 0.95),
    ".wsf": ("WINDOWS_SCRIPT", 0.95),
    ".hta": ("HTML_APPLICATION", 0.95),
    ".lnk": ("WINDOWS_SHORTCUT", 0.90),
    ".iso": ("DISK_IMAGE_LURE", 0.92),
    ".img": ("DISK_IMAGE_LURE", 0.90),
    ".vhd": ("VIRTUAL_DISK", 0.90),
    ".docm": ("MACRO_ENABLED_DOCUMENT", 0.92),
    ".xlsm": ("MACRO_ENABLED_SPREADSHEET", 0.92),
    ".pptm": ("MACRO_ENABLED_PRESENTATION", 0.90)
}

SUSPICIOUS_ARCHIVES = {".zip", ".rar", ".7z", ".tar.gz", ".ace", ".gz"}

def extract_attachment_metadata(msg: Any, raw_text: str = "") -> List[Dict[str, Any]]:
    """
    Traverses message parts and regex patterns to discover and assess attached files.
    Detects dangerous extensions, double extensions (e.g. invoice.pdf.exe), and macro-enabled documents.
    """
    attachments = []
    seen_names = set()

    # 1. Walk MIME parts if available
    try:
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition", ""))
            filename = part.get_filename()
            if not filename and "filename=" in disposition:
                match = re.search(r'filename=["\']?([^"\';\r\n]+)', disposition)
                if match:
                    filename = match.group(1).strip()

            if filename and filename not in seen_names:
                seen_names.add(filename)
                attachments.append(assess_filename(filename, part.get_content_type()))
    except Exception:
        pass

    # 2. Check for filename / attachment declarations in raw headers / text
    if raw_text:
        fn_matches = re.findall(r'(?:filename|attachment|name)=["\']?([^"\'\r\n;]+\.[a-zA-Z0-9]{2,5})["\']?', raw_text, re.IGNORECASE)
        for fn in fn_matches:
            fn_clean = fn.strip().strip('"').strip("'")
            if fn_clean and fn_clean not in seen_names and not fn_clean.endswith(".jpg") and not fn_clean.endswith(".png") and not fn_clean.endswith(".gif"):
                seen_names.add(fn_clean)
                attachments.append(assess_filename(fn_clean, "application/octet-stream"))

    return attachments

def assess_filename(filename: str, content_type: str = "") -> Dict[str, Any]:
    """Analyzes a single attachment filename for threats, double extensions, and danger rating."""
    lower_fn = filename.lower().strip()
    
    # Check for double extension (e.g. invoice.pdf.exe, report.docx.vbs)
    double_ext_match = re.search(r'\.(pdf|doc|docx|xls|xlsx|txt|jpg|png|csv)\.(exe|scr|vbs|bat|cmd|js|ps1|hta|iso)$', lower_fn)
    is_double_ext = bool(double_ext_match)

    ext = ""
    if "." in lower_fn:
        ext = "." + lower_fn.split(".")[-1]

    is_dangerous = False
    danger_category = "CLEAN"
    risk_score = 0.0

    if is_double_ext:
        is_dangerous = True
        danger_category = "DOUBLE_EXTENSION_SPOOF"
        risk_score = 0.99
    elif ext in DANGEROUS_EXTENSIONS:
        is_dangerous = True
        danger_category, risk_score = DANGEROUS_EXTENSIONS[ext]
    elif ext in SUSPICIOUS_ARCHIVES:
        is_dangerous = True
        danger_category = "ARCHIVE_CONTAINER"
        risk_score = 0.55
    elif ext in [".pdf", ".docx", ".xlsx", ".csv", ".txt", ".png", ".jpg"]:
        danger_category = "STANDARD_DOCUMENT"
        risk_score = 0.05
    else:
        danger_category = "UNKNOWN_EXTENSION"
        risk_score = 0.25

    return {
        "filename": filename,
        "extension": ext,
        "is_dangerous": is_dangerous,
        "is_double_extension": is_double_ext,
        "danger_category": danger_category,
        "risk_score": risk_score,
        "content_type": content_type or "application/octet-stream"
    }

def calculate_auth_score(auth_summary: Dict[str, Any]) -> float:
    """
    Computes S_auth authentication penalty score (0.0 = All Pass / Safe, 1.0 = All Fail / Dangerous)
    """
    spf = auth_summary.get("spf_status", "NONE")
    dkim_s = auth_summary.get("dkim_status", "NONE")
    dmarc = auth_summary.get("dmarc_status", "NONE")
    dkim_aligned = auth_summary.get("dkim_aligned", True)
    reply_to_mismatch = auth_summary.get("reply_to_mismatch", False)

    spf_penalty = 0.0 if "PASS" in spf else (0.8 if "FAIL" in spf else 0.3)
    dkim_penalty = 0.0 if "PASS" in dkim_s else (0.8 if "FAIL" in dkim_s else 0.3)
    if not dkim_aligned:
        dkim_penalty = max(dkim_penalty, 0.7)

    dmarc_penalty = 0.0 if "PASS" in dmarc else (1.0 if "FAIL" in dmarc else 0.4)
    reply_penalty = 0.5 if reply_to_mismatch else 0.0

    # Weighted Auth Score
    s_auth = (0.25 * spf_penalty) + (0.25 * dkim_penalty) + (0.35 * dmarc_penalty) + (0.15 * reply_penalty)
    return round(min(max(s_auth, 0.0), 1.0), 4)
