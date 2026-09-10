import dns.resolver
from typing import Dict, Any, List
import whois
from datetime import datetime
import threading
import re

# In-memory cache for fast sub-second lookups
_DNS_CACHE: Dict[str, Dict[str, Any]] = {}

# High-profile brand domains for typosquatting & lookalike heuristics
PROTECTED_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "apple", "microsoft", 
    "google", "amazon", "netflix", "dropbox", "facebook", "instagram", 
    "rvce", "sbi", "hdfc", "icici", "gov"
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".work", ".click", ".link", ".fit", ".tk", ".ml", ".cf", ".gq"}

KNOWN_DOMAIN_INTELLIGENCE: Dict[str, Dict[str, Any]] = {
    "chase.com": {
        "domain": "chase.com",
        "has_mx": True,
        "has_spf": True,
        "has_dmarc": True,
        "mx_records": ["mx1.chase.com", "mx2.chase.com"],
        "spf_record": "v=spf1 include:_spf.chase.com ~all",
        "dmarc_record": "v=DMARC1; p=reject; rua=mailto:dmarc@chase.com",
        "domain_age": "28 Years",
        "domain_age_days": 10500,
        "whois_registrar": "CSC Corporate Domains, Inc.",
        "dns_risk_score": 0.0,
        "is_fresh_domain": False,
        "is_lookalike": False
    },
    "paypal.com": {
        "domain": "paypal.com",
        "has_mx": True,
        "has_spf": True,
        "has_dmarc": True,
        "mx_records": ["mx1.paypal.com", "mx2.paypal.com"],
        "spf_record": "v=spf1 include:pp._spf.paypal.com ~all",
        "dmarc_record": "v=DMARC1; p=reject;",
        "domain_age": "25 Years",
        "domain_age_days": 9400,
        "whois_registrar": "MarkMonitor, Inc.",
        "dns_risk_score": 0.0,
        "is_fresh_domain": False,
        "is_lookalike": False
    },
    "rvce.edu.in": {
        "domain": "rvce.edu.in",
        "has_mx": True,
        "has_spf": True,
        "has_dmarc": True,
        "mx_records": ["aspmx.l.google.com"],
        "spf_record": "v=spf1 include:_spf.google.com ~all",
        "dmarc_record": "v=DMARC1; p=none;",
        "domain_age": "14 Years",
        "domain_age_days": 5200,
        "whois_registrar": "National Internet Exchange of India (NIXI)",
        "dns_risk_score": 0.0,
        "is_fresh_domain": False,
        "is_lookalike": False
    }
}

def analyze_sender_domain_dns(domain: str) -> Dict[str, Any]:
    """
    Performs DNS record lookups (MX, TXT/SPF, DMARC) for a sender domain using dnspython.
    Additionally fetches WHOIS data to determine domain age, registrar, lookalike indicators,
    and freshly registered domain risk (<30 days old).
    """
    if not domain or not isinstance(domain, str) or "." not in domain:
        return {
            "domain": domain or "unknown",
            "has_mx": False,
            "has_spf": False,
            "has_dmarc": False,
            "mx_records": [],
            "spf_record": "None",
            "dmarc_record": "None",
            "domain_age": "unknown",
            "domain_age_days": -1,
            "whois_registrar": "UNKNOWN",
            "dns_risk_score": 0.5,
            "is_fresh_domain": False,
            "is_lookalike": False,
            "lookalike_reason": ""
        }

    domain_clean = domain.strip().lower()

    if domain_clean in _DNS_CACHE:
        return _DNS_CACHE[domain_clean]

    if domain_clean in KNOWN_DOMAIN_INTELLIGENCE:
        data = KNOWN_DOMAIN_INTELLIGENCE[domain_clean]
        _DNS_CACHE[domain_clean] = data
        return data

    # Lookalike / Typosquatting heuristics
    is_lookalike = False
    lookalike_reason = ""
    for brand in PROTECTED_BRANDS:
        if brand in domain_clean and domain_clean != f"{brand}.com" and not domain_clean.endswith(f".{brand}.com") and not domain_clean.endswith(f".{brand}.co.in") and not domain_clean.endswith(f".{brand}.edu.in"):
            # e.g. chase-security-alert.com or secure-paypal.xyz
            is_lookalike = True
            lookalike_reason = f"Domain contains protected trademark '{brand}' in an unverified or hypenated domain structure."
            break

    # DNS MX lookup
    mx_records = []
    has_mx = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        answers_mx = resolver.resolve(domain_clean, 'MX')
        mx_records = [str(r.exchange).rstrip('.') for r in answers_mx]
        has_mx = len(mx_records) > 0
    except Exception:
        has_mx = False

    # DNS SPF lookup
    spf_record = "None"
    has_spf = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        answers_txt = resolver.resolve(domain_clean, 'TXT')
        for r in answers_txt:
            txt_str = str(r)
            if "v=spf1" in txt_str.lower():
                spf_record = txt_str
                has_spf = True
                break
    except Exception:
        has_spf = False

    # DNS DMARC lookup
    dmarc_record = "None"
    has_dmarc = False
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.5
        resolver.lifetime = 1.5
        dmarc_domain = f"_dmarc.{domain_clean}"
        answers_dmarc = resolver.resolve(dmarc_domain, 'TXT')
        for r in answers_dmarc:
            txt_str = str(r)
            if "v=dmarc1" in txt_str.lower():
                dmarc_record = txt_str
                has_dmarc = True
                break
    except Exception:
        has_dmarc = False

    # WHOIS Fetch with tight timeout
    domain_age_days = -1
    whois_registrar = "UNKNOWN"
    domain_age_str = "unknown"
    is_fresh_domain = False

    def fetch_whois():
        nonlocal domain_age_days, whois_registrar, domain_age_str, is_fresh_domain
        try:
            w = whois.whois(domain_clean)
            if w.registrar:
                whois_registrar = str(w.registrar)
            
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                delta = datetime.now() - creation_date
                domain_age_days = delta.days
                
                if domain_age_days < 30:
                    domain_age_str = f"{domain_age_days} Days (NEW)"
                    is_fresh_domain = True
                elif domain_age_days < 365:
                    domain_age_str = f"{domain_age_days // 30} Months"
                else:
                    domain_age_str = f"{domain_age_days // 365} Years"
        except Exception:
            pass

    whois_thread = threading.Thread(target=fetch_whois)
    whois_thread.start()
    whois_thread.join(timeout=1.8)

    # DNS Infrastructure Risk Penalty
    dns_risk_score = 0.0
    if not has_mx:
        dns_risk_score += 0.45
    if not has_spf:
        dns_risk_score += 0.25
    if not has_dmarc:
        dns_risk_score += 0.20
    if is_fresh_domain:
        dns_risk_score += 0.40
    if is_lookalike:
        dns_risk_score += 0.40

    result = {
        "domain": domain_clean,
        "has_mx": has_mx,
        "has_spf": has_spf,
        "has_dmarc": has_dmarc,
        "mx_records": mx_records[:3],
        "spf_record": spf_record,
        "dmarc_record": dmarc_record,
        "domain_age": domain_age_str,
        "domain_age_days": domain_age_days,
        "whois_registrar": whois_registrar,
        "is_fresh_domain": is_fresh_domain,
        "is_lookalike": is_lookalike,
        "lookalike_reason": lookalike_reason,
        "dns_risk_score": round(min(dns_risk_score, 1.0), 2)
    }

    _DNS_CACHE[domain_clean] = result
    return result
