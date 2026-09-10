from typing import Tuple, Optional
from urllib.parse import urlparse
import difflib

# Define Protected Entities and their Allowed Domains
PROTECTED_ENTITIES = {
    "paypal": ["paypal.com", "paypal-objects.com"],
    "google": ["google.com", "accounts.google.com", "gmail.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "azure.com"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "bank of america": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"]
}

PROTECTED_DOMAINS = [d for domains in PROTECTED_ENTITIES.values() for d in domains]

def check_homoglyphs(domain: str) -> Tuple[float, Optional[str]]:
    """
    Checks if the domain is suspiciously similar to a protected domain (Typosquatting).
    """
    if not domain:
        return 0.0, None
        
    for protected in PROTECTED_DOMAINS:
        # Skip if exact match or subdomain (already authorized or safe)
        if domain == protected or domain.endswith("." + protected):
            continue
            
        # Calculate similarity
        # We focus on the 'SLD' (Second Level Domain) mainly, but checking full string is a decent start
        ratio = difflib.SequenceMatcher(None, domain, protected).ratio()
        
        # Threshold 0.85 allows detecting 'paypa1.com' vs 'paypal.com' (ratio ~0.9)
        if ratio > 0.85:
            return 0.6, f"Typosquatting Detected: '{domain}' is deceptively similar to '{protected}'."
            
    return 0.0, None

def analyze_impersonation(title: Optional[str], url: Optional[str]) -> Tuple[float, Optional[str]]:
    """
    Checks for:
    1. Entity Mismatch: Title claims 'PayPal' but URL is not paypal.com
    2. Homoglyphs: URL is 'paypa1.com' (regardless of title)
    """
    if not url:
        return 0.0, None

    # Parse domain
    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
             parsed_url = urlparse(f"http://{url}")
        
        domain = parsed_url.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
    except:
        return 0.0, None

    # 1. Homoglyph / Typosquatting Check (Independent of Title)
    # This catches 'paypa1.com' even if title is generic "Login"
    typo_score, typo_warning = check_homoglyphs(domain)
    if typo_score > 0:
        return typo_score, typo_warning

    # 2. Entity Mismatch Check
    if not title:
        return 0.0, None
        
    title_lower = title.lower()
    
    for entity, allowed_domains in PROTECTED_ENTITIES.items():
        if entity in title_lower:
            # The Title claims to be this entity.
            # Check if current domain is authorized.
            is_authorized = False
            for allowed in allowed_domains:
                if domain == allowed or domain.endswith("." + allowed):
                    is_authorized = True
                    break
            
            if not is_authorized:
                return 0.4, f"Impersonation Detected: Page claims to be '{entity.title()}' but is hosted on '{domain}'."

    return 0.0, None
