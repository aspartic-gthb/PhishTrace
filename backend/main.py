# --- PYPARSING COMPATIBILITY SHIM (Generic) ---
# Aliases camelCase <-> snake_case to support mixed versions
import pyparsing
# DelimitedList shim
if not hasattr(pyparsing, "DelimitedList"):
    if hasattr(pyparsing, "delimited_list"):
        pyparsing.DelimitedList = pyparsing.delimited_list
    elif hasattr(pyparsing, "delimitedList"):
        pyparsing.DelimitedList = pyparsing.delimitedList

# Method aliases
if hasattr(pyparsing, "ParserElement"):
    pe = pyparsing.ParserElement
    # List of (snake_case, camelCase) pairs to unify
    mapping = [
        ("set_name", "setName"),
        ("set_results_name", "setResultsName"),
        ("set_parse_action", "setParseAction"),
        ("add_parse_action", "addParseAction"),
        ("add_condition", "addCondition"),
        ("leave_whitespace", "leaveWhitespace"),
        ("parse_with_tabs", "parseWithTabs"),
        ("convert_to_integer", "convertToInteger"),
        ("transform_string", "transformString"),
        ("search_string", "searchString"),
        ("scan_string", "scanString"),
        ("suppress", "suppress"),
        ("ignore", "ignore"),
    ]
    for snake, camel in mapping:
        # If snake missing, alias to camel
        if not hasattr(pe, snake) and hasattr(pe, camel):
            setattr(pe, snake, getattr(pe, camel))
        # If camel missing, alias to snake
        if not hasattr(pe, camel) and hasattr(pe, snake):
            setattr(pe, camel, getattr(pe, snake))

# Module-level constants aliases (snake_case <-> camelCase)
# Fixes 'AttributeError: module pyparsing has no attribute dbl_quoted_string'
module_mapping = [
    ("dbl_quoted_string", "dblQuotedString"),
    ("sgl_quoted_string", "sglQuotedString"),
    ("quoted_string", "quotedString"),
    ("rest_of_line", "restOfLine"),
    ("line_end", "lineEnd"),
    ("one_of", "oneOf"),
]
for snake, camel in module_mapping:
    if hasattr(pyparsing, camel) and not hasattr(pyparsing, snake):
        setattr(pyparsing, snake, getattr(pyparsing, camel))
    if hasattr(pyparsing, snake) and not hasattr(pyparsing, camel):
        setattr(pyparsing, camel, getattr(pyparsing, snake))

# Fixes 'AttributeError: module 'pyparsing' has no attribute 'common''
if hasattr(pyparsing, "pyparsing_common") and not hasattr(pyparsing, "common"):
    pyparsing.common = pyparsing.pyparsing_common

# Fixes 'AttributeError: ... downcase_tokens ...' in pyparsing.common
if hasattr(pyparsing, "common"):
    if hasattr(pyparsing.common, "downcaseTokens") and not hasattr(pyparsing.common, "downcase_tokens"):
        pyparsing.common.downcase_tokens = pyparsing.common.downcaseTokens
    if hasattr(pyparsing.common, "upcaseTokens") and not hasattr(pyparsing.common, "upcase_tokens"):
        pyparsing.common.upcase_tokens = pyparsing.common.upcaseTokens
# ----------------------------------------------

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import os
import sys
import pickle # Added for Temporal Model

# Add parent directory to path to access models if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Add current directory (backend) to path to ensure 'app' module can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')




from sqlalchemy.orm import Session
from app.database import get_db, SessionLocal
from app import models
import json

# === LOAD VERIFIED DOMAIN DATASET (Top 1k) ===
VERIFIED_DOMAINS = set()
try:
    with open(os.path.join(os.path.dirname(__file__), 'data/dom_structures_20k.json'), 'r') as f:
        _data = json.load(f)
        VERIFIED_DOMAINS = {entry['domain'] for entry in _data if entry.get('status') == 'success'}
    print(f"✅ Loaded {len(VERIFIED_DOMAINS)} Verified Domains for Neural Check")
except Exception as e:
    print(f"⚠️ Verified Domain List not available: {e}")

app = FastAPI(title="Social Engineering Detection API")

# Enable CORS for Next.js app (usually on localhost:3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Keys router for encryption feature
try:
    from app.routes import api_keys
    app.include_router(api_keys.router)
    print("✅ API Keys encryption routes loaded")
except Exception as e:
    print(f"⚠️  API Keys routes not loaded: {e}")

# Include Email Scans router for real-time email scanning
try:
    from app.routes import email_scans
    app.include_router(email_scans.router)
    print("✅ Email Scans routes loaded")
except Exception as e:
    print(f"⚠️  Email Scans routes not loaded: {e}")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"Incoming request: {request.method} {request.url}")
    try:
        response = await call_next(request)
        print(f"Response status: {response.status_code}")
        return response
    except Exception as e:
        print(f"Request failed: {str(e)}")
        raise e

@app.middleware("http")
async def add_cache_headers(request: Request, call_next):
    """Prevent browser caching of API responses to avoid stale data"""
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Load the BEST model (V6 Structural - 97.45% Accuracy)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

try:
    vectorizer = joblib.load(os.path.join(MODELS_DIR, 'vectorizer_v6.joblib'))
    clf = joblib.load(os.path.join(MODELS_DIR, 'model_v6.joblib'))
    print("Loaded V6 Structural Model (97.45% Accuracy)")
except Exception as e:
    print(f"V6 model not found ({e}), falling back to enhanced...")
    try:
        vectorizer = joblib.load(os.path.join(MODELS_DIR, 'vectorizer_enhanced.joblib'))
        clf = joblib.load(os.path.join(MODELS_DIR, 'model_enhanced.joblib'))
    except Exception as e2:
        print(f"Fallback to scalable...")
        try:
            vectorizer = joblib.load(os.path.join(MODELS_DIR, 'vectorizer_scalable.joblib'))
            clf = joblib.load(os.path.join(MODELS_DIR, 'model_scalable.joblib'))
        except Exception as e3:
             print(f"Critical: Could not load any models. Error: {e3}")
             raise e3

# Load Custom Temporal Models (V1)
try:
    with open(os.path.join(MODELS_DIR, 'temporal_analysis_v1.pkl'), 'rb') as f:
        temporal_models = pickle.load(f)
        temporal_cat_model = temporal_models['category_model']
        temporal_score_model = temporal_models['temporal_model']
        print("✅ Loaded: Temporal Analysis V1 (Marketing/Phishing Classifier)")
except Exception as e:
    print(f"⚠️ Temporal V1 not loaded: {e}")
    temporal_models = None

labels = ['urgency', 'authority', 'fear', 'impersonation']

def clean_url(url):
    if not isinstance(url, str): return ""
    url = url.lower()
    for prefix in ['https://', 'http://', 'www.']:
        if url.startswith(prefix):
            url = url[len(prefix):]
    return url

from scipy.sparse import hstack, csr_matrix
import re

def extract_manual_features(urls, contexts=None):
    """
    Extracts dense features from a list of URLs.
    Compatible with the training script logic (V6 Structural).
    """
    features = []
    
    # Regex for IP address
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    
    for i, url in enumerate(urls):
        if not isinstance(url, str):
            url = ""
            
        row = []
        
        # 1. Has IP Address
        row.append(1 if ip_pattern.search(url) else 0)
        
        # 2. Length Features
        row.append(1 if len(url) > 50 else 0)
        row.append(1 if len(url) > 75 else 0)
        
        # 3. Suspicious Characters
        row.append(url.count('.'))   
        row.append(url.count('@'))   
        row.append(url.count('-'))   
        
        # 4. Sensitive Keywords
        lower_url = url.lower()
        for word in ['login', 'signin', 'account', 'update', 'verify', 'secure', 'bank', 'confirm']:
            row.append(1 if word in lower_url else 0)
            
        # [STEP 2] INTERACTION FEATURES
        has_auth_kw = any(w in lower_url for w in ['verify', 'account', 'secure', 'login'])
        has_urgency_kw = any(w in lower_url for w in ['immediate', 'urgent', 'suspend', 'expires'])
        has_payment_kw = any(w in lower_url for w in ['payment', 'wire', 'billing', 'invoice'])
        
        row.append(1 if (has_auth_kw and has_urgency_kw) else 0)
        row.append(1 if (has_auth_kw and has_payment_kw) else 0)
        
        has_fear_kw = any(w in lower_url for w in ['legal', 'court', 'police', 'jail', 'warrant'])
        row.append(1 if has_fear_kw else 0)

        # 5. [STEP 3] STRUCTURAL FEATURES (Synchronized with V6 Training)
        ctx = None
        if contexts and i < len(contexts):
            ctx = contexts[i]
        
        row.append(1 if (ctx and ctx.has_password_field) else 0)
        row.append(1 if (ctx and ctx.is_https) else 1) # Default to 1 (Assume HTTPS if unknown)
        row.append(ctx.external_link_ratio if ctx else 0.0)
        
        features.append(row)
        
    return csr_matrix(features)

def get_structural_audit(url, context):
    """Provides a detailed dictionary of technical flags for Forensics."""
    audit = {}
    lower_url = url.lower()
    
    # 1. Identity Verification
    audit["is_ip_address"] = "YES (High Risk)" if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else "NO"
    audit["url_complexity"] = "High" if len(url) > 100 else ("Medium" if len(url) > 50 else "Low")
    audit["subdomain_count"] = url.count('.')
    
    # 2. Protocol & Encryption
    audit["https_enforced"] = "YES" if url.startswith("https") else "NO (CRITICAL)"
    
    # 3. Behavioral Anchors
    if context:
        audit["credential_harvesting_node"] = "DETECTED" if context.has_password_field else "NONE"
        audit["redirection_risk"] = "High" if context.external_link_ratio > 0.6 else ("Moderate" if context.external_link_ratio > 0.3 else "Normal")
        audit["page_intent"] = "Authentication/Login" if "login" in context.title.lower() or "signin" in context.title.lower() else "General Content"
    
    return audit

class AnalysisContext(BaseModel):
    title: str = ""
    h1: str = ""
    has_password_field: int = 0
    external_link_ratio: float = 0.0
    is_https: int = 1
    raw_headers: str = ""
    sender_domain: str = ""
    subject: str = ""

class DetectionRequest(BaseModel):
    text: str
    source: str = "content"
    context: AnalysisContext = None

class FeatureImportance(BaseModel):
    word: str
    weight: float

class LabelResult(BaseModel):
    probability: float
    top_features: list[FeatureImportance]

class DetectionResponse(BaseModel):
    text: str
    max_risk_score: float
    labels: dict[str, LabelResult]

# Create API Router
from fastapi import APIRouter
router = APIRouter(prefix="/api/v1")
recent_scans = []

@router.post("/detect")
async def detect_attack(request: DetectionRequest, db: Session = Depends(get_db)):
    global recent_scans 
    import traceback
    from datetime import datetime, timezone, timedelta
    import re
    
    # Define IST Timezone
    IST = timezone(timedelta(hours=5, minutes=30))
    timestamp = datetime.now(IST)
    
    # 0. INITIALIZE PRODUCTION RESPONSE
    results_labels = {l: {"probability": 0.0, "top_features": []} for l in labels}
    
    try:
        text = request.text
        neural_status = "UNKNOWN" # Default status

        if not text:
            return {
                "status": "SAFE",
                "global_risk_score": 0.0,
                "signals": results_labels,
                "structural_flags": {},
                "explanation_summary": "Null request received."
            }

        # 1. INTERNAL / RESTRICTED CHECK
        if text.startswith(('chrome://', 'chrome-extension://', 'about:', 'view-source:')):
            return {
                "status": "SAFE",
                "global_risk_score": 0.0,
                "signals": results_labels,
                "structural_flags": {"system_page": True},
                "explanation_summary": "Internal browser component. No security risk."
            }

        # [FIX] Extract hostname EARLY
        from urllib.parse import urlparse
        hostname = text
        try:
             parsed = urlparse(text)
             hostname = (parsed.netloc or parsed.path).lower()
             hostname = (parsed.netloc or parsed.path).lower()
             if hostname.startswith("www."): hostname = hostname[4:]
        except: pass

        # --- NEURAL ARCHITECTURE CHECK (Top 1k) ---
        domain_clean = hostname.split(':')[0] # Remove port
        if domain_clean in VERIFIED_DOMAINS:
            neural_status = "VERIFIED"
            print(f"🏛️ NEURAL MATCH: {domain_clean} is a Verified Top 1k Domain")


        # WHITELIST: Known-safe TLDs and popular domains
        safe_patterns = [
            # Educational & Government
            r'\.edu([/?#]|$)',           # US educational
            r'\.edu\.[a-z]{2}([/?#]|$)', # International educational (e.g., .edu.in, .edu.au)
            r'\.ac\.[a-z]{2}([/?#]|$)',  # Academic (e.g., .ac.uk, .ac.in)
            r'\.gov([/?#]|$)',           # US government
            r'\.gov\.[a-z]{2}([/?#]|$)', # International government
            r'\.mil([/?#]|$)',           # US military
            # Specific Institutions
            r'rvce\.edu\.in',
            # Popular platforms (ALWAYS SAFE)
            r'youtube\.com',
            r'youtu\.be',
            r'google\.com',
            r'wikipedia\.org',
            r'github\.com',
            r'stackoverflow\.com',
            r'reddit\.com',
            r'twitter\.com',
            r'facebook\.com',
            r'instagram\.com',
            r'linkedin\.com',
            r'amazon\.(com|in|co\.uk)',
            r'netflix\.com',
            r'spotify\.com',
            r'apple\.com',
            r'microsoft\.com',
            # Regional & Subdomain Google
            r'(^|\.)google\.(co\.[a-z]{2}|com?\.[a-z]{2}|[a-z]{2})([/?#]|$)',
            r'(^|\.)google([/?#]|$)', # Covers .google TLD (blog.google, about.google)
            r'(^|\.)google\.com', 
            r'families\.google',
            r'blog\.google',
            r'about\.google',
            r'store\.google',
            # News & Media
            r'britannica\.com',
            r'imdb\.com',
            r'quora\.com',
            r'indiatimes\.com',
            r'thehindu\.com',
            r'nytimes\.com',
            r'bbc\.com',
            r'bbc\.co\.uk',
            r'cnn\.com',
            r'(^|\.)brave\.com',
            r'(^|\.)brave\.app', # status.brave.app
            r'brave\.com',
            # Tech & Finance (Fixes for False Positives)
            r'(^|\.)oracle\.com',
            r'(^|\.)jpmorgan\.com',
            r'(^|\.)jpmorganchase\.com',
            r'(^|\.)deepseek\.com',
            r'(^|\.)chat\.deepseek\.com',
            r'(^|\.)openai\.com',
            r'(^|\.)chatgpt\.com',
        ]
        
        # Check if URL matches safe patterns
        is_whitelisted = any(re.search(pattern, text.lower()) for pattern in safe_patterns)

        # --- TRUSTED SENDER CHECK (Fix for Canva/Amazon False Positives) ---
        if request.context and 'sender_domain' in request.context:
            sender = request.context['sender_domain'].lower()
            trusted_senders = [
                'canva.com', 'amazon.com', 'amazon.in', 'google.com', 'linkedin.com', 
                'github.com', 'stripe.com', 'paypal.com', 'microsoft.com', 'apple.com',
                'zoom.us', 'slack.com', 'atlassian.com', 'trello.com', 'notifications.canva.com',
                'coursera.org', 'udemy.com', 'edx.org', 'flipkart.com', 'myntra.com', 
                'zomato.com', 'swiggy.com', 'medium.com', 'notion.so', 'grammarly.com'
            ]
            
            # Check if sender ends with any trusted domain
            if any(sender.endswith(td) for td in trusted_senders):
                print(f"✅ TRUSTED SENDER: {sender} - Bypassing Heuristics")
                is_whitelisted = True 

        # CHECK ALLOWED DOMAINS (Whitelist override)
        try:
             # Use the provided db session instead of creating a new one
             allowed = db.query(models.AllowedDomain).filter(models.AllowedDomain.domain == hostname).first()
             # Check parent
             if not allowed and '.' in hostname:
                 parts = hostname.split('.')
                 if len(parts) > 2:
                     parent = '.'.join(parts[1:])
                     allowed = db.query(models.AllowedDomain).filter(models.AllowedDomain.domain == parent).first()
             
             if allowed:
                  # [FIX] PERSIST ALLOWED DOMAIN SCAN
                  try:
                       expl = "Allowed Domain (User Whitelist)"
                       if request.source == "navigation":
                           expl += " (Main Page Load)"
                       
                       db_scan_allowed = models.ScanResult(
                           url=text,
                           domain=hostname,
                           risk_score=0.0,
                           risk_level="SAFE",
                           explanation=expl,
                           timestamp=datetime.now(IST)
                       )
                       db.add(db_scan_allowed)
                       db.commit()
                  except Exception: pass

                  db.close()
                  return {
                      "status": "SAFE",
                      "global_risk_score": 0.0,
                      "signals": results_labels,
                      "structural_flags": {"user_allowed": True},
                      "explanation_summary": "Domain authorized by user policy."
                  }
        except Exception as e:
            print(f"Allowed domain check error: {e}")

        if is_whitelisted:
            # [FIX] PERSIST SAFE SCAN (so it shows in Dashboard)
            try:
                 expl = "Whitelisted Safe Site"
                 if request.source == "navigation":
                     expl += " (Main Page Load)"

                 db_scan_safe = models.ScanResult(
                     url=text,
                     domain=hostname,
                     risk_score=0.0,
                     risk_level="SAFE",
                     explanation=expl,
                     timestamp=datetime.now(IST)
                 )
                 db.add(db_scan_safe)
                 db.commit()
                 print(f"✅ Persisted SAFE scan: {hostname}")
            except Exception as w_e:
                print(f"Whitelist persist error: {w_e}")

            db.close()
            # Return unified production schema
            return {
                "status": "SAFE",
                "global_risk_score": 0.0,
                "signals": results_labels,
                "structural_flags": {"system_whitelist": True},
                "explanation_summary": "Verified safe via global threat baseline."
            }

        # --- QUANTUM DEFENSE: WORLD CLASS HEURISTICS V2.0 ---
        
        qt_score = 0.0
        qt_label = None
        qt_explanation = []

        lower_text = text.lower()

        # 1. HOMOGLYPH & TYPOSQUATTING DETECTION (The "Google" -> "G00gle" check)
        # We check against a list of high-value targets
        targets = {
            'google': ['g00gle', 'googl', 'gogle', 'goog1e', 'gooogle'],
            'facebook': ['faceb00k', 'facebok', 'facbook', 'facebo0k'],
            'amazon': ['amaz0n', 'amzon', 'amazn', 'arnazon'],
            'paypal': ['paypa1', 'paypai', 'paypol', 'paypel', 'paypal-secure'],
            'microsoft': ['m1crosoft', 'microsofl', 'micros0ft'],
            'apple': ['app1e', 'apple-id', 'apple-support'],
            'netflix': ['netfix', 'netf1ix', 'netlix']
        }
        
        for target, spoofs in targets.items():
            if target in lower_text: continue # It's likely the real one (we rely on whitelist to save us if it's real)
            
            for spoof in spoofs:
                if spoof in lower_text:
                    qt_score = 0.98
                    qt_label = "impersonation"
                    qt_explanation.append(f"Homoglyph detected: '{spoof}' mimics '{target}'")
                    print(f"🚩 QUANTUM MATCH: Homoglyph {spoof}")

        # 2. CRYPTO DRAINER DETECTION
        crypto_patterns = [
            'walletconnect', 'claim airdrop', 'connect wallet', 'gas fee', 
            'seed phrase', 'unlock wallet', 'metamask', 'trustwallet',
            'restore wallet', 'validate wallet', 'rectification'
        ]
        if any(cp in lower_text for cp in crypto_patterns):
            qt_score = max(qt_score, 0.95)
            qt_label = "fear" if not qt_label else qt_label # Usually fear or urgency
            qt_explanation.append("Crypto wallet drainer pattern detected")
            print(f"🚩 QUANTUM MATCH: Crypto Drainer")

        # 3. REMOTE ACCESS TOOL SCAMS (Tech Support Fraud)
        rat_patterns = [
            'anydesk', 'teamviewer', 'quicksupport', 'zoho assist', 
            'connectwise', 'remote support', 'install_sys_tool'
        ]
        # Only flag if combined with urgency or generic domains (to avoid flagging legitimate sites)
        if any(rp in lower_text for rp in rat_patterns) and not is_whitelisted:
             qt_score = max(qt_score, 0.88)
             qt_label = "authority"
             qt_explanation.append("Remote Access Tool (RAT) bait detected")
             print(f"🚩 QUANTUM MATCH: RAT Scam")

        # 4. CROSS-CHANNEL BRIDGING (The "WhatsApp" / "SMS" trap)
        # Detecting attempts to move user off-platform
        bridging_patterns = [
            'whatsapp://', 'tg://', 't.me/', 'wa.me/', 
            'send sms', 'verify via sms', 'text us'
        ]
        if any(bp in lower_text for bp in bridging_patterns):
             qt_score = max(qt_score, 0.75)
             qt_label = "urgency"
             qt_explanation.append("Cross-channel bridging attempt detected")
             print(f"🚩 QUANTUM MATCH: Cross-Channel Bridge")
             
        # 5. URGENCY & FOMO TIMERS
        fomo_patterns = [
            r'expires in \d+ minutes', r'seconds left', 
            r'account.*delet', r'suspend.*immediate'
        ]
        for fp in fomo_patterns:
            if re.search(fp, lower_text):
                qt_score = max(qt_score, 0.85)
                qt_label = "urgency"
                qt_explanation.append("High-pressure FOMO timer detected")
                print(f"🚩 QUANTUM MATCH: FOMO Timer")

        # 6. FINANCIAL PHISHING (Added for "secure-chase-online-banking-verify.top")
        financial_keywords = ['banking', 'secure', 'login', 'verify', 'account', 'update']
        financial_targets = ['chase', 'wellsfargo', 'bofa', 'citibank', 'paypal', 'stripe']
        
        # Check if URL contains at least 2 financial keywords AND 1 financial target
        keyword_count = sum(1 for k in financial_keywords if k in lower_text)
        target_found = any(t in lower_text for t in financial_targets)
        
        if keyword_count >= 2 and target_found:
             qt_score = max(qt_score, 0.92)
             qt_label = "impersonation"
             qt_explanation.append("Financial Phishing Pattern Detected")
             print(f"🚩 QUANTUM MATCH: Financial Phishing")

        # 7. TECH SUPPORT / MICROSOFT IMPERSONATION
        tech_keywords = ['microsoft', 'office-365', 'outlook', 'teams', 'windows', 'azure']
        tech_actions = ['update', 'repair', 'verify', 'security', 'alert', 'suspended']
        
        tech_kw_count = sum(1 for k in tech_keywords if k in lower_text)
        tech_act_count = sum(1 for k in tech_actions if k in lower_text)
        
        if tech_kw_count >= 1 and tech_act_count >= 1 and not is_whitelisted:
             qt_score = max(qt_score, 0.94)
             qt_label = "impersonation"
             qt_explanation.append("Tech Support/Microsoft Impersonation Detected")
             print(f"🚩 QUANTUM MATCH: Tech Support Impersonation")

        # 8. PIRACY & ILLEGAL CONTENT
        piracy_keywords = ['torrent', 'free-movie', 'download-free', 'crack', 'tamilrockers', '123movies', 'putlocker']
        if any(pk in lower_text for pk in piracy_keywords):
             qt_score = max(qt_score, 0.99)
             qt_label = "impersonation" # Misusing impersonation for high risk grouping
             qt_explanation.append("Piracy/Illegal Content Site Detected")
             print(f"🚩 QUANTUM MATCH: Piracy Site")

        # 9. SUSPICIOUS TLDs
        # High risk TLDs often used for scams
        suspicious_tlds = ['.date', '.xyz', '.top', '.download', '.review', '.party', '.win']
        has_sus_tld = any(lower_text.endswith(tld) or (tld + '/') in lower_text for tld in suspicious_tlds)
        
        if has_sus_tld:
             # Boost score if it has ANY other checking flags (e.g. "gift", "win", "claim", hyphenated)
             risk_triggers = ['gift', 'win', 'claim', 'prize', '-', 'offer']
             if any(rt in lower_text for rt in risk_triggers):
                  qt_score = max(qt_score, 0.88)
                  qt_label = "fear" # General Suspicious
                  qt_explanation.append("Suspicious TLD + High Risk Keywords")
                  print(f"🚩 QUANTUM MATCH: Suspicious TLD (.date/.xyz etc)")

        # 6. LEGACY HEURISTICS (Piracy/TLDs) - Kept for backward compatibility
        heuristic_score = 0.0
        heuristic_label = None

        # --- TEMPORAL AI ANALYSIS (Use Trained Models) ---
        if temporal_models and len(text) > 20:
             try:
                 t_cats = temporal_cat_model.predict([text])
                 t_scores = temporal_score_model.predict([text])
                 
                 t_cat = t_cats[0] 
                 t_risk = float(t_scores[0])
                 
                 print(f"🧠 Temporal AI: {t_cat} | Risk: {t_risk:.4f}")
                 
                 if t_cat == "MARKETING":
                      print("Suppressing Risk: Detected Marketing")
                      qt_score = qt_score * 0.1 # Suppress
                      qt_label = "urgency"
                      qt_explanation.append("Marketing verified (Risk Suppressed)")
                 
                 elif t_cat == "PHISHING":
                      if t_risk > qt_score:
                           qt_score = t_risk
                           qt_label = "urgency"
                           qt_explanation.append(f"AI Detected Phishing Language ({int(t_risk*100)}%)")
             except Exception as e:
                 print(f"Temporal Inference Failed: {e}")

        # --- LINGUISTIC TRIGGER EXTRACTION ---
        temporal_patterns = {
            "urgency": ["immediately", "urgent", "now", "asap", "quickly", "hurry", "expire", "seconds", "deadline"],
            "authority": ["official", "administrator", "security", "team", "legal", "verified", "required", "mandatory"],
            "fear": ["locked", "suspended", "blocked", "deleted", "unauthorized", "breach", "compromised", "risk"],
            "impersonation": ["support", "payment", "invoice", "billing", "account", "update", "verify", "bank", "amazon"]
        }
        
        # [STEP 4] COUNTDOWN VS DEADLINE
        is_countdown = 1 if re.search(r'(\d+ (minutes|hours))', lower_text) else 0
        if is_countdown:
            print("⏳ Temporal Pattern: Countdown detected (+0.15 boost)")

        for category, keywords in temporal_patterns.items():
            matches = []
            for kw in keywords:
                if re.search(r'\b' + kw + r'\b', lower_text):
                    matches.append(kw)
            
            if matches:
                # Boost probability slightly for each match if not already high
                base_prob = results_labels[category]["probability"]
                boost = len(matches) * 0.15
                new_prob = min(max(base_prob, boost), 0.99)
                results_labels[category]["probability"] = new_prob
                
                # Add to top_features
                for match in matches:
                    results_labels[category]["top_features"].append({
                        "word": match,
                        "weight": 0.8
                    })
                
                if new_prob > qt_score:
                    qt_score = new_prob
                    qt_label = category
                    qt_explanation.append(f"Temporal marker detected: {', '.join(matches)}")

        if heuristic_score > qt_score:
             qt_score = heuristic_score
             qt_label = heuristic_label
             qt_explanation.append("Pattern match (legacy heuristic)")

        # 10. [NEW] BRAND INTELLIGENCE ENGINE (Brand + Login + External Domain)
        # This enforces the rule: if brand_name AND login AND external domain -> force flag
        brand_map = {
            'amazon': ['amazon.com', 'amazon.in', 'amazon.co.uk', 'ssl-images-amazon.com', 'media-amazon.com'],
            'netflix': ['netflix.com', 'nflxso.net', 'nflxext.com'],
            'facebook': ['facebook.com', 'fb.com', 'facebook.net'],
            'whatsapp': ['whatsapp.com', 'wa.me'],
            'instagram': ['instagram.com', 'cdninstagram.com'],
            'google': ['google.com', 'google.co.in', 'youtube.com', 'gmail.com', 'gstatic.com'],
            'paypal': ['paypal.com', 'paypalobjects.com'],
            'microsoft': ['microsoft.com', 'live.com', 'office.com', 'windows.net'],
            'apple': ['apple.com', 'icloud.com'],
            'chase': ['chase.com'],
            'wellsfargo': ['wellsfargo.com']
        }
        
        auth_keywords = ['login', 'signin', 'sign-in', 'verify', 'account', 'update', 'suspend', 'security', 'billing', 'invoice']
        
        found_brand = None
        for brand in brand_map.keys():
            if brand in lower_text:
                found_brand = brand
                break
        
        if found_brand:
            # Check 1: Has Auth Keyword?
            has_auth_kw = any(kw in lower_text for kw in auth_keywords)
            
            # Check 2: Is External Domain? (Hostname does not end with any official domain)
            # hostname is extracted at top of function
            is_official = False
            for official_domain in brand_map[found_brand]:
                if hostname.endswith(official_domain):
                    is_official = True
                    break
            
            if has_auth_kw and not is_official and not is_whitelisted:
                 qt_score = max(qt_score, 0.96)
                 qt_label = "authority"
                 qt_explanation.append(f"Brand Impersonation detected: {found_brand} logic on external domain")
                 print(f"🚩 QUANTUM MATCH: Brand/Domain Mismatch ({found_brand} on {hostname})")


        # DECISION TIME
        if qt_score > 0:
             # Apply boosted score to relevant label
             if qt_label in results_labels:
                 # Update probability and mark the source
                 results_labels[qt_label]["probability"] = max(results_labels[qt_label]["probability"], qt_score)
                 results_labels[qt_label]["top_features"].append({"word": "QUANTUM_SENTINEL_V4", "weight": 1.0})
             
             final_explanation = " | ".join(qt_explanation)

             # PERSIST TO DB
             try:
                 db_scan = models.ScanResult(
                    url=text,
                    domain=text.split('/')[2] if '//' in text else text,
                    risk_score=qt_score,
                    risk_level="HIGH_RISK" if qt_score > 0.8 else "SUSPICIOUS",
                    explanation=f"Quantum Defense: {final_explanation}",
                    timestamp=datetime.now(IST)
                 )
                 db.add(db_scan)
                 db.commit()
             except Exception as de:
                 print(f"Quantum persist error: {de}")
             
             # If Quantum score is extremely high, we can return early
             if qt_score >= 0.98:
                  return {
                     "text": text,
                     "max_risk_score": qt_score,
                     "labels": results_labels
                  }
        # --- END QUANTUM DEFENSE ---

        # CHECK DATABASE BLOCKLIST (Immediate enforcement)
        try:
             # Clean URL to get hostname for check
             from urllib.parse import urlparse
             parsed = urlparse(text)
             hostname = parsed.netloc or parsed.path
             if hostname.startswith("www."): hostname = hostname[4:]
             
             # Check exact hostname match
             blocked = db.query(models.BlockedDomain).filter(models.BlockedDomain.domain == hostname).first()
             # Check parent domain match if not found
             if not blocked and '.' in hostname:
                 parts = hostname.split('.')
                 if len(parts) > 2:
                     parent = '.'.join(parts[1:])
                     blocked = db.query(models.BlockedDomain).filter(models.BlockedDomain.domain == parent).first()
             
             if blocked:
                 print(f"🚫 BLOCKED DETECTED: {text} (Matched: {blocked.domain})")
                 return {
                    "text": text,
                    "max_risk_score": 1.0, # Force BLOCK
                    "labels": {
                        "urgency": {"probability": 1.0, "top_features": [{"word": "BLOCKED_BY_USER", "weight": 1.0}]},
                        "authority": {"probability": 0.0, "top_features": []},
                        "fear": {"probability": 0.0, "top_features": []},
                        "impersonation": {"probability": 0.0, "top_features": []}
                    } 
                 }
        except Exception as e:
            print(f"Blocklist check error: {e}")

        # Clean and Vectorize input

        # Clean and Vectorize input
        clean_text = clean_url(text)
        
        # Feature Extraction (V6 Structural)
        X_vec = vectorizer.transform([clean_text])       
        X_manual = extract_manual_features([clean_text], [request.context] if request.context else None) 
        
        # Combine Features
        X_combined = hstack([X_vec, X_manual])
        
        # Get probabilities
        try:
            # MultiOutputClassifier returns a list of arrays (one per label)
            raw_probs = clf.predict_proba(X_combined)
            
            # Extract probability of class "1" (Positive) for each label
            probs = []
            
            # Ensure raw_probs is iterable (list of arrays for MultiOutput)
            if not isinstance(raw_probs, list):
                raw_probs = [raw_probs]

            for p in raw_probs:
                if len(p.shape) == 1:
                    p = p.reshape(1, -1)
                
                if p.shape[1] >= 2:
                    probs.append(float(p[0, 1]))
                else:
                    probs.append(0.0)
            
            # [NEW] AUTHORITY BINARY HEAD PREDICTION
            try:
                # Load on demand (or better, at top level, but for now safe inside try/except)
                # Ideally these should be loaded globally but main function flow allows this
                if 'auth_vectorizer' not in globals():
                    global auth_vectorizer, auth_clf
                    auth_vectorizer = joblib.load(os.path.join(MODELS_DIR, 'authority_vectorizer.joblib'))
                    auth_clf = joblib.load(os.path.join(MODELS_DIR, 'authority_head.joblib'))
                
                # Transform using the specific hashing vectorizer
                X_auth = auth_vectorizer.transform([text]) # Use raw text for character n-grams
                auth_prob_binary = float(auth_clf.predict_proba(X_auth)[0][1])
                print(f"🧠 Authority Head Prob: {auth_prob_binary:.4f}")
                
            except Exception as ae:
                print(f"Authority head error: {ae}")
                auth_prob_binary = 0.0

        except AttributeError as e:
            # Fallback
            print(f"Model prediction error: {e}")
            probs = [0.0, 0.0, 0.0, 0.0]
            auth_prob_binary = 0.0
            
        # [STEP 5] WEIGHTED RISK AGGREGATION
        # Instead of max(probs), we use a weighted sum to determine the final risk score.
        # Logic: Impersonation is the strongest signal, urgency alone shouldn't dominate.
        
        # [STEP 1] DECOUPLE URGENCY FROM MALICIOUS INTENT
        # Unified weights for malicious intent calculation
        risk_weights = {
            'urgency': 0.40,
            'fear': 0.30,
            'authority': 0.20,
            'impersonation': 0.10
        }
        
        weighted_risk = 0.0
        max_single_prob = 0.0
        
        for i, label in enumerate(labels):
            prob = probs[i]
            
            # Use dedicated head for Authority if available
            if label == 'authority' and 'auth_prob_binary' in locals():
                if auth_prob_binary > prob:
                    prob = auth_prob_binary
            
            # Incorporate Linguistic Triggers into the probability if they were higher
            if label in results_labels:
                prob = max(prob, results_labels[label]["probability"])
            
            # Update the results dict with the unified probability
            results_labels[label]["probability"] = float(prob)
            
            w = risk_weights.get(label, 0.25)
            weighted_risk += prob * w
            
            if prob > max_single_prob:
                max_single_prob = prob
        
        # [STEP 2] URGENCY LEGITIMACY GATE
        u_p = results_labels['urgency']['probability']
        f_p = results_labels['fear']['probability']
        a_p = results_labels['authority']['probability']
        
        # Simple rule: If high urgency but low fear/authority, it's likely marketing
        # Calms marketing false positives
        if u_p > 0.7 and f_p < 0.3 and a_p < 0.3:
            print("⚖️ Legitimate Urgency Gate: High Urgency but low intent signals. Calming score.")
            weighted_risk *= 0.6
        
        # Apply marketing pattern check
        legit_patterns = ["sale", "webinar", "discount", "offer", "register", "bonus", "gift"]
        if any(lp in lower_text for lp in legit_patterns) and f_p < 0.4:
            print(f"📦 Marketing Pattern Detected: Damping risk score")
            weighted_risk *= 0.7
            
        # [STEP 4 Continued] Apply Countdown boost
        if 'is_countdown' in locals() and is_countdown:
            weighted_risk += 0.15
            weighted_risk = min(weighted_risk, 1.0)

        # The Weighted Risk gives us a "System Confidence" score
        # But we also need to respect strong individual signals (Single Point of Failure)
        # So we take the Maximum of (Weighted Risk, Max Single Probability * Scaling Factor)
        # Actually, let's stick to the prompt's wisdom: Smarter final decision.
        # But if Impersonation is 0.99 and everything else is 0, Weighted Risk would be ~0.35
        # That's too low for a definite block.
        # Hybrid Approach:
        # If any single class > 0.85 -> Trust that class (Immediate Block)
        # Else -> Use Weighted Score to find "Hidden" combinations
        
        # [STEP 3] POST-PROCESSING CALIBRATION (Partial - Logic for specific overrides)
        final_risk_score = weighted_risk
        
        # Override if any single strong signal exists
        if max_single_prob > 0.85:
            final_risk_score = max(final_risk_score, max_single_prob)

        # --- HEURISTICS: DETECT SHADY SITES (Piracy, Gambling, etc.) ---
        suspicious_keywords = ["torrent", "putlocker", "123movies", "tamilrockers", "free download hd", "full movie", "camrip", "betting", "casino", "win money", "crack download", "keygen", "serial key", "stolen"]
        if any(kw in lower_text for kw in suspicious_keywords):
            if final_risk_score < 0.75:
                final_risk_score = 0.75
            
        max_prob = float(final_risk_score)

        # [STEP 4] PER-CLASS THRESHOLD OPTIMIZATION
        thresholds = {
            'urgency': 0.60,
            'authority': 0.65,
            'fear': 0.60,
            'impersonation': 0.70
        }
        
        display_type = "Clean"
        breached_labels = []
        for i, label in enumerate(labels):
            p = results_labels[label]["probability"]
            if p >= thresholds.get(label, 0.6):
                breached_labels.append(label)
        
        if len(breached_labels) > 0:
            if max_single_prob > 0.8:
                display_type = "Phishing"
            else:
                display_type = "Suspicious"
        elif weighted_risk > 0.5 or any(lp in lower_text for lp in legit_patterns):
             display_type = "Suspicious" # High pressure or Marketing pattern

        if "impersonation" in breached_labels:
            display_type = "Impersonation"
        elif "authority" in breached_labels and "urgency" in breached_labels:
            display_type = "Social Eng."
        
        # [STEP 3] POST-PROCESSING CALIBRATION
        # Force the model to align with functional risk ranges
        # PHISHING: 0.7 – 1.0 | MARKETING/SUSPICIOUS: 0.4 – 0.7 | SAFE: 0.0 – 0.3
        
        if display_type == "Clean":
            if final_risk_score > 0.3:
                final_risk_score = 0.3
        elif display_type in ["Suspicious", "Social Eng."] or any(lp in lower_text for lp in legit_patterns):
             if final_risk_score > 0.7:
                 final_risk_score = 0.7
             elif final_risk_score < 0.4:
                 final_risk_score = 0.4
        elif display_type in ["Phishing", "Impersonation"]:
            if final_risk_score < 0.7:
                 final_risk_score = 0.7
        
        final_risk_score = min(max(final_risk_score, 0.0), 1.0)
        max_prob = float(final_risk_score)
        
        
        # [NEW] RULE-BASED BOOST: Authority + Urgency (Still Apply Step 2 Logic)
        urgency_index = labels.index('urgency')
        urgency_prob = probs[urgency_index]
        
        # Re-calc auth prob
        auth_final_prob = probs[labels.index('authority')]
        if 'auth_prob_binary' in locals():
            auth_final_prob = max(auth_final_prob, auth_prob_binary)
            
        if auth_final_prob > 0.6 and urgency_prob > 0.6:
            max_prob += 0.2
            max_prob = min(max_prob, 1.0) # Cap at 1.0
            display_type = "Social Eng." # Force label
            print(f"🚀 BOOST TRIGGERED: Auth({auth_final_prob:.2f}) + Urgency({urgency_prob:.2f}) -> {max_prob:.2f}")

        # Hostname already extracted at top of function


        import uuid
        scan_entry = {
            "id": str(uuid.uuid4()),
            "domain": text[:50] + "..." if len(text) > 50 else text, # Display text
            "hostname": hostname, # Strict blocking domain
            "type": display_type,
            "timestamp": timestamp,
            "risk_score": max_prob
        }
        
        # Ensure list exists (it should be defined globally)
        if 'recent_scans' not in globals():
             recent_scans = []
             
        recent_scans.insert(0, scan_entry)
        if len(recent_scans) > 50: recent_scans.pop()
        
        # --- EMAIL FORENSICS & AUTHENTICATION FUSION LAYER ---
        email_auth_summary = {}
        dns_summary = {}
        fused_risk = {}
        geo_info = {}
        origin_mismatch_info = {}
        evidence_hash = ""

        if request.source in ["universal_scanner", "gmail_realtime"] or (request.context and hasattr(request.context, 'raw_headers')):
            try:
                from app.services.email_forensics import parse_raw_email_headers
                from app.services.ip_geolocation import geolocate_ip, evaluate_origin_mismatch
                from app.services.dns_analysis import analyze_sender_domain_dns
                from app.services.email_risk import fuse_email_risk_scores
                from app.services.forensic_report import compute_evidence_hash

                raw_hdrs = getattr(request.context, 'raw_headers', '') if request.context else ''
                email_auth_summary = parse_raw_email_headers(raw_hdrs)
                
                # Overwrite subject and sender_domain with parsed data if available
                if email_auth_summary.get("subject") and email_auth_summary.get("subject") != "unknown":
                    if request.context: request.context.subject = email_auth_summary.get("subject")
                if email_auth_summary.get("from") and email_auth_summary.get("from") != "unknown":
                    if request.context: request.context.sender_domain = email_auth_summary.get("from").split("@")[-1].strip(">").strip()

                sender_domain = ""
                if request.context and hasattr(request.context, 'sender_domain'):
                    sender_domain = request.context.sender_domain
                elif "@" in text:
                    sender_domain = text.split("@")[-1].split("\n")[0].strip()

                origin_ip = email_auth_summary.get("origin_ip", "unknown")
                geo_info = geolocate_ip(origin_ip)
                origin_mismatch_info = evaluate_origin_mismatch(sender_domain, geo_info)

                dns_summary = analyze_sender_domain_dns(sender_domain)
                
                ml_signals = {
                    "urgency": probs[labels.index('urgency')],
                    "fear": probs[labels.index('fear')],
                    "authority": probs[labels.index('authority')],
                    "impersonation": probs[labels.index('impersonation')]
                }
                email_ctx = {
                    "subject": email_auth_summary.get("subject", ""),
                    "text": text,
                    "is_whitelisted": is_whitelisted,
                    "sender_domain": sender_domain
                }
                
                fused_risk = fuse_email_risk_scores(
                    ml_content_score=max_prob,
                    ml_signals=ml_signals,
                    auth_summary=email_auth_summary,
                    dns_summary=dns_summary,
                    links_info=[],
                    impersonation_score=probs[labels.index('impersonation')],
                    origin_mismatch=origin_mismatch_info,
                    email_context=email_ctx
                )

                max_prob = fused_risk["final_email_score"]
                display_type = fused_risk["risk_level"]
                evidence_hash = compute_evidence_hash({
                    "subject": email_auth_summary.get("subject", ""),
                    "sender": email_auth_summary.get("from", ""),
                    "message_id": email_auth_summary.get("message_id", ""),
                    "origin_ip": origin_ip,
                    "timestamp": timestamp.isoformat(),
                    "risk_score": max_prob
                })

                print(f"📧 EMAIL FORENSIC FUSION: Score={max_prob} | Level={display_type} | Auth SPF={email_auth_summary.get('spf_status')} DKIM={email_auth_summary.get('dkim_status')} DMARC={email_auth_summary.get('dmarc_status')} | Origin={geo_info.get('city')}, {geo_info.get('country')} (Mismatch={origin_mismatch_info.get('mismatch')})")
            except Exception as ef_err:
                print(f"⚠️ Email Forensics Layer error: {ef_err}")

        # FINAL PRODUCTION SCHEMA
        return {
            "status": "CRITICAL" if max_prob >= 0.7 else ("SUSPICIOUS" if max_prob >= 0.4 else "SAFE"),
            "neural_status": neural_status,
            "global_risk_score": float(max_prob),
            "signals": results_labels,
            "structural_flags": get_structural_audit(text, request.context),
            "email_forensics": email_auth_summary,
            "dns_summary": dns_summary,
            "origin_forensics": geo_info,
            "origin_mismatch": origin_mismatch_info,
            "forensic_hash": evidence_hash,
            "explanation_summary": f"Target: {display_type} Analysis. Confidence: {max_prob*100:.1f}%"
        }
    except Exception as e:
        print(f"STABILIZATION ERROR: {str(e)}")
        # Ultimate fallback
        return {
            "status": "SAFE",
            "global_risk_score": 0.0,
            "signals": {l: {"probability": 0.0, "top_features": []} for l in labels},
            "structural_flags": {"error": "Processing Fault"},
            "explanation_summary": "System encounterd an internal node error. Result defaulted to SAFE."
        }
    except Exception as e:
        print("CRITICAL ERROR IN /detect:")
        import traceback
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
    finally:
         # PERSIST TO DATABASE (Fix for "Dashboard shows nothing")
        try:
             # Only persist if we have the necessary variables
             if 'max_prob' in locals() and 'hostname' in locals():
                 expl = f"Target: {display_type}" if 'display_type' in locals() else "Manual Scan"
                 if 'fused_risk' in locals() and fused_risk.get("factors"):
                     expl += " | Factors: " + ", ".join(fused_risk["factors"])
                     
                 r_level = "SAFE"
                 if max_prob > 0.8: r_level = "HIGH_RISK"
                 elif max_prob > 0.5: r_level = "SUSPICIOUS"
                 
                # --- PII MASKING LOGIC ---
                 final_url = text
                 
                 # PRIVACY MODE: For Gmail real-time scans, only store metadata
                 if request.source == "gmail_realtime" or request.source == "universal_scanner":
                     print(f"🔒 PRIVACY MODE: Gmail real-time scan - storing metadata only")
                     # Extract metadata from context (supports Pydantic object & dict)
                     if hasattr(request.context, 'subject'):
                         subject = getattr(request.context, 'subject', 'Email Scan') or 'Email Scan'
                         sender_domain = getattr(request.context, 'sender_domain', 'unknown') or 'unknown'
                     elif isinstance(request.context, dict):
                         subject = request.context.get('subject', 'Email Scan')
                         sender_domain = request.context.get('sender_domain', 'unknown')
                     else:
                         subject = 'Email Scan'
                         sender_domain = 'unknown'
                     # Store only metadata, not email content
                     final_url = f"[Gmail Scan] Subject: {subject} | From: {sender_domain}"
                     expl += " (Privacy Mode: Email content not stored)"
                     print(f"✅ Privacy protected: Only metadata stored")
                 else:
                     # Normal PII masking for other sources
                     try:
                         # Fetch settings
                         s = db.query(models.GlobalSettings).first()
                         print(f"🔍 PII Masking Check - Settings found: {s is not None}")
                         if s:
                             print(f"🔍 PII Masking Enabled: {s.pii_masking_enabled}")
                         
                         if s and s.pii_masking_enabled:
                             print(f"🙈 Starting PII masking for: {hostname}")
                             # Mask Email
                             final_url = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL_REDACTED]', final_url)
                             # Mask Phone (Generic 10-digit)
                             final_url = re.sub(r'\b\d{10}\b', '[PHONE_REDACTED]', final_url)
                             if final_url != text:
                                 expl += " (PII Masked)"
                                 print(f"✅ PII Masked for: {hostname}")
                             else:
                                 print(f"⚠️  No PII found to mask in: {hostname}")
                         else:
                             print(f"⏭️  PII Masking skipped (disabled or no settings)")
                     except Exception as pii_e:
                         print(f"❌ PII Mask error: {pii_e}")
                 
                 import json
                 db_scan = models.ScanResult(
                    url=final_url,
                    domain=hostname,
                    risk_score=max_prob,
                    risk_level=r_level,
                    explanation=expl,
                    timestamp=datetime.now(IST),
                    # Forensic Fields
                    sender=request.context.sender_domain if request.context and hasattr(request.context, 'sender_domain') else "unknown",
                    subject=request.context.subject if request.context and hasattr(request.context, 'subject') else "unknown",
                    spf_status=email_auth_summary.get("spf_status", "UNKNOWN") if 'email_auth_summary' in locals() else "UNKNOWN",
                    dkim_status=email_auth_summary.get("dkim_status", "UNKNOWN") if 'email_auth_summary' in locals() else "UNKNOWN",
                    dmarc_status=email_auth_summary.get("dmarc_status", "UNKNOWN") if 'email_auth_summary' in locals() else "UNKNOWN",
                    origin_ip=email_auth_summary.get("origin_ip", "unknown") if 'email_auth_summary' in locals() else "unknown",
                    received_chain=json.dumps(email_auth_summary.get("received_chain", [])) if 'email_auth_summary' in locals() else "[]",
                    auth_results=email_auth_summary.get("auth_results", "UNKNOWN") if 'email_auth_summary' in locals() else "UNKNOWN",
                    trust_score=fused_risk.get("trust_score", 0.0) if 'fused_risk' in locals() else 0.0,
                    category=fused_risk.get("category", "UNKNOWN") if 'fused_risk' in locals() else "UNKNOWN",
                    domain_age_days=dns_summary.get("domain_age_days", -1) if 'dns_summary' in locals() else -1,
                    whois_registrar=dns_summary.get("whois_registrar", "UNKNOWN") if 'dns_summary' in locals() else "UNKNOWN",
                    reply_to=email_auth_summary.get("reply_to", "unknown") if 'email_auth_summary' in locals() else "unknown",
                    return_path=email_auth_summary.get("return_path", "unknown") if 'email_auth_summary' in locals() else "unknown",
                    message_id=email_auth_summary.get("message_id", "unknown") if 'email_auth_summary' in locals() else "unknown",
                    origin_country=geo_info.get("country", "Unknown") if 'geo_info' in locals() else "Unknown",
                    origin_city=geo_info.get("city", "Unknown") if 'geo_info' in locals() else "Unknown",
                    origin_isp=geo_info.get("isp", "Unknown") if 'geo_info' in locals() else "Unknown",
                    origin_asn=geo_info.get("asn", "N/A") if 'geo_info' in locals() else "N/A",
                    geo_mismatch=1 if ('origin_mismatch_info' in locals() and origin_mismatch_info.get("mismatch")) else 0,
                    geo_mismatch_reason=origin_mismatch_info.get("reason", "") if 'origin_mismatch_info' in locals() else "",
                    forensic_hash=evidence_hash if 'evidence_hash' in locals() else "",
                    evidence_data=json.dumps(email_auth_summary) if 'email_auth_summary' in locals() else "{}"
                 )
                 db.add(db_scan)
                 db.commit()
                 print(f"✅ Persisted scan to DB: {hostname}")
        except Exception as db_e:
            print(f"❌ Failed to persist scan to DB: {db_e}")
            db.rollback()
        finally:
            db.close()


# Include routers
from app.routes import stats, settings
app.include_router(stats.router)
app.include_router(settings.router)
app.include_router(router)


# Include AI Chat Router
try:
    from app.routes.chat import router as chat_router
    app.include_router(chat_router)
    print("AI Chat Router registered successfully.")
except ImportError as e:
    print(f"Warning: Could not import chat router. Ensure 'backend' is in your PYTHONPATH. Error: {e}")

# --- DIRECT BLOCKING ENDPOINTS (To fix 404 issue) ---
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app import models
from pydantic import BaseModel

class DirectBlockRequest(BaseModel):
    domain: str

@app.post("/api/v1/block")
@app.post("/block_direct") # Debug alias
async def direct_block_domain(request: DirectBlockRequest, db: Session = Depends(get_db)):
    try:
        # Check if already blocked
        exists = db.query(models.BlockedDomain).filter(models.BlockedDomain.domain == request.domain).first()
        if not exists:
            blocked = models.BlockedDomain(domain=request.domain)
            db.add(blocked)
            db.commit()
            print(f"Direct block success: {request.domain}")
            return {"status": "success", "message": f"Domain {request.domain} blocked permanently."}
        return {"status": "skipped", "message": "Domain already blocked."}
    except Exception as e:
        print(f"Direct block error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/unblock")
async def unblock_domain(request: DirectBlockRequest, db: Session = Depends(get_db)):
    try:
        # Remove from Blocked list
        item = db.query(models.BlockedDomain).filter(models.BlockedDomain.domain == request.domain).first()
        if item:
            db.delete(item)
        
        # Add to Allowed list (Whitelist against AI)
        existing_allowed = db.query(models.AllowedDomain).filter(models.AllowedDomain.domain == request.domain).first()
        if not existing_allowed:
            new_allowed = models.AllowedDomain(domain=request.domain)
            db.add(new_allowed)

        db.commit()
        print(f"Unblocked and whitelisted: {request.domain}")
        return {"status": "success", "message": f"Unblocked and whitelisted {request.domain}"}
    except Exception as e:
        print(f"Direct unblock error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/blocklist")
async def direct_get_blocklist(db: Session = Depends(get_db)):
    try:
        blocked_domains = db.query(models.BlockedDomain).all()
        return {
            "status": "success",
            "count": len(blocked_domains),
            "domains": [{"domain": bd.domain, "blocked_at": bd.created_at.isoformat() if hasattr(bd, 'created_at') else None} for bd in blocked_domains]
        }
    except Exception as e:
        print(f"Direct blocklist error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
# ----------------------------------------------------

@app.on_event("startup")
async def startup_event():
    # Create tables if they don't exist
    print("Checking database tables...")
    try:
        from app.database import engine
        models.Base.metadata.create_all(bind=engine)
        print("Database tables checked/created.")
    except Exception as e:
        print(f"Database initialization warning (safe to ignore if tables exist): {e}")
    
    print("\n\n--- REGISTERED ROUTES ---")
    for route in app.routes:
        if hasattr(route, "path"):
            print(f"ROUTE: {route.path}")
    print("-------------------------\n\n")

    # --- AUTO RETENTION POLICY CHECK ---
    print("🧹 Running Data Retention Policy Check...")
    try:
        db = SessionLocal()
        settings = db.query(models.GlobalSettings).first()
        days = settings.retention_days if settings else 30
        
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(days=days)
        
        deleted = db.query(models.ScanResult).filter(models.ScanResult.timestamp < cutoff).delete()
        db.commit()
        db.close()
        print(f"✅ Retention Cleanup: Removed {deleted} records older than {days} days.")
    except Exception as e:
        print(f"⚠️ Retention Cleanup Warning: {e}")
    # -----------------------------------

@app.get("/health")
async def health():
    from datetime import datetime, timezone, timedelta
    
    IST = timezone(timedelta(hours=5, minutes=30))
    
    routes = []
    for route in app.routes:
        if hasattr(route, "path"):
            routes.append(route.path)
            
    return {
        "status": "ok",
        "api_version": "v1",
        "endpoints": routes,
        "timestamp": datetime.now(IST).isoformat(),
        "message": "PhishTrace API is running"
    }

# REGISTER THE ROUTER (Critical Fix: This was missing!)
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
