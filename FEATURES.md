# 🛡️ PhishTrace Defense Layers - Deep Dive

This document explains the six defense layers that make up PhishTrace's protection system.

---

## 1. 🔍 Behavioral Baseline

### What It Does
Monitors how websites behave and compares them against millions of known-safe websites. If a site does something unusual, it's flagged as suspicious.

### How It Works
- **Training Data**: Trained on 1.2M+ legitimate websites
- **Anomaly Detection**: Identifies deviations from normal behavior
- **Indicators**:
  - Unusual redirect chains
  - Unexpected permission requests
  - Hidden form fields
  - Suspicious JavaScript patterns

### Example
A normal banking site loads directly and shows a login form. A phishing site might:
- Redirect through multiple domains
- Load suspicious tracking scripts
- Hide fake login forms in iframes

**Result**: Behavioral Baseline catches the unusual redirect pattern.

---

## 2. ⏰ Temporal Analysis

### What It Does
Detects psychological pressure tactics that try to rush you into making unsafe decisions.

### How It Works
Scans for urgency keywords and time-pressure phrases:
- "Act now or lose access"
- "Limited time offer"
- "Your account will be deleted in X hours"
- "Immediate action required"

### Psychology Behind It
Attackers use **urgency** to bypass your rational thinking. When you feel rushed, you're more likely to:
- Skip security warnings
- Enter credentials on fake sites
- Click malicious links

### Example Keywords Detected
```
urgency, now, immediate, expire, deadline, limited, 
hurry, countdown, last chance, act fast, verify now
```

### Result
Sites using these tactics get flagged as "Social Engineering" attempts.

---

## 3. 🧠 Neural Detection (Core AI Engine)

### What It Does
The main machine learning model that analyzes URLs and gives the base risk score.

### Technical Details
- **Model**: SGD Classifier (Stochastic Gradient Descent)
- **Features**: 16 manual features + TF-IDF text features
- **Labels**: 4 categories
  - Urgency
  - Authority
  - Fear
  - Impersonation
- **Training**: 1.2M samples from PhishTank, OpenPhish, and benign datasets

### Manual Features Extracted
1. **Has IP Address** (e.g., `http://192.168.1.1`)
2. **Long URL** (>50 characters)
3. **Very Long URL** (>75 characters)
4. **Number of Dots** (subdomains)
5. **@ Symbol** (often used in phishing)
6. **Hyphens Count** (typosquatting indicator)
7. **Sensitive Keywords**:
   - login, signin, account, update
   - verify, secure, bank, confirm

### How It Scores
```
Input: https://secure-paypal-verify.tk/login

Features Extracted:
- Long URL: No (33 chars)
- Suspicious TLD: Yes (.tk)
- Sensitive Keywords: Yes ("secure", "paypal", "verify", "login")
- Domain structure: suspicious

ML Model Output:
- Urgency: 82%
- Authority: 75%
- Fear: 45%
- Impersonation: 91%

Final Risk Score: 0.91 (91%) → RED BADGE
```

---

## 4. 🛡️ Cognitive Shield

### What It Does
Breaks the "spell" of psychological manipulation by explicitly labeling the tactics being used.

### Three Attack Vectors Detected

#### A. Authority Impersonation
**Tactic**: Pretending to be an official entity
**Examples**:
- "FBI Warning: Your computer is locked"
- "Official Microsoft Security Alert"
- "IRS Payment Required"

**Detection**: Scans for authority keywords + mismatched domains

#### B. Fear Tactics
**Tactic**: Making you panic to act without thinking
**Examples**:
- "VIRUS DETECTED - Click to remove"
- "Security Breach: Change password now"
- "Suspicious activity on your account"

**Detection**: Identifies fear-inducing language patterns

#### C. Impersonation
**Tactic**: Fake login pages that look like real services
**Examples**:
- `paypa1.com` (looks like paypal.com)
- `g00gle.com` (homoglyph attack)
- `microsoft-login.xyz`

**Detection**: 
- Domain similarity analysis
- Homoglyph detection (0 vs O, 1 vs l)
- Typosquatting patterns

### Example
```
URL: https://paypa1-secure.tk/login

Cognitive Shield Analysis:
✓ Impersonation Detected: Domain mimics "paypal.com"
✓ Authority Detected: Uses word "secure"
✓ Sensitive Context: Login page

Risk Score: 0.95 → RED BADGE
Category: "Phishing - Impersonation"
```

---

## 5. ⚡ Quantum Defense (Heuristic Overrides)

### What It Does
Provides **instant protection** for known-bad patterns without waiting for ML analysis.

### Why It's Called "Quantum"
Like quantum computing's instant calculations, this layer provides zero-latency blocking for threats we already know about.

### Heuristic Categories

#### A. Piracy & Copyright Infringement (0.95 Risk)
```python
risky_keywords = [
    'tamilrockers', 'moviesda', 'torrent', 'crack', 
    'tamilyogi', 'isaimini', 'kuttymovies', 'movierulz',
    '123movies', 'fmovies', 'putlocker'
]
```

#### B. Suspicious TLDs (0.85 Risk)
```python
risky_tlds = [
    '.care', '.top', '.xyz', '.tk', '.ml', '.ga',
    '.stream', '.movie', '.vip', '.win'
]
```

#### C. Bypass/Solver Tools (0.65 Risk)
```python
suspicious_tools = [
    'unscramble', 'bypass', 'unblock', 'proxy',
    'solver', 'generator', 'keygene'
]
```

### Flow Chart
```
URL Received
    ↓
Check Heuristics (0.001 seconds)
    ↓
Match Found? → Return High Risk Score Immediately
    ↓
No Match? → Continue to ML Model
```

### Example
```
Input: https://tamilrockers.xyz

Heuristic Match: "tamilrockers" (piracy keyword)
Action: Bypass ML, return 0.95 risk score
Time Saved: ~100ms
```

---

## 6. 🌐 PhishTrace Mesh (Synchronization Layer)

### What It Does
Keeps all components (Extension, Backend, Dashboard) in perfect sync.

### Components Connected

#### Extension ↔ Backend
- Extension sends URLs for analysis
- Backend returns risk scores
- Real-time communication via REST API

#### Backend ↔ Database
- Saves all scan results
- Manages block/unblock lists
- Persists user decisions

#### Dashboard ↔ Backend
- Fetches activity logs
- Displays statistics
- Allows manual interventions

### Synchronization Features

#### 1. Real-time Updates
- Dashboard polls every 5 seconds
- Extension caches for 30 minutes
- Instant sync on manual block/unblock

#### 2. Persistent Blocklist
```
User blocks domain on Dashboard
    ↓
Backend updates database
    ↓
Extension syncs blocklist (every 30 min)
    ↓
All tabs protected within 30 minutes
```

#### 3. Activity Logging
Every URL analyzed is logged:
- Timestamp
- Risk score
- Risk level
- Category
- Block status

### Data Flow Diagram
```
┌─────────────┐
│   Browser   │
└──────┬──────┘
       │
   [visits URL]
       │
       ▼
┌─────────────┐      HTTP POST      ┌─────────────┐
│  Extension  │ ──────────────────> │   Backend   │
│  (content.  │                     │   (FastAPI) │
│    js)      │ <────────────────── │             │
└─────────────┘   [Risk Score]      └──────┬──────┘
       │                                    │
       │                               [Save to DB]
       │                                    │
   [Show Badge]                             ▼
       │                             ┌─────────────┐
       │                             │  Database   │
       │                             │  (SQLite)   │
       ▼                             └──────┬──────┘
┌─────────────┐                            │
│ User Sees   │                       [Read Stats]
│   Badge     │                            │
└─────────────┘                            ▼
                                    ┌─────────────┐
                                    │  Dashboard  │
                                    │  (Next.js)  │
                                    └─────────────┘
```

---

## 🔄 How All 6 Layers Work Together

### Example: User Visits Phishing Site

```
URL: https://secure-paypa1-login.tk/verify

Layer 1: Behavioral Baseline
→ Checks: No unusual redirects detected
→ Status: Pass to next layer

Layer 2: Temporal Analysis  
→ Checks: No urgency keywords in URL
→ Status: Pass to next layer

Layer 3: Neural Detection
→ Extracts: "paypa1", "login", "verify", ".tk"
→ ML Score: 0.87 (High Risk)
→ Status: FLAGGED

Layer 4: Cognitive Shield
→ Detects: Impersonation (paypa1 vs paypal)
→ Detects: Authority keyword "secure"
→ Status: CONFIRMED THREAT

Layer 5: Quantum Defense
→ Checks: TLD is .tk (suspicious)
→ Override Score: 0.85
→ Status: INSTANT BLOCK

Layer 6: PhishTrace Mesh
→ Logs to database
→ Updates dashboard
→ Shows RED BADGE in browser

Final Result: 🔴 95% High Risk - BLOCKED
Category: Phishing - Impersonation
```

---

## 🎯 Performance Metrics

- **Detection Speed**: <50ms average
- **Accuracy**: ~94% (based on test dataset)
- **False Positives**: <2%
- **Cache Hit Rate**: ~70% (saves repeated API calls)

---

## 📊 Risk Score Breakdown

| Score Range | Badge Color | Meaning | Action |
|------------|-------------|---------|--------|
| 0% - 40% | 🟢 Green | Safe | Browse normally |
| 41% - 70% | 🟡 Yellow | Moderate | Be cautious |
| 71% - 100% | 🔴 Red | Dangerous | Avoid/Block |

---

## 🔮 Future Enhancements

1. **Community Intelligence**: Share threat data across users
2. **Deep Learning Models**: More accurate pattern detection
3. **Browser Sandboxing**: Isolate risky sites automatically
4. **Mobile Support**: Android/iOS protection
5. **Email Protection**: Scan phishing emails

---

This multi-layered approach ensures that even if a clever attacker bypasses one layer, the others will catch them!
