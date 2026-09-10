# 🔧 Backend Documentation

The PhishTrace backend is a FastAPI-powered REST API that provides real-time phishing and social engineering detection.

---

## 📁 File Structure

```
backend/
├── main.py              # Main FastAPI app, ML model, heuristics
├── app/
│   ├── models.py       # SQLAlchemy database models
│   ├── database.py     # Database configuration
│   └── routes/
│       ├── stats.py    # Dashboard statistics endpoints
│       ├── analysis.py # URL analysis endpoints
│       └── events.py   # Event logging endpoints
├── sql_app.db          # SQLite database (auto-created)
└── README.md           # This file
```

---

## 🚀 Starting the Server

```bash
# From project root
python start_server_v3.py
```

The server will start on `http://127.0.0.1:8002`

---

## 🔌 API Endpoints

### Core Detection

#### POST `/api/v1/detect`
**Purpose**: Analyze a URL for phishing/social engineering

**Request Body**:
```json
{
  "text": "https://example.com"
}
```

**Response**:
```json
{
  "text": "https://example.com",
  "max_risk_score": 0.85,
  "labels": {
    "urgency": {
      "probability": 0.12,
      "top_features": [...]
    },
    "authority": {
      "probability": 0.75,
      "top_features": [...]
    },
    "fear": {
      "probability": 0.45,
      "top_features": [...]
    },
    "impersonation": {
      "probability": 0.85,
      "top_features": [...]
    }
  }
}
```

**What Happens**:
1. Checks if URL is whitelisted (instant return 0.0)
2. Runs heuristic checks (piracy, suspicious tools, TLDs)
3. Checks database blocklist
4. Runs ML model if no match
5. Returns highest risk score
6. Saves result to database

---

### Dashboard Statistics

#### GET `/api/v1/dashboard`
**Purpose**: Get overview statistics

**Response**:
```json
{
  "kpi": {
    "total_scans": 456,
    "threats_blocked": 23,
    "critical_blocked": 12,
    "safety_score": 85
  },
  "recent_interventions": [...],
  "activity_trend": [...]
}
```

---

#### GET `/api/v1/activity`
**Purpose**: Get detailed activity log

**Query Parameters**:
- `limit`: Number of results (default: 20)
- `offset`: Pagination offset (default: 0)

**Response**:
```json
[
  {
    "id": 1,
    "domain": "example.com",
    "timestamp": "2025-12-30T10:30:00Z",
    "risk_score": 0.85,
    "risk_level": "HIGH_RISK",
    "status": "BLOCKED",
    "category": "Phishing",
    "explanation": "Heuristic Flag: Risky pattern detected",
    "is_blocked": true
  }
]
```

---

### Block Management

#### POST `/api/v1/block`
**Purpose**: Manually block a domain

**Request Body**:
```json
{
  "domain": "dangerous-site.com"
}
```

---

#### POST `/api/v1/unblock`
**Purpose**: Unblock a previously blocked domain

**Request Body**:
```json
{
  "domain": "safe-site.com"
}
```

---

#### GET `/api/v1/blocklist`
**Purpose**: Get list of all blocked domains

**Response**:
```json
{
  "blocked_domains": ["site1.com", "site2.xyz"]
}
```

---

## 🧠 Machine Learning Model

### Model Details
- **Algorithm**: SGD Classifier (Stochastic Gradient Descent)
- **Vectorizer**: HashingVectorizer (TF-IDF)
- **Features**: 16 manual + TF-IDF text features
- **Labels**: 4 outputs (multi-label classification)
  - urgency
  - authority
  - fear
  - impersonation

### Manual Features (16 total)

Located in `extract_manual_features()` function:

1. **has_ip_address**: URL contains IP (e.g., `192.168.1.1`)
2. **length_gt_50**: URL longer than 50 chars
3. **length_gt_75**: URL longer than 75 chars
4. **dot_count**: Number of `.` in URL (subdomain indicator)
5. **at_symbol_count**: Number of `@` symbols
6. **hyphen_count**: Number of hyphens (typosquatting indicator)
7. **has_login**: Contains "login" keyword
8. **has_signin**: Contains "signin" keyword
9. **has_account**: Contains "account" keyword
10. **has_update**: Contains "update" keyword
11. **has_verify**: Contains "verify" keyword
12. **has_secure**: Contains "secure" keyword
13. **has_bank**: Contains "bank" keyword
14. **has_confirm**: Contains "confirm" keyword

### Model Files
- `models/model_enhanced.joblib`: Trained classifier
- `models/vectorizer_enhanced.joblib`: Text vectorizer

---

## 🛡️ Heuristic Detection

### Whitelisted Patterns
Located in `safe_patterns` list (line ~150):

```python
safe_patterns = [
    'google.com', 'youtube.com', 'facebook.com',
    'amazon.com', 'wikipedia.org', 'reddit.com',
    'github.com', 'stackoverflow.com',
    # ... 50+ trusted domains
]
```

**Purpose**: Instant 0.0 risk for known-safe sites

---

### Piracy Detection (0.95 Risk Score)
Located around line 257:

```python
risky_keywords = [
    'tamilrockers', 'moviesda', 'torrent', 'crack',
    'tamilyogi', 'isaimini', 'kuttymovies', 'movierulz',
    '123movies', 'fmovies', 'putlocker', '1tamilmv', 'tamilgun'
]
```

---

### Suspicious Tools Detection (0.65 Risk Score)
Located around line 277:

```python
suspicious_tools = [
    'unscramble', 'bypass', 'unblock', 'proxy',
    'solver', 'generator', 'keygene'
]
```

---

### Suspicious TLDs (0.85 Risk Score)
Located around line 259:

```python
risky_tlds = [
    '.care', '.top', '.best', '.win', '.bid', '.date',
    '.tk', '.ml', '.ga', '.xyz', '.stream', '.movie', '.vip'
]
```

---

## 🗄️ Database Schema

### scan_results Table
```sql
CREATE TABLE scan_results (
    id INTEGER PRIMARY KEY,
    url TEXT,
    domain TEXT,
    risk_score FLOAT,
    risk_level TEXT,  -- 'SAFE', 'SUSPICIOUS', 'HIGH_RISK'
    explanation TEXT,
    timestamp DATETIME
);
```

### blocked_domains Table
```sql
CREATE TABLE blocked_domains (
    id INTEGER PRIMARY KEY,
    domain TEXT UNIQUE,
    timestamp DATETIME
);
```

### allowed_domains Table
```sql
CREATE TABLE allowed_domains (
    id INTEGER PRIMARY KEY,
    domain TEXT UNIQUE,
    timestamp DATETIME
);
```

---

## ⚡ Performance Optimizations

### 1. SQL Indexes
- `timestamp` column indexed for fast sorting
- `domain` columns indexed for quick lookups

### 2. Set-based Lookups
- Blocklist checks use Python sets (O(1) lookup)
- Avoids nested loops for better performance

### 3. Limit Defaults
- Activity endpoint limits to 20 results by default
- Prevents slow queries on large datasets

### 4. Simplified Trend Calculation
- Dashboard trend uses heuristic calculation
- Avoids expensive date aggregation queries

---

## 🔧 Configuration

### Database Path
Located in `app/database.py`:

```python
SQLALCHEMY_DATABASE_URL = "sqlite:///D:/coding_files/DTLshit/backend/app/sql_app.db"
```

**Important**: Uses absolute path to avoid conflicts

### CORS Settings
Located in `main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## 🐛 Debugging

### Enable Detailed Logging
The backend prints debug info:
- `🚩 HEURISTIC MATCH (Piracy): [url]`
- `🚩 HEURISTIC MATCH (Suspicious Tool): [url]`
- `🚩 HEURISTIC MATCH (TLD): [url]`

### Check Database
```bash
sqlite3 backend/app/sql_app.db
.tables
SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT 10;
```

### API Documentation
Visit: `http://127.0.0.1:8002/docs`

FastAPI provides interactive Swagger UI for testing endpoints.

---

## 🔄 Code Flow

### Detection Pipeline
```
Request: POST /api/v1/detect
    ↓
1. Extract URL from request.text
    ↓
2. Clean URL (remove http://, www.)
    ↓
3. Check Whitelist
   → If match: return 0.0 score
    ↓
4. Check Heuristic Overrides
   → Piracy keywords? → 0.95 score
   → Suspicious tools? → 0.65 score
   → Risky TLD? → 0.85 score
   → If match: return score & save to DB
    ↓
5. Check Database Blocklist
   → If blocked: return 1.0 score
    ↓
6. Run ML Model
   → Extract manual features
   → Vectorize text
   → Predict 4 labels
   → Get max probability
    ↓
7. Save to Database
    ↓
8. Return Response
```

---

## 📊 Adding New Heuristics

### Example: Detect Gambling Sites
1. Edit `main.py` around line 256
2. Add keywords:
```python
gambling_keywords = ['casino', 'poker', 'slots', 'betting']
```
3. Add check after suspicious tools:
```python
elif any(kw in text.lower() for kw in gambling_keywords):
    heuristic_score = 0.75
    heuristic_label = "authority"
    print(f"🚩 HEURISTIC MATCH (Gambling): {text}")
```
4. Restart backend

---

## 🧪 Testing Endpoints

### Using curl
```bash
curl -X POST http://127.0.0.1:8002/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "https://tamilrockers.com"}'
```

### Using PowerShell
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8002/api/v1/detect" `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"text": "https://example.com"}'
```

---

## 📈 Monitoring

### Health Check
```bash
curl http://127.0.0.1:8002/docs
```

Should return Swagger UI if backend is running.

### Database Stats
```python
import sqlite3
conn = sqlite3.connect('backend/app/sql_app.db')
cursor = conn.cursor()
print(cursor.execute('SELECT COUNT(*) FROM scan_results').fetchone())
```

---

**Technical Support**: See [Developer Guide](../DEVELOPER_GUIDE.md) for extending the backend.
