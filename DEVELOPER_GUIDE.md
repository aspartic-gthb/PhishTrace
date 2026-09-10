# 🔧 Developer Guide

This guide is for developers who want to extend, modify, or contribute to PhishTrace.

---

## 🏗️ Architecture Overview

```
┌─────────────────┐
│  Chrome         │
│  Extension      │ ← User interacts here
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│  Backend API    │
│  (FastAPI)      │ ← ML model runs here
└────────┬────────┘
         │ SQL
         ▼
┌─────────────────┐
│  SQLite DB      │ ← Data stored here
└─────────────────┘
         ▲
         │ HTTP
┌─────────────────┐
│  Dashboard      │
│  (Next.js)      │ ← Admin monitors here
└─────────────────┘
```

---

## 🛠️ Development Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- Chrome browser
- Git

### Clone & Install
```bash
# Clone repository
cd d:\coding_files\DTLshit

# Backend dependencies
pip install -r requirements.txt

# Frontend dependencies
cd my-app
npm install
```

---

## 🧠 Machine Learning Pipeline

### Model Training
Located in training scripts (not included in this repo):

1. **Data Collection**
   - PhishTank API
   - OpenPhish feeds
   - Benign URLs from Alexa top sites

2. **Feature Engineering**
   ```python
   def extract_manual_features(urls):
       # 16 hand-crafted features
       # + TF-IDF vectorization
   ```

3. **Training**
   ```python
   from sklearn.linear_model import SGDClassifier
   clf = SGDClassifier(loss='log', max_iter=100)
   clf.fit(X_train, y_train)
   ```

4. **Evaluation**
   - Accuracy: ~94%
   - F1-Score: ~0.92
   - Precision: ~0.96 (low false positives)

### Model Files
- `models/model_enhanced.joblib`
- `models/vectorizer_enhanced.joblib`

---

## 🔧 Adding New Features

### 1. Add Heuristic Detection

**File**: `backend/main.py`

```python
# Around line 256, add new keywords
gambling_keywords = ['casino', 'poker', 'betting']

# Around line 277, add detection logic
elif any(kw in text.lower() for kw in gambling_keywords):
    heuristic_score = 0.70
    heuristic_label = "authority"
    print(f"🚩 HEURISTIC MATCH (Gambling): {text}")
```

---

### 2. Add Database Table

**File**: `backend/app/models.py`

```python
class ReportedDomain(Base):
    __tablename__ = "reported_domains"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    reason = Column(String)
    timestamp = Column(DateTime, server_default=func.now())
```

---

### 3. Add API Endpoint

**File**: `backend/app/routes/analysis.py`

```python
@router.post("/report")
async def report_false_positive(
    domain: str, 
    reason: str,
    db: Session = Depends(get_db)
):
    report = models.ReportedDomain(
        domain=domain,
        reason=reason
    )
    db.add(report)
    db.commit()
    return {"status": "success"}
```

---

### 4. Add Dashboard Component

**File**: `my-app/components/ReportButton.tsx`

```typescript
export function ReportButton({ domain }: { domain: string }) {
  const handleReport = async () => {
    await fetch(`${API_BASE_URL}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        domain, 
        reason: "False positive" 
      })
    });
  };
  
  return <button onClick={handleReport}>Report</button>;
}
```

---

## 🧪 Testing

### Backend Tests
```bash
# Install pytest
pip install pytest

# Run tests
pytest backend/tests/
```

### Frontend Tests
```bash
cd my-app
npm run test
```

### Extension Testing
1. Load unpacked extension
2. Make code changes
3. Click reload at `chrome://extensions/`
4. Test on search page

---

## 🔍 Debugging

### Backend Debugging
```python
# Add logging to main.py
import logging
logging.basicConfig(level=logging.DEBUG)

# In detect endpoint
print(f"DEBUG: URL={text}, Score={heuristic_score}")
```

### Frontend Debugging
```typescript
// In page.tsx
console.log("Dashboard data:", data);
```

### Extension Debugging
```javascript
// In content.js
console.log("[PhishTrace] Analysis result:", response);
```

---

## 📊 Database Schema

### Migrations
When changing models:
```python
# backend/app/database.py
from app.models import Base
Base.metadata.create_all(bind=engine)
```

### Backup Database
```bash
cp backend/app/sql_app.db backend/app/sql_app.db.backup
```

### Query Database
```bash
sqlite3 backend/app/sql_app.db
.schema scan_results
SELECT * FROM scan_results LIMIT 10;
```

---

## 🚀 Deployment

### Backend Deployment
```bash
# Using gunicorn
pip install gunicorn
gunicorn backend.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### Dashboard Deployment
```bash
cd my-app
npm run build
npm start
```

### Extension Distribution
1. Zip `extension-clean` folder
2. Upload to Chrome Web Store
3. Or distribute as `.crx` file

---

## 🔐 Security Best Practices

### Backend
- Use environment variables for secrets
- Enable HTTPS in production
- Restrict CORS origins
- Validate all inputs
- Rate limit API endpoints

### Frontend
- Sanitize user inputs
- Use HTTPS for API calls
- Implement CSP headers
- Avoid inline scripts

### Extension
- Minimize permissions
- Validate API responses
- Sanitize DOM injections
- Use Content Security Policy

---

## 📝 Code Style

### Python (Backend)
```python
# Use Black formatter
pip install black
black backend/

# Use type hints
def analyze_url(url: str) -> float:
    pass
```

### TypeScript (Frontend)
```typescript
// Use Prettier
npm install --save-dev prettier
npm run format

// Use strict typing
const score: number = 0.85;
```

### JavaScript (Extension)
```javascript
// Use ESLint
npm install --save-dev eslint
```

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Make changes
4. Test thoroughly
5. Commit: `git commit -m "Add feature"`
6. Push: `git push origin feature-name`
7. Create Pull Request

---

## 📚 Resources

### Machine Learning
- [Scikit-learn Docs](https://scikit-learn.org/)
- [PhishTank](https://www.phishtank.com/)
- [OpenPhish](https://openphish.com/)

### Web Development
- [FastAPI Docs](https://fastapi.tiangolo.com/)
- [Next.js Docs](https://nextjs.org/docs)
- [Chrome Extensions](https://developer.chrome.com/docs/extensions/)

### Security
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Phishing Detection Papers](https://scholar.google.com/)

---

## 🐛 Known Issues

1. **Cache clearing**: Extension cache persists across reloads
2. **Blocklist sync**: 30-minute delay for new blocks
3. **Dashboard polling**: Can cause high CPU on slow machines
4. **ML model**: Limited to English URLs

---

## 🔮 Future Roadmap

### Short Term
- [ ] Export activity logs
- [ ] Custom risk thresholds
- [ ] Email alerts
- [ ] Mobile app

### Long Term
- [ ] Deep learning models
- [ ] Browser fingerprinting
- [ ] Community threat sharing
- [ ] Enterprise features

---

**Questions?** See [Main README](./README.md) or check existing documentation files.
