# 🌐 Chrome Extension Documentation

PhishTrace Chrome Extension provides real-time phishing protection in your browser.

---

## 📁 Files

```
extension-final/
├── manifest.json           # Extension config
├── src/
│   ├── background/
│   │   └── service-worker.js  # API communication
│   └── content/
│       └── content.js      # Badge injection
├── blocked.html           # Warning page
└── README.md             # This file
```

---

## 🎯 How It Works

### Content Script (`content.js`)
Runs on search pages and injects badges.

**Key Functions**:
- `scanLink(link)` - Analyzes URL via backend
- `addBadge(link, data)` - Shows colored badge
- `createRiskPopup(data)` - Detailed risk info

### Background Script (`service-worker.js`)
Handles API calls and caching.

**Key Features**:
- Calls `/detect` API
- Caches results (30 min)
- Syncs blocklist
- Blocks dangerous sites

---

## 🎨 Badge Colors

- 🟢 **Green** (0-40%): Safe
- 🟡 **Yellow** (41-70%): Moderate risk
- 🔴 **Red** (71-100%): Dangerous

---

## 🔧 Configuration

### API Endpoint
```javascript
const API_BASE = "http://127.0.0.1:8005/api/v1";
```

### Cache Settings
```javascript
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes
const MAX_CACHE_SIZE = 100;
```

---

## 🐛 Troubleshooting

**Badges not showing?**
1. Check backend: `http://127.0.0.1:8005/docs`
2. Open extension background console:
   - `chrome://extensions` -> Inspect views: `service worker`
3. Reload extension: click refresh icon on extension card
4. Verify backend is running on `http://127.0.0.1:8005`

**Extension slow?**
1. Reload to clear cache (100-item limit)
2. Close unused tabs

---

## 📊 Performance

- Analysis: <50ms per URL
- Badge injection: <10ms
- Cache hit rate: ~70%
- Memory: <5MB

---

## 🔐 Permissions

- `storage` - Cache results
- `webNavigation` - Intercept navigation
- `alarms` - Periodic sync

---

**See**: [Main README](../README.md) for complete documentation
