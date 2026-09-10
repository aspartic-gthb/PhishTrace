# 📖 PhishTrace User Guide

Welcome to PhishTrace! This guide will help you understand and use all the features to stay safe online.

---

## 🚀 Getting Started

### Step 1: Installation

1. **Start the Backend** (This runs the AI detection engine)
   ```bash
   python start_server_v3.py
   ```
   You should see: `Uvicorn running on http://127.0.0.1:8002`

2. **Install the Chrome Extension**
   - Open Chrome and type: `chrome://extensions/`
   - Toggle "Developer mode" ON (top right)
   - Click "Load unpacked"
   - Navigate to and select the `extension-clean` folder
   - You should see the PhishTrace icon appear

3. **Open the Dashboard** (Optional - for monitoring)
   ```bash
   cd my-app
   npm run dev
   ```
   Visit: `http://localhost:3000`

---

## 🎨 Understanding the Badges

When you search on Google or Brave, you'll see small colored dots next to each result:

### 🟢 Green Badge (Safe)
- **Risk Score**: 0% - 40%
- **Meaning**: The website is safe to visit
- **Example**: Google.com, Wikipedia.org

### 🟡 Yellow Badge (Be Careful)
- **Risk Score**: 41% - 70%
- **Meaning**: The website has some suspicious elements
- **Action**: Proceed with caution, don't enter personal information
- **Example**: Word unscramblers, proxy sites, ad-heavy pages

### 🔴 Red Badge (Dangerous)
- **Risk Score**: 71% - 100%
- **Meaning**: High risk of phishing or malware
- **Action**: DO NOT VISIT
- **Example**: Fake bank login pages, piracy sites, scam portals

---

## 🔍 How to Use the Badges

### On Search Results
1. Search for anything on Google or Brave
2. Look for small colored dots next to each result
3. Hover over the dot to see detailed info

### Click for Details
Click any badge to see:
- Risk percentage
- Category (Phishing, Social Engineering, etc.)
- Detection signals

---

## 📊 Using the Dashboard

### Accessing the Dashboard
1. Make sure the backend is running
2. Open your browser to: `http://localhost:3000`
3. Navigate to **Dashboard** from the navbar

### Dashboard Features

#### 1. Overview Page
Shows key statistics:
- **Total Scans**: How many websites analyzed
- **Threats Blocked**: How many dangerous sites found
- **Critical Blocked**: How many red-flagged sites
- **Safety Score**: Your overall protection level

#### 2. Activity Insights
View all browsing history:
- **Domain**: Which website you visited
- **Timestamp**: When you visited
- **Risk Score**: The danger level (%)
- **Status**: Blocked, Warned, or Safe
- **Category**: Type of threat detected

#### 3. Block/Unblock Sites

**To Block a Website:**
1. Go to Activity Insights
2. Find the website you want to block
3. Click the 🚫 icon next to it
4. The site will turn red and show "BLOCKED"
5. Reload your Chrome extension (`chrome://extensions/` → Reload button)

**To Unblock a Website:**
1. Find the blocked site in Activity Insights
2. Click the 🔓 icon next to it
3. The block status will be removed
4. Reload your Chrome extension

---

## 🛡️ Real-Time Protection

### How It Works
Every time you visit a website:
1. Extension sends the URL to the backend
2. Backend analyzes it in <50ms
3. Extension shows a badge based on risk
4. Dashboard logs the activity

### What Gets Analyzed
- URL structure
- Domain name
- Keywords in the URL
- TLD (top-level domain like .com, .tk)
- Behavioral patterns

---

## ⚙️ Advanced Features

### Manual Allowlist
If a safe site is incorrectly flagged:
1. Note the domain name
2. Edit `backend/main.py`
3. Add the domain to `safe_patterns` list
4. Restart the backend

### Clear Cache
If badges aren't updating:
1. Go to `chrome://extensions/`
2. Find PhishTrace
3. Click "Reload"
4. Refresh your search page

---

## 🎯 Common Use Cases

### Use Case 1: Safe Online Shopping
**Problem**: Not sure if a shopping site is legitimate

**Solution**:
1. Search for the store name on Google
2. Check the badge color:
   - 🟢 Green = Safe to shop
   - 🟡 Yellow = Be cautious, check reviews
   - 🔴 Red = Avoid completely

### Use Case 2: Avoiding Phishing Emails
**Problem**: Received email with suspicious link

**Solution**:
1. Copy the link (don't click!)
2. Search for the domain on Google
3. Check PhishTrace's badge
4. If red or yellow, delete the email

### Use Case 3: Safe Downloading
**Problem**: Need to download software

**Solution**:
1. Search for the official website
2. Only download if badge is 🟢 Green
3. Avoid sites with yellow or red badges

---

## 📈 Understanding Risk Categories

### Phishing
**What**: Fake websites trying to steal passwords
**Badge**: Usually 🔴 Red
**Example**: `paypa1.com` pretending to be PayPal

### Social Engineering
**What**: Sites using psychological tricks
**Badge**: Usually 🟡 Yellow or 🔴 Red
**Example**: "Your account will be deleted in 2 hours!"

### Piracy
**What**: Illegal content streaming/download sites
**Badge**: Always 🔴 Red
**Example**: Tamilrockers, 123Movies

### Suspicious Tools
**What**: Sites offering bypass/solver services
**Badge**: Usually 🟡 Yellow
**Example**: Word unscramblers, proxy sites

---

## 🔧 Troubleshooting

### Problem: Badges Not Appearing
**Solutions**:
1. Check backend is running: Visit `http://127.0.0.1:8002/docs`
2. Reload extension at `chrome://extensions/`
3. Clear browser cache and reload page

### Problem: Wrong Risk Score
**Solutions**:
1. Check Recent Updates: Model might need retraining
2. Manual Override: Add to allowlist in backend
3. Report: Note the URL for model improvement

### Problem: Dashboard Shows "Loading..."
**Solutions**:
1. Verify backend is running on port 8002
2. Check browser console for errors (F12)
3. Restart the Next.js server (`npm run dev`)

### Problem: Extension Slow After Many Searches
**Solutions**:
1. The extension caches results
2. If it gets slow, reload it at `chrome://extensions/`
3. Cache automatically clears when it reaches 100 items

---

## 🔒 Privacy & Security

### What Data is Collected?
- URLs you visit (stored locally only)
- Risk scores
- Block/unblock decisions

### What is NOT Collected?
- No personal information
- No browsing habits shared externally
- No third-party tracking

### Where is Data Stored?
- Everything is stored locally on your computer
- Database location: `backend/app/sql_app.db`
- No cloud sync, no external servers

---

## 💡 Tips & Best Practices

### 1. Trust the Red Badges
If something shows 🔴 Red, **avoid it completely**. The system has detected multiple risk factors.

### 2. Be Cautious with Yellow
🟡 Yellow means "proceed with caution":
- Don't enter personal info
- Don't download files
- Don't make payments

### 3. Check the Dashboard Weekly
Review your Activity Insights to see:
- What risky sites you encountered
- Patterns in threat types
- Your overall safety score

### 4. Keep the Backend Running
PhishTrace only works when the backend is running. Consider:
- Running it on startup
- Using a background service
- Creating a shortcut for easy launch

### 5. Update Regularly
When new threat patterns emerge:
- Update the codebase
- Retrain the model
- Refresh your extension

---

## ❓ FAQ

**Q: Does this slow down my browsing?**
A: No. Analysis takes <50ms, and results are cached for 30 minutes.

**Q: Can I use this with other browsers?**
A: Currently Chrome only. Firefox support is planned.

**Q: Does it work offline?**
A: No. The backend server must be running for analysis.

**Q: Can I customize the risk thresholds?**
A: Yes, but requires editing the source code in `content.js`.

**Q: Is PhishTrace always right?**
A: While very accurate (~94%), no system is perfect. Use your judgment too.

**Q: Can I contribute threat data?**
A: Not yet, but community intelligence is planned for future versions.

---

## 🆘 Getting Help

If you encounter issues:
1. Check this guide first
2. Review error messages in browser console (F12)
3. Check backend logs for detailed errors
4. Consult the [Developer Guide](./DEVELOPER_GUIDE.md) for technical details

---

**Stay Safe Online! 🛡️**
