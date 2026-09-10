# Gmail Email Scanner - Troubleshooting Guide

## Quick Checklist

### 1. Extension Reloaded?
- Go to `chrome://extensions/`
- Find "PhishTrace"
- Click "Reload" button
- **Status:** ⬜ Not Done / ✅ Done

### 2. Gmail Page Open?
- URL should be: `https://mail.google.com/*`
- Not: `gmail.com` (needs https://mail.google.com)
- **Status:** ⬜ Not Done / ✅ Done

### 3. Email Opened?
- Click on an email to view it
- Wait 3-5 seconds
- **Status:** ⬜ Not Done / ✅ Done

### 4. Check Console for Logs
- Press F12 on Gmail page
- Go to "Console" tab
- Look for: `[EmailScanner]` messages
- **Status:** ⬜ Not Done / ✅ Done

---

## Expected Console Output

When working correctly, you should see:

```
[EmailScanner] Gmail scanner loaded - Privacy Mode
[EmailScanner] Gmail detected, starting email monitor
[EmailScanner] 🔒 Privacy Mode: Email content analyzed but NOT stored
[EmailScanner] 📧 New email detected, scanning...
[EmailScanner] 🔍 Scanning email: Your Email Subject
[EmailScanner] 📊 Risk Score: 15%
[EmailScanner] ✅ Email appears safe
```

---

## Common Issues

### Issue 1: No Console Logs at All
**Problem:** Extension not loaded on Gmail
**Solution:**
1. Reload extension
2. Close and reopen Gmail tab
3. Check manifest.json has Gmail content script

### Issue 2: "Gmail scanner loaded" but nothing else
**Problem:** Not detecting email opens
**Solution:**
1. Click on a different email
2. Wait 3 seconds
3. Check if email body is visible

### Issue 3: CORS Error
**Problem:** Backend not accessible
**Solution:**
1. Check backend is running: `http://127.0.0.1:8002/docs`
2. Check port 8000 is correct
3. Restart backend if needed

### Issue 4: "Failed to fetch" Error
**Problem:** Backend not responding
**Solution:**
```bash
# Check if backend is running
curl http://127.0.0.1:8002/api/v1/email-scans/stats
```

---

## Manual Test

### Step 1: Open Console
```
1. Go to Gmail
2. Press F12
3. Click "Console" tab
```

### Step 2: Check if Scanner Loaded
Look for:
```
[EmailScanner] Gmail scanner loaded - Privacy Mode
[EmailScanner] Gmail detected, starting email monitor
```

### Step 3: Open an Email
```
1. Click on any email
2. Wait 3 seconds
3. Look for new console messages
```

### Step 4: Check for Errors
Look for:
- ❌ Red error messages
- ⚠️ Yellow warnings
- Any "Failed to fetch" messages

---

## Quick Fixes

### Fix 1: Reload Everything
```
1. chrome://extensions/ → Reload extension
2. Close Gmail tab
3. Open new Gmail tab
4. Open an email
```

### Fix 2: Check Backend
```
1. Open: http://127.0.0.1:8002/docs
2. Should see API documentation
3. If not, restart backend
```

### Fix 3: Check Manifest
```
1. Open: extension-final/manifest.json
2. Look for:
   "matches": ["*://mail.google.com/*"]
3. Should be present
```

---

## Debug Commands

### Check if Backend is Running:
```bash
curl http://127.0.0.1:8002/api/v1/email-scans/stats
```

Expected response:
```json
{
  "total_emails_scanned_24h": 0,
  "phishing_detected_24h": 0,
  "safe_emails_24h": 0,
  "detection_rate": 0
}
```

### Check Extension Console:
```
1. chrome://extensions/
2. Find PhishTrace
3. Click "service worker" (if visible)
4. Check for errors
```

---

## What to Check Right Now

**Open Gmail and press F12, then tell me:**

1. Do you see `[EmailScanner] Gmail scanner loaded`?
   - YES / NO

2. Do you see `[EmailScanner] Gmail detected, starting email monitor`?
   - YES / NO

3. When you click an email, do you see `[EmailScanner] 📧 New email detected`?
   - YES / NO

4. Are there any RED error messages?
   - YES / NO (if yes, copy the error)

5. Is the backend running at http://127.0.0.1:8002/docs?
   - YES / NO

---

**Send me the answers to these 5 questions and I'll tell you exactly what's wrong!**
