/**
 * PhishTrace Service Worker v3.0
 * Real-time blocking enabled
 */

const API_BASE = "http://127.0.0.1:8005/api/v1";
console.log("[PhishTrace] Service Worker v3.1 ACTIVE - Workspace Match Confirmed");
console.log("[PhishTrace] API_BASE:", API_BASE);

// Cache for analyzed URLs
const cache = new Map();
const CACHE_DURATION = 3600000; // 1 hour
const MAX_CACHE_SIZE = 100; // Limit cache to 100 entries to prevent memory leak

// Temporary whitelist (session only)
const tempWhitelist = new Set();

// Permanent blocklist (synced from backend)
let permanentBlocklist = new Set();

// Settings
const DEFAULT_SETTINGS = {
    blockingEnabled: true,
    blockThreshold: 0.65,  // Optimized threshold (0.65) to catch more threats
    showWarnings: true
};

/**
 * Dynamic blocking using declarativeNetRequest
 */
async function updateBlockingRules() {
    try {
        // Get all blocked domains
        const blockedDomains = Array.from(permanentBlocklist);

        if (blockedDomains.length === 0) {
            // Clear all rules if no domains to block
            const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
            const ruleIds = existingRules.map(rule => rule.id);
            if (ruleIds.length > 0) {
                await chrome.declarativeNetRequest.updateDynamicRules({
                    removeRuleIds: ruleIds
                });
            }
            console.log("[PhishTrace] 🧹 Cleared all blocking rules");
            return;
        }

        // Create blocking rules for each domain
        const rules = [];
        let ruleId = 1;

        blockedDomains.forEach(domain => {
            // Rule for subdomain wildcard
            rules.push({
                id: ruleId++,
                priority: 1,
                action: {
                    type: "redirect",
                    redirect: {
                        url: chrome.runtime.getURL('blocked.html') +
                            '?url=' + encodeURIComponent(`https://${domain}`) +
                            '&risk=1.0&permanent=true'
                    }
                },
                condition: {
                    urlFilter: `*://*.${domain}/*`,
                    resourceTypes: ["main_frame"]
                }
            });

            // Rule for exact domain match
            rules.push({
                id: ruleId++,
                priority: 1,
                action: {
                    type: "redirect",
                    redirect: {
                        url: chrome.runtime.getURL('blocked.html') +
                            '?url=' + encodeURIComponent(`https://${domain}`) +
                            '&risk=1.0&permanent=true'
                    }
                },
                condition: {
                    urlFilter: `*://${domain}/*`,
                    resourceTypes: ["main_frame"]
                }
            });
        });

        // Get existing rules and remove them
        const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
        const existingRuleIds = existingRules.map(rule => rule.id);

        // Update rules atomically
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: existingRuleIds,
            addRules: rules
        });

        console.log(`[PhishTrace] ⚡ INSTANT BLOCKING ACTIVE: ${blockedDomains.length} domains`);
        console.log("[PhishTrace] Blocked domains:", blockedDomains);
    } catch (error) {
        console.error("[PhishTrace] ❌ Failed to update blocking rules:", error);
    }
}

/**
 * Sync permanent blocklist from backend
 */
async function syncBlocklist() {
    try {
        const response = await fetch(`${API_BASE}/blocklist`, {
            method: "GET",
            cache: "no-cache"
        });

        if (response.ok) {
            const data = await response.json();
            console.log("[PhishTrace] 📥 Received blocklist data:", data);

            permanentBlocklist.clear();

            if (data.domains && Array.isArray(data.domains)) {
                data.domains.forEach(item => {
                    permanentBlocklist.add(item.domain.toLowerCase().trim()); // Normalize
                });
                console.log(`[PhishTrace] 📋 Synced ${permanentBlocklist.size} permanently blocked domains:`, Array.from(permanentBlocklist));

                // Update blocking rules immediately for instant effect
                await updateBlockingRules();
            }
        } else {
            console.error(`[PhishTrace] ❌ Blocklist sync failed: ${response.status}`);
        }
    } catch (error) {
        console.error("[PhishTrace] ❌ Failed to sync blocklist (Network Error):", error);
    }
}

/**
 * Check if domain is in permanent blocklist
 */
function isPermanentlyBlocked(url) {
    try {
        const urlObj = new URL(url);
        const domain = urlObj.hostname.toLowerCase(); // Normalize

        console.log(`[PhishTrace] 🔍 Checking: ${domain} (Blocklist size: ${permanentBlocklist.size})`);

        // Debug: Log first 5 items if list is small or debugging
        if (permanentBlocklist.size > 0 && permanentBlocklist.size < 10) {
            console.log("[PhishTrace] Blocklist content:", Array.from(permanentBlocklist));
        }

        // Check exact match
        if (permanentBlocklist.has(domain)) {
            console.log(`[PhishTrace] 🚫 EXACT MATCH found for: ${domain}`);
            return true;
        }

        // Check if any parent domain is blocked
        const parts = domain.split('.');
        for (let i = 0; i < parts.length - 1; i++) {
            const parentDomain = parts.slice(i).join('.');
            if (permanentBlocklist.has(parentDomain)) {
                return true;
            }
        }

        return false;
    } catch (error) {
        return false;
    }
}

/**
 * Get user settings
 */
async function getSettings() {
    const result = await chrome.storage.local.get(['settings', 'protectionEnabled']);
    // Fallback to protectionEnabled if settings.blockingEnabled is not set
    const protectionEnabled = result.protectionEnabled !== undefined ? result.protectionEnabled : DEFAULT_SETTINGS.blockingEnabled;
    return { ...DEFAULT_SETTINGS, ...result.settings, blockingEnabled: protectionEnabled };
}

/**
 * Check backend health on startup
 */
async function checkBackend() {
    try {
        const res = await fetch("http://127.0.0.1:8005/health", {
            method: "GET",
            cache: "no-cache"
        });
        if (res.ok) {
            console.log("[PhishTrace] ✅ Backend online (v1)");
            return true;
        }
    } catch (err) {
        console.warn("[PhishTrace] ⚠️ Backend offline - start with: python start_server.py");
    }
    return false;
}

// Check backend on install/startup
chrome.runtime.onInstalled.addListener(() => {
    console.log("[PhishTrace] Extension installed");
    checkBackend();
    syncBlocklist(); // Sync blocklist on install
});

// Sync blocklist every 5 minutes
setInterval(syncBlocklist, 5 * 60 * 1000);

// Initial sync
syncBlocklist();

/**
 * Analyze URL for phishing/malicious content
 */
async function analyzeURL(url, isMainFrame = false, context = null) {
    // Check cache first (ONLY if not main frame - we want to log every main page visit)
    if (!isMainFrame) {
        const cached = cache.get(url);
        if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
            return cached.data;
        }
    }

    try {
        console.log(`[PhishTrace] 🚀 Analyzing: ${url.substring(0, 50)}...`, context ? "+ Context" : "");

        const payload = {
            text: url,
            source: isMainFrame ? "navigation" : "content",
            ...context // Spread context into payload
        };

        const response = await fetch(`${API_BASE}/detect`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        console.log(`[PhishTrace] 📉 Result for ${url.substring(0, 30)}: ${Math.round(data.max_risk_score * 100)}%`);

        // Cache result
        cache.set(url, {
            data: data,
            timestamp: Date.now()
        });

        // Limit cache size
        if (cache.size > MAX_CACHE_SIZE) {
            const firstKey = cache.keys().next().value;
            cache.delete(firstKey);
        }

        // Track stats for popup
        await updateStats(url, data.max_risk_score, isMainFrame);

        return data;
    } catch (error) {
        console.error("[PhishTrace] API Error:", error.message);
        // Return safe default on error
        return {
            max_risk_score: 0,
            text: url,
            labels: { error: { probability: 1.0, top_features: [{ word: "BACKEND_OFFLINE", weight: 1.0 }] } }
        };
    }
}

/**
 * Update statistics for popup
 */
async function updateStats(url, riskScore, isMainFrame) {
    try {
        const result = await chrome.storage.local.get(['scansToday', 'threatsBlocked', 'recentScans', 'lastResetDate']);

        const today = new Date().toDateString();
        let scansToday = result.scansToday || 0;
        let threatsBlocked = result.threatsBlocked || 0;
        let recentScans = result.recentScans || [];

        // Reset daily count if new day
        if (result.lastResetDate !== today) {
            scansToday = 0;
            await chrome.storage.local.set({ lastResetDate: today });
        }

        // Increment counters
        scansToday++;
        if (riskScore > 0.5) {
            threatsBlocked++;
            // Badge text for threats
            chrome.action.setBadgeText({ text: "!" });
            chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
        }

        // HISTORY LOGIC:
        // Only log if it's the MAIN PAGE we visited, OR if it's a THREAT found on the page.
        if (isMainFrame || riskScore > 0.5) {
            // Avoid duplicate consecutive entries
            if (recentScans.length === 0 || recentScans[0].url !== url) {
                recentScans.unshift({
                    url: url,
                    risk_score: Number.isFinite(Number(riskScore)) ? Number(riskScore) : 0,
                    timestamp: Date.now()
                });
                recentScans = recentScans.slice(0, 10);
            }
        }

        // Save updated stats
        await chrome.storage.local.set({
            scansToday,
            threatsBlocked,
            recentScans
        });
    } catch (error) {
        console.error("[PhishTrace] Stats update failed:", error);
    }
}

/**
 * Web Navigation Listener - Real-time blocking
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only process main frame navigations
    if (details.frameId !== 0) return;

    const url = details.url;
    const tabId = details.tabId;

    // Skip chrome:// and extension pages
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
        return;
    }

    // Check if URL is whitelisted
    if (tempWhitelist.has(url)) {
        console.log("[PhishTrace] ✅ Whitelisted:", url);
        return;
    }

    // Get settings
    const settings = await getSettings();
    if (!settings.blockingEnabled) {
        console.log("[PhishTrace] ⏸️ Blocking disabled");
        return;
    }

    // PRIORITY 1: Check permanent blocklist (instant block, no API call needed)
    if (isPermanentlyBlocked(url)) {
        console.log("[PhishTrace] 🚫 PERMANENTLY BLOCKED:", url);

        // Redirect to blocking page with permanent block indicator
        const blockedPageUrl = chrome.runtime.getURL('blocked.html') +
            '?url=' + encodeURIComponent(url) +
            '&risk=1.0' +
            '&permanent=true' +
            '&labels=' + encodeURIComponent(JSON.stringify({
                blocked: { probability: 1.0, top_features: [] }
            }));

        chrome.tabs.update(tabId, { url: blockedPageUrl });
        return;
    }

    // PRIORITY 2: Analyze URL with AI model
    console.log("[PhishTrace] 🔍 Analyzing navigation:", url);
    const analysis = await analyzeURL(url, true);

    // Check if should block based on risk score
    if (analysis.max_risk_score >= settings.blockThreshold) {
        console.log("[PhishTrace] 🛑 BLOCKING:", url, "Risk:", analysis.max_risk_score);

        // Redirect to blocking page
        const blockedPageUrl = chrome.runtime.getURL('blocked.html') +
            '?url=' + encodeURIComponent(url) +
            '&risk=' + analysis.max_risk_score +
            '&labels=' + encodeURIComponent(JSON.stringify(analysis.labels));

        chrome.tabs.update(tabId, { url: blockedPageUrl });
    } else {
        console.log("[PhishTrace] ✅ Safe:", url, "Risk:", analysis.max_risk_score);
    }
});

/**
 * Message handler
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYZE_URL") {
        analyzeURL(message.url, message.isMainFrame, message.context)
            .then(data => sendResponse({ success: true, data }))
            .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
    }

    if (message.type === "WHITELIST_TEMP") {
        // Add URL to temporary whitelist
        tempWhitelist.add(message.url);
        console.log("[PhishTrace] ➕ Whitelisted:", message.url);
        sendResponse({ success: true });
        return false;
    }

    if (message.type === "LOG_BLOCKED") {
        // Log blocked attempt
        console.log("[PhishTrace] 📝 Logged block:", message.url);
        sendResponse({ success: true });
        return false;
    }

    if (message.type === "REPORT_FALSE_POSITIVE") {
        // Handle false positive report
        console.log("[PhishTrace] 📢 False positive reported:", message.url);
        // Could send to backend for retraining
        sendResponse({ success: true });
        return false;
    }

    if (message.type === "PING") {
        sendResponse({ status: "ok" });
        return false;
    }

    if (message.type === "SCAN_CONTENT") {
        console.log(`[PhishTrace] 📨 Proxying scan request for: ${message.data.subject}`);

        fetch(`${API_BASE}/detect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                text: message.data.fullText,
                source: 'universal_scanner', // Changed source name
                context: {
                    subject: message.data.subject,
                    sender_domain: message.data.senderDomain,
                    timestamp: message.data.timestamp,
                    privacy_mode: true,
                    raw_headers: message.data.rawHeaders || ""
                }
            })
        })
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => sendResponse({ success: true, data }))
            .catch(err => sendResponse({ success: false, error: err.message }));

        return true; // Keep channel open for async response
    }

    if (message.type === "GET_RAW_EMAIL_API") {
        console.log(`[PhishTrace] Gmail API authentication requested for message ID: ${message.messageId}`);
        
        chrome.identity.getAuthToken({ interactive: true }, function(token) {
            if (chrome.runtime.lastError || !token) {
                console.warn("[PhishTrace] Gmail API authentication failed or user denied access.", chrome.runtime.lastError);
                sendResponse({ success: false, reason: "AUTH_FAILED" });
                return;
            }
            
            console.log(`[PhishTrace] Gmail API authentication successful. Requesting raw message: ${message.messageId}`);
            
            fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${message.messageId}?format=raw`, {
                method: "GET",
                headers: {
                    "Authorization": `Bearer ${token}`
                }
            })
            .then(res => {
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                return res.json();
            })
            .then(data => {
                if (!data || !data.raw) {
                    throw new Error("No raw field in Gmail API response");
                }
                console.log("[PhishTrace] Gmail API response received");
                
                // Base64URL decode
                let base64 = data.raw.replace(/-/g, '+').replace(/_/g, '/');
                // Pad with = to make it a multiple of 4
                while (base64.length % 4 !== 0) {
                    base64 += '=';
                }
                
                const rawMime = atob(base64);
                
                console.log("[PhishTrace] Raw MIME acquired: YES");
                console.log(`[PhishTrace] Decoded bytes: ${rawMime.length}`);
                console.log(`[PhishTrace] From header present: ${/^From:/im.test(rawMime) ? 'YES' : 'NO'}`);
                console.log(`[PhishTrace] Date header present: ${/^Date:/im.test(rawMime) ? 'YES' : 'NO'}`);
                console.log(`[PhishTrace] Subject header present: ${/^Subject:/im.test(rawMime) ? 'YES' : 'NO'}`);
                console.log(`[PhishTrace] Received header present: ${/^Received:/im.test(rawMime) ? 'YES' : 'NO'}`);
                console.log(`[PhishTrace] Authentication-Results present: ${/^Authentication-Results:/im.test(rawMime) ? 'YES' : 'NO'}`);
                console.log(`[PhishTrace] Return-Path present: ${/^Return-Path:/im.test(rawMime) ? 'YES' : 'NO'}`);
                
                sendResponse({ success: true, messageId: message.messageId, raw: rawMime });
            })
            .catch(err => {
                console.error("[PhishTrace] Failed to fetch raw message via API:", err);
                sendResponse({ success: false, reason: "API_FETCH_FAILED" });
            });
        });
        
        return true; // Keep channel open for async response
    }
});

console.log("[PhishTrace] Service Worker ready - Blocking enabled");

/**
 * Navigation Completion Listener - Ensures correct Dashboard logging
 * Captures the final URL after all redirects
 */
chrome.webNavigation.onCompleted.addListener(async (details) => {
    // Only capture top-level frame (frameId 0)
    if (details.frameId !== 0) return;

    const url = details.url;

    // Ignore chrome internal pages
    if (!url.startsWith("http")) return;

    console.log("[PhishTrace] 🏁 Navigation Completed:", url);

    // Send main URL to backend with source='navigation'
    // This bypasses the cache to ensure the Dashboard gets the event
    try {
        await fetch(`${API_BASE}/detect`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                text: url,
                source: "navigation"
            })
        });
        console.log("[PhishTrace] ✅ Logged navigation event to Dashboard");
    } catch (err) {
        console.error("[PhishTrace] ❌ Failed to log navigation:", err);
    }
}, {
    url: [{ schemes: ["http", "https"] }]
});
