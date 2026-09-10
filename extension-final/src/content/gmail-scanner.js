/**
 * PhishTrace Universal Scanner
 * 
 * Works on ALL websites.
 * 1. Checks if it's Gmail (uses deep scanning).
 * 2. If not, uses generic page scanning.
 * 3. Proxies all requests through background script.
 */

console.log("%c[PhishTrace] ACTIVE", "font-size: 16px; color: cyan;");

if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    const existing = document.getElementById('ss-status-panel');
    if (existing) existing.remove();
}

const scannedContent = new Set();
let statusPanel = null;
let lastScanResult = null; // CACHE FOR POPUP

// ============================================
// UI: UNIVERSAL STATUS PANEL
// ============================================
function createStatusPanel() {
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        const existing = document.getElementById('ss-status-panel');
        if (existing) existing.remove();
        return;
    }

    if (document.getElementById('ss-status-panel')) return;

    const panel = document.createElement('div');
    panel.id = 'ss-status-panel';
    panel.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #09090b;
        color: white;
        padding: 10px 14px;
        border-radius: 8px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.5);
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 12px;
        display: flex;
        align-items: center;
        gap: 10px;
        border: 1px solid #27272a;
        transition: all 0.3s ease;
        cursor: default;
        user-select: none;
    `;

    const dot = document.createElement('div');
    dot.id = 'ss-status-dot';
    dot.style.cssText = "width: 8px; height: 8px; background: #71717a; border-radius: 50%; transition: all 0.3s;";

    const content = document.createElement('div');
    content.innerHTML = `
        <div style="font-weight: 800; font-size: 10px; text-transform: uppercase; color: #52525b; letter-spacing: 1px; margin-bottom: 2px;">PhishTrace</div>
        <div id="ss-status-text" style="font-weight: 600; color: #d4d4d8;">Standby</div>
    `;

    panel.appendChild(dot);
    panel.appendChild(content);
    document.body.appendChild(panel);
    statusPanel = panel;
}

function updateStatus(text, type = 'normal') {
    if (!statusPanel) createStatusPanel();
    const textEl = document.getElementById('ss-status-text');
    const dotEl = document.getElementById('ss-status-dot');

    if (!textEl || !dotEl) return;

    textEl.innerText = text;

    const colors = {
        scanning: '#3b82f6', // Blue
        safe: '#10b981',     // Green
        danger: '#ef4444',   // Red
        idle: '#71717a'      // Gray
    };

    if (type === 'scanning') {
        textEl.style.color = colors.scanning;
        dotEl.style.background = colors.scanning;
        dotEl.style.boxShadow = `0 0 8px ${colors.scanning}`;
    } else if (type === 'safe') {
        textEl.style.color = colors.safe;
        dotEl.style.background = colors.safe;
        dotEl.style.boxShadow = `0 0 8px ${colors.safe}`;
    } else if (type === 'danger') {
        textEl.style.color = colors.danger;
        dotEl.style.background = colors.danger;
        dotEl.style.boxShadow = `0 0 12px ${colors.danger}`;
    } else {
        textEl.style.color = '#d4d4d8';
        dotEl.style.background = colors.idle;
        dotEl.style.boxShadow = 'none';
    }
}

// ============================================
// CONTENT EXTRACTION
// ============================================
function extractContent() {
    const isGmail = window.location.hostname.includes("mail.google.com");

    if (isGmail) {
        // GMAIL LOGIC
        const bodySelectors = ['.a3s.aiL', '.ii.gt', '.adP.adO', 'div[role="listitem"] .a3s'];
        let bodyEl = null;
        for (const sel of bodySelectors) {
            bodyEl = document.querySelector(sel);
            if (bodyEl) break;
        }

        if (!bodyEl) return null;


        const messageContainer = bodyEl.closest('[data-legacy-message-id]');
        const messageId = messageContainer ? messageContainer.getAttribute('data-legacy-message-id') : null;
        
        const match = window.location.pathname.match(/\/u\/(\d+)\//);
        const userIndex = match ? match[1] : '0';

        const subject = (document.querySelector('h2.hP') || document.querySelector('h2'))?.innerText || "Unknown Subject";
        const senderEl = document.querySelector('.gD') || document.querySelector('span[email]');
        const sender = senderEl ? (senderEl.getAttribute('email') || senderEl.innerText) : "Unknown Sender";

        // Extract attachment chips from Gmail DOM
        const attachmentEls = document.querySelectorAll('.aQH, span.aV3, div[role="button"][download_url], .aQy');
        const detectedAttachments = [];
        attachmentEls.forEach(el => {
            const name = el.getAttribute('download_url')?.split(':')[1] || el.innerText || '';
            const cleanName = name.split('\n')[0].trim();
            if (cleanName && cleanName.includes('.') && !detectedAttachments.includes(cleanName)) {
                detectedAttachments.push(cleanName);
            }
        });

        const attachmentStr = detectedAttachments.length > 0 ? `\nAttachments: ${detectedAttachments.join(', ')}` : '';

        return {
            type: 'email',
            subject,
            sender,
            senderDomain: sender.includes('@') ? sender.split('@')[1] : 'unknown',
            body: bodyEl.innerText,
            attachments: detectedAttachments,
            fullText: `Subject: ${subject}\nFrom: ${sender}${attachmentStr}\n\n${bodyEl.innerText}`,
            id: subject + (bodyEl.innerText.substring(0, 50)),
            messageId,
            userIndex
        };
    } else {
        // GENERIC LOGIC
        const hostname = window.location.hostname;
        if (hostname === 'localhost' || hostname === '127.0.0.1') return null;

        const bodyText = document.body.innerText;
        if (bodyText.length < 100) return null;

        return {
            type: 'webpage',
            subject: document.title,
            sender: window.location.hostname,
            senderDomain: window.location.hostname,
            body: bodyText.substring(0, 5000),
            fullText: `Page: ${document.title}\nURL: ${window.location.href}\n\n${bodyText.substring(0, 5000)}`,
            id: document.title + bodyText.substring(0, 100)
        };
    }
}

// ============================================
// SCANNING
// ============================================
function scanContent(data) {
    updateStatus("Scanning Content...", "scanning");

    const performScan = (rawHeaders = null) => {
        chrome.runtime.sendMessage({
            type: "SCAN_CONTENT",
            data: {
                subject: data.subject,
                senderDomain: data.senderDomain,
                fullText: data.fullText,
                timestamp: new Date().toISOString(),
                rawHeaders: rawHeaders
            }
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("Extension Error:", chrome.runtime.lastError);
                updateStatus("Extension Error", "danger");
                return;
            }

            if (response && response.success && response.data) {
                let risk = response.data.global_risk_score;
                // Ensure valid number
                if (typeof risk !== 'number' || isNaN(risk)) {
                    risk = response.data.max_risk_score || 0;
                }

                const score = Math.round(risk * 100);

                // USER REQUEST: Status Panel must reflect Domain Safety (Gmail = Safe)
                // We do NOT show "Threat" in the floating widget for email text checks.
                updateStatus("PhishTrace: Active", "safe");

                const resultData = {
                    subject: data.subject,
                    sender_domain: data.senderDomain,
                    risk_score: risk,
                    risk_level: response.data.status || (score > 50 ? "SUSPICIOUS" : "SAFE"),
                    signals: response.data.signals, // PASS SIGNALS
                    timestamp: new Date().toISOString()
                };

                // INJECT IN-GMAIL WARNING BANNER IF SUSPICIOUS OR CRITICAL
                injectGmailWarningBanner(resultData, response.data);

                // CACHE RESULT
                lastScanResult = resultData;

                // SAVE TO STORAGE (Robust Fix)
                chrome.storage.local.set({
                    'latestScan': resultData
                }, () => {
                    console.log("[PhishTrace] Saved scan to storage");
                });

                chrome.runtime.sendMessage({
                    type: 'EMAIL_SCANNED',
                    data: resultData
                });

            } else {
                console.error("Scan Failed:", response?.error);
                updateStatus("Connection Fail", "danger");
            }
        });
    };

    if (data.type === 'email' && data.messageId) {
        console.log(`[PhishTrace] Requesting raw email for message ID: ${data.messageId} (User: ${data.userIndex})`);
        
        let apiResponded = false;
        
        const timeoutId = setTimeout(() => {
            if (!apiResponded) {
                console.warn("[PhishTrace] Gmail API request timed out after 10 seconds. Falling back to DOM scan.");
                apiResponded = true;
                performScan(null);
            }
        }, 10000);

        chrome.runtime.sendMessage({
            type: "GET_RAW_EMAIL_API",
            messageId: data.messageId
        }, async (response) => {
            if (apiResponded) return; // Prevent double execution if timeout already fired
            apiResponded = true;
            clearTimeout(timeoutId);

            if (chrome.runtime.lastError) {
                console.warn("[PhishTrace] GET_RAW_EMAIL_API error:", chrome.runtime.lastError);
                performScan(null);
            } else if (!response || !response.success || !response.raw) {
                console.warn(`[PhishTrace] Gmail API raw acquisition failed. Reason: ${response ? response.reason : "No response"}`);
                performScan(null);
            } else {
                console.log(`[PhishTrace] Successfully acquired raw email headers via Gmail API! (${response.raw.length} bytes)`);
                performScan(response.raw);
            }
        });
        
    } else {
        performScan(null);
    }
}

// ============================================
// IN-GMAIL TOP WARNING BANNER UI
// ============================================
function injectGmailWarningBanner(scanResult, fullResponse) {
    if (!window.location.hostname.includes("mail.google.com")) return;

    const existingBanner = document.getElementById("ss-gmail-banner");
    if (existingBanner) existingBanner.remove();

    const score = Math.round(scanResult.risk_score * 100);
    const status = scanResult.risk_level;

    // Only inject banner for SUSPICIOUS or CRITICAL threats (or if risk > 35%)
    if (score < 35 && status === "SAFE") return;

    const targetContainer = document.querySelector('.a3s.aiL') || document.querySelector('.ii.gt');
    if (!targetContainer) return;

    const banner = document.createElement("div");
    banner.id = "ss-gmail-banner";
    const isCritical = status === "CRITICAL" || score >= 70;
    const bgGradient = isCritical 
        ? "linear-gradient(135deg, #450a0a 0%, #7f1d1d 100%)" 
        : "linear-gradient(135deg, #451a03 0%, #78350f 100%)";
    const borderColor = isCritical ? "#ef4444" : "#f59e0b";
    const icon = isCritical ? "⚠️ CRITICAL THREAT WARNING" : "⚠ CAUTION SUSPICIOUS EMAIL";

    const authInfo = fullResponse?.email_forensics || {};
    const spf = authInfo.spf_status || "NONE";
    const dkim = authInfo.dkim_status || "NONE";
    const dmarc = authInfo.dmarc_status || "NONE";
    
    // Extract contextual explanation
    const explanation = fullResponse?.explanation_summary || "Contextual threat detected.";

    banner.style.cssText = `
        margin: 12px 0 16px 0;
        padding: 14px 18px;
        background: ${bgGradient};
        border-left: 5px solid ${borderColor};
        border-radius: 8px;
        color: #ffffff;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 9999;
    `;

        const geoInfo = fullResponse?.origin_forensics || {};
        const geoMismatch = fullResponse?.origin_mismatch || {};

        let geoBannerHtml = "";
        if (geoMismatch.mismatch) {
            geoBannerHtml = `<div style="margin-top: 6px; padding: 6px 10px; background: rgba(245, 158, 11, 0.2); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 6px; font-size: 11px; color: #fde68a; font-weight: 600;">
                ⚠️ ${geoMismatch.reason || "Origin Mismatch: Sending IP location conflicts with claimed sender domain."}
            </div>`;
        }

        banner.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <div style="font-weight: 800; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; color: ${borderColor}; display: flex; align-items: center; gap: 8px;">
                ${icon} <span style="background: rgba(255,255,255,0.15); padding: 2px 8px; border-radius: 12px; font-size: 11px; color: white;">Risk Score: ${score}%</span>
            </div>
            <span style="font-size: 11px; color: #d4d4d8;">PhishTrace Forensic Engine</span>
        </div>
        <div style="font-size: 13px; font-weight: 600; line-height: 1.5; color: #f4f4f5; margin-bottom: 6px;">
            ${explanation}
        </div>
        ${geoBannerHtml}
        <div style="font-size: 11px; color: #a1a1aa; padding-top: 6px; margin-top: 6px; border-top: 1px solid rgba(255,255,255,0.1); display: flex; flex-wrap: wrap; gap: 12px; justify-content: space-between;">
            <div>
                Authentication: 
                <span style="color: ${spf.includes('PASS') ? '#34d399' : '#f87171'}">SPF: ${spf}</span> | 
                <span style="color: ${dkim.includes('PASS') ? '#34d399' : '#f87171'}">DKIM: ${dkim}</span> | 
                <span style="color: ${dmarc.includes('PASS') ? '#34d399' : '#f87171'}">DMARC: ${dmarc}</span>
            </div>
            ${geoInfo.country ? `<div>Origin IP: <span style="color: #93c5fd; font-family: monospace;">${geoInfo.ip || "unknown"}</span> (${geoInfo.city ? geoInfo.city + ', ' : ''}${geoInfo.country})</div>` : ''}
        </div>
    `;

    targetContainer.parentNode.insertBefore(banner, targetContainer);
    console.log("✅ Injected In-Gmail Warning Banner above email body with Forensics");
}

// ============================================
// COMMUNICATE WITH POPUP
// ============================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'GET_LAST_SCAN') {
        const activeContent = extractContent();
        if (activeContent && activeContent.type === 'email') {
            console.log("[PhishTrace] Sending active email scan to popup:", lastScanResult);
            sendResponse(lastScanResult);
        } else {
            console.log("[PhishTrace] No active email open on current tab");
            sendResponse(null);
        }
    }
});

// ============================================
// MONITORING
// ============================================
function startMonitor() {
    const hostname = window.location.hostname;
    if (hostname === 'localhost' || hostname === '127.0.0.1') return;

    createStatusPanel();
    updateStatus("PhishTrace Active", "idle");

    setInterval(() => {
        const data = extractContent();
        if (data) {
            if (!scannedContent.has(data.id)) {
                scannedContent.add(data.id);
                console.log("[PhishTrace] New content:", data.subject);
                scanContent(data);
            }
        }
    }, 2000);
}

if (document.readyState === "complete") {
    setTimeout(startMonitor, 1000);
} else {
    window.addEventListener('load', () => setTimeout(startMonitor, 1000));
}
