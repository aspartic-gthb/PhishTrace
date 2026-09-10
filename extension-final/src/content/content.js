/**
 * PhishTrace Content Script v3.7 (Gmail Enhanced)
 * Robust handling for:
 * - Gmail redirects (google.com/url?q=...)
 * - Dynamic iframes (about:blank)
 * - Nested structures
 * - Debounced observations
 * - Message handling for popup
 */

// Restricted Zone Safety Guard
if (!window.location.protocol.startsWith('http')) {
    console.log("[PhishTrace] Protocol Restricted: Analysis Bypassed.");
    throw new Error("Sentinel: RESTRICTED_PROTOCOL");
}

// Configuration
const CONFIG = {
    DEBOUNCE_MS: 500,
    MAX_RETRY: 2,
    IGNORED_DOMAINS: ['localhost', '127.0.0.1', 'mail.google.com', 'docs.google.com'] // Don't scan the app itself
};

// State
const processed = new Set();
let scanTimeout = null;

/**
 * Message Listener for Popup/Background
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "FORCE_SCAN") {
        scanScope(document);
        sendResponse({ success: true });
        return true;
    }

    if (msg.type === "GET_PAGE_CONTEXT") {
        const structural = {
            title: document.title,
            text: document.body.innerText.slice(0, 3000),
            links: [...document.querySelectorAll("a[href]")]
                .map(a => ({
                    text: a.innerText.trim() || a.title || 'Link',
                    url: a.href
                }))
                .filter(a => a.url.startsWith('http'))
                .slice(0, 50),
            hasPasswordField: !!document.querySelector("input[type=password]"),
            isHttps: window.location.protocol === 'https:',
            externalLinkRatio: calculateExternalLinkRatio()
        };
        sendResponse(structural);
        return true;
    }
});

function calculateExternalLinkRatio() {
    const links = document.querySelectorAll('a[href]');
    if (links.length === 0) return 0;
    const currentHost = window.location.hostname;
    let externalCount = 0;
    links.forEach(link => {
        try {
            const linkHost = new URL(link.href).hostname;
            if (linkHost && linkHost !== currentHost) externalCount++;
        } catch (e) { }
    });
    return externalCount / links.length;
}

/**
 * Utility: Debounce function execution
 */
function debounce(func, wait) {
    return function (...args) {
        clearTimeout(scanTimeout);
        scanTimeout = setTimeout(() => func.apply(this, args), wait);
    };
}

/**
 * Utility: Extract real URL from Gmail redirect or return original
 */
function extractRealUrl(rawUrl) {
    try {
        const urlObj = new URL(rawUrl);

        // Handle Gmail Redirection
        if (urlObj.hostname === 'www.google.com' && urlObj.pathname === '/url') {
            const realUrl = urlObj.searchParams.get('q');
            if (realUrl) return realUrl;
        }

        return rawUrl;
    } catch (e) {
        return rawUrl;
    }
}

/**
 * Utility: Check if URL should be ignored
 */
function shouldIgnore(url) {
    if (!url || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('#')) return true;
    try {
        const hostname = new URL(url).hostname;
        return CONFIG.IGNORED_DOMAINS.some(d => hostname.endsWith(d));
    } catch {
        return true;
    }
}

/**
 * UI: Create Risk Popup (Enhanced)
 */
function createRiskPopup(data, badge) {
    const score = parseFloat(data.max_risk_score) || 0;
    const percentage = Math.round(score * 100);

    // Determine visual style
    let theme = { color: '#10b981', label: 'SAFE' };
    if (score > 0.7) theme = { color: '#ef4444', label: 'HIGH RISK' };
    else if (score > 0.4) theme = { color: '#f59e0b', label: 'MODERATE' };

    const popup = document.createElement("div");
    popup.className = "sentinel-popup";
    // Inline styles for isolation
    popup.style.cssText = `
        position: absolute; z-index: 2147483647;
        background: #09090b; border: 1px solid ${theme.color};
        border-radius: 12px; padding: 16px; min-width: 280px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 0 1px ${theme.color}30;
        font-family: 'Segoe UI', system-ui, sans-serif; display: none;
        color: #e4e4e7; font-size: 13px; line-height: 1.5;
    `;

    popup.innerHTML = `
        <div style="display: flex; justify-content: space-between; margin-bottom: 12px; align-items: center;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="width: 8px; height: 8px; border-radius: 50%; background: ${theme.color}; box-shadow: 0 0 8px ${theme.color};"></span>
                <span style="font-weight: 700; letter-spacing: 0.5px; font-size: 11px; text-transform: uppercase;">PhishTrace Analysis</span>
            </div>
            <button onclick="this.closest('.sentinel-popup').style.display='none'" style="background:none; border:none; color:#71717a; cursor:pointer; font-size:18px;">&times;</button>
        </div>
        
        <div style="background: ${theme.color}15; border-left: 3px solid ${theme.color}; padding: 12px; border-radius: 6px; margin-bottom: 12px;">
            <div style="color: ${theme.color}; font-size: 10px; font-weight: 700; text-transform: uppercase; margin-bottom: 4px;">Threat Level</div>
            <div style="display: flex; align-items: baseline; gap: 8px;">
                <span style="font-size: 24px; font-weight: 700; color: #fff;">${percentage}%</span>
                <span style="color: ${theme.color}; font-size: 12px; font-weight: 600;">${theme.label}</span>
            </div>
        </div>
        
        <div style="background: #18181b; padding: 8px; border-radius: 6px; font-family: monospace; font-size: 11px; color: #a1a1aa; word-break: break-all;">
            ${data.text || 'Unknown URL'}
        </div>
    `;
    return popup;
}

/**
 * logic: Inject Badge
 */
function injectBadge(link, data) {
    if (link.querySelector(".sentinel-badge-host")) return; // Prevent duplicates

    const score = parseFloat(data.max_risk_score) || 0;

    // Choose Color
    let color = "#10b981"; // Green
    if (score > 0.7) color = "#ef4444"; // Red
    else if (score > 0.4) color = "#f59e0b"; // Yellow

    // Shadow Host
    const container = document.createElement("span");
    container.className = "sentinel-badge-host";
    container.style.cssText = "display: inline-block; vertical-align: middle; margin: 0 4px; width: 12px; height: 12px; position: relative; z-index: 10;";

    const shadow = container.attachShadow({ mode: 'closed' });

    // Badge
    const badge = document.createElement("div");
    badge.style.cssText = `
        width: 10px; height: 10px; border-radius: 50%;
        background: ${color}; border: 1.5px solid #fff;
        box-shadow: 0 0 0 1px ${color}, 0 2px 4px rgba(0,0,0,0.1);
        cursor: pointer; transition: transform 0.2s;
    `;
    badge.onmouseenter = () => badge.style.transform = "scale(1.2)";
    badge.onmouseleave = () => badge.style.transform = "scale(1)";

    // Popup
    const popup = createRiskPopup(data, badge);

    // Interaction
    badge.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        const allPopups = document.querySelectorAll('.sentinel-popup');
        allPopups.forEach(p => p !== popup && (p.style.display = 'none'));

        if (popup.style.display === 'block') {
            popup.style.display = 'none';
        } else {
            popup.style.display = 'block';
            // Position Logic
            const rect = container.getBoundingClientRect();
            popup.style.top = `${window.scrollY + rect.bottom + 10}px`;
            popup.style.left = `${window.scrollX + rect.left}px`;
        }
    };

    shadow.appendChild(badge);
    document.body.appendChild(popup);

    // SMARTER INJECTION STRATEGY
    // 1. If it's a button or image wrapper, append AFTER
    // 2. If it's inside a heading, append INLINE
    // 3. Default: Append inside link

    const isBlocky = link.tagName === 'BUTTON' ||
        link.getAttribute('role') === 'button' ||
        link.querySelector('img') ||
        link.querySelector('div') ||
        (link.offsetWidth > 100 && link.offsetHeight > 30);

    if (isBlocky) {
        if (link.nextSibling) {
            link.parentNode.insertBefore(container, link.nextSibling);
        } else {
            link.parentNode.appendChild(container);
        }
        container.style.marginLeft = "8px";
    } else {
        link.appendChild(container);
    }
}

/**
 * logic: Scan Single Link
 */
async function scanLink(link) {
    const rawUrl = link.href;
    const realUrl = extractRealUrl(rawUrl);

    if (shouldIgnore(realUrl) || processed.has(realUrl)) return;

    // Mark as processed immediately to prevent double-scanning
    processed.add(realUrl);

    // IMPORTANT: Also mark the raw URL to prevent scanning the redirect again
    if (rawUrl !== realUrl) processed.add(rawUrl);

    // Send to Background
    try {
        chrome.runtime.sendMessage({
            type: "ANALYZE_URL",
            url: realUrl,
            isMainFrame: false
        }, (response) => {
            if (response && response.success && response.data) {
                injectBadge(link, response.data);
            }
        });
    } catch (e) {
        // Extension Context Invalidated (Update/Reload happened)
        // Usually safe to ignore
    }
}

/**
 * logic: Scan All Links in Scope
 */
function scanScope(root = document) {
    // Select all links
    const links = root.querySelectorAll('a[href]');
    links.forEach(link => scanLink(link));
}

// ---------------------------------------------------------
// OBSERVERS
// ---------------------------------------------------------

// Debounced Scanner
const debouncedScan = debounce(() => {
    // console.log("[PhishTrace] Rescanning DOM...");
    scanScope(document);
}, CONFIG.DEBOUNCE_MS);

// Mutation Observer
const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
            shouldScan = true;
            break;
        }
    }
    if (shouldScan) debouncedScan();
});

// Start Observing
observer.observe(document.body, {
    childList: true,
    subtree: true
});

// Self Scan: Immediately analyze the current page url (Main Frame only)
if (window.self === window.top) {
    try {
        // [STEP 5] POST-LOAD STRUCTURAL ANALYSIS
        // Grab lightweight DOM features to detect high-quality phishing
        const pageTitle = document.title || "";
        const h1 = document.querySelector('h1')?.innerText || "";
        const hasPassword = !!document.querySelector('input[type="password"]');
        const links = document.querySelectorAll('a[href]');

        let externalLinks = 0;
        const currentHost = window.location.hostname;

        links.forEach(l => {
            try {
                if (new URL(l.href).hostname !== currentHost) externalLinks++;
            } catch (e) { }
        });

        const extRatio = links.length > 0 ? externalLinks / links.length : 0;

        // Prepare context payload
        const contextData = {
            title: pageTitle,
            h1: h1,
            has_password_field: hasPassword ? 1 : 0,
            external_link_ratio: extRatio,
            is_https: window.location.protocol === 'https:' ? 1 : 0
        };

        chrome.runtime.sendMessage({
            type: "ANALYZE_URL",
            url: window.location.href,
            isMainFrame: true,
            context: contextData // Send structure to backend
        });
        console.log("[PhishTrace] 🔍 Self-Scan initiated with Structural Context:", contextData);
    } catch (e) {
        // Ignore extension context invalidation
    }
}

// Initial Scan
setTimeout(() => scanScope(document), 1000);

// Close popups on click outside
document.addEventListener('click', (e) => {
    if (!e.target.closest('.sentinel-badge-host') && !e.target.closest('.sentinel-popup')) {
        document.querySelectorAll('.sentinel-popup').forEach(p => p.style.display = 'none');
    }
});

// ---------------------------------------------------------
// COGNITIVE SHIELD IMPLEMENTATION (REAL-TIME SUPPRESSION)
// ---------------------------------------------------------

class CognitiveShield {
    constructor() {
        this.active = true; // Default to active for demo
        this.suppressedCount = 0;
        this.stylesInjected = false;
    }

    init() {
        console.log("%c[PhishTrace] Cognitive Shield: INITIALIZED", "color: #3b82f6; font-weight: bold;");
        this.injectStyles();
        this.scanAndSuppress();

        // Piggyback on the existing debounce scanner or separate interval?
        // Let's use a separate efficient interval for UI cleanup
        setInterval(() => this.scanAndSuppress(), 2000);
    }

    injectStyles() {
        if (this.stylesInjected) return;
        const style = document.createElement('style');
        style.textContent = `
            .sentinel-suppressed {
                filter: blur(4px) grayscale(100%) !important;
                opacity: 0.3 !important;
                pointer-events: none !important;
                transition: all 0.5s ease !important;
            }
            .sentinel-suppressed:hover {
                filter: none !important;
                opacity: 1 !important;
                pointer-events: auto !important;
            }
            .sentinel-hidden {
                display: none !important;
            }
        `;
        document.head.appendChild(style);
        this.stylesInjected = true;
    }

    scanAndSuppress() {
        if (!this.active || shouldIgnore(window.location.href)) return;

        this.suppressPopups();
        this.suppressStickyHeaders();
        this.suppressSocialWidgets();
    }

    suppressPopups() {
        // Generic heuristics for modals/overlays
        // High Z-Index + Fixed Position + Center of Screen
        const candidates = document.querySelectorAll('div, section, aside');

        candidates.forEach(el => {
            if (el.classList.contains('sentinel-suppressed') || el.classList.contains('sentinel-hidden')) return;

            const style = window.getComputedStyle(el);
            if (style.position === 'fixed' && parseInt(style.zIndex) > 100) {
                const rect = el.getBoundingClientRect();
                const isCentered = (
                    Math.abs(rect.left + rect.width / 2 - window.innerWidth / 2) < 100 &&
                    Math.abs(rect.top + rect.height / 2 - window.innerHeight / 2) < 100
                );

                // Must be reasonably large but not the whole screen (bg overlay)
                const isOverlaySize = rect.width > 200 && rect.height > 100 && rect.width < window.innerWidth;

                if (isCentered && isOverlaySize) {
                    console.log("[PhishTrace] Suppressing Popup:", el);
                    el.classList.add('sentinel-hidden');
                    this.suppressedCount++;
                }
            }
        });
    }

    suppressStickyHeaders() {
        // Find sticky headers taking up too much space
        const candidates = document.querySelectorAll('header, div[role="banner"], .header, .nav, .navbar');

        candidates.forEach(el => {
            if (el.classList.contains('sentinel-suppressed')) return;

            const style = window.getComputedStyle(el);
            if ((style.position === 'fixed' || style.position === 'sticky') && style.top === '0px') {
                const rect = el.getBoundingClientRect();
                // If it takes up more than 15% of the viewport height, suppress it
                if (rect.height > window.innerHeight * 0.15) {
                    console.log("[PhishTrace] Suppressing Sticky Header:", el);
                    el.classList.add('sentinel-suppressed');
                    this.suppressedCount++;
                }
            }
        });
    }

    suppressSocialWidgets() {
        // Common selectors for chat widgets, social shares
        const selectors = [
            'iframe[title*="chat"]',
            'div[class*="chat"]',
            'div[id*="chat"]',
            '.intercom-lightweight-app',
            '#fb-root',
            '.addthis_toolbox',
            '.social-share',
            '.share-buttons'
        ];

        selectors.forEach(sel => {
            const els = document.querySelectorAll(sel);
            els.forEach(el => {
                if (!el.classList.contains('sentinel-hidden')) {
                    // Check if it's fixed/floating (distraction)
                    const style = window.getComputedStyle(el);
                    if (style.position === 'fixed') {
                        console.log("[PhishTrace] Suppressing Social Widget:", el);
                        el.classList.add('sentinel-hidden');
                    }
                }
            });
        });
    }
}

// Activate Shield
const cognitiveShield = new CognitiveShield();
// Delay slightly to let page load
setTimeout(() => cognitiveShield.init(), 2500);
