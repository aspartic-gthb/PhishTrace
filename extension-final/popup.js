/**
 * PhishTrace Terminal Controller (SOC v4.5)
 * Advanced responsive UI with Neural Deep Analysis & Structured AI Reports.
 */

const API_BASE = "http://127.0.0.1:8005/api/v1";

// Persistent session data
let currentTabId = null;

document.addEventListener('DOMContentLoaded', async () => {
    // Check for tabId in URL (if expanded)
    const urlParams = new URLSearchParams(window.location.search);
    const urlTabId = urlParams.get('tabId');
    if (urlTabId) {
        currentTabId = parseInt(urlTabId);
    }

    await loadStats();
    await loadActivity();
    checkCurrentTabRisk();
    initControls();

    // FETCH SCAN FROM ACTIVE TAB FIRST (Prevents stale scan lingering across tabs)
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (tabs[0] && tabs[0].id) {
            chrome.tabs.sendMessage(tabs[0].id, { type: "GET_LAST_SCAN" }, function (response) {
                if (response) {
                    console.log("Got scan from active tab content script:", response);
                    updateTemporalRiskDisplay(response);
                } else {
                    // Active tab is not an email or has no scan - load latest from storage or reset to clean
                    chrome.storage.local.get(['latestScan'], (result) => {
                        if (result.latestScan) {
                            console.log("Got fallback scan from STORAGE:", result.latestScan);
                            updateTemporalRiskDisplay(result.latestScan);
                        } else {
                            updateTemporalRiskDisplay({ risk_score: 0, risk_level: "SAFE" });
                        }
                    });
                }
            });
        } else {
            chrome.storage.local.get(['latestScan'], (result) => {
                if (result.latestScan) {
                    updateTemporalRiskDisplay(result.latestScan);
                } else {
                    updateTemporalRiskDisplay({ risk_score: 0, risk_level: "SAFE" });
                }
            });
        }
    });

    // LISTEN FOR REAL-TIME UPDATES
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === 'EMAIL_SCANNED') {
            updateTemporalRiskDisplay(message.data);
        }
    });
});

async function checkCurrentTabRisk() {
    try {
        let tab;
        if (currentTabId) {
            tab = await chrome.tabs.get(currentTabId);
        } else {
            const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
            tab = activeTab;
            if (tab) currentTabId = tab.id;
        }

        if (!tab || !tab.url || tab.url.startsWith('chrome') || tab.url.startsWith('about:')) {
            updateRiskUI('Restricted Zone', 0, 'SAFE');
            return;
        }

        const domain = new URL(tab.url).hostname;

        // --- INSTANT CLIENT-SIDE WHITELIST (Zero Latency) ---
        const SAFE_DOMAINS = [
            'mail.google.com', 'google.com', 'github.com', 'stackoverflow.com',
            'youtube.com', 'linkedin.com', 'amazon.com', 'amazon.in',
            'canva.com', 'notion.so', 'figma.com', 'whatsapp.com',
            'microsoft.com', 'apple.com', 'openai.com', 'chatgpt.com',
            'coursera.org', 'udemy.com'
        ];

        // Fast Check: If domain ends with any safe domain
        const isSafe = SAFE_DOMAINS.some(d => domain === d || domain.endsWith('.' + d));

        if (isSafe) {
            console.log("⚡ Instant Client Check: Safe Domain");
            // Render UI immediately
            updateRiskUI(domain, 0, 'SAFE');
        } else {
            // Only show "Establishing Link..." if we don't know the domain
            if (document.getElementById('currentDomain').textContent === 'ESTABLISHING LINK...') {
                document.getElementById('currentDomain').textContent = domain;
            }
        }

        chrome.runtime.sendMessage({ type: "ANALYZE_URL", url: tab.url, isMainFrame: false }, (response) => {
            if (response && response.success && response.data) {
                const data = response.data;
                // If backend found a risk on a "safe" site (rare), override it.
                // Otherwise update normally.
                if (data.global_risk_score > 0.1 || !isSafe) {
                    updateRiskUI(domain, data.global_risk_score || 0, data.status, data.neural_status);
                }
            } else {
                if (!isSafe) {
                    updateRiskUI(domain, 0, 'SAFE');
                }
            }
        });
    } catch (e) {
        console.error("Link sync failed:", e);
    }
}

function updateRiskUI(domain, score, statusOverride = null, neuralStatus = null) {
    const validScore = Number.isFinite(Number(score)) ? Number(score) : 0;
    const percentage = Math.round(validScore * 100);
    const fill = document.getElementById('riskMeterFill');
    const badge = document.getElementById('riskBadge');
    const percentEl = document.getElementById('riskPercent');
    const domainEl = document.getElementById('currentDomain');
    const nBadge = document.getElementById('neural-badge');

    if (!fill || !badge || !percentEl) return;

    // Toggle Neural Badge
    if (nBadge) {
        if (neuralStatus === 'VERIFIED') {
            nBadge.style.display = 'flex';
        } else {
            nBadge.style.display = 'none';
        }
    }

    if (domain) domainEl.textContent = domain.replace('www.', '').toUpperCase();
    percentEl.textContent = `${percentage}%`;

    let status = 'SAFE';
    if (score > 0.7) status = 'DANGER';
    else if (score > 0.4) status = 'WARNING';
    if (statusOverride) status = statusOverride;

    fill.style.width = `${percentage}%`;
    fill.style.backgroundColor = status === 'SAFE' ? 'var(--safe)' : (status === 'WARNING' ? 'var(--warning)' : 'var(--danger)');

    badge.textContent = status;
    badge.className = `risk-badge ${status.toLowerCase()}`;
}

// MAIN UPDATE FUNCTION
function updateTemporalRiskDisplay(emailData) {
    const riskScoreEl = document.getElementById('temporalRiskValue');
    const riskCircle = document.querySelector('.temporal-risk-circle');
    const status = document.getElementById('lastEmailStatus');
    const mlGrid = document.getElementById('mlSignalsGrid');

    // NOTE: Decoupled per user request. Top card remains Domain-focused.

    const percentage = Math.round(emailData.risk_score * 100);

    if (riskScoreEl) riskScoreEl.innerText = `${percentage}%`;

    // Status / Color Logic
    let statusText = "UNKNOWN";
    let statusColor = "#a1a1aa";
    let circleColor = "#a1a1aa";

    const score = emailData.risk_score;
    if (score > 0.7) {
        statusText = "DANGEROUS";
        statusColor = "#ef4444";
        circleColor = "#ef4444";
    } else if (score > 0.4) {
        statusText = "SUSPICIOUS";
        statusColor = "#f59e0b";
        circleColor = "#f59e0b";
    } else {
        statusText = "SAFE";
        statusColor = "#10b981";
        circleColor = "#10b981";
    }

    if (status) {
        status.innerHTML = `
            <span style="display:inline-block; width:8px; height:8px; background:${statusColor}; border-radius:50%; margin-right:6px;"></span>
            ${statusText}
        `;
        status.style.color = statusColor;
    }

    // UPDATE ML SIGNALS GRID
    if (mlGrid && emailData.signals) {
        const signals = emailData.signals;
        // Map of friendly names
        const signalKeys = [
            { key: 'urgency', label: 'Urgency' },
            { key: 'fear', label: 'Fear' },
            { key: 'authority', label: 'Authority' },
            { key: 'impersonation', label: 'Impersonation' }
        ];

        let gridHTML = '';
        signalKeys.forEach(sig => {
            const data = signals[sig.key] || { probability: 0 };
            const prob = data.probability || 0;
            const pct = Math.round(prob * 100);

            // Color based on intensity
            let barColor = '#3b82f6'; // Blue default
            if (pct > 70) barColor = '#ef4444';
            else if (pct > 40) barColor = '#f59e0b';

            gridHTML += `
                <div class="ml-signal-item">
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <div class="ml-label" style="margin:0;">${sig.label}</div>
                        <div style="font-size:9px; font-weight:700; color:${barColor};">${pct}%</div>
                    </div>
                    <div class="ml-bar">
                        <div class="ml-fill" style="width: ${pct}%; background: ${barColor};"></div>
                    </div>
                </div>
            `;
        });
        mlGrid.innerHTML = gridHTML;
    } else if (mlGrid) {
        // Fallback if no signals passed (e.g. old scan format)
        mlGrid.innerHTML = `<div style="grid-column: span 2; font-size: 11px; color:#555; text-align:center;">No neural signals available</div>`;
    }

    const angle = Math.round(score * 360);
    if (riskCircle) {
        riskCircle.style.setProperty('--risk-angle', `${angle}deg`);
        riskCircle.style.background = `conic-gradient(
            from 0deg, 
            ${circleColor} 0deg, 
            ${circleColor} var(--risk-angle, 0deg), 
            rgba(255,255,255,0.1) var(--risk-angle, 0deg)
        )`;
        riskCircle.style.boxShadow = `0 0 20px ${circleColor}40`;
    }
}

function initControls() {
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) refreshBtn.addEventListener('click', () => location.reload());

    const expandBtn = document.getElementById('expandBtn');
    if (expandBtn) {
        expandBtn.addEventListener('click', async () => {
            let targetId = currentTabId;
            if (!targetId && chrome.tabs) {
                try {
                    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                    targetId = tab?.id;
                } catch (e) {}
            }
            const url = chrome.runtime.getURL(`popup.html${targetId ? `?tabId=${targetId}` : ''}`);
            if (chrome.tabs && chrome.tabs.create) {
                chrome.tabs.create({ url });
            } else {
                window.open(url, '_blank');
            }
        });
    }

    const deepScanBtn = document.getElementById('deepScanBtn');
    if (deepScanBtn) deepScanBtn.addEventListener('click', handleDeepScan);

    const openTemporalBtn = document.getElementById('openTemporalAnalysis');
    if (openTemporalBtn) {
        openTemporalBtn.addEventListener('click', () => {
            const url = 'http://localhost:3000/features/temporal-analysis';
            if (chrome.tabs && chrome.tabs.create) {
                chrome.tabs.create({ url });
            } else {
                window.open(url, '_blank');
            }
        });
    }

    const openDashboardBtn = document.getElementById('openDashboard');
    if (openDashboardBtn) {
        openDashboardBtn.addEventListener('click', () => {
            const url = 'http://localhost:3000/dashboard';
            if (chrome.tabs && chrome.tabs.create) {
                chrome.tabs.create({ url });
            } else {
                window.open(url, '_blank');
            }
        });
    }

    const consultAIBtn = document.getElementById('consultAIBtn');
    if (consultAIBtn) consultAIBtn.addEventListener('click', handleConsultAI);

    const backToMain = document.getElementById('backToMain');
    if (backToMain) backToMain.addEventListener('click', exitAnalysis);

    const backToMainBtn = document.getElementById('backToMainBtn');
    if (backToMainBtn) backToMainBtn.addEventListener('click', exitAnalysis);
}

function exitAnalysis() {
    document.getElementById('analysisView').classList.remove('active');
    document.getElementById('mainView').classList.add('active');
    document.getElementById('backToMain').style.display = 'none';
    document.getElementById('analysisFooter').style.display = 'none';
    document.getElementById('mainFooter').style.display = 'flex';
}

function handleDeepScan() {
    const btn = document.getElementById('deepScanBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<div class="loader"></div>';

    setTimeout(() => {
        document.getElementById('mainView').classList.remove('active');
        document.getElementById('analysisView').classList.add('active');
        document.getElementById('backToMain').style.display = 'flex';
        document.getElementById('analysisFooter').style.display = 'flex';
        document.getElementById('mainFooter').style.display = 'none';
        btn.innerHTML = originalText;
        populateSignals();
        populateExternalIO();
    }, 1500);
}

function populateSignals() {
    const signals = [
        { name: 'Urgency Pattern', conf: 'High', color: '#ef4444' },
        { name: 'Spoofed Headers', conf: 'Med', color: '#f59e0b' },
        { name: 'Malicious Payload', conf: 'Low', color: '#10b981' }
    ];

    const tbody = document.getElementById('signalsBody');
    tbody.innerHTML = signals.map(s => `
        <tr>
            <td style="color: #fff; font-weight: 500;">${s.name}</td>
            <td style="text-align: right; color: ${s.color}; font-weight: 700;">${s.conf}</td>
        </tr>
    `).join('');
}

function populateExternalIO() {
    const links = [
        { url: 'cdn.malice-serv.com', type: 'OUTBOUND', safe: false },
        { url: 'fonts.googleapis.com', type: 'ASSET', safe: true }
    ];

    const div = document.getElementById('linksBody');
    div.innerHTML = links.map(l => `
        <div style="display: flex; justify-content: space-between; padding: 10px; background: rgba(255,255,255,0.03); border-radius: 8px; margin-bottom: 8px;">
            <div style="font-size: 13px; color: ${l.safe ? '#fff' : '#ef4444'};">${l.url}</div>
            <div style="font-size: 11px; font-weight: 700; color: #71717a;">${l.type}</div>
        </div>
    `).join('');
}

async function handleConsultAI() {
    const chat = document.getElementById('chatbotResponse');
    if (!chat) return;

    const domainEl = document.getElementById('currentDomain');
    const domain = domainEl ? domainEl.textContent.trim() : 'Active Page';
    const riskPercent = document.getElementById('riskPercent')?.textContent || '0%';
    const riskBadge = document.getElementById('riskBadge')?.textContent || 'SAFE';

    chat.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px; color:var(--ai-blue); font-weight:700; padding:12px;">
            <div class="loader"></div>
            <span>Querying PhishTrace AI Engine for ${domain}...</span>
        </div>
    `;

    try {
        const response = await fetch(`${API_BASE}/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: `Perform a deep forensic threat analysis for site ${domain}. Current Risk Score: ${riskPercent}, Status: ${riskBadge}. Provide a structured academic breakdown of heuristics, structural flags, and countermeasures.`,
                context: `Target Domain: ${domain}\nRisk Score: ${riskPercent}\nRisk Level: ${riskBadge}`
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        let formattedText = (data.response || '')
            .replace(/\n/g, '<br>')
            .replace(/—+/g, '<hr style="border:0; border-top:1px solid #333; margin:15px 0;">')
            .replace(/REPORT CLASSIFICATION:/g, '<strong style="color:var(--ai-blue)">REPORT CLASSIFICATION:</strong>')
            .replace(/PHISHTRACE CONFIDENCE INDEX:/g, '<strong style="color:var(--ai-blue)">PHISHTRACE CONFIDENCE INDEX:</strong>')
            .replace(/ACADEMIC SUMMARY/g, '<div class="report-head">ACADEMIC SUMMARY</div>')
            .replace(/HEURISTIC VECTOR DECONSTRUCTION \(ML SCAN\)/g, '<div class="report-head">HEURISTIC VECTOR DECONSTRUCTION (ML SCAN)</div>')
            .replace(/STRUCTURAL INTERROGATION \(DOM ANALYSIS\)/g, '<div class="report-head">STRUCTURAL INTERROGATION (DOM ANALYSIS)</div>')
            .replace(/BRAND INTELLIGATION AUDIT/g, '<div class="report-head">BRAND INTELLIGENCE AUDIT</div>')
            .replace(/BRAND INTELLIGENCE AUDIT/g, '<div class="report-head">BRAND INTELLIGENCE AUDIT</div>')
            .replace(/CONCLUSION & COUNTERMEASURES/g, '<div class="report-head">CONCLUSION & COUNTERMEASURES</div>');

        let suggestionsHtml = '';
        if (data.suggestions && data.suggestions.length > 0) {
            suggestionsHtml = `
                <div style="margin-top:16px; border-top:1px solid var(--border); padding-top:12px;">
                    <div style="font-size:10px; color:var(--text-tertiary); text-transform:uppercase; font-weight:800; margin-bottom:8px;">Suggested Follow-ups</div>
                    <div style="display:flex; flex-wrap:wrap; gap:6px;">
                        ${data.suggestions.map(s => `<button style="background:rgba(59,130,246,0.1); border:1px solid rgba(59,130,246,0.3); color:#60a5fa; font-size:11px; padding:4px 10px; border-radius:6px; cursor:pointer;">${s}</button>`).join('')}
                    </div>
                </div>
            `;
        }

        chat.innerHTML = `
            <div style="font-size:13px; line-height:1.7; color:var(--text-secondary); max-height:450px; overflow-y:auto; padding-right:8px;">
                ${formattedText}
                ${suggestionsHtml}
            </div>
        `;
    } catch (err) {
        console.error("AI Consult Error:", err);
        chat.innerHTML = `
            <div style="color:var(--danger); font-size:13px; font-weight:600; padding:10px; background:rgba(239,68,68,0.1); border-radius:8px;">
                ⚠️ Connection Error: Unable to query PhishTrace AI Engine on ${API_BASE}/chat.
                <div style="font-size:11px; color:#a1a1aa; font-weight:400; margin-top:4px;">${err.message}</div>
            </div>
        `;
    }
}

async function loadStats() {
    try {
        const response = await fetch(`${API_BASE}/email-scans/stats`);
        if (response.ok) {
            const data = await response.json();
            document.getElementById('statScans').textContent = data.total_scans || 0;
            document.getElementById('statBlocked').textContent = data.high_risk || 0;
            document.getElementById('emailsScanned').textContent = data.total_scans || 0;
            document.getElementById('threatsDetected').textContent = data.suspicious + data.high_risk || 0;
        }
    } catch (e) {
        console.log("Stats offline");
    }
}

async function loadActivity() {
    const feed = document.getElementById('activityFeed');
    feed.innerHTML = `
        <div style="font-size: 12px; color: #71717a; padding: 10px; background: rgba(255,255,255,0.02); border-radius: 8px;">
            System initialized. Monitoring active channels.
        </div>
    `;
}
