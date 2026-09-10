// Parse URL parameters
const params = new URLSearchParams(window.location.search);
const blockedUrl = decodeURIComponent(params.get('url') || '');
const riskScore = parseFloat(params.get('risk') || '0');
const isPermanent = params.get('permanent') === 'true';
const labels = params.get('labels') ? JSON.parse(decodeURIComponent(params.get('labels'))) : {};

// Display blocked URL
document.getElementById('blocked-url').textContent = blockedUrl || 'Unknown URL';

// Display risk score
const riskScoreElement = document.getElementById('risk-score');
const riskFillElement = document.getElementById('risk-fill');

if (riskScore > 0) {
    const percentage = (riskScore * 100).toFixed(1);
    riskScoreElement.textContent = `${percentage}%`;
    riskFillElement.style.width = `${percentage}%`;
} else {
    riskScoreElement.textContent = 'HIGH';
    riskFillElement.style.width = '100%';
}

// If permanently blocked, update UI
if (isPermanent) {
    const titleElement = document.querySelector('.title');
    titleElement.textContent = '🚫 Permanently Blocked Domain';
    
    const subtitleElement = document.querySelector('.subtitle');
    subtitleElement.textContent = 'This domain has been permanently blocked by your security settings';
    
    // Hide "Proceed Anyway" button for permanent blocks
    const proceedBtn = document.getElementById('proceed-btn');
    if (proceedBtn) {
        proceedBtn.style.display = 'none';
    }
    
    // Update reasons
    const reasonsList = document.getElementById('reasons-list');
    reasonsList.innerHTML = '<li>This domain is in your permanent blocklist</li><li>It was manually blocked from the dashboard</li><li>Contact your administrator to unblock</li>';
}

// Display threat tags
const threatTagsContainer = document.getElementById('threat-tags');
if (labels && Object.keys(labels).length > 0) {
    Object.entries(labels).forEach(([label, data]) => {
        if (data.probability > 0.5 || isPermanent) {
            const tag = document.createElement('div');
            tag.className = 'threat-tag';
            tag.textContent = label.charAt(0).toUpperCase() + label.slice(1);
            threatTagsContainer.appendChild(tag);
        }
    });
} else {
    // Default tags if no labels provided
    const defaultTags = isPermanent ? ['Blocked', 'Permanent'] : ['Phishing', 'Suspicious URL', 'High Risk'];
    defaultTags.forEach(tagText => {
        const tag = document.createElement('div');
        tag.className = 'threat-tag';
        tag.textContent = tagText;
        threatTagsContainer.appendChild(tag);
    });
}

// Update reasons based on detected patterns (only if not permanent)
if (!isPermanent) {
    const reasonsList = document.getElementById('reasons-list');
    const reasons = [];

    if (blockedUrl.includes('login') || blockedUrl.includes('signin')) {
        reasons.push('URL contains login-related keywords often used in phishing');
    }
    if (blockedUrl.includes('verify') || blockedUrl.includes('confirm')) {
        reasons.push('URL uses verification language to create urgency');
    }
    if (blockedUrl.match(/\.(xyz|top|tk|ml|ga|cf|gq)$/)) {
        reasons.push('Uses a suspicious top-level domain commonly associated with scams');
    }
    if (blockedUrl.includes('-') && blockedUrl.split('-').length > 3) {
        reasons.push('Excessive hyphens suggest domain squatting');
    }

    if (reasons.length > 0) {
        reasonsList.innerHTML = '';
        reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            reasonsList.appendChild(li);
        });
    }
}

// Button handlers
document.getElementById('go-back').addEventListener('click', () => {
    window.history.back();
});

document.getElementById('proceed-btn').addEventListener('click', () => {
    // Show confirmation dialog
    document.getElementById('proceed-confirm').style.display = 'block';
    document.getElementById('proceed-btn').style.display = 'none';
});

document.getElementById('cancel-proceed').addEventListener('click', () => {
    // Hide confirmation dialog
    document.getElementById('proceed-confirm').style.display = 'none';
    document.getElementById('proceed-btn').style.display = 'block';
});

document.getElementById('proceed-final').addEventListener('click', () => {
    // Add to temporary whitelist and navigate
    chrome.runtime.sendMessage({
        type: 'WHITELIST_TEMP',
        url: blockedUrl
    }, (response) => {
        if (response && response.success) {
            // Navigate to the blocked URL
            window.location.href = blockedUrl;
        } else {
            alert('Failed to whitelist URL. Please try again.');
        }
    });
});

document.getElementById('report-false').addEventListener('click', (e) => {
    e.preventDefault();
    
    // Send false positive report
    chrome.runtime.sendMessage({
        type: 'REPORT_FALSE_POSITIVE',
        url: blockedUrl,
        riskScore: riskScore
    }, (response) => {
        if (response && response.success) {
            alert('Thank you for your report! This will help improve our detection.');
            // Optionally whitelist and proceed
            if (confirm('Would you like to proceed to this site?')) {
                document.getElementById('proceed-final').click();
            }
        }
    });
});

// Log blocked attempt
chrome.runtime.sendMessage({
    type: 'LOG_BLOCKED',
    url: blockedUrl,
    riskScore: riskScore,
    timestamp: Date.now()
});

console.log('[PhishTrace] Blocked page loaded for:', blockedUrl, 'Risk:', riskScore);
