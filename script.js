// --- DATA FOR ANALYSIS ---
const URL_SHORTENERS = ['bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'soo.gd', 'rb.gy'];
const SUSPICIOUS_TLDS = ['.vip', '.xyz', '.top', '.club', 'live', '.info', '.biz', '.ws', '.cc'];
const URGENCY_KEYWORDS = [
    'final notice', 'enforcement penalties', 'suspend', 'suspension', 'action required', 
    'urgent', 'immediate', 'verify', 'validate', 'confirm', 'account will be locked',
    'eligible for a refund', 'outstanding traffic ticket', 'pay immediately', 'legal disputes'
];
const SENSITIVE_KEYWORDS = ['login', 'secure', 'account', 'update', 'password', 'signin'];

// --- DOM ELEMENTS ---
const scanButton = document.getElementById('scan-button');
const urlInput = document.getElementById('url-input');
const messageContent = document.getElementById('message-content');
const senderInput = document.getElementById('sender-input');
const analysisReport = document.getElementById('analysis-report');
const urlResults = document.getElementById('url-results');
const contentResults = document.getElementById('content-results');
const senderResults = document.getElementById('sender-results');
const summaryResults = document.getElementById('summary-results');

// --- EVENT LISTENER ---
scanButton.addEventListener('click', () => {
    const url = urlInput.value.trim();
    const content = messageContent.value.trim();
    const sender = senderInput.value.trim();

    if (!url) {
        alert('Please enter a URL to scan.');
        return;
    }

    performAnalysis(url, content, sender);
});

// --- ANALYSIS FUNCTIONS ---

function performAnalysis(url, content, sender) {
    // Clear previous results
    urlResults.innerHTML = '';
    contentResults.innerHTML = '';
    senderResults.innerHTML = '';
    summaryResults.innerHTML = '';
    
    let riskScore = 0;
    let reportItems = [];

    // 1. URL Analysis
    try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;

        // Check HTTPS
        if (urlObj.protocol !== 'https:') {
            reportItems.push({type: 'danger', section: 'url', text: 'Connection is not secure (HTTP).'});
            riskScore += 2;
        } else {
            reportItems.push({type: 'safe', section: 'url', text: 'Uses a secure connection (HTTPS).'});
        }

        // Check for IP address
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
             reportItems.push({type: 'danger', section: 'url', text: 'URL is a direct IP address, not a domain name.'});
             riskScore += 3;
        }

        // Check for URL Shorteners
        if (URL_SHORTENERS.some(shortener => hostname.includes(shortener))) {
            reportItems.push({type: 'warning', section: 'url', text: 'Uses a known URL shortener which can hide the final destination.'});
            riskScore += 2;
        }
        
        // Check for Suspicious TLD
        if (SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld))) {
            reportItems.push({type: 'danger', section: 'url', text: `Uses a suspicious Top-Level Domain (TLD): ${hostname.substring(hostname.lastIndexOf('.'))}`});
            riskScore += 2;
        }

        // Check for sensitive keywords in subdomains/path
        if (SENSITIVE_KEYWORDS.some(keyword => url.toLowerCase().includes(keyword))) {
            if (sender && !hostname.toLowerCase().includes(sender.toLowerCase())) {
                reportItems.push({type: 'warning', section: 'url', text: 'URL contains sensitive keywords like "login" but does not match the sender.'});
                riskScore += 1;
            }
        }

    } catch (error) {
        reportItems.push({type: 'danger', section: 'url', text: 'The entered URL is invalid.'});
        riskScore += 5;
    }

    // 2. Content Analysis
    if (content) {
        const lowerContent = content.toLowerCase();
        const foundKeywords = URGENCY_KEYWORDS.filter(keyword => lowerContent.includes(keyword));
        if (foundKeywords.length > 0) {
            reportItems.push({type: 'warning', section: 'content', text: `Message contains keywords that create urgency: "${foundKeywords.join(', ')}".`});
            riskScore += foundKeywords.length;
        } else {
             reportItems.push({type: 'safe', section: 'content', text: 'No high-urgency keywords found in the message.'});
        }
    } else {
        reportItems.push({type: 'info', section: 'content', text: 'No message content provided to analyze.'});
    }

    // 3. Sender Analysis
    if (sender) {
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname.replace('www.', '');
            if (!domain.toLowerCase().includes(sender.toLowerCase().split(' ').join(''))) {
                reportItems.push({type: 'danger', section: 'sender', text: `Sender "${sender}" does not match the URL's domain (${domain}).`});
                riskScore += 3;
            } else {
                reportItems.push({type: 'safe', section: 'sender', text: `Sender "${sender}" appears to match the URL's domain.`});
            }
        } catch(e) { /* URL validity already checked */ }
    } else {
         reportItems.push({type: 'info', section: 'sender', text: 'No sender provided for comparison.'});
    }

    displayResults(reportItems, riskScore);
}

function displayResults(items, score) {
    const iconMap = {
        'safe': '✅',
        'warning': '⚠️',
        'danger': '❌',
        'info': 'ℹ️'
    };

    items.forEach(item => {
        const resultElement = document.createElement('div');
        resultElement.className = `report-item ${item.type}`;
        resultElement.innerHTML = `<span class="icon">${iconMap[item.type]}</span><span>${item.text}</span>`;
        
        const targetSection = document.getElementById(`${item.section}-results`);
        if (targetSection) {
            targetSection.appendChild(resultElement);
        }
    });

    // Display Summary
    let summaryText = '';
    let summaryClass = 'safe';

    if (score > 8) {
        summaryText = "High Risk: This has multiple indicators of a phishing attempt.";
        summaryClass = 'danger';
    } else if (score > 3) {
        summaryText = "Medium Risk: Proceed with extreme caution. Several red flags were detected.";
        summaryClass = 'warning';
    } else if (score > 0) {
        summaryText = "Low Risk: Some elements are worth noting. Be cautious.";
        summaryClass = 'warning';
    } else {
        summaryText = "No obvious risks detected, but always remain vigilant.";
        summaryClass = 'safe';
    }
    
    const summaryElement = document.createElement('div');
    summaryElement.className = `report-item ${summaryClass}`;
    summaryElement.innerHTML = `<strong>${summaryText}</strong>`;
    summaryResults.appendChild(summaryElement);

    analysisReport.style.display = 'block';
}
