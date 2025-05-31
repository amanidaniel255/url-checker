// Debug mode
const DEBUG = true;
function debug(...args) {
  if (DEBUG) console.log('[Peruzi Salama Background]:', ...args);
}

// Cache for URL check results
const urlCache = new Map();
const CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

// Initialize context menu
chrome.runtime.onInstalled.addListener(() => {
  debug('Extension installed/updated');
  chrome.contextMenus.create({
    id: 'checkLink',
    title: 'Check link safety',
    contexts: ['link']
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'checkLink') {
    debug('Context menu clicked for URL:', info.linkUrl);
    checkUrl(info.linkUrl).then(result => {
      // Show result in a more visible way
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: showUrlCheckResult,
        args: [result, info.linkUrl]
      });
    });
  }
});

// Function to show results in the page
function showUrlCheckResult(result, url) {
  const container = document.createElement('div');
  container.style.cssText = `
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: white;
    border: 2px solid ${result.safe ? '#22c55e' : '#ef4444'};
    border-radius: 8px;
    padding: 20px;
    max-width: 400px;
    z-index: 10000000;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  `;

  container.innerHTML = `
    <div style="display: flex; align-items: start; gap: 12px;">
      <div style="flex-shrink: 0;">
        ${result.safe ? 
          '<svg style="width: 24px; height: 24px; color: #22c55e;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>' :
          '<svg style="width: 24px; height: 24px; color: #ef4444;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>'
        }
      </div>
      <div>
        <div style="font-weight: bold; color: ${result.safe ? '#15803d' : '#991b1b'}; margin-bottom: 8px;">
          ${result.safe ? 'Safe Link' : 'Warning: Potentially Unsafe Link'}
        </div>
        <div style="color: #4b5563; font-size: 0.9em; margin-bottom: 8px;">
          ${url}
        </div>
        ${result.warnings && result.warnings.length > 0 ? `
          <div style="color: #7f1d1d; font-size: 0.9em;">
            ${result.warnings.map(w => `• ${w}`).join('<br>')}
          </div>
        ` : ''}
        ${result.analysis ? `
          <div style="margin-top: 8px; font-size: 0.8em; color: #666; border-top: 1px solid #e5e7eb; padding-top: 8px;">
            ${result.analysis.hasSSL ? '🔒 Secure connection' : '⚠️ Insecure connection'}<br>
            ${result.analysis.isWellKnownTLD ? '✓ Known domain type' : '⚠️ Uncommon domain type'}
          </div>
        ` : ''}
      </div>
    </div>
  `;

  document.body.appendChild(container);
  setTimeout(() => container.remove(), 5000);
}

// Listen for messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  debug('Received message:', request);
  if (request.action === 'checkUrl') {
    checkUrl(request.url)
      .then(result => {
        debug('Sending response:', result);
        sendResponse(result);
      })
      .catch(error => {
        debug('Error in checkUrl:', error);
        sendResponse({
          safe: false,
          warnings: ['Error checking URL safety'],
          analysis: null
        });
      });
    return true; // Will respond asynchronously
  }
});

// URL analysis function
function analyzeURL(urlString) {
  try {
    const url = new URL(urlString);
    const domainParts = url.hostname.split('.');
    const tld = domainParts[domainParts.length - 1].toLowerCase();
    
    return {
      protocol: url.protocol,
      domain: url.hostname,
      path: url.pathname,
      hasSSL: url.protocol === 'https:',
      hasSubdomain: domainParts.length > 2,
      isIP: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname),
      hasSuspiciousWords: /login|account|verify|secure|banking/i.test(url.hostname),
      isWellKnownTLD: ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'me', 'app'].includes(tld)
    };
  } catch (e) {
    debug('Error analyzing URL:', e);
    return null;
  }
}

// Main URL checking function
async function checkUrl(url) {
  debug('Checking URL:', url);
  
  // Check cache first
  if (urlCache.has(url)) {
    const cached = urlCache.get(url);
    if (Date.now() - cached.timestamp < CACHE_DURATION) {
      debug('Returning cached result');
      return cached.result;
    }
    urlCache.delete(url);
  }

  try {
    // Local analysis
    const analysis = analyzeURL(url);
    if (!analysis) {
      debug('Invalid URL format');
      return {
        safe: false,
        warnings: ['Invalid URL format'],
        analysis: null
      };
    }

    const warnings = [];
    let isSafe = true;

    // Check protocol
    if (!analysis.hasSSL) {
      warnings.push('This URL uses an insecure connection (HTTP)');
    }

    // Check for suspicious patterns
    if (analysis.hasSuspiciousWords) {
      warnings.push('URL contains suspicious keywords');
      isSafe = false;
    }

    if (analysis.isIP) {
      warnings.push('URL uses an IP address instead of a domain name');
      isSafe = false;
    }

    if (!analysis.isWellKnownTLD) {
      warnings.push('URL uses an uncommon top-level domain');
    }

    // Check against Google Safe Browsing API
    try {
      const apiKey = await chrome.storage.sync.get('apiKey');
      debug('API Key status:', apiKey.apiKey ? 'Present' : 'Missing');
      
      if (apiKey.apiKey) {
        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey.apiKey}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            client: {
              clientId: 'peruzisalama',
              clientVersion: '1.0.0'
            },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url }]
            }
          })
        });

        const data = await response.json();
        debug('Google Safe Browsing API response:', data);
        
        if (data.matches && data.matches.length > 0) {
          isSafe = false;
          warnings.push('Google Safe Browsing detected this URL as potentially harmful');
          data.matches.forEach(match => {
            warnings.push(`Threat type: ${match.threatType}`);
          });
        }
      } else {
        warnings.push('Google Safe Browsing check skipped - API key not configured');
      }
    } catch (error) {
      debug('Safe Browsing API error:', error);
      warnings.push('Unable to check against Google Safe Browsing');
    }

    const result = {
      safe: isSafe,
      warnings,
      analysis
    };
    
    // Cache the result
    urlCache.set(url, {
      timestamp: Date.now(),
      result
    });

    // Update badge
    updateBadge(isSafe);
    debug('Final result:', result);

    return result;
  } catch (error) {
    debug('Error checking URL:', error);
    return {
      safe: false,
      warnings: ['Error checking URL safety'],
      analysis: null
    };
  }
}

// Update extension badge
function updateBadge(isSafe) {
  chrome.action.setBadgeText({ text: isSafe ? '✓' : '!' });
  chrome.action.setBadgeBackgroundColor({ color: isSafe ? '#4CAF50' : '#F44336' });
} 