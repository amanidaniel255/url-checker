// Debug mode
const DEBUG = true;
function debug(...args) {
  if (DEBUG) console.log('[Peruzi Salama]:', ...args);
}

// Check if we're in a Chrome extension context
const isExtensionContext = !!(window.chrome && chrome.runtime && chrome.runtime.sendMessage);
debug('Extension context:', isExtensionContext);

// Create tooltip element
const tooltip = document.createElement('div');
tooltip.style.cssText = `
  position: fixed;
  padding: 10px;
  background: white;
  border: 1px solid #ccc;
  border-radius: 4px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.2);
  z-index: 10000000;
  max-width: 300px;
  display: none;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  pointer-events: none;
`;
document.body.appendChild(tooltip);

// Track hover state
let hoverTimeout;
let currentLink;
let isTooltipVisible = false;

// Function to check URL safety
async function checkUrlSafety(url) {
  if (!isExtensionContext) {
    debug('Not in extension context, cannot check URL');
    return {
      safe: false,
      warnings: ['Extension context not available'],
      analysis: null
    };
  }

  try {
    debug('Sending check request for:', url);
    return await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        action: 'checkUrl',
        url: url
      }, response => {
        if (chrome.runtime.lastError) {
          debug('Runtime error:', chrome.runtime.lastError);
          reject(chrome.runtime.lastError);
        } else {
          debug('Received response:', response);
          resolve(response);
        }
      });
    });
  } catch (error) {
    debug('Error checking URL:', error);
    return {
      safe: false,
      warnings: ['Error checking URL safety'],
      analysis: null
    };
  }
}

// Handle link hover
function handleLinkHover(event) {
  const link = event.target.closest('a');
  if (!link || !link.href) {
    return;
  }

  debug('Hovering over link:', link.href);
  currentLink = link;
  const url = link.href;

  // Clear any existing timeout
  clearTimeout(hoverTimeout);

  // Set new timeout
  hoverTimeout = setTimeout(async () => {
    try {
      // Position tooltip near the link
      const rect = link.getBoundingClientRect();
      const tooltipX = Math.min(rect.right + 10, window.innerWidth - 310);
      const tooltipY = Math.min(rect.top, window.innerHeight - 200);

      tooltip.style.left = `${tooltipX}px`;
      tooltip.style.top = `${tooltipY}px`;

      // Show loading state
      tooltip.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px;">
          <div style="width: 16px; height: 16px; border: 2px solid #2563eb; border-top-color: transparent; border-radius: 50%; animation: spin 1s linear infinite;"></div>
          <span>Checking link safety...</span>
        </div>
        <style>
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
        </style>
      `;
      tooltip.style.display = 'block';
      isTooltipVisible = true;

      const result = await checkUrlSafety(url);
      debug('Check result:', result);

      // Only update if this is still the current link
      if (currentLink === link && isTooltipVisible) {
        updateTooltip(result);
      }
    } catch (error) {
      debug('Error in hover handler:', error);
      if (currentLink === link && isTooltipVisible) {
        tooltip.innerHTML = `
          <div style="color: #dc2626;">
            <svg style="width: 20px; height: 20px; margin-bottom: 4px;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>Error checking link safety</div>
          </div>
        `;
      }
    }
  }, 300);
}

// Update tooltip content
function updateTooltip(result) {
  debug('Updating tooltip with result:', result);
  const backgroundColor = result.safe ? '#f0fdf4' : '#fef2f2';
  const borderColor = result.safe ? '#86efac' : '#fecaca';
  const textColor = result.safe ? '#166534' : '#991b1b';

  tooltip.style.backgroundColor = backgroundColor;
  tooltip.style.borderColor = borderColor;
  tooltip.style.color = textColor;

  let content = `
    <div style="margin-bottom: 8px; font-weight: bold; display: flex; align-items: center; gap: 6px;">
      ${result.safe ? 
        '<svg style="width: 20px; height: 20px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>' :
        '<svg style="width: 20px; height: 20px;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>'
      }
      ${result.safe ? 'Safe Link' : '⚠️ Warning'}
    </div>
  `;

  if (result.warnings && result.warnings.length > 0) {
    content += `
      <div style="color: #666; font-size: 0.9em;">
        ${result.warnings.map(w => `• ${w}`).join('<br>')}
      </div>
    `;
  }

  if (result.analysis) {
    content += `
      <div style="margin-top: 8px; font-size: 0.8em; color: #666;">
        ${result.analysis.hasSSL ? '🔒 Secure connection' : '⚠️ Insecure connection'}<br>
        ${result.analysis.isWellKnownTLD ? '✓ Known domain type' : '⚠️ Uncommon domain type'}
      </div>
    `;
  }

  tooltip.innerHTML = content;
}

// Handle mouse leave
function handleMouseLeave(event) {
  const link = event.target.closest('a');
  if (!link) return;

  debug('Mouse left link');
  clearTimeout(hoverTimeout);
  tooltip.style.display = 'none';
  isTooltipVisible = false;
  currentLink = null;
}

// Add event listeners
debug('Adding event listeners');
document.addEventListener('mouseover', handleLinkHover);
document.addEventListener('mouseout', handleMouseLeave);

// Handle pasted URLs
document.addEventListener('paste', async (event) => {
  if (!isExtensionContext) {
    debug('Not in extension context, cannot check pasted URL');
    return;
  }

  // Get the active element
  const activeElement = document.activeElement;
  if (!activeElement || !['input', 'textarea'].includes(activeElement.tagName.toLowerCase())) {
    return; // Only process paste events in input/textarea elements
  }

  const pastedText = event.clipboardData.getData('text');
  debug('Paste detected:', pastedText);
  
  // More lenient URL validation
  if (pastedText.match(/^(https?:\/\/|www\.)/i)) {
    debug('URL detected in paste, checking...');
    try {
      const result = await checkUrlSafety(
        pastedText.startsWith('http') ? pastedText : `http://${pastedText}`
      );
      
      if (!result.safe) {
        event.preventDefault();
        const warningMessage = `⚠️ Warning: The URL you're trying to paste may be unsafe.\n\nRisks detected:\n${result.warnings.join('\n')}`;
        debug('Showing warning for unsafe URL:', warningMessage);
        
        // Create a more visible warning
        const warningDiv = document.createElement('div');
        warningDiv.style.cssText = `
          position: fixed;
          top: 20px;
          left: 50%;
          transform: translateX(-50%);
          background: #fee2e2;
          border: 2px solid #ef4444;
          border-radius: 8px;
          padding: 16px;
          max-width: 400px;
          z-index: 10000000;
          box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        `;
        
        warningDiv.innerHTML = `
          <div style="display: flex; align-items: start; gap: 12px;">
            <svg style="width: 24px; height: 24px; color: #dc2626; flex-shrink: 0;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <div style="font-weight: bold; color: #991b1b; margin-bottom: 8px;">Unsafe URL Detected</div>
              <div style="color: #7f1d1d;">${result.warnings.map(w => `• ${w}`).join('<br>')}</div>
            </div>
          </div>
        `;
        
        document.body.appendChild(warningDiv);
        setTimeout(() => warningDiv.remove(), 5000);
      }
    } catch (error) {
      debug('Error checking pasted URL:', error);
    }
  }
}); 