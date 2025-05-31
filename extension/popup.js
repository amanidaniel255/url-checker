document.addEventListener('DOMContentLoaded', async () => {
  const apiKeyInput = document.getElementById('apiKey');
  const saveButton = document.getElementById('saveKey');
  const statusDiv = document.getElementById('status');

  // Load saved API key
  const { apiKey } = await chrome.storage.sync.get('apiKey');
  if (apiKey) {
    apiKeyInput.value = apiKey;
  }

  // Save API key
  saveButton.addEventListener('click', async () => {
    const newApiKey = apiKeyInput.value.trim();
    
    if (!newApiKey) {
      statusDiv.textContent = 'Please enter an API key';
      statusDiv.style.color = '#dc2626';
      return;
    }

    try {
      // Test the API key
      const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${newApiKey}`, {
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
            threatTypes: ['MALWARE'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url: 'http://example.com' }]
          }
        })
      });

      if (response.ok) {
        await chrome.storage.sync.set({ apiKey: newApiKey });
        statusDiv.textContent = 'API key saved successfully!';
        statusDiv.style.color = '#059669';
      } else {
        throw new Error('Invalid API key');
      }
    } catch (error) {
      statusDiv.textContent = 'Invalid API key. Please check and try again.';
      statusDiv.style.color = '#dc2626';
    }
  });
}); 