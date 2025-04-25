// List of query parameters to identify OAuth requests
const OAuthParams = [
  'client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope',
  'state', 'connection'
];

// Initialize OAuth data globally if needed
async function initializeGlobalData() {
  try {
    const data = await browser.storage.local.get("oauthData");
    if (!data.oauthData) {
      await browser.storage.local.set({
        oauthData: { endpoints: [], counter: 0 }
      });
    }
  } catch (error) {
    console.error('Error initializing global OAuth data:', error);
  }
}

// Clear all OAuth data
async function clearOAuthData() {
  try {
    await browser.storage.local.set({ oauthData: { endpoints: [], counter: 0 } });
    const tabs = await browser.tabs.query({});
    for (const tab of tabs) {
      browser.browserAction.setBadgeText({ text: "", tabId: tab.id });
    }
    updateGlobalBadge();
  } catch (error) {
    console.error('Error clearing OAuth data:', error);
  }
}

// Helper: unique check
function arrayToSet(array) {
  return new Set(array || []);
}

// Update the global badge (total unique endpoints found)
async function updateGlobalBadge() {
  try {
    const data = await browser.storage.local.get("oauthData");
    const count = (data.oauthData && data.oauthData.counter) || 0;
    const text = count > 0 ? count.toString() : "";
    browser.browserAction.setBadgeBackgroundColor({ color: "#C41E3A" });

    const tabs = await browser.tabs.query({});
    for (const tab of tabs) {
      browser.browserAction.setBadgeText({ text, tabId: tab.id });
    }
  } catch (error) {
    console.error('Error updating global badge:', error);
  }
}

// Listen for web requests
browser.webRequest.onBeforeRequest.addListener(
  async (details) => {
    if (details.tabId === -1) return;

    let url;
    try {
      url = new URL(details.url);
    } catch {
      return;
    }

    // **Only** log if redirect_uri is present
    const isOAuth = url.searchParams.has('redirect_uri');
    if (!isOAuth) return;

    try {
      const data = await browser.storage.local.get("oauthData");
      const oauthData = data.oauthData || { endpoints: [], counter: 0 };
      const endpointsSet = arrayToSet(oauthData.endpoints);

      if (!endpointsSet.has(details.url)) {
        oauthData.endpoints.push(details.url);
        oauthData.counter++;
        await browser.storage.local.set({ oauthData });
        updateGlobalBadge();
      }
    } catch (error) {
      console.error("Error processing OAuth request:", error);
    }
  },
  { urls: ["<all_urls>"] },
  []
);

// Keep badge up to date
browser.tabs.onActivated.addListener(updateGlobalBadge);
browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete') {
    updateGlobalBadge();
  }
});

// Handle “Clear” from popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "clearOAuthData") {
    clearOAuthData()
      .then(() => sendResponse({ success: true }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
});

initializeGlobalData().then(updateGlobalBadge);

