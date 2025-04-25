// List of query parameters to identify OAuth requests
const OAuthParams = [
  'client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 
  'state', 'connection'
];

// Clear all data in local storage on extension load (first time or refresh)
async function clearLocalStorage() {
  try {
    // Clear all data in local storage
    await browser.storage.local.clear();
    console.log('Local storage cleared.');
  } catch (error) {
    console.error('Error clearing local storage:', error);
  }
}

// Listen for web requests
browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    // Get the tab ID of the request
    const tabId = details.tabId;

    // Parse the URL of the request
    const url = new URL(details.url);

    // Check if the URL has any of the specified OAuth callback parameters
    const isOAuth = OAuthParams.some(param => url.searchParams.has(param));

    if (isOAuth) {
      // Retrieve the current tab data from local storage
      browser.storage.local.get("tabData").then((data) => {
        let tabData = data.tabData || {};

        // Ensure there is an entry for the tab
        if (!tabData[tabId]) {
          tabData[tabId] = {
            OAuthCounter: 0,
            OAuthEndpoints: new Set()
          };
        }

        // Extract the base URL (excluding query params) for the endpoint
        const baseUrl = url.origin + url.pathname + url.search;

        // Add the endpoint only if it is unique (Set ensures uniqueness)
        if (!tabData[tabId].OAuthEndpoints.has(baseUrl)) {
          tabData[tabId].OAuthEndpoints.add(baseUrl);

          // Increment the counter for OAuth requests on this tab
          tabData[tabId].OAuthCounter++;

          // Update the badge for the current tab
          const badgeText = tabData[tabId].OAuthCounter > 0 ? tabData[tabId].OAuthCounter.toString() : "";
          browser.browserAction.setBadgeBackgroundColor({ color: "#C41E3A" });
          browser.browserAction.setBadgeText({ text: badgeText, tabId });

          // Store updated tab data in local storage
          browser.storage.local.set({ tabData });
        }
      }).catch((err) => {
        console.error("Error fetching or setting tab data: ", err);
      });
    }
  },
  { urls: ["<all_urls>"] }
);

// Update the badge when a tab is switched or reloaded
browser.tabs.onActivated.addListener((activeInfo) => {
  const tabId = activeInfo.tabId;

  // Retrieve the tab data from local storage and update the badge
  browser.storage.local.get("tabData").then((data) => {
    const tabData = data.tabData || {};
    const badgeText = tabData[tabId] ? tabData[tabId].OAuthCounter.toString() : "";
    browser.browserAction.setBadgeText({ text: badgeText, tabId });
  }).catch((err) => {
    console.error("Error fetching tab data: ", err);
  });
});

// Update the badge when the tab is updated (loaded/reloaded)
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    // Retrieve the tab data from local storage and update the badge
    browser.storage.local.get("tabData").then((data) => {
      const tabData = data.tabData || {};
      const badgeText = tabData[tabId] ? tabData[tabId].OAuthCounter.toString() : "";
      browser.browserAction.setBadgeText({ text: badgeText, tabId });
    }).catch((err) => {
      console.error("Error fetching tab data: ", err);
    });
  }
});

clearLocalStorage();
