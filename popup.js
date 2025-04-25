// Utility function to encode URL to base64
function encodeUrlToBase64(url) {
  return btoa(unescape(encodeURIComponent(url)));
}

// List of query parameters to identify OAuth requests
const OAuthParams = [
  'client_id', 'redirect_uri', 'response_type', 'response_mode', 'scope', 
  'state', 'connection'
];

// Query the active tab in the current window
browser.tabs.query({ active: true, currentWindow: true }).then((tabs) => {
  const tabId = tabs[0].id;

  // Retrieve the tab-specific data from local storage
  browser.storage.local.get("tabData").then((data) => {
    const OAuthListElement = document.getElementById("OAuth-list");
    OAuthListElement.innerHTML = ""; // Clear previous content

    // If data exists for the current tab, display the endpoints and query parameters
    if (data.tabData && data.tabData[tabId]) {
      const tabOAuthData = data.tabData[tabId];

      // Display each unique OAuth endpoint with its query parameters
      if (tabOAuthData.OAuthEndpoints.size > 0) {
        tabOAuthData.OAuthEndpoints.forEach((endpoint) => {
          const url = new URL(endpoint);
          const li = document.createElement("li");
          li.classList.add('endpoint-item');
          
          // Add the endpoint text to the card without the "Endpoint:" prefix
          const endpointText = document.createElement("p");
          endpointText.textContent = url.origin + url.pathname;
          li.appendChild(endpointText);
          
          // Add query parameters below the endpoint
          const queryParams = Array.from(url.searchParams.entries());

          // Filter out only the OAuth-related parameters
          const OAuthQueryParams = queryParams.filter(([param, value]) => OAuthParams.includes(param));
          
          if (OAuthQueryParams.length > 0) {
            const paramList = document.createElement("ul");
            OAuthQueryParams.forEach(([param, value]) => {
              const paramItem = document.createElement("li");
              paramItem.textContent = `${param}: ${value}`;

              // Highlight the OAuth parameter in red
              paramItem.style.color = 'red';
              
              paramList.appendChild(paramItem);
            });

            li.appendChild(paramList);
          } else {
            const noParamsMessage = document.createElement("li");
            noParamsMessage.textContent = "No OAuth parameters found.";
            li.appendChild(noParamsMessage);
          }

          // Add the exploit button to each endpoint
          const exploitButton = document.createElement("button");
          exploitButton.textContent = "Exploit";
          exploitButton.style.backgroundColor = "#ff6347"; // Subtle button style
          exploitButton.style.color = "white";
          exploitButton.style.border = "none";
          exploitButton.style.padding = "5px 10px";
          exploitButton.style.cursor = "pointer";
          exploitButton.style.fontSize = "12px";
          exploitButton.style.marginTop = "10px";

          // Handle the exploit button click
          exploitButton.addEventListener('click', (event) => {
            event.stopPropagation(); // Prevent opening the endpoint in a new tab

            // Encode the modified URL to base64
            const base64Url = encodeUrlToBase64(url.href);

            // Open a new tab with the base64-encoded URL
            const newTab = window.open(`https://noauth.com/?url=${base64Url}`);
          });

          li.appendChild(exploitButton);

          OAuthListElement.appendChild(li);

          // Add click event listener to open the endpoint in a new tab
          li.addEventListener('click', () => {
            browser.tabs.create({ url: endpoint });  // Open the endpoint URL in a new tab
          });
        });
      } else {
        const li = document.createElement("li");
        li.textContent = "No OAuth flows found for this tab.";
        OAuthListElement.appendChild(li);
      }
    } else {
      const li = document.createElement("li");
      li.textContent = "No OAuth flows found for this tab.";
      OAuthListElement.appendChild(li);
    }
  }).catch((err) => {
    console.error("Error fetching tab data: ", err);
  });
});
