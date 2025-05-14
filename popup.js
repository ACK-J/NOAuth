// Utility to base64-encode URLs
function encodeUrlToBase64(url) {
  return btoa(unescape(encodeURIComponent(url)));
}

const OAuthParams = [
  'client_id', 'redirect_uri', 'response_type', 'response_mode',
  'scope', 'state', 'connection'
];

// Check for OpenID configuration
async function checkOpenIDConfiguration(domain) {
  const configUrl = `${domain}/.well-known/openid-configuration`;
  try {
    const response = await fetch(configUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json'
      }
    });
    
    if (response.ok) {
      return {
        exists: true,
        data: await response.json(),
        url: configUrl
      };
    } else {
      return {
        exists: false,
        status: response.status,
        url: configUrl
      };
    }
  } catch (error) {
    return {
      exists: false,
      error: error.message,
      url: configUrl
    };
  }
}

// Create result element for OpenID configuration
function createOpenIDResultElement(result) {
  const container = document.createElement("div");
  container.className = "analysis-result openid-check";
  
  const title = document.createElement("h3");
  title.textContent = "OpenID Configuration Check";
  container.appendChild(title);
  
  const resultText = document.createElement("p");
  if (result.exists) {
    resultText.innerHTML = "<span class='success'>✓ Found OpenID Configuration</span>";
    container.appendChild(resultText);
    
    // Add clickable link to the OpenID configuration
    const configLink = document.createElement("a");
    configLink.className = "config-link";
    configLink.href = result.url; // We'll pass this in the result object
    configLink.textContent = "View raw configuration";
    configLink.target = "_blank"; // Open in new tab
    configLink.addEventListener('click', (evt) => {
      evt.stopPropagation(); // Prevent the card click from triggering
    });
    container.appendChild(configLink);
    
    // Line break after the link
    container.appendChild(document.createElement("br"));
    
    // Add configuration details
    const configDetails = document.createElement("div");
    configDetails.className = "config-details";
    
    const toggleButton = document.createElement("button");
    toggleButton.className = "toggle-button";
    toggleButton.textContent = "Show Details";
    toggleButton.addEventListener('click', () => {
      const isVisible = configDetails.style.display !== "none";
      configDetails.style.display = isVisible ? "none" : "block";
      toggleButton.textContent = isVisible ? "Show Details" : "Hide Details";
    });
    container.appendChild(toggleButton);
    
    // Pre-formatted JSON container
    const jsonContainer = document.createElement("pre");
    jsonContainer.className = "json-container";
    jsonContainer.textContent = JSON.stringify(result.data, null, 2);
    configDetails.appendChild(jsonContainer);
    
    // Initially hide the details
    configDetails.style.display = "none";
    container.appendChild(configDetails);
    
    // Extract and display key endpoints
    const keyEndpoints = document.createElement("ul");
    keyEndpoints.className = "key-endpoints";
    
    const importantKeys = [
      'authorization_endpoint', 
      'token_endpoint', 
      'userinfo_endpoint', 
      'jwks_uri', 
      'registration_endpoint'
    ];
    
    importantKeys.forEach(key => {
      if (result.data[key]) {
        const item = document.createElement("li");
        // Make each endpoint a clickable link
        item.innerHTML = `<strong>${key}:</strong> <a href="${result.data[key]}" target="_blank" class="endpoint-link">${result.data[key]}</a>`;
        item.querySelector('a').addEventListener('click', (evt) => {
          evt.stopPropagation(); // Prevent the card click from triggering
        });
        keyEndpoints.appendChild(item);
      }
    });
    
    if (keyEndpoints.children.length > 0) {
      const endpointsTitle = document.createElement("h4");
      endpointsTitle.textContent = "Key Endpoints:";
      container.appendChild(endpointsTitle);
      container.appendChild(keyEndpoints);
    }
    
  } else {
    resultText.innerHTML = "<span class='failure'>✗ No OpenID Configuration Found</span>";
    
    if (result.status) {
      resultText.innerHTML += `<br>Status: ${result.status}`;
    }
    
    if (result.error) {
      resultText.innerHTML += `<br>Error: ${result.error}`;
    }
    
    container.appendChild(resultText);
  }
  
  return container;
}

// NEW: Check state parameter presence and validation
async function checkStateParameter(fullUrl) {
  try {
    const url = new URL(fullUrl);
    const stateParam = url.searchParams.get('state');
    
    // Result container
    const container = document.createElement("div");
    container.className = "analysis-result state-check";
    
    const title = document.createElement("h3");
    title.textContent = "State Parameter Check";
    container.appendChild(title);
    
    const resultText = document.createElement("p");
    
    // Check if state parameter exists
    if (!stateParam) {
      resultText.innerHTML = `<span class='failure'>⚠️ No State Parameter Found</span>
        <br><br><strong>Vulnerability:</strong> This OAuth flow may be vulnerable to Cross-Site Request Forgery (CSRF).
        <br><strong>Impact:</strong> Attackers could perform forced OAuth profile linking or potentially exploit self-XSS vulnerabilities.
        <br><strong>Recommendation:</strong> Implement a state parameter to prevent CSRF attacks.`;
      container.appendChild(resultText);
      return container;
    }
    
    // Create a modified URL with state parameter removed
    const modifiedUrl = new URL(fullUrl);
    modifiedUrl.searchParams.delete('state'); // Remove state parameter
    
    resultText.innerHTML = `<span class='pending'>⏳ Testing state parameter validation...</span>`;
    container.appendChild(resultText);
    
    try {
      // Send a request with state parameter removed
      const response = await fetch(modifiedUrl.toString(), {
        method: 'GET',
        credentials: 'omit', // Don't send cookies
        redirect: 'manual' // Don't follow redirects
      });
      
      // Check the response
      if (response.status === 200) {
        resultText.innerHTML = `<span class='failure'>⚠️ State Parameter May Not Be Validated</span>
          <br><br><strong>Vulnerability:</strong> The server accepted a request without the state parameter.
          <br><strong>Impact:</strong> This OAuth flow may be vulnerable to CSRF attacks.
          <br><strong>Recommendation:</strong> Ensure the state parameter is properly validated server-side.`;
      } else {
        resultText.innerHTML = `<span class='success'>✓ State Parameter Appears to be Validated</span>
          <br><br>The server rejected the request with an invalid state parameter (Status: ${response.status}).
          <br>This suggests proper CSRF protection is in place.`;
      }
    } catch (error) {
      resultText.innerHTML = `<span class='warning'>⚠️ Could not verify state parameter validation</span>
        <br><br>Error: ${error.message}
        <br><strong>Recommendation:</strong> Manually verify that the state parameter is validated server-side.`;
    }
    
    return container;
  } catch (error) {
    const container = document.createElement("div");
    container.className = "analysis-result";
    container.innerHTML = `<h3>State Parameter Check</h3>
      <p><span class='failure'>Error checking state parameter: ${error.message}</span></p>`;
    return container;
  }
}

// Toggle analysis results visibility
function toggleAnalysisResults(parentElement, button) {
  const resultsContainer = parentElement.querySelector('.analysis-results');
  if (resultsContainer) {
    // Toggle visibility of existing results
    const isVisible = resultsContainer.style.display !== "none";
    resultsContainer.style.display = isVisible ? "none" : "block";
    button.textContent = isVisible ? "Analyze" : "Hide Analysis";
  }
}

// Populate the list
function displayGlobalOAuthEndpoints() {
  browser.storage.local.get("oauthData")
    .then((data) => {
      const listEl = document.getElementById("OAuth-list");
      listEl.innerHTML = "";

      const { endpoints = [], counter = 0 } = data.oauthData || {};
      document.getElementById("counter-display").textContent =
        `Total OAuth Endpoints Detected: ${counter}`;

      if (endpoints.length === 0) {
        const empty = document.createElement("li");
        empty.textContent = "No OAuth flows detected yet.";
        empty.classList.add('no-flows');
        listEl.appendChild(empty);
        return;
      }

      endpoints.forEach((fullUrl) => {
        try {
          const url = new URL(fullUrl);
          const li = document.createElement("li");
          li.className = 'endpoint-item';

          // URL
          const p = document.createElement("p");
          p.className = 'endpoint-url';
          p.textContent = url.origin + url.pathname;
          li.appendChild(p);

          // Params
          const params = Array.from(url.searchParams.entries())
            .filter(([k]) => OAuthParams.includes(k));
          if (params.length) {
            const ul = document.createElement("ul");
            ul.className = 'param-list';
            params.forEach(([key, val]) => {
              const item = document.createElement("li");
              item.className = 'param-item';
              item.style.color = 'red';
              item.textContent = `${key}: ${val}`;
              ul.appendChild(item);
            });
            li.appendChild(ul);
          } else {
            const none = document.createElement("p");
            none.className = 'no-params';
            none.textContent = "No OAuth parameters found.";
            li.appendChild(none);
          }

          // Analyze button
          const btn = document.createElement("button");
          btn.className = 'analyze-button';
          btn.textContent = "Analyze";
          btn.addEventListener('click', async (evt) => {
            evt.stopPropagation();
            
            // Find existing analysis results container
            let resultsContainer = li.querySelector('.analysis-results');
            
            // If results already exist, just toggle visibility
            if (resultsContainer) {
              toggleAnalysisResults(li, btn);
              return;
            }
            
            // Show loading state
            btn.textContent = "Analyzing...";
            btn.disabled = true;
            
            // Create results container
            resultsContainer = document.createElement("div");
            resultsContainer.className = "analysis-results";
            
            // Check for state parameter first (NEW)
            const stateResultElement = await checkStateParameter(fullUrl);
            resultsContainer.appendChild(stateResultElement);
            
            // Check for OpenID configuration
            const openIDResult = await checkOpenIDConfiguration(url.origin);
            const openIDResultElement = createOpenIDResultElement(openIDResult);
            resultsContainer.appendChild(openIDResultElement);
            
            // Append results to card
            li.appendChild(resultsContainer);
            
            // Update button state
            btn.textContent = "Hide Analysis";
            btn.disabled = false;
          });
          li.appendChild(btn);

          // Clicking the card opens the full URL
          li.addEventListener('click', (evt) => {
            // Only open the URL if the click wasn't on a button or analysis result
            if (!evt.target.closest('button') && 
                !evt.target.closest('.analysis-results')) {
              browser.tabs.create({ url: fullUrl });
            }
          });

          listEl.appendChild(li);
        } catch {
          const bad = document.createElement("li");
          bad.textContent = "Invalid OAuth URL encountered";
          listEl.appendChild(bad);
        }
      });
    })
    .catch((err) => {
      console.error("Error loading OAuth data:", err);
      const listEl = document.getElementById("OAuth-list");
      listEl.innerHTML = "";
      const errLi = document.createElement("li");
      errLi.style.color = "red";
      errLi.textContent = "Error loading OAuth data. Please try again.";
      listEl.appendChild(errLi);
    });
}

document.addEventListener('DOMContentLoaded', () => {
  // Attach clear button listener exactly once
  document.getElementById("clear-button").addEventListener('click', () => {
    browser.runtime.sendMessage({ action: "clearOAuthData" })
      .then(resp => { if (resp.success) displayGlobalOAuthEndpoints(); })
      .catch(console.error);
  });

  // Initial draw
  displayGlobalOAuthEndpoints();
});

