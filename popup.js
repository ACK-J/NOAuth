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
    configLink.textContent = result.url;
    configLink.target = "_blank"; // Open in new tab
    configLink.addEventListener('click', (evt) => {
      evt.stopPropagation(); // Prevent the card click from triggering
    });
    container.appendChild(configLink);
   
    
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
        // Make each endpoint a clickable link on the same line (no bold)
        item.innerHTML = `${key}: <a href="${result.data[key]}" target="_blank" class="endpoint-link">${result.data[key]}</a>`;
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
          <br><br>The server rejected the request with an invalid state parameter.
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

// NEW: Check redirect_uri parameter for open redirect vulnerabilities
async function checkRedirectUri(fullUrl) {
  try {
    const originalUrl = new URL(fullUrl);
    const redirectUri = originalUrl.searchParams.get('redirect_uri');
    
    if (!redirectUri) {
      const container = document.createElement("div");
      container.className = "analysis-result redirect-uri-check";
      container.innerHTML = `<h3>Redirect URI Check</h3>
        <p><span class='warning'>No redirect_uri parameter found</span></p>`;
      return container;
    }
    
    // Result container
    const container = document.createElement("div");
    container.className = "analysis-result redirect-uri-check";
    
    const title = document.createElement("h3");
    title.textContent = "Redirect URI Check";
    container.appendChild(title);
    
    const description = document.createElement("p");
    description.innerHTML = "Testing redirect_uri parameter for potential open redirect vulnerabilities.";
    container.appendChild(description);
    
    const loadingText = document.createElement("p");
    loadingText.innerHTML = "<span class='pending'>⏳ Running tests...</span>";
    container.appendChild(loadingText);
    
    try {
      // Parse the redirect_uri
      const redirectUriObj = new URL(redirectUri);
      const targetDomain = redirectUriObj.hostname;
      const targetProtocol = redirectUriObj.protocol;
      const targetPath = redirectUriObj.pathname;
      
      // Define test cases
      const testCases = [
        {
          name: "Baseline (Original)",
          uri: redirectUri,
          description: "Original redirect_uri without modifications"
        },
        {
          name: "Different Domain",
          uri: "https://example.com",
          description: "Complete domain change"
        },
        {
          name: "Subdomain Attack",
          uri: `https://${targetDomain}.attacker.com`,
          description: "Attacker domain with target as subdomain"
        },
        {
          name: "Protocol Relative",
          uri: `//attacker.com${targetPath}`,
          description: "Protocol-relative URL"
        },
        {
          name: "URL Parsing Trick",
          uri: `https://attacker.com\\@${targetDomain}${targetPath}`,
          description: "Backslash and @ symbol trick"
        },
        {
          name: "Parameter Trick",
          uri: `https://attacker.com?@${targetDomain}${targetPath}`,
          description: "Parameter and @ symbol trick"
        },
        {
          name: "HTTP Downgrade",
          uri: redirectUri.replace("https://", "http://"),
          description: "Downgrade from HTTPS to HTTP"
        },
        {
          name: "CRLF Injection",
          uri: `https://attacker.com%0d%0a${targetDomain}${targetPath}`,
          description: "CRLF injection attack"
        },
        {
          name: "Relative Path",
          uri: `${targetProtocol}//${targetDomain}${targetPath}/../redirect`,
          description: "Path traversal with ../"
        },
        {
          name: "Query Append",
          uri: `${redirectUri}?`,
          description: "Appending a query parameter separator"
        }
      ];
      
      // Run the tests
      const results = [];
      let baselineStatus = null;
      
      // Get baseline response
      for (const testCase of testCases) {
        // Create a modified URL
        const testUrl = new URL(fullUrl);
        testUrl.searchParams.set('redirect_uri', testCase.uri);
        
        try {
          // Send a request
          const response = await fetch(testUrl.toString(), {
            method: 'GET',
            credentials: 'omit',
            redirect: 'manual'
          });
          
          // Save the result
          const result = {
            name: testCase.name,
            status: response.status,
            uri: testCase.uri,
            description: testCase.description,
            matches: false
          };
          
          // Save baseline status for comparison
          if (testCase.name === "Baseline (Original)") {
            baselineStatus = response.status;
          } else if (baselineStatus !== null) {
            result.matches = (response.status === baselineStatus);
          }
          
          results.push(result);
        } catch (error) {
          results.push({
            name: testCase.name,
            status: "Error",
            uri: testCase.uri,
            description: testCase.description,
            error: error.message,
            matches: false
          });
        }
      }
      
      // Create results table
      const table = document.createElement("table");
      table.className = "redirect-uri-results";
      
      // Create table header
      const thead = document.createElement("thead");
      thead.innerHTML = `<tr>
        <th>Test Case</th>
        <th>Status</th>
        <th>Result</th>
      </tr>`;
      table.appendChild(thead);
      
      // Create table body
      const tbody = document.createElement("tbody");
      
      let vulnerabilitiesFound = false;
      
      results.forEach(result => {
        const row = document.createElement("tr");
        
        const testCase = document.createElement("td");
        testCase.innerHTML = `<strong>${result.name}</strong><br><small>${result.description}</small>`;
        row.appendChild(testCase);
        
        const status = document.createElement("td");
        status.textContent = result.status;
        row.appendChild(status);
        
        const resultCell = document.createElement("td");
        if (result.name === "Baseline (Original)") {
          resultCell.innerHTML = "<span class='info'>Baseline</span>";
        } else if (result.matches) {
          resultCell.innerHTML = "<span class='failure'>⚠️ Possible vulnerability</span>";
          vulnerabilitiesFound = true;
        } else {
          resultCell.innerHTML = "<span class='success'>✓ Properly rejected</span>";
        }
        row.appendChild(resultCell);
        
        tbody.appendChild(row);
      });
      
      table.appendChild(tbody);
      
      // Remove loading text
      container.removeChild(loadingText);
      
      // Add summary
      const summary = document.createElement("p");
      if (vulnerabilitiesFound) {
        summary.innerHTML = `<span class='failure'>⚠️ Potential open redirect vulnerabilities detected!</span>
          <br><br><strong>Vulnerability:</strong> This OAuth implementation may be vulnerable to open redirect attacks.
          <br><strong>Impact:</strong> Attackers could redirect users to malicious sites after authentication.
          <br><strong>Recommendation:</strong> Implement strict redirect_uri validation against a whitelist of allowed URIs.`;
      } else {
        summary.innerHTML = `<span class='success'>✓ No redirect_uri vulnerabilities detected</span>
          <br>The server appears to properly validate the redirect_uri parameter.`;
      }
      container.appendChild(summary);
      
      // Add the results table
      container.appendChild(table);
      
      return container;
    } catch (error) {
      loadingText.innerHTML = `<span class='failure'>Error checking redirect_uri: ${error.message}</span>`;
      return container;
    }
  } catch (error) {
    const container = document.createElement("div");
    container.className = "analysis-result";
    container.innerHTML = `<h3>Redirect URI Check</h3>
      <p><span class='failure'>Error checking redirect_uri parameter: ${error.message}</span></p>`;
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
            
            // NEW: Check for redirect_uri vulnerabilities
            const redirectUriResultElement = await checkRedirectUri(fullUrl);
            resultsContainer.appendChild(redirectUriResultElement);
            
            // Check for state parameter
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

