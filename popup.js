// Utility to base64-encode URLs
function encodeUrlToBase64(url) {
  return btoa(unescape(encodeURIComponent(url)));
}

const OAuthParams = [
  'client_id', 'redirect_uri', 'response_type', 'response_mode',
  'scope', 'state', 'connection'
];

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
          btn.textContent = "Analyze Vulnerabilities";
          btn.addEventListener('click', (evt) => {
            evt.stopPropagation();
            const encoded = encodeUrlToBase64(url.href);
            browser.tabs.create({ url: `https://noauth.com/?url=${encoded}` });
          });
          li.appendChild(btn);

          // Clicking the card opens the full URL
          li.addEventListener('click', () => {
            browser.tabs.create({ url: fullUrl });
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

