// SmartShield background.js — FINAL WORKING VERSION

const SERVER = "http://localhost:8080";

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status !== "loading") return;
  const url = tab.url;
  if (!url) return;
  if (url.startsWith("chrome") || url.startsWith("about") ||
      url.startsWith("file") || url.includes("blocked.html") ||
      url.includes("dashboard.html")) return;

  let domain = "";
  try { domain = new URL(url).hostname; }
  catch(e) { return; }

  // Check bypass list in storage (persistent — survives service worker sleep)
  chrome.storage.local.get(["bypassed"], function(r) {
    const list = r.bypassed || [];
    if (list.includes(domain)) return; // user ne approve kiya tha

    fetch(SERVER + "/?url=" + encodeURIComponent(url))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.status === "BLOCKED") {
          const page = chrome.runtime.getURL("blocked.html")
            + "?domain="  + encodeURIComponent(data.domain  || domain)
            + "&score="   + encodeURIComponent(data.score   || 0)
            + "&reason="  + encodeURIComponent(data.reason  || "")
            + "&origUrl=" + encodeURIComponent(url);
          chrome.tabs.update(tabId, { url: page });
          chrome.action.setBadgeText({ text: "!" });
          chrome.action.setBadgeBackgroundColor({ color: "#ff1744" });
        } else if (data.status === "HTTP_WARNING") {
          chrome.action.setBadgeText({ text: "!" });
          chrome.action.setBadgeBackgroundColor({ color: "#ffab00" });
        } else {
          chrome.action.setBadgeText({ text: "" });
        }
      })
      .catch(function() {});
  });
});