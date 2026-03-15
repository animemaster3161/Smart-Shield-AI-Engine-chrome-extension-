// SmartShield popup.js v4.0
const SERVER = "http://localhost:8080/";

const card         = document.getElementById('statusCard');
const labelEl      = document.getElementById('statusLabel');
const descEl       = document.getElementById('statusDesc');
const scoreRow     = document.getElementById('scoreRow');
const scoreFill    = document.getElementById('scoreFill');
const scoreVal     = document.getElementById('scoreVal');
const urlVal       = document.getElementById('urlVal');
const safeCount    = document.getElementById('safeCount');
const blockedCount = document.getElementById('blockedCount');
const serverStat   = document.getElementById('serverStatus');
const serverTxt    = document.getElementById('serverStatusTxt');

// Load stats
chrome.storage.local.get(['safe_count','blocked_count'], result => {
  safeCount.textContent    = result.safe_count    || 0;
  blockedCount.textContent = result.blocked_count || 0;
});

// Check current tab
chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
  const url = tabs[0]?.url || '';
  urlVal.textContent = url.length > 42 ? url.slice(0, 42) + '…' : url;

  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    setStatus('safe', 'Browser Page', 'Internal Chrome page.', 0);
    return;
  }

  fetch(SERVER + "?url=" + encodeURIComponent(url), { signal: AbortSignal.timeout(3000) })
    .then(r => r.json())
    .then(data => {
      serverStat.className = 'server-status online';
      serverTxt.textContent = 'ENGINE ONLINE';
      const score = parseFloat(data.score) || 0;

      if (data.status === 'BLOCKED') {
        setStatus('danger', 'THREAT DETECTED', 'Malicious site. Do not proceed.', score);
      } else if (data.status === 'HTTP_WARNING') {
        setStatus('http', 'Insecure HTTP', 'No encryption (HTTP). Data can be intercepted.', score);
      } else {
        setStatus('safe', 'Site is Safe', 'No threats detected.', score);
      }
    })
    .catch(() => {
      serverStat.className = 'server-status offline-txt';
      serverTxt.textContent = 'ENGINE OFFLINE';
      serverTxt.style.color = '#ffab00';
      setStatus('offline', 'Server Offline', 'Start smartshield_server.exe', 0);
    });
});

function setStatus(type, label, desc, score) {
  card.className = 'status-card ' + (type === 'http' ? 'http-warn' : type);
  labelEl.textContent = label;
  descEl.textContent  = desc;
  if (type === 'http') {
    card.style.background    = 'rgba(255,171,0,0.07)';
    card.style.borderColor   = 'rgba(255,171,0,0.3)';
    labelEl.style.color      = '#ffab00';
    document.querySelector('.status-dot').style.background = '#ffab00';
    document.querySelector('.status-dot').style.boxShadow  = '0 0 8px #ffab00';
    document.querySelector('.status-dot').style.animation  = 'none';
  }
  if (score > 0) {
    scoreRow.style.display = 'flex';
    const pct = Math.min((score / 20) * 100, 100);
    setTimeout(() => { scoreFill.style.width = pct + '%'; }, 100);
    scoreVal.textContent = 'Score: ' + score.toFixed(1);
  }
}

// Dashboard button
document.getElementById('dashBtn').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
});