document.addEventListener('DOMContentLoaded', () => {
    // ------------------------------------------
    //  CONSTANTS
    // ------------------------------------------
    const API = 'http://localhost:8080';
    const REFRESH_MS = 3000;

    // ------------------------------------------
    //  CLOCK
    // ------------------------------------------
    function updateClock() {
        document.getElementById('clockDisplay').textContent =
            new Date().toLocaleTimeString('en-IN', {hour12:false});
    }
    updateClock();
    setInterval(updateClock, 1000);

    // ------------------------------------------
    //  GAUGE CANVAS
    // ------------------------------------------
    function drawGauge(pct) {
        const canvas = document.getElementById('gaugeCanvas');
        const ctx    = canvas.getContext('2d');
        const W = 180, H = 100;
        ctx.clearRect(0, 0, W, H);

        const cx = W / 2, cy = H - 10;
        const r  = 80;
        const startAngle = Math.PI;
        const endAngle   = 2 * Math.PI;

        // Background arc
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, endAngle);
        ctx.lineWidth = 14;
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        ctx.lineCap = 'round';
        ctx.stroke();

        // Color gradient arc
        const grad = ctx.createLinearGradient(0, cy, W, cy);
        grad.addColorStop(0,    '#00e676');
        grad.addColorStop(0.45, '#ffab00');
        grad.addColorStop(1,    '#ff1744');

        const fillEnd = startAngle + (endAngle - startAngle) * Math.min(pct / 100, 1);
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, fillEnd);
        ctx.strokeStyle = grad;
        ctx.lineWidth   = 14;
        ctx.lineCap     = 'round';
        ctx.stroke();

        // Needle
        const angle = startAngle + (endAngle - startAngle) * Math.min(pct / 100, 1);
        const nx = cx + (r - 7) * Math.cos(angle);
        const ny = cy + (r - 7) * Math.sin(angle);
        ctx.beginPath();
        ctx.arc(nx, ny, 5, 0, 2 * Math.PI);
        ctx.fillStyle = '#fff';
        ctx.shadowColor = '#fff';
        ctx.shadowBlur  = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
    }
    drawGauge(0);

    // ------------------------------------------
    //  ACTIVITY CHART (simple bar chart on canvas)
    // ------------------------------------------
    let activityData = []; // array of {status, score}

    function drawActivity() {
        const canvas = document.getElementById('activityChart');
        const W = canvas.offsetWidth || 600;
        const H = 140;
        canvas.width  = W;
        canvas.height = H;
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, W, H);

        if (activityData.length === 0) {
            ctx.fillStyle = 'rgba(255,255,255,0.1)';
            ctx.font = '11px Share Tech Mono';
            ctx.textAlign = 'center';
            ctx.fillText('No activity yet', W/2, H/2);
            return;
        }

        const last20 = activityData.slice(0, 20).reverse();
        const barW   = Math.floor((W - 20) / 20) - 2;
        const maxScore = Math.max(...last20.map(d => d.score), 15);

        // Grid lines
        ctx.strokeStyle = 'rgba(255,255,255,0.04)';
        ctx.lineWidth = 1;
        for (let i = 0; i <= 4; i++) {
            const y = 10 + (H - 30) * (i / 4);
            ctx.beginPath(); ctx.moveTo(10, y); ctx.lineTo(W - 10, y); ctx.stroke();
        }

        last20.forEach((d, i) => {
            const x = 10 + i * ((W - 20) / 20);
            const barH = Math.max(4, ((d.score / maxScore) * (H - 40)));
            const y = H - 20 - barH;

            let color = '#00e676';
            if (d.status === 'THREAT_DETECTED' || d.status === 'BLACKLISTED') color = '#ff1744';
            else if (d.status === 'HTTP_WARNING') color = '#ffab00';
            else if (d.status === 'WHITELISTED') color = '#00e5ff';

            // Glow effect for threats
            if (d.status === 'THREAT_DETECTED') {
                ctx.shadowColor = '#ff1744';
                ctx.shadowBlur  = 10;
            }

            ctx.fillStyle = color + '99';
            ctx.fillRect(x, y, barW, barH);

            ctx.fillStyle = color;
            ctx.fillRect(x, y, barW, 2);

            ctx.shadowBlur = 0;
        });
    }

    // ------------------------------------------
    //  STATUS PILL HELPER
    // ------------------------------------------
    function statusPill(s) {
        const map = {
            'SAFE_VISIT':      ['pill-safe',    'SAFE'],
            'WHITELISTED':     ['pill-white',   'TRUSTED'],
            'THREAT_DETECTED': ['pill-threat',  'BLOCKED'],
            'BLACKLISTED':     ['pill-blocked', 'BLACKLISTED'],
            'HTTP_WARNING':    ['pill-http',    'HTTP'],
        };
        const [cls, label] = map[s] || ['pill-safe', s];
        return `<span class="pill ${cls}">${label}</span>`;
    }

    // ------------------------------------------
    //  FETCH & RENDER
    // ------------------------------------------
    function setOnline(online) {
        const pill = document.getElementById('engineStatus');
        const overlay = document.getElementById('offlineOverlay');
        if (online) {
            pill.className = 'live-pill';
            pill.innerHTML = '<div class="live-dot"></div>ENGINE LIVE';
            overlay.classList.remove('show');
        } else {
            pill.className = 'offline-pill';
            pill.innerHTML = '? OFFLINE';
            overlay.classList.add('show');
        }
    }

    async function fetchStats() {
        const r = await fetch(`${API}/stats`, {});
        if (!r.ok) throw new Error('stats ' + r.status);
        return r.json();
    }

    async function fetchLogs() {
        const r = await fetch(`${API}/logs`, {});
        if (!r.ok) throw new Error('logs ' + r.status);
        return r.json();
    }

    async function fetchBlacklist() {
        const r = await fetch(`${API}/blacklist`, {});
        if (!r.ok) throw new Error('bl ' + r.status);
        return r.json();
    }

    // Track last values to force update even if animateNumber skips
    const lastVals = {};
    function animateNumber(el, target) {
        const id = el.id;
        // Force text update even if value same (handles first-load edge case)
        if (lastVals[id] === target) return;
        lastVals[id] = target;

        const cur = parseInt(el.textContent.replace(/,/g, '')) || 0;
        if (cur === target) { el.textContent = target.toLocaleString(); return; }

        const duration = 600;
        const steps = 20;
        const diff = target - cur;
        let step = 0;
        const interval = setInterval(() => {
            step++;
            const val = Math.round(cur + diff * (step / steps));
            el.textContent = val.toLocaleString();
            if (step >= steps) {
                el.textContent = target.toLocaleString();
                clearInterval(interval);
            }
        }, duration / steps);
    }

    function renderStats(data) {
        animateNumber(document.getElementById('sc-total'),   data.total        || 0);
        animateNumber(document.getElementById('sc-safe'),    data.safe         || 0);
        animateNumber(document.getElementById('sc-blocked'), data.blocked      || 0);
        animateNumber(document.getElementById('sc-http'),    data.http_warnings|| 0);
        animateNumber(document.getElementById('sc-bl'),      data.blacklist_size||0);

        const total = data.total || 0;
        const blocked = data.blocked || 0;
        const pct = total > 0 ? Math.min(Math.round((blocked / total) * 100), 100) : 0;
        document.getElementById('threatPct').textContent = pct + '%';
        drawGauge(pct);

        const lbl = document.getElementById('threatLabel');
        if (pct < 10)      { lbl.textContent='LOW';    lbl.className='tl-badge tl-low'; }
        else if (pct < 30) { lbl.textContent='MEDIUM'; lbl.className='tl-badge tl-medium'; }
        else               { lbl.textContent='HIGH';   lbl.className='tl-badge tl-high'; }
    }

    function renderLogs(logs) {
        document.getElementById('logCount').textContent = logs.length + ' EVENTS';
        activityData = logs;
        // Force canvas to correct size before drawing
        const canvas = document.getElementById('activityChart');
        canvas.width  = canvas.parentElement.offsetWidth || 600;
        canvas.height = 140;
        drawActivity();

        const tbody = document.getElementById('logBody');
        if (!logs || logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#3d4a5c;padding:24px;">No events yet...</td></tr>';
            return;
        }

        tbody.innerHTML = logs.slice(0, 60).map(e => {
            const timePart = e.ts ? e.ts.split(' ').slice(-1)[0] : '—';
            const score = parseFloat(e.score) || 0;
            return `<tr>
      <td class="td-time">${timePart}</td>
      <td class="td-domain" title="${e.domain||''}">${e.domain || '—'}</td>
      <td>${statusPill(e.status)}</td>
      <td style="color:${score>9?'#ff1744':score>4?'#ffab00':'#00e676'}">${score.toFixed(1)}</td>
      <td class="td-reason" title="${e.reason||''}">${e.reason || '—'}</td>
    </tr>`;
        }).join('');
    }

    function renderBlacklist(list) {
        document.getElementById('blCount').textContent = list.length;
        const el = document.getElementById('blList');
        if (!list || list.length === 0) {
            el.innerHTML = '<div class="bl-empty">No blocked domains yet</div>';
            return;
        }
        el.innerHTML = list.map(d =>
            `<div class="bl-item">
      <span class="bl-icon">?</span>
      <span class="bl-domain" title="${d}">${d}</span>
    </div>`
        ).join('');
    }

    // ------------------------------------------
    //  STATUS BAR (bottom of page)
    // ------------------------------------------
    function showError(msg) {
        let bar = document.getElementById('errorBar');
        if (!bar) {
            bar = document.createElement('div');
            bar.id = 'errorBar';
            bar.style.cssText = `
      position:fixed;bottom:0;left:0;right:0;
      background:#2a1c00;border-top:1px solid #ffab00;
      color:#ffab00;font-family:'Share Tech Mono',monospace;
      font-size:10px;padding:6px 16px;z-index:999;
      display:flex;align-items:center;justify-content:space-between;
    `;
            document.body.appendChild(bar);
        }
        bar.innerHTML = `? ${msg} &nbsp;<span style="cursor:pointer;color:#ff1744" id="closeError">?</span>`;
        document.getElementById('closeError').addEventListener('click', function() {
            this.parentElement.remove();
        });
    }

    function clearError() {
        const bar = document.getElementById('errorBar');
        if (bar) bar.remove();
    }

    // ------------------------------------------
    //  MAIN POLLING LOOP
    // ------------------------------------------
    async function refresh() {
        try {
            const [stats, logs, bl] = await Promise.all([
                fetchStats(), fetchLogs(), fetchBlacklist()
            ]);
            setOnline(true);
            clearError();
            renderStats(stats);
            renderLogs(logs);
            renderBlacklist(bl);
        } catch(e) {
            setOnline(false);
            // Show actual error so user knows what's wrong
            const msg = e.name === 'AbortError'
                ? 'Server timeout — is smartshield_server.exe running on port 8080?'
                : `Cannot reach server: ${e.message} — start smartshield_server.exe`;
            showError(msg);
            console.error('[SmartShield Dashboard]', e);
        }
    }

    // Redraw chart on resize
    window.addEventListener('resize', () => {
        const canvas = document.getElementById('activityChart');
        if (canvas) {
            canvas.width  = canvas.parentElement.offsetWidth || 600;
            canvas.height = 140;
        }
        drawActivity();
    });

    // Initial load + polling
    refresh();
    setInterval(refresh, REFRESH_MS);
});