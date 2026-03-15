document.addEventListener('DOMContentLoaded', () => {
    const params  = new URLSearchParams(window.location.search);
    const domain  = params.get('domain') || 'unknown';
    const score   = parseFloat(params.get('score') || 0);
    const reason  = params.get('reason') || '';
    const origUrl = params.get('origUrl') || ('https://' + domain);

    document.getElementById('domainDisplay').textContent = domain;
    document.getElementById('scoreDisplay').textContent  = score.toFixed(1) + ' / 100';
    document.getElementById('reasonDisplay').textContent = reason || '—';

    const pct = Math.min((score / 20) * 100, 100);
    setTimeout(function() {
        document.getElementById('scoreBar').style.width = pct + '%';
    }, 300);

    function tick() {
        var now = new Date();
        document.getElementById('ts').textContent = now.toTimeString().slice(0,8);
        document.getElementById('dateDisplay').textContent = now.toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'});
    }
    tick();
    setInterval(tick, 1000);

    // Button event listeners
    document.getElementById('btnReturnToSafety').addEventListener('click', () => {
        window.location.href = 'https://www.google.com';
    });

    document.getElementById('btnToggleConfirm').addEventListener('click', () => {
        document.getElementById('confirmPanel').classList.toggle('show');
    });

    document.getElementById('btnCancelConfirm').addEventListener('click', () => {
        document.getElementById('confirmPanel').classList.remove('show');
    });

    document.getElementById('btnProceedAnyway').addEventListener('click', () => {
        var btn = document.getElementById('btnProceedAnyway');
        btn.textContent = 'Going...';
        btn.disabled = true;

        chrome.storage.local.get(['bypassed'], function(r) {
            var list = r.bypassed || [];
            if (list.indexOf(domain) === -1) list.push(domain);
            chrome.storage.local.set({ bypassed: list }, function() {
                fetch('http://localhost:8080/unblock?domain=' + encodeURIComponent(domain))
                    .catch(function(){});

                setTimeout(function() {
                    window.location.href = origUrl;
                }, 500);
            });
        });
    });
});