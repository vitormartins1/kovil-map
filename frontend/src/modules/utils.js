export function escapeHtml(text) {
    if (!text) return text;
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

export function safeText(value) {
    if (value === null || value === undefined) return '';
    return String(value);
}

export function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        log(`Copied to clipboard: ${text}`, 'info');
    });
}

export function log(message, type = 'info') {
    const logPanel = document.getElementById('log-panel');
    if (!logPanel) return;
    
    const div = document.createElement('div');
    div.className = `log-entry`;
    
    let typeClass = '';
    if (type === 'error') typeClass = 'log-danger';
    else if (type === 'warn') typeClass = 'log-warn';
    else if (type === 'success') typeClass = 'log-highlight';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = new Date().toLocaleTimeString();

    const msgSpan = document.createElement('span');
    msgSpan.className = `log-msg ${typeClass}`.trim();
    msgSpan.textContent = safeText(message);

    div.appendChild(timeSpan);
    div.appendChild(document.createTextNode(' '));
    div.appendChild(msgSpan);
    logPanel.prepend(div);
}

export function bootLog(msg) {
    const bootLog = document.getElementById('boot-log');
    if(bootLog) {
        const entry = document.createElement('div');
        entry.className = 'boot-log-entry';

        const tag = document.createElement('span');
        tag.className = 'boot-log-tag';
        tag.textContent = 'BOOT';

        const text = document.createElement('span');
        text.className = 'boot-log-msg';
        text.textContent = `[BOOT] ${safeText(msg)}`;

        entry.appendChild(tag);
        entry.appendChild(text);
        bootLog.appendChild(entry);
        bootLog.scrollTop = bootLog.scrollHeight;
    }
}

// Monotonic chain convex hull, returns points in counter-clockwise order.
export function convexHull(points) {
    if (!points || points.length <= 2) return points ? points.slice() : [];

    const pts = points.map(p => ({ lat: p.lat, lng: p.lng }));
    pts.sort((a, b) => (a.lng === b.lng ? a.lat - b.lat : a.lng - b.lng));

    const cross = (o, a, b) => (a.lng - o.lng) * (b.lat - o.lat) - (a.lat - o.lat) * (b.lng - o.lng);

    const lower = [];
    for (const p of pts) {
        while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) {
            lower.pop();
        }
        lower.push(p);
    }

    const upper = [];
    for (let i = pts.length - 1; i >= 0; i--) {
        const p = pts[i];
        while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) {
            upper.pop();
        }
        upper.push(p);
    }

    upper.pop();
    lower.pop();
    return lower.concat(upper);
}

function destinationPoint(lat, lng, distanceM, bearingDeg) {
    const R = 6371000;
    const brng = (bearingDeg * Math.PI) / 180;
    const lat1 = (lat * Math.PI) / 180;
    const lon1 = (lng * Math.PI) / 180;
    const dR = distanceM / R;

    const lat2 = Math.asin(
        Math.sin(lat1) * Math.cos(dR) +
        Math.cos(lat1) * Math.sin(dR) * Math.cos(brng)
    );
    const lon2 = lon1 + Math.atan2(
        Math.sin(brng) * Math.sin(dR) * Math.cos(lat1),
        Math.cos(dR) - Math.sin(lat1) * Math.sin(lat2)
    );

    return { lat: (lat2 * 180) / Math.PI, lng: (lon2 * 180) / Math.PI };
}

export function expandPointsByAccuracy(points, segments = 8) {
    if (!points || points.length === 0) return [];
    const expanded = [];
    const step = 360 / segments;

    for (const p of points) {
        const lat = p.lat;
        const lng = p.lng;
        if (lat == null || lng == null) continue;

        expanded.push({ lat, lng });
        const acc = Math.max(0, Number(p.acc || 0));
        if (!acc) continue;

        for (let i = 0; i < segments; i++) {
            expanded.push(destinationPoint(lat, lng, acc, i * step));
        }
    }

    return expanded;
}
