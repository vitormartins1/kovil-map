import { escapeHtml } from '../utils.js';
import { buildHintLabel } from '../ui_components/ui_hints.js';

const RECON_SECURITY_ORDER = ['OPEN', 'WEP', 'WPA', 'WPA2', 'WPA3', 'UNKNOWN'];
const RECON_SECURITY_COLORS = {
    OPEN: '#e6b422',
    WEP: '#e68a22',
    WPA: '#2faad4',
    WPA2: '#22c55e',
    WPA3: '#c678dd',
    UNKNOWN: '#7a8b92',
};
const RECON_SOURCE_ORDER = ['wardrive', 'pwnagotchi', 'brucegotchi', 'm5evil', 'rawsniffer', 'unknown'];
const RECON_SOURCE_COLORS = {
    wardrive: '#47c6b5',
    pwnagotchi: '#73b8ff',
    brucegotchi: '#d79a54',
    m5evil: '#8dcf63',
    rawsniffer: '#9c83d8',
    unknown: '#7a8b92',
};
const RECON_DEVICE_ORDER = ['router_ap', 'phone', 'tablet', 'laptop', 'camera', 'iot', 'bridge', 'watch', 'unknown'];
const RECON_DEVICE_COLORS = {
    router_ap: '#5ab0ff',
    phone: '#ff8c42',
    tablet: '#ffd166',
    laptop: '#7bd389',
    camera: '#ff6b8a',
    iot: '#b388eb',
    bridge: '#4dd4c6',
    watch: '#f4978e',
    unknown: '#7a8b92',
};

const RECON_HINTS = {
    pmkid: 'A PMKID hash can often be attacked offline without capturing a full 4-way handshake.',
    eapol_hash: 'A converted 4-way handshake hash that is ready for offline cracking tools.',
    eapol_evidence: 'Networks where raw EAPOL frames were observed, even if a usable .22000 hash has not been generated yet.',
    with_handshake: 'Networks that already have at least one handshake-related artifact linked to them, such as a capture or converted hash.',
    crackable_remaining: 'Targets not yet cracked that still look operationally worth attacking next based on the current dataset.',
    multi_source: 'Networks seen by more than one collection source, which usually improves confidence and context.',
    avg_score: 'Average attack score across the currently listed targets.',
    readiness_score: 'Heuristic readiness for attack based on available artifacts, radio evidence and hash presence.',
    success_rate: 'Cracked attacks divided by total recorded attack attempts in the selected period.',
    avg_time: 'Average runtime for attacks with usable timing data.',
    wordlist_roi: 'How efficiently each wordlist converts attempts into successful cracks.',
    crack_velocity: 'Timeline of successful crack events, useful to see when campaigns were most productive.',
    with_gps: 'Networks with usable latitude/longitude available for spatial analysis.',
    without_coordinates: 'Networks currently missing usable coordinates.',
    coverage_rate: 'Percentage of networks in the current dataset that already have GPS coordinates.',
    known_ssid: 'The probed SSID already exists in the discovered network dataset, which may indicate likely roaming or revisit behavior.',
    derandomization: 'Heuristic grouping of client MACs that share the same probe fingerprint. It suggests, but does not prove, that multiple randomized MACs may belong to one device.',
    geocorrelation: 'Builds a location hypothesis from probe-request SSIDs that also exist as GPS-tagged networks in Recon. It is heuristic and can become ambiguous when the same SSID exists in multiple places.',
    probe_intel_scope: 'Probe Intelligence is built from probe-request frames found in SIGINT captures. It is separate from Deep Analysis / Threat Analysis jobs.',
    unmatched_target_ssids: 'SSIDs seen in directed probe requests that do not currently match any known network in Recon. They may represent hidden, transient or off-dataset targets.',
    most_probed_ssids: 'Ranks SSIDs by how often clients asked for them. High client counts suggest broad interest; high probes-per-client suggests repeated search behavior.',
    top_probing_clients: 'Shows the clients generating the most probe activity, along with vendor/OUI context and how much of their search behavior matches known networks.',
    ssid_shape: 'Classifies the SSID name pattern to highlight UUID-like, hex-like or auto-generated naming that may be harder to interpret at a glance.',
    congested_channels: 'Channels whose share of observed networks exceeds the Recon congestion threshold.',
    signal_by_encryption: 'Average RSSI split by encryption family to compare physical signal quality across network types.',
    strong_signal_targets: 'Targets above -50 dBm. These are usually physically close and good candidates for prioritization.',
    mixed_cluster: 'This label appears when no first SSID term accounts for at least half of the networks in the cluster.',
    links_per_ap: 'Average number of observed client links per access point in the communication graph.',
    invalid_details: '.details files that exist but cannot be parsed as valid JSON.',
    missing_details: 'Handshake captures imported from Bruce or M5Evil that still do not have a matching .details metadata file.',
    orphaned_handshakes: 'PCAP handshake files whose base name has no matching .details file in the handshakes directory.',
    without_gps: 'Networks in the dataset that still do not have coordinates attached.',
    pending_raw_files: 'RAW sniffer captures waiting to be processed or refreshed into structured metadata.',
};

export function reconHintLabel(label, hintKey, options = {}) {
    const hintText = RECON_HINTS[hintKey] || String(hintKey || '').trim();
    if (!hintText) return escapeHtml(label);
    return buildHintLabel(label, hintText, options);
}

export function normalizeReconSecurityLabel(label) {
    const raw = String(label || '').trim().toUpperCase();
    if (!raw || raw === 'UNK' || raw === 'UNKN' || raw === 'UNKNOWN' || raw === 'NONE') return 'UNKNOWN';
    if (raw.includes('WPA3')) return 'WPA3';
    if (raw.includes('WPA2')) return 'WPA2';
    if (raw.includes('WEP')) return 'WEP';
    if (raw === 'OPEN' || raw.includes('OPEN')) return 'OPEN';
    if (raw.includes('WPA')) return 'WPA';
    return raw;
}

export function getReconSecurityEntries(distribution) {
    const totals = new Map();
    for (const [label, value] of Object.entries(distribution || {})) {
        const count = Number(value) || 0;
        if (count <= 0) continue;
        const normalized = normalizeReconSecurityLabel(label);
        totals.set(normalized, (totals.get(normalized) || 0) + count);
    }
    return Array.from(totals.entries())
        .map(([label, count]) => ({ label, count }))
        .sort((a, b) => {
            const ai = RECON_SECURITY_ORDER.indexOf(a.label);
            const bi = RECON_SECURITY_ORDER.indexOf(b.label);
            if (ai !== -1 || bi !== -1) {
                if (ai === -1) return 1;
                if (bi === -1) return -1;
                if (ai !== bi) return ai - bi;
            }
            return b.count - a.count || a.label.localeCompare(b.label);
        });
}

export function getReconSecurityColor(label) {
    return RECON_SECURITY_COLORS[label] || '#4d7894';
}

export function normalizeReconSourceLabel(label) {
    const raw = String(label || '').trim().toLowerCase();
    if (!raw) return 'unknown';
    if (raw.includes('wardrive') || raw.includes('war drive') || raw.includes('hard drive')) return 'wardrive';
    if (raw.includes('pwnagotchi') || raw.includes('pwn')) return 'pwnagotchi';
    if (raw.includes('brucegotchi') || raw.includes('bruceghost') || raw.includes('bruce')) return 'brucegotchi';
    if (raw.includes('m5')) return 'm5evil';
    if (raw.includes('raw')) return 'rawsniffer';
    return raw;
}

export function formatReconSourceLabel(label) {
    const normalized = normalizeReconSourceLabel(label);
    const map = {
        wardrive: 'Wardrive',
        pwnagotchi: 'Pwnagotchi',
        brucegotchi: 'Brucegotchi',
        m5evil: 'M5Evil',
        rawsniffer: 'RawSniffer',
        unknown: 'Unknown',
    };
    return map[normalized] || String(label || 'Unknown');
}

function getReconSourceEntries(distribution) {
    const totals = new Map();
    for (const [label, value] of Object.entries(distribution || {})) {
        const count = Number(value) || 0;
        if (count <= 0) continue;
        const normalized = normalizeReconSourceLabel(label);
        totals.set(normalized, (totals.get(normalized) || 0) + count);
    }
    return Array.from(totals.entries())
        .map(([label, count]) => ({ label: formatReconSourceLabel(label), sortKey: label, count }))
        .sort((a, b) => {
            const ai = RECON_SOURCE_ORDER.indexOf(a.sortKey);
            const bi = RECON_SOURCE_ORDER.indexOf(b.sortKey);
            if (ai !== -1 || bi !== -1) {
                if (ai === -1) return 1;
                if (bi === -1) return -1;
                if (ai !== bi) return ai - bi;
            }
            return b.count - a.count || a.label.localeCompare(b.label);
        })
        .map(({ label, count }) => ({ label, count }));
}

export function getReconSourceColor(label) {
    return RECON_SOURCE_COLORS[normalizeReconSourceLabel(label)] || '#4d7894';
}

export function normalizeReconDeviceLabel(label) {
    const raw = String(label || '').trim().toLowerCase();
    if (!raw) return 'unknown';
    if (raw.includes('router') || raw.includes('ap')) return 'router_ap';
    if (raw.includes('phone') || raw.includes('mobile')) return 'phone';
    if (raw.includes('tablet')) return 'tablet';
    if (raw.includes('laptop') || raw.includes('notebook')) return 'laptop';
    if (raw.includes('camera') || raw.includes('cam')) return 'camera';
    if (raw.includes('bridge') || raw.includes('repeater') || raw.includes('extender')) return 'bridge';
    if (raw.includes('watch')) return 'watch';
    if (raw.includes('iot') || raw.includes('sensor') || raw.includes('smart')) return 'iot';
    return raw;
}

export function formatReconDeviceLabel(label) {
    const normalized = normalizeReconDeviceLabel(label);
    const map = {
        router_ap: 'Router/AP',
        phone: 'Phone',
        tablet: 'Tablet',
        laptop: 'Laptop',
        camera: 'Camera',
        iot: 'IoT',
        bridge: 'Bridge',
        watch: 'Watch',
        unknown: 'Unknown',
    };
    return map[normalized] || String(label || 'Unknown');
}

function getReconDeviceEntries(distribution) {
    const totals = new Map();
    for (const [label, value] of Object.entries(distribution || {})) {
        const count = Number(value) || 0;
        if (count <= 0) continue;
        const normalized = normalizeReconDeviceLabel(label);
        totals.set(normalized, (totals.get(normalized) || 0) + count);
    }
    return Array.from(totals.entries())
        .map(([label, count]) => ({ label: formatReconDeviceLabel(label), sortKey: label, count }))
        .sort((a, b) => {
            const ai = RECON_DEVICE_ORDER.indexOf(a.sortKey);
            const bi = RECON_DEVICE_ORDER.indexOf(b.sortKey);
            if (ai !== -1 || bi !== -1) {
                if (ai === -1) return 1;
                if (bi === -1) return -1;
                if (ai !== bi) return ai - bi;
            }
            return b.count - a.count || a.label.localeCompare(b.label);
        })
        .map(({ label, count }) => ({ label, count }));
}

export function getReconDeviceColor(label) {
    return RECON_DEVICE_COLORS[normalizeReconDeviceLabel(label)] || '#4d7894';
}

function renderReconDistributionMiniBar(
    entries,
    {
        title = 'Distribution',
        compact = false,
        showLegend = true,
        legendLimit = 3,
        className = '',
        colorResolver = () => '#4d7894',
    } = {},
) {
    if (!entries.length) return '';
    const total = entries.reduce((sum, entry) => sum + entry.count, 0);
    const classes = ['recon-security-mini'];
    if (compact) classes.push('recon-security-mini--compact');
    if (className) classes.push(className);
    const segmentsHtml = entries.map((entry) => {
        const pct = total > 0 ? (entry.count / total) * 100 : 0;
        return `<span class="recon-security-mini-segment" style="width:${pct}%;--recon-security-color:${colorResolver(entry.label)}" title="${escapeHtml(entry.label)} ${entry.count}"></span>`;
    }).join('');
    let legendHtml = '';
    if (showLegend) {
        const visibleEntries = entries.slice(0, legendLimit);
        legendHtml = `<div class="recon-security-mini-legend">${visibleEntries.map((entry) => `
            <span class="recon-security-mini-pill">
                <span class="recon-security-mini-dot" style="--recon-security-color:${colorResolver(entry.label)}"></span>
                <span>${escapeHtml(entry.label)}</span>
                <strong>${entry.count}</strong>
            </span>
        `).join('')}${entries.length > legendLimit ? `<span class="recon-security-mini-more">+${entries.length - legendLimit}</span>` : ''}</div>`;
    }
    return `<div class="${classes.join(' ')}">
        <div class="recon-security-mini-head">
            <span class="recon-security-mini-title">${escapeHtml(title)}</span>
            <span class="recon-security-mini-total">${total}</span>
        </div>
        <div class="recon-security-mini-track">${segmentsHtml}</div>
        ${legendHtml}
    </div>`;
}

export function renderReconSecurityMiniBar(distribution, {
    title = 'Security mix',
    compact = false,
    showLegend = true,
    legendLimit = 3,
    className = '',
} = {}) {
    return renderReconDistributionMiniBar(getReconSecurityEntries(distribution), {
        title,
        compact,
        showLegend,
        legendLimit,
        className,
        colorResolver: getReconSecurityColor,
    });
}

export function renderReconSourceMiniBar(distribution, options = {}) {
    return renderReconDistributionMiniBar(getReconSourceEntries(distribution), {
        title: 'Origins',
        compact: true,
        showLegend: true,
        legendLimit: 4,
        colorResolver: getReconSourceColor,
        ...options,
    });
}

export function renderReconDeviceMiniBar(distribution, options = {}) {
    return renderReconDistributionMiniBar(getReconDeviceEntries(distribution), {
        title: 'Devices',
        compact: true,
        showLegend: true,
        legendLimit: 4,
        colorResolver: getReconDeviceColor,
        ...options,
    });
}

export function renderReconFindingsPanel(findings) {
    const encEntries = getReconSecurityEntries(findings?.encryption_distribution);
    const encTotal = encEntries.reduce((sum, entry) => sum + entry.count, 0);
    let cumulative = 0;
    const encStops = encEntries.map((entry) => {
        const start = cumulative;
        const pct = encTotal > 0 ? (entry.count / encTotal) * 100 : 0;
        cumulative += pct;
        return `${getReconSecurityColor(normalizeReconSecurityLabel(entry.label))} ${start}% ${cumulative}%`;
    }).join(', ');

    const deviceEntries = Object.entries(findings?.device_distribution || {})
        .map(([label, count]) => ({ label: formatReconDeviceLabel(label), count: Number(count) || 0 }))
        .filter((entry) => entry.count > 0)
        .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
    const deviceTotal = deviceEntries.reduce((sum, entry) => sum + entry.count, 0);
    const topDevices = deviceEntries.slice(0, 5);
    const kpis = [
        { label: 'Total', value: findings.total_networks ?? 0 },
        { label: 'Cracked', value: findings.cracked ?? 0, tone: 'success' },
        { label: reconHintLabel('Remaining', 'crackable_remaining'), value: findings.crackable_remaining ?? 0, tone: 'warn' },
        { label: reconHintLabel('Handshake', 'with_handshake'), value: findings.with_handshake ?? 0 },
        { label: reconHintLabel('EAPOL', 'eapol_evidence'), value: findings.with_eapol_evidence ?? 0 },
        { label: 'Rate', value: `${Number(findings.crack_rate_percent || 0).toFixed(1)}%`, tone: 'accent' },
    ];

    return `<div class="recon-findings-grid">
        <div class="recon-findings-panel">
            <div class="recon-findings-panel-title">Key Findings</div>
            <div class="recon-findings-kpi-grid">
                ${kpis.map((item) => `
                    <div class="recon-findings-kpi recon-findings-kpi--${item.tone || 'default'}">
                        <span class="recon-findings-kpi-value">${escapeHtml(String(item.value ?? '—'))}</span>
                        <span class="recon-findings-kpi-label">${item.label}</span>
                    </div>
                `).join('')}
            </div>
        </div>
        <div class="recon-findings-panel">
            <div class="recon-findings-panel-title">Encryption Distribution</div>
            ${encEntries.length ? `<div class="recon-findings-encryption">
                <div class="recon-findings-donut" style="background:conic-gradient(${encStops || '#7a8b92 0 100%'})">
                    <div class="recon-findings-donut-hole"></div>
                </div>
                <div class="recon-findings-legend">
                    ${encEntries.map((entry) => {
                        const pct = encTotal > 0 ? Math.round((entry.count / encTotal) * 100) : 0;
                        return `<span class="recon-findings-legend-item">
                            <span class="recon-findings-legend-dot" style="--recon-security-color:${getReconSecurityColor(normalizeReconSecurityLabel(entry.label))}"></span>
                            <span>${escapeHtml(entry.label)}</span>
                            <strong>${entry.count}</strong>
                            <small>${pct}%</small>
                        </span>`;
                    }).join('')}
                </div>
            </div>` : '<div class="recon-empty">No encryption data.</div>'}
        </div>
        <div class="recon-findings-panel">
            <div class="recon-findings-panel-title">Device Distribution</div>
            ${topDevices.length ? `<div class="recon-findings-device-list">
                ${topDevices.map((entry) => {
                    const pct = deviceTotal > 0 ? Math.round((entry.count / deviceTotal) * 100) : 0;
                    return `<div class="recon-findings-device-row">
                        <div class="recon-findings-device-head">
                            <span class="recon-findings-device-label">${escapeHtml(entry.label)}</span>
                            <span class="recon-findings-device-val">${entry.count} <small>${pct}%</small></span>
                        </div>
                        <div class="recon-findings-device-track">
                            <span class="recon-findings-device-fill" style="width:${pct}%"></span>
                        </div>
                    </div>`;
                }).join('')}
                ${deviceEntries.length > topDevices.length ? `<div class="recon-findings-device-more">+${deviceEntries.length - topDevices.length} more device types</div>` : ''}
            </div>` : '<div class="recon-empty">No device distribution data.</div>'}
        </div>
    </div>`;
}
