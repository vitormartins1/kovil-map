import { escapeHtml } from '../utils.js';
import {
    formatReconDeviceLabel,
    reconHintLabel,
    renderReconDeviceMiniBar,
    renderReconSecurityMiniBar,
    renderReconSourceMiniBar,
} from './ui_helpers.js';
import {
    getCommsGraphAnalytics,
    getCommsGraphNodeColor,
    getCommsGraphNodeTone,
    renderCommsGraphSelection,
    renderCommsGraphSelectionPlaceholder,
    renderCommsGraphTopList,
} from './sigint_graph_helpers.js';

function formatReconChannels(channels, limit = 3) {
    const entries = Object.entries(channels || {})
        .map(([channel, count]) => ({ channel, count: Number(count) || 0 }))
        .filter((entry) => entry.count > 0)
        .sort((a, b) => b.count - a.count || Number(a.channel) - Number(b.channel))
        .slice(0, limit);
    if (!entries.length) return '—';
    return entries.map((entry) => `CH${entry.channel} (${entry.count})`).join(' · ');
}

function formatReconRssiStat(value) {
    return value == null ? '—' : String(value);
}

function renderCommsSection(key, title, collapsed, contentFn) {
    const isCollapsed = collapsed.has(key);
    const arrow = isCollapsed ? '▸' : '▾';
    let html = `<div class="recon-section-toggle" data-comms-section="${key}"><span class="recon-section-arrow">${arrow}</span> ${title}</div>`;
    html += `<div class="recon-report-block${isCollapsed ? ' recon-collapsed' : ''}">`;
    if (!isCollapsed) html += contentFn();
    html += '</div>';
    return html;
}

function renderCommsSectionLoading(copy = 'Loading…') {
    return `<div class="recon-loading-sm">${escapeHtml(copy)}</div>`;
}

export function renderCommsSpectrum(spectrum) {
    let html = '';
    if (!spectrum || !spectrum.channels || spectrum.channels.length === 0) {
        return html + '<div class="recon-empty">No channel data available. Start a <strong>wardrive capture</strong> to collect spectrum information.</div>';
    }
    html += '<div class="recon-section-note">WiFi channel utilization, band distribution, and congestion indicators from wardrive data.</div>';

    const total = spectrum.total_with_channel || 0;
    const pct24 = total > 0 ? Math.round((spectrum.band_24ghz / total) * 100) : 0;
    const pct5 = total > 0 ? Math.round((spectrum.band_5ghz / total) * 100) : 0;
    const congCount = (spectrum.congested_channels || []).length;

    html += `<div class="recon-kpi-row">
        <div class="recon-kpi"><span class="recon-kpi-val">${spectrum.band_24ghz || 0}</span><span class="recon-kpi-label">2.4 GHz (${pct24}%)</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${spectrum.band_5ghz || 0}</span><span class="recon-kpi-label">5 GHz (${pct5}%)</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${total}</span><span class="recon-kpi-label">TOTAL</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val ${congCount > 0 ? 'recon-kpi-val--alert' : ''}">${congCount}</span><span class="recon-kpi-label">${reconHintLabel('CONGESTED CH', 'congested_channels')}</span></div>
    </div>`;

    html += '<div class="recon-spectrum-canvas-wrap"><canvas id="recon-spectrum-canvas" width="700" height="220"></canvas></div>';
    html += `<div class="recon-spectrum-legend" aria-label="Spectrum legend">
        <span class="recon-spectrum-legend-item"><span class="recon-spectrum-legend-dot recon-spectrum-legend-dot--preferred"></span>Non-overlap (1/6/11)</span>
        <span class="recon-spectrum-legend-item"><span class="recon-spectrum-legend-dot recon-spectrum-legend-dot--congested"></span>Congested (>15%)</span>
        <span class="recon-spectrum-legend-item"><span class="recon-spectrum-legend-dot recon-spectrum-legend-dot--normal"></span>Normal</span>
    </div>`;

    if (congCount > 0) {
        html += `<div class="recon-comms-alert">⚠ Congested channels: ${spectrum.congested_channels.join(', ')} (>15% of networks)</div>`;
    }

    return html;
}

export function renderCommsSignalLandscape(landscape, q) {
    let html = '';
    if (!landscape || !landscape.total_with_rssi) {
        return html + '<div class="recon-empty">No RSSI data available. Start a <strong>wardrive capture</strong> to collect signal strength data.</div>';
    }
    html += '<div class="recon-section-note">Signal strength distribution and strong-signal target identification.</div>';

    const s = landscape.summary || {};
    html += `<div class="recon-kpi-row">
        <div class="recon-kpi"><span class="recon-kpi-val">${landscape.total_with_rssi}</span><span class="recon-kpi-label">WITH RSSI</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${s.avg != null ? s.avg : '—'}</span><span class="recon-kpi-label">AVG dBm</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${s.max != null ? s.max : '—'}</span><span class="recon-kpi-label">STRONGEST</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${s.min != null ? s.min : '—'}</span><span class="recon-kpi-label">WEAKEST</span></div>
    </div>`;

    html += '<div class="recon-signal-canvas-wrap"><canvas id="recon-signal-canvas" width="500" height="180"></canvas></div>';

    if (landscape.by_encryption && Object.keys(landscape.by_encryption).length > 0) {
        html += `<div class="recon-section-sub">${reconHintLabel('SIGNAL BY ENCRYPTION', 'signal_by_encryption')}</div>`;
        html += '<div class="recon-signal-enc-grid">';
        for (const [enc, stats] of Object.entries(landscape.by_encryption)) {
            if (!stats) continue;
            html += `<div class="recon-signal-enc-card">
                <span class="recon-signal-enc-label">${escapeHtml(enc)}</span>
                <span class="recon-signal-enc-val">${stats.avg} avg</span>
                <span class="recon-badge recon-badge--dim">${stats.count}</span>
            </div>`;
        }
        html += '</div>';
    }

    let strong = landscape.strong_signals || [];
    if (q) {
        strong = strong.filter((t) => (t.ssid || '').toLowerCase().includes(q) || (t.mac || '').toLowerCase().includes(q) || (t.encryption || '').toLowerCase().includes(q));
    }
    if (strong.length > 0) {
        html += `<div class="recon-section-sub">${reconHintLabel(`STRONG-SIGNAL TARGETS (> -50 dBm) — ${strong.length} total`, 'strong_signal_targets')}</div>`;
        const INITIAL_SHOW = 12;
        const showAll = strong.length <= INITIAL_SHOW;
        html += '<div class="recon-signal-strong-grid">';
        for (const t of strong.slice(0, INITIAL_SHOW)) {
            html += `<div class="recon-signal-strong-card">
                <span class="recon-signal-strong-ssid">${escapeHtml(t.ssid || t.mac)}</span>
                <span class="recon-signal-strong-rssi">${t.rssi} dBm</span>
                <span class="recon-badge recon-badge--dim">${escapeHtml(t.encryption)}</span>
            </div>`;
        }
        html += '</div>';
        if (!showAll) {
            html += `<button class="recon-comms-expand-btn" data-comms-toggle="strong-all">▸ Show all ${strong.length}</button>`;
            html += '<div class="recon-comms-expand-body" data-comms-expand="strong-all" style="display:none"><div class="recon-signal-strong-grid">';
            for (const t of strong.slice(INITIAL_SHOW)) {
                html += `<div class="recon-signal-strong-card">
                    <span class="recon-signal-strong-ssid">${escapeHtml(t.ssid || t.mac)}</span>
                    <span class="recon-signal-strong-rssi">${t.rssi} dBm</span>
                    <span class="recon-badge recon-badge--dim">${escapeHtml(t.encryption)}</span>
                </div>`;
            }
            html += '</div></div>';
        }
    }

    return html;
}

export function renderCommsDeviceIntel(fingerprints, q) {
    let html = '';
    if (!fingerprints || !fingerprints.total) {
        return html + '<div class="recon-empty">No device data available. Device intelligence is built from wardrive and SIGINT captures.</div>';
    }
    html += '<div class="recon-section-note">Device types, encryption posture, and raw frame activity across observed infrastructure and clients.</div>';

    const ra = fingerprints.raw_activity || {};
    html += `<div class="recon-kpi-row">
        <div class="recon-kpi"><span class="recon-kpi-val">${fingerprints.total}</span><span class="recon-kpi-label">DEVICES</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${(fingerprints.by_type || []).length}</span><span class="recon-kpi-label">TYPES</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${ra.beacons || 0}</span><span class="recon-kpi-label">BEACONS</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${ra.eapol || 0}</span><span class="recon-kpi-label">EAPOL</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${ra.probes || 0}</span><span class="recon-kpi-label">PROBES</span></div>
    </div>`;

    let byType = fingerprints.by_type || [];
    if (q) {
        byType = byType.filter((t) => t.type.toLowerCase().includes(q));
    }
    html += '<div class="recon-comms-device-grid">';
    for (const t of byType) {
        const pct = fingerprints.total > 0 ? Math.round((t.count / fingerprints.total) * 100) : 0;
        const rssi = t.rssi_stats || {};
        const channelsLabel = formatReconChannels(t.channel_distribution);
        html += `<div class="recon-comms-device-card">
            <div class="recon-comms-device-header">
                <span class="recon-comms-device-tag">${escapeHtml(t.type)}</span>
                <span class="recon-fp-count">${t.count} <small>(${pct}%)</small></span>
            </div>
            <div class="recon-comms-device-bar-wrap">
                <div class="recon-comms-device-bar" style="width:${pct}%"></div>
            </div>
            <div class="recon-comms-device-metrics">
                <div class="recon-comms-device-metric">
                    <span class="recon-comms-device-metric-label">Share</span>
                    <span class="recon-comms-device-metric-value">${pct}% of total</span>
                </div>
                <div class="recon-comms-device-metric">
                    <span class="recon-comms-device-metric-label">RSSI</span>
                    <span class="recon-comms-device-metric-value">${formatReconRssiStat(rssi.min)} / ${formatReconRssiStat(rssi.avg)} / ${formatReconRssiStat(rssi.max)}</span>
                </div>
                <div class="recon-comms-device-metric recon-comms-device-metric--wide">
                    <span class="recon-comms-device-metric-label">Channels</span>
                    <span class="recon-comms-device-metric-value">${escapeHtml(channelsLabel)}</span>
                </div>
            </div>
            ${renderReconSecurityMiniBar(t.encryption, {
                compact: true,
                title: 'Security',
                legendLimit: 4,
                className: 'recon-comms-device-security',
            })}`;
        html += '</div>';
    }
    html += '</div>';
    return html;
}

export function renderCommsTopVendors(fingerprints, q) {
    let html = '';
    if (!fingerprints || !fingerprints.total) {
        return html + '<div class="recon-empty">No vendor profile available yet. Top vendors are derived from observed MAC OUIs in wardrive and SIGINT captures.</div>';
    }
    html += '<div class="recon-section-note">OUI vendor concentration, sampled devices, and security posture for the most represented vendors in the current dataset.</div>';

    let byOui = (fingerprints.by_oui || []).slice(0, 15);
    if (q) {
        byOui = byOui.filter((o) => {
            const vendor = (o.vendor || '').toLowerCase();
            const prefixes = (o.oui_prefixes || []).join(' ').toLowerCase();
            const macs = (o.sample_macs || []).some((m) => (m.mac || '').toLowerCase().includes(q) || (m.ssid || '').toLowerCase().includes(q));
            return vendor.includes(q) || prefixes.includes(q) || macs;
        });
    }
    if (byOui.length === 0) {
        return html + '<div class="recon-empty">No vendors match the current filter.</div>';
    }
    html += '<div class="recon-oui-grid">';
    for (const o of byOui) {
        const vendor = o.vendor || 'Unknown';
        const prefixes = (o.oui_prefixes || []).map((p) => escapeHtml(p)).join(', ');
        html += `<div class="recon-oui-card">
            <div class="recon-oui-layout">
                <div class="recon-oui-main">
                    <div class="recon-oui-header">
                        <span class="recon-oui-vendor">${escapeHtml(vendor)}</span>
                        <span class="recon-badge">${o.count}</span>
                    </div>
                    ${prefixes ? `<div class="recon-oui-prefixes">${prefixes}</div>` : ''}
                    ${(o.sample_macs || []).length > 0 ? `<div class="recon-oui-devices">${(o.sample_macs || []).map((m) => {
                        const label = m.ssid ? `${escapeHtml(m.ssid)}` : '';
                        return `<div class="recon-comms-net-row"><span class="recon-comms-net-mac">${escapeHtml(m.mac)}</span>${label ? `<span class="recon-comms-net-ssid">${label}</span>` : ''}</div>`;
                    }).join('')}</div>` : ''}
                </div>
                <div class="recon-oui-side">
                    ${renderReconSecurityMiniBar(o.encryption, {
                        compact: true,
                        title: 'Security',
                        legendLimit: 4,
                    })}
                </div>
            </div>`;
        html += '</div>';
    }
    html += '</div>';
    return html;
}

export function renderCommsClusters(colocation, q) {
    let html = '';
    if (!colocation || !(colocation.clusters || []).length) {
        return html + '<div class="recon-empty">No GPS data for co-location analysis. Ensure wardrive captures include GPS coordinates.</div>';
    }
    html += '<div class="recon-section-note">Geospatial clusters of co-located networks with encryption posture and signal context.</div>';

    let clusters = colocation.clusters || [];
    if (q) {
        clusters = clusters.filter((cl) => {
            const label = (cl.label || '').toLowerCase();
            const enc = (cl.dominant_encryption || '').toLowerCase();
            const nets = (cl.networks || []).some((n) => (n.ssid || '').toLowerCase().includes(q) || (n.mac || '').toLowerCase().includes(q));
            return label.includes(q) || enc.includes(q) || nets;
        });
    }
    const totalNets = clusters.reduce((s, c) => s + (c.count || 0), 0);
    const largest = Math.max(...clusters.map((c) => c.count || 0));

    html += `<div class="recon-kpi-row">
        <div class="recon-kpi"><span class="recon-kpi-val">${clusters.length}</span><span class="recon-kpi-label">CLUSTERS</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${colocation.total_located || 0}</span><span class="recon-kpi-label">GPS NETWORKS</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${largest}</span><span class="recon-kpi-label">LARGEST</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${clusters.length > 0 ? Math.round(totalNets / clusters.length) : 0}</span><span class="recon-kpi-label">AVG SIZE</span></div>
    </div>`;

    html += '<div class="recon-comms-cluster-grid">';
    for (let i = 0; i < clusters.length; i++) {
        const cl = clusters[i];
        const label = cl.label || `Cluster ${i + 1}`;
        const radius = cl.radius_m != null ? `${Math.round(cl.radius_m)}m` : '—';
        const domEnc = cl.dominant_encryption || '—';
        const avgRssi = cl.avg_rssi != null ? `${cl.avg_rssi} dBm` : '—';
        const isMixed = String(label).trim().toLowerCase() === 'mixed';

        html += `<div class="recon-comms-cluster-card">
            <div class="recon-comms-cluster-header">
                <div class="recon-comms-cluster-title-wrap">
                    <span class="recon-comms-cluster-label">${escapeHtml(label)}</span>
                    ${isMixed ? `<span class="recon-comms-cluster-hint">${reconHintLabel('No shared SSID prefix reaches 50%', 'mixed_cluster')}</span>` : ''}
                </div>
                <span class="recon-badge">${cl.count} nets</span>
            </div>
            <div class="recon-comms-cluster-meta">
                <span><strong>Radius</strong> ${radius}</span>
                <span><strong>Dominant</strong> ${escapeHtml(domEnc)}</span>
                <span><strong>Avg RSSI</strong> ${avgRssi}</span>
            </div>`;

        html += renderReconSourceMiniBar(cl.source_breakdown, {
            className: 'recon-comms-cluster-origins',
            legendLimit: 5,
        });

        html += renderReconDeviceMiniBar(cl.device_breakdown, {
            className: 'recon-comms-cluster-devices',
            legendLimit: 5,
        });

        html += renderReconSecurityMiniBar(cl.encryption_breakdown, {
            compact: true,
            title: 'Security',
            legendLimit: 4,
            className: 'recon-comms-cluster-security',
        });

        html += '</div>';
    }
    html += '</div>';
    return html;
}

export function renderCommsGraph(graph) {
    const analytics = getCommsGraphAnalytics(graph);
    const probeContext = graph?.probe_context || {};
    const summary = probeContext.summary || {};
    const probeReady = Boolean(probeContext.available);
    const hasGraphData = analytics.edges.length > 0 || analytics.clients.length > 0 || analytics.targets.length > 0;

    if (!probeReady) {
        return `<div class="recon-panel-card recon-comms-graph-shell">
            <div class="recon-comms-graph-state-head">
                <div>
                    <div class="recon-comms-graph-title">Probe intelligence not ready yet</div>
                    <div class="recon-section-note">This graph only becomes meaningful after Recon processes probe-request data from SIGINT scans or imported captures.</div>
                </div>
                <div class="recon-comms-graph-status-row">
                    <span class="recon-comms-graph-status-pill">Cache idle</span>
                    <span class="recon-comms-graph-status-pill">${probeContext.pcap_count || 0} PCAPs found</span>
                </div>
            </div>
            <div class="recon-comms-graph-empty-copy">
                <strong>How to populate it</strong>
                <span>1. Run a probe scan in <strong>SIGINT</strong> or import captures with probe-request frames.</span>
                <span>2. Recon will map clients to known APs when the probed SSID exists in the dataset.</span>
                <span>3. Probe targets that do not match a discovered AP will still appear as unresolved SSID nodes.</span>
            </div>
        </div>`;
    }

    const avgLinks = graph.ap_count > 0 ? (analytics.edges.length / graph.ap_count).toFixed(1) : '0';
    const topAps = analytics.apInsights.slice(0, 4);
    const topTargets = analytics.targetInsights.slice(0, 4);

    let html = `<div class="recon-panel-card recon-comms-graph-shell">
        <div class="recon-comms-graph-state-head">
            <div>
                <div class="recon-comms-graph-title">Probe-to-network relationship map</div>
                <div class="recon-section-note">Inner nodes are discovered APs, the middle ring shows unresolved SSIDs seen in probes, and the outer ring shows client devices. Click any node to inspect how it connects.</div>
            </div>
            <div class="recon-comms-graph-status-row">
                <span class="recon-comms-graph-status-pill recon-comms-graph-status-pill--good">Probe intel ready</span>
                ${probeContext.stale ? '<span class="recon-comms-graph-status-pill recon-comms-graph-status-pill--warn">Cache stale</span>' : ''}
                <span class="recon-comms-graph-status-pill">${summary.pcaps_scanned || probeContext.pcap_count || 0} PCAPs</span>
                <span class="recon-comms-graph-status-pill">${summary.total_probes || 0} probes</span>
            </div>
        </div>
        <div class="recon-kpi-row recon-kpi-row--compact">
            <div class="recon-kpi"><span class="recon-kpi-val">${graph.ap_count || 0}</span><span class="recon-kpi-label">KNOWN APs</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${graph.ssid_target_count || 0}</span><span class="recon-kpi-label">UNRESOLVED SSIDs</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${graph.client_count || 0}</span><span class="recon-kpi-label">CLIENTS</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${analytics.knownLinks.length}</span><span class="recon-kpi-label">KNOWN LINKS</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${analytics.unresolvedLinks.length}</span><span class="recon-kpi-label">UNRESOLVED LINKS</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${avgLinks}</span><span class="recon-kpi-label">${reconHintLabel('LINKS/AP', 'links_per_ap')}</span></div>
        </div>`;

    if (!hasGraphData) {
        html += `<div class="recon-comms-graph-empty-copy recon-comms-graph-empty-copy--soft">
            <strong>Probe intelligence was processed, but no graphable relationships were found yet.</strong>
            <span>This usually means the imported probe data does not currently overlap with the discovered AP dataset.</span>
        </div></div>`;
        return html;
    }

    html += `<div class="recon-comms-graph-layout">
        <div class="recon-comms-graph-canvas-panel">
            <div class="recon-comms-graph-readline">
                <span class="recon-comms-graph-inline-legend"><i style="--recon-graph-color:#e63946"></i>Locked AP</span>
                <span class="recon-comms-graph-inline-legend"><i style="--recon-graph-color:#22c55e"></i>Cracked AP</span>
                <span class="recon-comms-graph-inline-legend"><i style="--recon-graph-color:#f4b942"></i>Unresolved SSID</span>
                <span class="recon-comms-graph-inline-legend"><i style="--recon-graph-color:#2faad4"></i>Client</span>
            </div>
            <div class="recon-graph-wrap recon-graph-wrap--enhanced"><canvas id="recon-graph-canvas" width="1120" height="420"></canvas></div>
        </div>
        <div class="recon-comms-graph-panels-row">
            <div class="recon-comms-graph-panel">
                <div class="recon-comms-graph-panel-title">How to read</div>
                <div class="recon-comms-graph-reading">
                    <span><strong>Inner ring:</strong> discovered APs already present in the Recon dataset.</span>
                    <span><strong>Middle ring:</strong> SSIDs requested by clients but not yet matched to a known AP.</span>
                    <span><strong>Outer ring:</strong> probing clients extracted from SIGINT or imported captures.</span>
                </div>
            </div>
            ${renderCommsGraphTopList('Most linked APs', topAps, (item, index) => `
                <div class="recon-comms-graph-list-row">
                    <span class="recon-comms-graph-list-rank">${index + 1}</span>
                    <div class="recon-comms-graph-list-copy">
                        <strong>${escapeHtml(item.node.label || item.node.id)}</strong>
                        <span>${item.knownCount} known link${item.knownCount === 1 ? '' : 's'} · ${item.peerCount} client${item.peerCount === 1 ? '' : 's'}</span>
                    </div>
                </div>
            `)}
            ${renderCommsGraphTopList('Unresolved probe targets', topTargets, (item, index) => `
                <div class="recon-comms-graph-list-row">
                    <span class="recon-comms-graph-list-rank recon-comms-graph-list-rank--target">${index + 1}</span>
                    <div class="recon-comms-graph-list-copy">
                        <strong>${escapeHtml(item.node.label || item.node.id)}</strong>
                        <span>${item.unresolvedCount} unresolved link${item.unresolvedCount === 1 ? '' : 's'} · ${item.peerCount} client${item.peerCount === 1 ? '' : 's'}</span>
                    </div>
                </div>
            `)}
            ${renderCommsGraphSelectionPlaceholder()}
        </div>
    </div></div>`;

    return html;
}

function drawSpectrumChart(spectrum, hiDpiCanvas, attachCanvasTooltip) {
    const canvas = document.getElementById('recon-spectrum-canvas');
    if (!canvas) return;
    const { ctx, W, H } = hiDpiCanvas(canvas);
    const PAD_L = 40, PAD_R = 10, PAD_T = 10, PAD_B = 30;
    const plotW = W - PAD_L - PAD_R;
    const plotH = H - PAD_T - PAD_B;

    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, W, H);

    const chs = spectrum.channels || [];
    if (!chs.length) return;
    const maxCount = Math.max(...chs.map((c) => c.count), 1);
    const barW = Math.max(Math.floor(plotW / chs.length) - 2, 4);
    const congested = new Set(spectrum.congested_channels || []);
    const preferred = new Set([1, 6, 11]);
    const hitRegions = [];

    for (let i = 0; i < chs.length; i++) {
        const ch = chs[i];
        const barH = Math.max(Math.round((ch.count / maxCount) * plotH), 2);
        const x = PAD_L + Math.round((i / chs.length) * plotW) + 1;
        const y = PAD_T + plotH - barH;

        const isCong = congested.has(ch.channel);
        const isPref = preferred.has(ch.channel);
        if (isCong) ctx.fillStyle = '#e63946';
        else if (isPref) ctx.fillStyle = '#22c55e';
        else ctx.fillStyle = '#2faad4';
        ctx.fillRect(x, y, barW, barH);
        hitRegions.push({ x, y, w: barW, h: barH, label: `CH ${ch.channel}: ${ch.count} networks${isCong ? ' (congested)' : ''}${isPref ? ' (non-overlap)' : ''}` });

        ctx.fillStyle = '#8b949e';
        ctx.font = '9px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(String(ch.channel), x + barW / 2, H - PAD_B + 12);

        if (ch.count > 0) {
            ctx.fillStyle = '#c9d1d9';
            ctx.fillText(String(ch.count), x + barW / 2, y - 3);
        }
    }

    ctx.save();
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px monospace';
    ctx.translate(12, PAD_T + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = 'center';
    ctx.fillText('networks', 0, 0);
    ctx.restore();

    attachCanvasTooltip(canvas, hitRegions);
}

function drawRssiHistogram(landscape, hiDpiCanvas, attachCanvasTooltip) {
    const canvas = document.getElementById('recon-signal-canvas');
    if (!canvas) return;
    const { ctx, W, H } = hiDpiCanvas(canvas);
    const PAD_L = 50, PAD_R = 10, PAD_T = 10, PAD_B = 30;
    const plotW = W - PAD_L - PAD_R;
    const plotH = H - PAD_T - PAD_B;

    ctx.fillStyle = '#0d1117';
    ctx.fillRect(0, 0, W, H);

    const hist = landscape.histogram || {};
    const labels = ['<-80', '-80:-70', '-70:-60', '-60:-50', '-50:-40', '>-40'];
    const colors = ['#e63946', '#d4603a', '#d4993a', '#bbd42f', '#5ed42f', '#22c55e'];
    const vals = labels.map((l) => hist[l] || 0);
    const maxVal = Math.max(...vals, 1);
    const barW = Math.floor(plotW / labels.length) - 4;
    const hitRegions = [];

    for (let i = 0; i < labels.length; i++) {
        const barH = Math.max(Math.round((vals[i] / maxVal) * plotH), 2);
        const x = PAD_L + Math.round((i / labels.length) * plotW) + 2;
        const y = PAD_T + plotH - barH;

        ctx.fillStyle = colors[i];
        ctx.fillRect(x, y, barW, barH);
        hitRegions.push({ x, y, w: barW, h: barH, label: `${labels[i]} dBm: ${vals[i]} networks` });

        ctx.fillStyle = '#8b949e';
        ctx.font = '9px monospace';
        ctx.textAlign = 'center';
        ctx.fillText(labels[i], x + barW / 2, H - PAD_B + 12);

        if (vals[i] > 0) {
            ctx.fillStyle = '#c9d1d9';
            ctx.fillText(String(vals[i]), x + barW / 2, y - 3);
        }
    }

    ctx.save();
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px monospace';
    ctx.translate(12, PAD_T + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = 'center';
    ctx.fillText('networks', 0, 0);
    ctx.restore();

    attachCanvasTooltip(canvas, hitRegions);
}

function drawRelationshipGraph(graph, hiDpiCanvas, attachCanvasTooltip) {
    const canvas = document.getElementById('recon-graph-canvas');
    if (!canvas) return;
    const analytics = getCommsGraphAnalytics(graph);
    if (!analytics.nodes.length || !analytics.edges.length) return;

    const defaultNode = analytics.apInsights[0]?.node || analytics.clientInsights[0]?.node || analytics.targetInsights[0]?.node || analytics.nodes[0];
    let selectedId = canvas.dataset.selectedNodeId || defaultNode?.id || '';

    const renderSelection = (nodeId) => {
        const detail = document.getElementById('recon-graph-detail');
        if (!detail) return;
        detail.innerHTML = renderCommsGraphSelection(analytics.nodeMap.get(nodeId), analytics);
    };

    const draw = (nodeId) => {
        const { ctx, W, H } = hiDpiCanvas(canvas);
        ctx.fillStyle = '#0d1117';
        ctx.fillRect(0, 0, W, H);

        const posMap = {};
        const cx = W / 2;
        const cy = H / 2 + 4;
        const baseRadius = Math.min(W, H);
        const rAp = baseRadius * 0.17;
        const rTarget = baseRadius * 0.29;
        const rClient = baseRadius * 0.42;

        const placeRing = (collection, radius, offset = -Math.PI / 2) => {
            collection.forEach((node, index) => {
                const angle = offset + ((Math.PI * 2) * index) / Math.max(collection.length, 1);
                posMap[node.id] = {
                    x: cx + radius * Math.cos(angle),
                    y: cy + radius * Math.sin(angle),
                };
            });
        };

        placeRing(analytics.aps, rAp);
        placeRing(analytics.targets, rTarget, -Math.PI / 2 + 0.15);
        placeRing(analytics.clients, rClient, -Math.PI / 2 + 0.35);

        const selectedNode = analytics.nodeMap.get(nodeId);
        const connectedEdges = new Set((analytics.adjacencyMap.get(nodeId) || []).map((edge) => `${edge.source}|${edge.target}|${edge.type}`));
        const connectedNodes = new Set([nodeId]);
        (analytics.adjacencyMap.get(nodeId) || []).forEach((edge) => {
            connectedNodes.add(edge.source);
            connectedNodes.add(edge.target);
        });

        ctx.save();
        ctx.strokeStyle = 'rgba(73, 89, 104, 0.45)';
        ctx.lineWidth = 1;
        ctx.setLineDash([6, 6]);
        [rAp, rTarget, rClient].forEach((radius) => {
            ctx.beginPath();
            ctx.arc(cx, cy, radius, 0, Math.PI * 2);
            ctx.stroke();
        });
        ctx.restore();

        ctx.font = '10px JetBrains Mono, monospace';
        ctx.textAlign = 'center';
        ctx.fillStyle = '#708392';
        ctx.fillText('Known APs', cx, cy - rAp - 12);
        if (analytics.targets.length) ctx.fillText('Unresolved SSIDs', cx, cy - rTarget - 10);
        ctx.fillText('Clients', cx, cy - rClient - 10);

        analytics.edges.forEach((edge) => {
            const src = posMap[edge.source];
            const tgt = posMap[edge.target];
            if (!src || !tgt) return;
            const edgeKey = `${edge.source}|${edge.target}|${edge.type}`;
            const isSelected = connectedEdges.has(edgeKey);
            ctx.save();
            ctx.strokeStyle = edge.type === 'probe_known'
                ? (isSelected ? 'rgba(64, 191, 255, 0.95)' : 'rgba(64, 191, 255, 0.34)')
                : (isSelected ? 'rgba(244, 185, 66, 0.92)' : 'rgba(244, 185, 66, 0.25)');
            ctx.lineWidth = isSelected ? 1.8 : 0.9;
            if (edge.type !== 'probe_known') ctx.setLineDash([4, 4]);
            if (selectedNode && !isSelected) ctx.globalAlpha = 0.22;
            ctx.beginPath();
            ctx.moveTo(src.x, src.y);
            ctx.lineTo(tgt.x, tgt.y);
            ctx.stroke();
            ctx.restore();
        });

        const hitRegions = [];
        analytics.nodes.forEach((node) => {
            const point = posMap[node.id];
            if (!point) return;
            const radius = node.type === 'ap' ? 7 : (node.type === 'ssid_target' ? 5.5 : 4.5);
            const isSelected = node.id === nodeId;
            const isConnected = connectedNodes.has(node.id);

            ctx.save();
            if (selectedNode && !isConnected) ctx.globalAlpha = 0.18;
            ctx.fillStyle = getCommsGraphNodeColor(node);
            ctx.beginPath();
            ctx.arc(point.x, point.y, isSelected ? radius + 2 : radius, 0, Math.PI * 2);
            ctx.fill();
            if (isSelected) {
                ctx.strokeStyle = '#f4f7fa';
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.arc(point.x, point.y, radius + 4.5, 0, Math.PI * 2);
                ctx.stroke();
            }
            ctx.restore();

            const tooltipBits = [getCommsGraphNodeTone(node), node.label || node.id];
            const linkCount = analytics.degreeMap.get(node.id) || 0;
            if (linkCount) tooltipBits.push(`${linkCount} link${linkCount === 1 ? '' : 's'}`);
            hitRegions.push({
                x: point.x - (radius + 4),
                y: point.y - (radius + 4),
                w: (radius + 4) * 2,
                h: (radius + 4) * 2,
                label: tooltipBits.join(' · '),
                nodeId: node.id,
            });
        });

        ctx.font = '10px JetBrains Mono, monospace';
        ctx.textAlign = 'left';
        ctx.fillStyle = '#94a7b4';
        ctx.fillText('Solid line = matched AP', 12, H - 22);
        ctx.fillStyle = '#caa35f';
        ctx.fillText('Dashed line = unresolved SSID target', 12, H - 10);

        attachCanvasTooltip(canvas, hitRegions);
        canvas.onclick = (event) => {
            const rect = canvas.getBoundingClientRect();
            const mx = event.clientX - rect.left;
            const my = event.clientY - rect.top;
            const hit = hitRegions.find((region) => mx >= region.x && mx <= region.x + region.w && my >= region.y && my <= region.y + region.h);
            if (!hit) return;
            selectedId = hit.nodeId;
            canvas.dataset.selectedNodeId = selectedId;
            draw(selectedId);
            renderSelection(selectedId);
        };
    };

    if (!analytics.nodeMap.has(selectedId)) selectedId = defaultNode?.id || '';
    canvas.dataset.selectedNodeId = selectedId;
    draw(selectedId);
    renderSelection(selectedId);
}

export function createCommsRenderer(deps) {
    const {
        API,
        reconState,
        tdcGet,
        tdcSet,
        getActiveTab,
        debounce,
        hiDpiCanvas,
        attachCanvasTooltip,
    } = deps;

    async function hydrateCommsSection(container, sectionKey) {
        const cacheKey = `comms:${sectionKey}`;
        if (tdcGet(cacheKey) != null) return;
        if (reconState.commsLoading[sectionKey]) return;

        reconState.commsLoading[sectionKey] = true;
        try {
            let data = null;
            if (sectionKey === 'graph') data = await API.getReconCommsRelationshipGraph().catch(() => null);
            else if (sectionKey === 'devices') data = await API.getReconCommsDeviceFingerprints().catch(() => null);
            else if (sectionKey === 'clusters') data = await API.getReconCommsColocation().catch(() => null);
            else if (sectionKey === 'spectrum') data = await API.getReconCommsSpectrum().catch(() => null);
            else if (sectionKey === 'signal') data = await API.getReconCommsSignalLandscape().catch(() => null);
            if (data != null) tdcSet(cacheKey, data);
        } finally {
            reconState.commsLoading[sectionKey] = false;
            if (container?.isConnected && getActiveTab() === 'comms') {
                renderComms(container);
            }
        }
    }

    async function renderComms(container) {
        let graph = tdcGet('comms:graph');
        let fingerprints = tdcGet('comms:devices');
        let colocation = tdcGet('comms:clusters');
        let spectrum = tdcGet('comms:spectrum');
        let landscape = tdcGet('comms:signal');

        if (reconState.commsResizeObserver) {
            reconState.commsResizeObserver.disconnect();
            reconState.commsResizeObserver = null;
        }

        let html = '<div class="recon-comms">';
        html += `<div class="recon-overview-card recon-panel-card">
            <div class="recon-overview-copy">
                <div class="recon-overview-title">Comms Intelligence</div>
                <div class="recon-overview-text">Multi-layer communication analysis: spectrum usage, signal strength, device census, geospatial clustering, and AP–client relationships.</div>
            </div>
            <div class="recon-overview-tags">
                <span class="recon-badge recon-badge--dim">Spectrum</span>
                <span class="recon-badge recon-badge--dim">Signal</span>
                <span class="recon-badge recon-badge--dim">Devices</span>
                <span class="recon-badge recon-badge--dim">Clusters</span>
                <span class="recon-badge recon-badge--dim">Graph</span>
            </div>
        </div>`;

        html += `<div class="recon-surface-search"><input type="text" class="recon-search-input" id="comms-search" placeholder="Search SSID / MAC / vendor / cluster…" value="${escapeHtml(reconState.commsSearch)}"></div>`;

        const collapsed = reconState.commsCollapsed;
        const commsQ = reconState.commsSearch.toLowerCase();
        html += renderCommsSection('spectrum', 'SPECTRUM ANALYSIS', collapsed, () => spectrum ? renderCommsSpectrum(spectrum) : renderCommsSectionLoading('Loading spectrum analysis…'));
        html += renderCommsSection('signal', 'SIGNAL LANDSCAPE', collapsed, () => landscape ? renderCommsSignalLandscape(landscape, commsQ) : renderCommsSectionLoading('Loading signal landscape…'));
        html += renderCommsSection('devices', 'DEVICE INTELLIGENCE', collapsed, () => fingerprints ? renderCommsDeviceIntel(fingerprints, commsQ) : renderCommsSectionLoading('Loading device intelligence…'));
        html += renderCommsSection('vendors', 'TOP VENDORS', collapsed, () => fingerprints ? renderCommsTopVendors(fingerprints, commsQ) : renderCommsSectionLoading('Loading vendor breakdown…'));
        html += renderCommsSection('clusters', 'CLUSTER INTELLIGENCE', collapsed, () => colocation ? renderCommsClusters(colocation, commsQ) : renderCommsSectionLoading('Loading cluster intelligence…'));
        html += renderCommsSection('graph', 'COMMUNICATION GRAPH', collapsed, () => graph ? renderCommsGraph(graph) : renderCommsSectionLoading('Loading communication graph…'));
        html += '</div>';
        container.innerHTML = html;

        if (graph && (graph.probe_context?.available || graph.client_count > 0 || (graph.edges || []).length > 0 || graph.ssid_target_count > 0)) {
            drawRelationshipGraph(graph, hiDpiCanvas, attachCanvasTooltip);
        }
        if (spectrum && (spectrum.channels || []).length > 0) {
            drawSpectrumChart(spectrum, hiDpiCanvas, attachCanvasTooltip);
        }
        if (landscape && landscape.histogram) {
            drawRssiHistogram(landscape, hiDpiCanvas, attachCanvasTooltip);
        }

        if (typeof ResizeObserver !== 'undefined') {
            const resizeRedraw = debounce(() => {
                if (spectrum && (spectrum.channels || []).length > 0) drawSpectrumChart(spectrum, hiDpiCanvas, attachCanvasTooltip);
                if (landscape && landscape.histogram) drawRssiHistogram(landscape, hiDpiCanvas, attachCanvasTooltip);
                if (graph && (graph.probe_context?.available || graph.client_count > 0 || (graph.edges || []).length > 0 || graph.ssid_target_count > 0)) drawRelationshipGraph(graph, hiDpiCanvas, attachCanvasTooltip);
            }, 200);
            const ro = new ResizeObserver(resizeRedraw);
            const commsEl = container.querySelector('.recon-comms');
            if (commsEl) ro.observe(commsEl);
            reconState.commsResizeObserver = ro;
        }

        container.querySelectorAll('[data-comms-toggle]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const target = container.querySelector(`[data-comms-expand="${btn.dataset.commsToggle}"]`);
                if (target) {
                    const open = target.style.display !== 'none';
                    target.style.display = open ? 'none' : 'block';
                    btn.textContent = open ? '▸ details' : '▾ hide';
                }
            });
        });

        container.querySelectorAll('[data-comms-section]').forEach((btn) => {
            btn.addEventListener('click', () => {
                const key = btn.dataset.commsSection;
                if (collapsed.has(key)) collapsed.delete(key);
                else collapsed.add(key);
                renderComms(container);
            });
        });

        const searchInput = container.querySelector('#comms-search');
        if (searchInput) {
            const rerender = debounce(() => {
                reconState.commsSearch = searchInput.value;
                renderComms(container);
            }, 300);
            searchInput.addEventListener('input', rerender);
            searchInput.focus();
            searchInput.setSelectionRange(searchInput.value.length, searchInput.value.length);
        }

        if (!spectrum && !collapsed.has('spectrum')) hydrateCommsSection(container, 'spectrum');
        if (!landscape && !collapsed.has('signal')) hydrateCommsSection(container, 'signal');
        if (!fingerprints && (!collapsed.has('devices') || !collapsed.has('vendors'))) hydrateCommsSection(container, 'devices');
        if (!colocation && !collapsed.has('clusters')) hydrateCommsSection(container, 'clusters');
        if (!graph && !collapsed.has('graph')) hydrateCommsSection(container, 'graph');
    }

    return {
        renderComms,
    };
}
