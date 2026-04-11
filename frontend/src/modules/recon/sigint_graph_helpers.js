import { escapeHtml } from '../utils.js';
import { focusReconGeoHypothesis } from '../map.js';
import {
    formatReconDeviceLabel,
    formatReconSourceLabel,
    getReconSecurityColor,
    normalizeReconSecurityLabel,
    renderReconSecurityMiniBar,
    renderReconSourceMiniBar,
} from './ui_helpers.js';

export function formatSigintVendor(client) {
    const vendor = String(client?.vendor || '').trim();
    if (vendor && vendor.toLowerCase() !== 'unknown') return vendor;
    return 'Unknown vendor';
}

export function formatSigintEpochDate(epoch) {
    if (epoch == null) return '—';
    const date = new Date(Number(epoch) * 1000);
    if (!Number.isFinite(date.getTime())) return '—';
    return date.toLocaleString();
}

export function formatSigintGeoWindow(client) {
    const first = formatSigintEpochDate(client?.first_seen);
    const last = formatSigintEpochDate(client?.last_seen);
    if (first === '—' && last === '—') return 'Time window unavailable';
    if (first === last) return first;
    return `${first} → ${last}`;
}

export function getSigintGeoConfidenceClass(level) {
    const normalized = String(level || 'low').trim().toLowerCase();
    if (normalized === 'high') return 'recon-mini-badge--pmkid';
    if (normalized === 'medium') return 'recon-mini-badge--eapol';
    return '';
}

export function formatSigintGeoContext(located) {
    const parts = [];
    if (located?.dominant_encryption) {
        parts.push(normalizeReconSecurityLabel(located.dominant_encryption));
    }
    if (located?.dominant_device_type) {
        parts.push(formatReconDeviceLabel(located.dominant_device_type));
    }
    if (Array.isArray(located?.sources) && located.sources.length) {
        parts.push(located.sources.slice(0, 2).map((src) => formatReconSourceLabel(src)).join('/'));
    }
    return parts.join(' · ') || 'Known network';
}

function sigintGeoLocalMeters(lat, lng, centerLat, centerLng) {
    const metersPerDegLat = 111320;
    const metersPerDegLng = metersPerDegLat * Math.max(Math.cos((centerLat * Math.PI) / 180), 0.0001);
    return {
        x: (lng - centerLng) * metersPerDegLng,
        y: (centerLat - lat) * metersPerDegLat,
    };
}

function renderSigintGeoPreview(client) {
    const centerLat = Number(client?.estimated_center?.lat);
    const centerLng = Number(client?.estimated_center?.lng);
    const points = Array.isArray(client?.located_ssids) ? client.located_ssids : [];
    if (!Number.isFinite(centerLat) || !Number.isFinite(centerLng) || !points.length) {
        return '<div class="recon-geocorr-preview recon-geocorr-preview--empty"><span>No spatial preview</span></div>';
    }

    const width = 168;
    const height = 108;
    const padding = 12;
    const radiusM = Math.max(Number(client?.estimated_radius_m) || 0, 50);
    const plotRadius = radiusM * 1.25;
    const localPoints = points
        .map((point) => {
            const lat = Number(point?.lat);
            const lng = Number(point?.lng);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
            return {
                ...point,
                ...sigintGeoLocalMeters(lat, lng, centerLat, centerLng),
            };
        })
        .filter(Boolean);
    const extent = Math.max(
        plotRadius,
        ...localPoints.map((point) => Math.max(Math.abs(point.x), Math.abs(point.y))),
        60,
    );
    const innerW = width - padding * 2;
    const innerH = height - padding * 2;
    const scale = Math.min(innerW, innerH) / (extent * 2);
    const centerX = width / 2;
    const centerY = height / 2;
    const circleRadius = Math.max(8, radiusM * scale);

    const dots = localPoints.map((point, index) => {
        const x = centerX + point.x * scale;
        const y = centerY + point.y * scale;
        const fill = getReconSecurityColor(normalizeReconSecurityLabel(point.dominant_encryption || 'UNKNOWN'));
        return `<circle cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="4.2" fill="${fill}" opacity="0.9">
            <title>${escapeHtml(`${point.ssid} · ${formatSigintGeoContext(point)}`)}</title>
        </circle>
        <text x="${(x + 6).toFixed(2)}" y="${(y - 5).toFixed(2)}" class="recon-geocorr-preview-label">${index + 1}</text>`;
    }).join('');

    return `<div class="recon-geocorr-preview">
        <svg viewBox="0 0 ${width} ${height}" class="recon-geocorr-preview-svg" aria-hidden="true">
            <rect x="0.5" y="0.5" width="${width - 1}" height="${height - 1}" rx="10" ry="10" class="recon-geocorr-preview-frame"></rect>
            <line x1="${padding}" y1="${centerY}" x2="${width - padding}" y2="${centerY}" class="recon-geocorr-preview-axis"></line>
            <line x1="${centerX}" y1="${padding}" x2="${centerX}" y2="${height - padding}" class="recon-geocorr-preview-axis"></line>
            <circle cx="${centerX}" cy="${centerY}" r="${circleRadius.toFixed(2)}" class="recon-geocorr-preview-ring"></circle>
            <circle cx="${centerX}" cy="${centerY}" r="4.8" class="recon-geocorr-preview-center"></circle>
            ${dots}
        </svg>
    </div>`;
}

function renderSigintGeocorrelationCard(client, index) {
    const totalProbedSsids = Math.max(Number(client?.total_probed_ssids) || 0, Number(client?.matched_ssid_count) || 0, 1);
    const matchedPct = Math.round((Number(client?.known_match_ratio) || 0) * 100);
    const ambiguity = String(client?.ambiguity_level || 'low').trim().toLowerCase();
    let ambiguityTitle = 'Convergent hypothesis';
    let ambiguityText = 'Known SSID matches converge into one dominant area.';
    if (ambiguity === 'high') {
        ambiguityTitle = 'Ambiguous hypothesis';
        ambiguityText = 'Multiple spatially distinct hypotheses compete for this client.';
    } else if (ambiguity === 'medium') {
        ambiguityTitle = 'Alternative hypotheses';
        ambiguityText = 'There are alternative candidate areas, but one cluster still leads.';
    }
    const locatedRows = (client?.located_ssids || []).slice(0, 5).map((located) => `
        <div class="recon-geocorr-ssid-row">
            <div class="recon-geocorr-ssid-main">
                <span class="recon-chip recon-chip--geo">${escapeHtml(located.ssid || 'Unknown')}</span>
                <span class="recon-geocorr-ssid-count">${Number(located.network_count) || 0} nets</span>
            </div>
            <div class="recon-geocorr-ssid-meta">
                <span>${escapeHtml(formatSigintGeoContext(located))}</span>
                <span>${located?.distance_to_center_m != null ? `${escapeHtml(String(located.distance_to_center_m))}m from center` : 'Distance unavailable'}</span>
            </div>
        </div>
    `).join('');

    return `<div class="recon-geocorr-card">
        <div class="recon-geocorr-head">
            <div>
                <div class="recon-geocorr-mac">${escapeHtml(client?.client_mac || 'Unknown client')}</div>
                <div class="recon-geocorr-vendor">${escapeHtml(formatSigintVendor(client))} · ${escapeHtml(client?.oui_prefix || client?.client_mac?.slice(0, 8) || 'Unknown OUI')}</div>
            </div>
            <div class="recon-geocorr-badges">
                <span class="recon-mini-badge ${getSigintGeoConfidenceClass(client?.confidence)}">${escapeHtml(client?.confidence || 'low')}</span>
                <span class="recon-badge">${Math.round(Number(client?.estimated_radius_m) || 0)}m</span>
            </div>
        </div>
        <div class="recon-geocorr-window">${escapeHtml(formatSigintGeoWindow(client))}</div>
        <div class="recon-geocorr-summary-grid">
            <div class="recon-geocorr-summary-item">
                <span class="recon-geocorr-summary-val">${Number(client?.matched_ssid_count) || 0}/${totalProbedSsids}</span>
                <span class="recon-geocorr-summary-label">Known SSIDs</span>
            </div>
            <div class="recon-geocorr-summary-item">
                <span class="recon-geocorr-summary-val">${Number(client?.match_count) || 0}</span>
                <span class="recon-geocorr-summary-label">Matched networks</span>
            </div>
            <div class="recon-geocorr-summary-item">
                <span class="recon-geocorr-summary-val">${matchedPct}%</span>
                <span class="recon-geocorr-summary-label">Match ratio</span>
            </div>
        </div>
        <div class="recon-geocorr-ambiguity recon-geocorr-ambiguity--${escapeHtml(ambiguity)}">
            <strong>${escapeHtml(ambiguityTitle)}</strong>
            <span>${escapeHtml(ambiguityText)}</span>
        </div>
        ${renderSigintGeoPreview(client)}
        ${renderReconSourceMiniBar(client?.source_breakdown, {
            className: 'recon-geocorr-origins',
            legendLimit: 4,
        })}
        ${renderReconSecurityMiniBar(client?.security_breakdown, {
            compact: true,
            title: 'Security',
            legendLimit: 4,
            className: 'recon-geocorr-security',
        })}
        <div class="recon-geocorr-sub">Correlated SSIDs</div>
        <div class="recon-geocorr-ssids">${locatedRows || '<span class="recon-muted">No correlated SSIDs in the selected hypothesis.</span>'}</div>
        <div class="recon-geocorr-actions">
            <button class="recon-btn recon-btn--sm recon-geocorr-focus-btn" data-geo-focus="${index}"><i class="fa-solid fa-location-crosshairs"></i> Focus on map</button>
            <span class="recon-geocorr-actions-meta">${Number(client?.alternative_cluster_count) || 0} alternative cluster${Number(client?.alternative_cluster_count) === 1 ? '' : 's'}</span>
        </div>
    </div>`;
}

export function renderSigintGeocorrelationPanel(payload) {
    const clients = Array.isArray(payload?.clients) ? payload.clients : [];
    const summary = payload?.summary || {};
    if (!clients.length) {
        return `<div class="recon-empty-state recon-empty-state--soft">
            <i class="fa-solid fa-location-crosshairs"></i>
            <div>
                <strong>No geocorrelation hypotheses yet</strong>
                <span>${escapeHtml(payload?.message || 'Run Probe Intelligence first, then collect GPS-tagged networks so Recon can correlate client probes with known locations.')}</span>
            </div>
        </div>`;
    }

    return `<div class="recon-geocorr-panel">
        <div class="recon-kpi-row recon-kpi-row--compact">
            <div class="recon-kpi"><span class="recon-kpi-val">${Number(summary.correlated_clients) || clients.length}</span><span class="recon-kpi-label">CORRELATED</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${Number(summary.high_confidence_clients) || 0}</span><span class="recon-kpi-label">HIGH CONF</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${Number(summary.matched_networks) || 0}</span><span class="recon-kpi-label">MATCHED NETS</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${summary.median_radius_m != null ? `${Math.round(Number(summary.median_radius_m) || 0)}m` : '—'}</span><span class="recon-kpi-label">MEDIAN RADIUS</span></div>
        </div>
        <div class="recon-section-note">Location hypotheses inferred from probe-request SSIDs that also exist as GPS-tagged networks in the current Recon dataset.</div>
        <div class="recon-geocorr-grid">${clients.map((client, index) => renderSigintGeocorrelationCard(client, index)).join('')}</div>
    </div>`;
}

export function bindSigintGeocorrelationActions(container, clients) {
    container.querySelectorAll('[data-geo-focus]').forEach((button) => {
        button.addEventListener('click', () => {
            const index = Number(button.dataset.geoFocus);
            const client = clients[index];
            if (!client) return;
            focusReconGeoHypothesis({
                center: client.estimated_center,
                radius_m: client.estimated_radius_m,
                points: (client.located_ssids || []).map((item) => ({ lat: item.lat, lng: item.lng })),
            });
        });
    });
}

export function getCommsGraphAnalytics(graph) {
    const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
    const nodeMap = new Map(nodes.map((node) => [node.id, node]));
    const validEdges = (graph?.edges || []).filter((edge) => nodeMap.has(edge.source) && nodeMap.has(edge.target));
    const aps = nodes.filter((node) => node.type === 'ap');
    const clients = nodes.filter((node) => node.type === 'client');
    const targets = nodes.filter((node) => node.type === 'ssid_target');
    const adjacencyMap = new Map(nodes.map((node) => [node.id, []]));
    const degreeMap = new Map(nodes.map((node) => [node.id, 0]));
    const knownLinks = [];
    const unresolvedLinks = [];

    validEdges.forEach((edge) => {
        adjacencyMap.get(edge.source)?.push(edge);
        adjacencyMap.get(edge.target)?.push(edge);
        degreeMap.set(edge.source, (degreeMap.get(edge.source) || 0) + 1);
        degreeMap.set(edge.target, (degreeMap.get(edge.target) || 0) + 1);
        if (edge.type === 'probe_known') knownLinks.push(edge);
        else unresolvedLinks.push(edge);
    });

    const toInsights = (collection, type) => collection
        .map((node) => {
            const linkedEdges = adjacencyMap.get(node.id) || [];
            const peers = linkedEdges
                .map((edge) => {
                    const peerId = edge.source === node.id ? edge.target : edge.source;
                    return nodeMap.get(peerId);
                })
                .filter(Boolean);
            const uniquePeers = Array.from(new Map(peers.map((peer) => [peer.id, peer])).values());
            const knownCount = linkedEdges.filter((edge) => edge.type === 'probe_known').length;
            const unresolvedCount = linkedEdges.filter((edge) => edge.type !== 'probe_known').length;
            return {
                node,
                type,
                linkedEdges,
                peers: uniquePeers,
                peerCount: uniquePeers.length,
                linkCount: linkedEdges.length,
                knownCount,
                unresolvedCount,
            };
        })
        .sort((a, b) => b.linkCount - a.linkCount || b.peerCount - a.peerCount || String(a.node.label || a.node.id).localeCompare(String(b.node.label || b.node.id)));

    return {
        nodes,
        nodeMap,
        edges: validEdges,
        aps,
        clients,
        targets,
        adjacencyMap,
        degreeMap,
        knownLinks,
        unresolvedLinks,
        apInsights: toInsights(aps, 'ap'),
        clientInsights: toInsights(clients, 'client'),
        targetInsights: toInsights(targets, 'ssid_target'),
    };
}

export function getCommsGraphNodeColor(node) {
    if (!node) return '#7a8b92';
    if (node.type === 'ap') return node.has_password ? '#22c55e' : '#e63946';
    if (node.type === 'ssid_target') return '#f4b942';
    if (node.type === 'client') return '#2faad4';
    return '#7a8b92';
}

export function getCommsGraphNodeTone(node) {
    if (!node) return 'Unknown';
    if (node.type === 'ap') return node.has_password ? 'AP (cracked)' : 'AP (locked)';
    if (node.type === 'ssid_target') return 'Unresolved SSID';
    if (node.type === 'client') return 'Client';
    return 'Node';
}

export function renderCommsGraphTopList(title, rows, formatter) {
    if (!rows.length) {
        return `<div class="recon-comms-graph-panel">
            <div class="recon-comms-graph-panel-title">${escapeHtml(title)}</div>
            <div class="recon-muted">No entries yet.</div>
        </div>`;
    }

    return `<div class="recon-comms-graph-panel">
        <div class="recon-comms-graph-panel-title">${escapeHtml(title)}</div>
        <div class="recon-comms-graph-list">${rows.map((row, index) => formatter(row, index)).join('')}</div>
    </div>`;
}

export function renderCommsGraphSelectionPlaceholder() {
    return `<div class="recon-comms-graph-panel recon-comms-graph-panel--selection" id="recon-graph-detail">
        <div class="recon-comms-graph-panel-title">Selected Node</div>
        <div class="recon-muted">Click a node in the graph to inspect its links and peers.</div>
    </div>`;
}

export function renderCommsGraphSelection(node, analytics) {
    if (!node) {
        return `<div class="recon-comms-graph-panel-title">Selected Node</div><div class="recon-muted">No node selected.</div>`;
    }

    const linkedEdges = analytics.adjacencyMap.get(node.id) || [];
    const peers = linkedEdges
        .map((edge) => analytics.nodeMap.get(edge.source === node.id ? edge.target : edge.source))
        .filter(Boolean);
    const uniquePeers = Array.from(new Map(peers.map((peer) => [peer.id, peer])).values());
    const knownLinks = linkedEdges.filter((edge) => edge.type === 'probe_known').length;
    const unresolvedLinks = linkedEdges.filter((edge) => edge.type !== 'probe_known').length;
    const chips = [];

    if (node.type === 'ap') {
        chips.push(`<span class="recon-comms-graph-chip">${knownLinks} client link${knownLinks === 1 ? '' : 's'}</span>`);
        chips.push(`<span class="recon-comms-graph-chip">${escapeHtml(normalizeReconSecurityLabel(node.encryption || 'UNKNOWN'))}</span>`);
        chips.push(`<span class="recon-comms-graph-chip">${node.has_password ? 'Cracked' : 'Locked'}</span>`);
    } else if (node.type === 'client') {
        chips.push(`<span class="recon-comms-graph-chip">${node.probe_count || 0} probes</span>`);
        chips.push(`<span class="recon-comms-graph-chip">${knownLinks} known AP${knownLinks === 1 ? '' : 's'}</span>`);
        chips.push(`<span class="recon-comms-graph-chip">${unresolvedLinks} unresolved target${unresolvedLinks === 1 ? '' : 's'}</span>`);
        if (node.avg_signal != null) chips.push(`<span class="recon-comms-graph-chip">${node.avg_signal} dBm avg</span>`);
    } else if (node.type === 'ssid_target') {
        chips.push(`<span class="recon-comms-graph-chip">${uniquePeers.length} client${uniquePeers.length === 1 ? '' : 's'}</span>`);
        chips.push(`<span class="recon-comms-graph-chip">${unresolvedLinks} unresolved link${unresolvedLinks === 1 ? '' : 's'}</span>`);
    }

    let note = '';
    if (node.type === 'ssid_target') {
        note = '<div class="recon-comms-graph-note">This SSID appeared in probe traffic but is not currently matched to a discovered AP in Recon.</div>';
    } else if (node.type === 'client') {
        note = '<div class="recon-comms-graph-note">Client nodes come from probe-request analysis and show what networks the device searched for.</div>';
    }

    const peerPreview = uniquePeers.slice(0, 5);
    return `<div class="recon-comms-graph-panel-title">Selected Node</div>
        <div class="recon-comms-graph-selected-head">
            <span class="recon-comms-graph-selected-type">${escapeHtml(getCommsGraphNodeTone(node))}</span>
            <strong>${escapeHtml(node.label || node.id)}</strong>
        </div>
        <div class="recon-comms-graph-chip-row">${chips.join('')}</div>
        ${note}
        <div class="recon-comms-graph-peer-title">Connected peers</div>
        ${peerPreview.length ? `<div class="recon-comms-graph-peer-list">${peerPreview.map((peer) => `
            <span class="recon-comms-graph-peer">
                <span class="recon-comms-graph-peer-dot" style="--recon-graph-color:${getCommsGraphNodeColor(peer)}"></span>
                <span>${escapeHtml(peer.label || peer.id)}</span>
            </span>
        `).join('')}${uniquePeers.length > peerPreview.length ? `<span class="recon-comms-graph-more">+${uniquePeers.length - peerPreview.length} more</span>` : ''}</div>` : '<div class="recon-muted">No linked peers.</div>'}`;
}
