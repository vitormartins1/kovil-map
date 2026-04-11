import { STATE, saveLists } from './state.js';
import { API } from './api.js';
import { log, escapeHtml } from './utils.js';
import { mapAnalyticsSourceLabel } from './source_tags.js';
import {
    setAnalyticsHeatmapLayer,
    clearAnalyticsHeatmapLayer,
    setAnalyticsHotspotsLayer,
    clearAnalyticsHotspotsLayer,
    setSelectedAnalyticsHotspot,
    focusAnalyticsHotspot,
} from './map.js';

export function setAnalyticsWorkspaceActive(active) {
    const enabled = !!active;
    if (!STATE.ui || typeof STATE.ui !== 'object') STATE.ui = {};
    STATE.ui.analyticsWorkspaceActive = enabled;

    const hud = document.getElementById('hud-layer');
    if (hud) hud.classList.toggle('analytics-workspace-active', enabled);

    const analyticsLeftHotspotsPanel = document.getElementById('analytics-left-hotspots-panel');
    const analyticsLeftDetailsPanel = document.getElementById('analytics-left-details-panel');
    const analyticsRightFiltersPanel = document.getElementById('analytics-right-filters-panel');
    const analyticsRightChannelsPanel = document.getElementById('analytics-right-channels-panel');
    if (analyticsLeftHotspotsPanel) analyticsLeftHotspotsPanel.style.display = enabled ? 'flex' : 'none';
    if (analyticsLeftDetailsPanel) analyticsLeftDetailsPanel.style.display = enabled ? 'flex' : 'none';
    if (analyticsRightFiltersPanel) analyticsRightFiltersPanel.style.display = enabled ? 'flex' : 'none';
    if (analyticsRightChannelsPanel) analyticsRightChannelsPanel.style.display = enabled ? 'flex' : 'none';

    const zonesPanel = document.getElementById('zones-panel');
    const targetsPanel = document.getElementById('targets-panel');
    const favoritesPanel = document.getElementById('favorites-panel');
    const crackingPanel = document.getElementById('cracking-panel');
    const processPanel = document.getElementById('process-panel');
    const logPanel = document.getElementById('log-panel');

    if (enabled) {
        if (zonesPanel) zonesPanel.style.display = 'none';
        if (targetsPanel) targetsPanel.style.display = 'none';
        if (favoritesPanel) favoritesPanel.style.display = 'none';
        if (crackingPanel) crackingPanel.style.display = 'none';
        if (processPanel) processPanel.style.display = 'none';
        if (logPanel) logPanel.style.display = 'none';
    } else {
        if (zonesPanel) zonesPanel.style.display = STATE.modes.zones ? 'flex' : 'none';
        if (targetsPanel) targetsPanel.style.display = STATE.modes.targets ? 'flex' : 'none';
        if (favoritesPanel) favoritesPanel.style.display = STATE.modes.favs ? 'flex' : 'none';
        if (crackingPanel) crackingPanel.style.display = STATE.modes.cracking ? 'flex' : 'none';
        if (processPanel) processPanel.style.display = STATE.modes.process ? 'flex' : 'none';
        if (logPanel) logPanel.style.display = STATE.modes.logs ? 'block' : 'none';
    }

    ['btn-toggle-cracking', 'btn-process', 'btn-logs', 'btn-zones', 'btn-targets', 'btn-favs'].forEach((id) => {
        const btn = document.getElementById(id);
        if (btn) {
            btn.classList.toggle('suspended', enabled);
            btn.disabled = enabled;
        }
    });

    const rightPanelsContainer = document.querySelector('.right-panels-container');
    if (rightPanelsContainer) {
        const hasCracking = !!STATE?.modes?.cracking;
        const hasProcess = !!STATE?.modes?.process;
        const hasLogs = !!STATE?.modes?.logs;
        rightPanelsContainer.classList.toggle('right-panels--has-cracking', hasCracking);
        rightPanelsContainer.classList.toggle('right-panels--has-process', hasProcess);
        rightPanelsContainer.classList.toggle('right-panels--has-logs', hasLogs);
        rightPanelsContainer.classList.toggle('right-panels--only-cracking', hasCracking && !hasProcess && !hasLogs);
        rightPanelsContainer.classList.toggle('right-panels--only-process', hasProcess && !hasCracking && !hasLogs);
        rightPanelsContainer.classList.toggle('right-panels--only-logs', hasLogs && !hasCracking && !hasProcess);
    }

    const left = document.querySelector('.controls-row');
    const right = document.querySelector('.stats-container-wrapper');
    if (left && right) {
        left.style.height = 'auto';
        right.style.height = 'auto';
        const leftHeight = left.offsetHeight;
        const rightHeight = right.offsetHeight;
        const targetHeight = Math.max(leftHeight, rightHeight);
        if (targetHeight > 0) {
            left.style.height = `${targetHeight}px`;
            right.style.height = `${targetHeight}px`;
        }
    }
}

export function getAnalyticsUiState() {
    if (!STATE.analyticsUi || typeof STATE.analyticsUi !== 'object') {
        STATE.analyticsUi = {};
    }
    const defaults = {
        metric: 'opportunity',
        source: 'all',
        security: 'all',
        deviceType: 'all',
        dimension: 'channel',
        timeWindow: 'all',
        channel: 'all',
        heatmap: null,
        channelSummary: null,
        hotspots: [],
        selectedHotspotId: null,
    };
    Object.keys(defaults).forEach((key) => {
        if (STATE.analyticsUi[key] === undefined || STATE.analyticsUi[key] === null) {
            STATE.analyticsUi[key] = defaults[key];
        }
    });
    if (!['channel', 'device'].includes(String(STATE.analyticsUi.dimension || '').toLowerCase())) {
        STATE.analyticsUi.dimension = 'channel';
    }
    return STATE.analyticsUi;
}

export function persistAnalyticsUi() {
    const analyticsUi = getAnalyticsUiState();
    localStorage.setItem('pwn_analytics_metric', analyticsUi.metric);
    localStorage.setItem('pwn_analytics_source', analyticsUi.source);
    localStorage.setItem('pwn_analytics_security', analyticsUi.security);
    localStorage.setItem('pwn_analytics_device_type', analyticsUi.deviceType);
    localStorage.setItem('pwn_analytics_dimension', analyticsUi.dimension);
    localStorage.setItem('pwn_analytics_time_window', analyticsUi.timeWindow);
    localStorage.setItem('pwn_analytics_channel', analyticsUi.channel);
}

function getDeviceTypeLabel(deviceType) {
    const value = String(deviceType || 'unknown').toLowerCase();
    const map = {
        router_ap: 'Router AP',
        phone_hotspot: 'Phone Hotspot',
        camera_ap: 'Camera AP',
        printer_ap: 'Printer AP',
        iot_ap: 'IoT AP',
        unknown: 'Unknown',
        router: 'Router AP',
    };
    return map[value] || value.replace(/_/g, ' ');
}

function getSelectedAnalyticsHotspot() {
    const analyticsUi = getAnalyticsUiState();
    const hotspots = Array.isArray(analyticsUi.hotspots) ? analyticsUi.hotspots : [];
    if (!hotspots.length) return null;
    if (!analyticsUi.selectedHotspotId) return null;
    return hotspots.find((item) => String(item.id) === String(analyticsUi.selectedHotspotId)) || null;
}

function getTransportModeMeta(mode) {
    const value = String(mode || '').trim().toLowerCase();
    const map = {
        walk: { icon: 'fa-person-walking', label: 'Walk' },
        bike: { icon: 'fa-bicycle', label: 'Bike' },
        motorcycle: { icon: 'fa-motorcycle', label: 'Motorcycle' },
        boat: { icon: 'fa-ship', label: 'Boat' },
        plane: { icon: 'fa-plane', label: 'Plane' },
        helicopter: { icon: 'fa-helicopter', label: 'Helicopter' },
        car: { icon: 'fa-car-side', label: 'Car' },
        bus: { icon: 'fa-bus-simple', label: 'Bus' },
        train: { icon: 'fa-train', label: 'Train' },
        metro: { icon: 'fa-train-subway', label: 'Metro' },
    };
    return map[value] || { icon: 'fa-circle-question', label: value ? value.toUpperCase() : 'Unknown' };
}

function syncGlobalTimeButtons(timeWindow) {
    const is24h = String(timeWindow || 'all').toLowerCase() === '24h';
    const btn24h = document.getElementById('btn-24h');
    const btnAll = document.getElementById('btn-all');
    if (btn24h) btn24h.classList.toggle('active', is24h);
    if (btnAll) btnAll.classList.toggle('active', !is24h);
}

function renderAnalyticsControls() {
    const analyticsUi = getAnalyticsUiState();
    const metricSelect = document.getElementById('analytics-metric-select');
    const sourceSelect = document.getElementById('analytics-source-select');
    const securitySelect = document.getElementById('analytics-security-select');
    const deviceTypeSelect = document.getElementById('analytics-device-type-select');
    const timeWindowSelect = document.getElementById('analytics-time-window-select');
    const channelSelect = document.getElementById('analytics-channel-select');
    const btnDimensionChannel = document.getElementById('btn-analytics-dimension-channel');
    const btnDimensionDevice = document.getElementById('btn-analytics-dimension-device');

    if (metricSelect) metricSelect.value = analyticsUi.metric;
    if (sourceSelect) sourceSelect.value = analyticsUi.source;
    if (securitySelect) securitySelect.value = analyticsUi.security;
    if (deviceTypeSelect) deviceTypeSelect.value = analyticsUi.deviceType;
    if (timeWindowSelect) timeWindowSelect.value = analyticsUi.timeWindow;
    if (btnDimensionChannel) btnDimensionChannel.classList.toggle('active', analyticsUi.dimension === 'channel');
    if (btnDimensionDevice) btnDimensionDevice.classList.toggle('active', analyticsUi.dimension === 'device');

    if (channelSelect) {
        const previous = analyticsUi.channel || 'all';
        const summaryChannels = Array.isArray(analyticsUi.channelSummary?.channels)
            ? analyticsUi.channelSummary.channels
            : [];
        const options = ['<option value="all">ALL CH</option>'];
        summaryChannels.forEach((item) => {
            const ch = Number(item?.channel);
            if (!Number.isFinite(ch)) return;
            options.push(`<option value="${ch}">CH ${ch}</option>`);
        });
        channelSelect.innerHTML = options.join('');
        if (
            previous !== 'all'
            && !summaryChannels.some((item) => String(item?.channel) === String(previous))
        ) {
            analyticsUi.channel = 'all';
        }
        channelSelect.value = String(analyticsUi.channel || 'all');
    }
}

function renderAnalyticsWardriveContext() {
    const target = document.getElementById('analytics-wardrive-context');
    if (!target) return;
    const analyticsUi = getAnalyticsUiState();
    const context = analyticsUi.channelSummary?.wardrive_context || {};
    const sessionsCount = Number(context?.sessions_count || 0);
    const networksCount = Number(context?.networks_count || 0);
    const pointsCount = Number(context?.points_count || 0);
    const topModes = Array.isArray(context?.top_transport_modes)
        ? context.top_transport_modes.slice(0, 8)
        : [];

    const topModesHtml = topModes.length
        ? topModes.map((item) => {
            const meta = getTransportModeMeta(item?.transport_mode);
            return `
                <span class="analytics-wardrive-mode-pill">
                    <i class="fa-solid ${escapeHtml(meta.icon)}"></i>
                    <span>${escapeHtml(meta.label)}</span>
                    <small>${escapeHtml(String(item?.networks_count ?? 0))} NET</small>
                </span>
            `;
        }).join('')
        : '<span class="analytics-wardrive-empty">No vehicle tags yet.</span>';

    target.innerHTML = `
        <div class="analytics-wardrive-header">
            <i class="fa-solid fa-route"></i>
            <span>WarDrive Context</span>
        </div>
        <div class="analytics-wardrive-kpis">
            <span class="analytics-wardrive-kpi">SESS ${escapeHtml(String(sessionsCount))}</span>
            <span class="analytics-wardrive-kpi">NET ${escapeHtml(String(networksCount))}</span>
            <span class="analytics-wardrive-kpi">PTS ${escapeHtml(String(pointsCount))}</span>
        </div>
        <div class="analytics-wardrive-top">
            ${topModesHtml}
        </div>
    `;
}

function renderAnalyticsKpis() {
    const analyticsUi = getAnalyticsUiState();
    const heatmap = analyticsUi.heatmap || {};
    const stats = heatmap.stats || {};
    const hotspots = Array.isArray(analyticsUi.hotspots) ? analyticsUi.hotspots : [];

    const networksEl = document.getElementById('analytics-kpi-networks');
    const cellsEl = document.getElementById('analytics-kpi-cells');
    const hotspotsEl = document.getElementById('analytics-kpi-hotspots');
    const valueEl = document.getElementById('analytics-kpi-value');

    if (networksEl) networksEl.textContent = String(Number(stats.networks_count || 0));
    if (cellsEl) cellsEl.textContent = String(Number(stats.cells_count || 0));
    if (hotspotsEl) hotspotsEl.textContent = String(hotspots.length);
    if (valueEl) valueEl.textContent = String(Number(stats.value_avg || 0).toFixed(1));
}

function renderAnalyticsChannelSummary() {
    const analyticsUi = getAnalyticsUiState();
    const tbody = document.getElementById('analytics-channel-body');
    const head = document.getElementById('analytics-channel-head');
    if (!tbody) return;

    const dimension = analyticsUi.dimension === 'device' ? 'device' : 'channel';
    if (head) {
        head.innerHTML = dimension === 'device'
            ? '<th>TYPE</th><th>NET</th><th>LCK</th><th>EAPOL</th><th>SCORE</th>'
            : '<th>CH</th><th>NET</th><th>LCK</th><th>EAPOL</th><th>SCORE</th>';
    }

    if (dimension === 'device') {
        const deviceRows = Array.isArray(analyticsUi.channelSummary?.device_summary)
            ? analyticsUi.channelSummary.device_summary
            : [];
        if (!deviceRows.length) {
            tbody.innerHTML = '<tr><td colspan="5">No device summary available.</td></tr>';
            return;
        }
        tbody.innerHTML = deviceRows.slice(0, 24).map((item) => {
            const score = Number(item?.opportunity_score || 0);
            return `
                <tr>
                    <td>${escapeHtml(getDeviceTypeLabel(item?.device_type))}</td>
                    <td>${escapeHtml(String(item?.networks ?? 0))}</td>
                    <td>${escapeHtml(String(item?.locked ?? 0))}</td>
                    <td>${escapeHtml(String(item?.raw_eapol_networks ?? 0))}</td>
                    <td>${escapeHtml(String(score))}</td>
                </tr>
            `;
        }).join('');
        return;
    }

    const channels = Array.isArray(analyticsUi.channelSummary?.channels)
        ? analyticsUi.channelSummary.channels
        : [];
    if (!channels.length) {
        tbody.innerHTML = '<tr><td colspan="5">No channel summary available.</td></tr>';
        return;
    }

    tbody.innerHTML = channels.slice(0, 24).map((item) => {
        const score = Number(item?.opportunity_score || 0);
        return `
            <tr>
                <td>${escapeHtml(String(item?.channel ?? '-'))}</td>
                <td>${escapeHtml(String(item?.networks ?? 0))}</td>
                <td>${escapeHtml(String(item?.locked ?? 0))}</td>
                <td>${escapeHtml(String(item?.raw_eapol_networks ?? 0))}</td>
                <td>${escapeHtml(String(score))}</td>
            </tr>
        `;
    }).join('');
}

function renderAnalyticsCharts() {
    const analyticsUi = getAnalyticsUiState();
    const channelTarget = document.getElementById('analytics-chart-channel-pressure');
    const sourceTarget = document.getElementById('analytics-chart-source-mix');
    const securityTarget = document.getElementById('analytics-chart-security-mix');
    const pressureTitle = document.getElementById('analytics-pressure-title');
    if (!channelTarget && !sourceTarget && !securityTarget) return;

    const channels = Array.isArray(analyticsUi.channelSummary?.channels)
        ? analyticsUi.channelSummary.channels
        : [];
    const deviceRows = Array.isArray(analyticsUi.channelSummary?.device_summary)
        ? analyticsUi.channelSummary.device_summary
        : [];
    const hotspots = Array.isArray(analyticsUi.hotspots) ? analyticsUi.hotspots : [];
    const dimension = analyticsUi.dimension === 'device' ? 'device' : 'channel';

    if (pressureTitle) pressureTitle.textContent = dimension === 'device' ? 'DEVICE PRESSURE' : 'CHANNEL PRESSURE';

    if (channelTarget) {
        const rows = (dimension === 'device' ? deviceRows : channels)
            .filter((item) => Number.isFinite(Number(item?.opportunity_score)))
            .slice(0, 6);
        const maxScore = rows.reduce((acc, item) => Math.max(acc, Number(item?.opportunity_score || 0)), 0);
        if (!rows.length || maxScore <= 0) {
            channelTarget.innerHTML = `<div class="analytics-chart-empty">No ${dimension} pressure data.</div>`;
        } else {
            channelTarget.innerHTML = rows.map((item) => {
                const score = Number(item?.opportunity_score || 0);
                const pct = Math.max(4, Math.round((score / maxScore) * 100));
                const label = dimension === 'device'
                    ? getDeviceTypeLabel(item?.device_type)
                    : `CH ${String(item?.channel ?? '-')}`;
                return `
                    <div class="analytics-chart-row">
                        <span class="analytics-chart-label">${escapeHtml(label)}</span>
                        <span class="analytics-chart-track"><span class="analytics-chart-fill" style="width:${pct}%"></span></span>
                        <span class="analytics-chart-value">${escapeHtml(String(score))}</span>
                    </div>
                `;
            }).join('');
        }
    }

    if (sourceTarget) {
        const sourceCounter = new Map();
        hotspots.forEach((hotspot) => {
            const topSources = Array.isArray(hotspot?.top_sources) ? hotspot.top_sources : [];
            topSources.forEach((sourceName, idx) => {
                const key = String(sourceName || '').trim().toUpperCase();
                if (!key) return;
                const weight = Math.max(1, 3 - idx);
                sourceCounter.set(key, (sourceCounter.get(key) || 0) + weight);
            });
        });
        const sourceRows = Array.from(sourceCounter.entries())
            .sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0))
            .slice(0, 6);
        const maxCount = sourceRows.reduce((acc, row) => Math.max(acc, Number(row[1] || 0)), 0);
        if (!sourceRows.length || maxCount <= 0) {
            sourceTarget.innerHTML = '<div class="analytics-chart-empty">No source mix data.</div>';
        } else {
            sourceTarget.innerHTML = sourceRows.map(([sourceName, count]) => {
                const pct = Math.max(4, Math.round((Number(count || 0) / maxCount) * 100));
                const label = mapAnalyticsSourceLabel(sourceName);
                return `
                    <div class="analytics-chart-row">
                        <span class="analytics-chart-label">${escapeHtml(label)}</span>
                        <span class="analytics-chart-track"><span class="analytics-chart-fill analytics-chart-fill--source" style="width:${pct}%"></span></span>
                        <span class="analytics-chart-value">${escapeHtml(String(count))}</span>
                    </div>
                `;
            }).join('');
        }
    }

    if (securityTarget) {
        const totals = channels.reduce((acc, item) => {
            acc.locked += Number(item?.locked || 0);
            acc.open += Number(item?.open || 0);
            acc.cracked += Number(item?.cracked || 0);
            return acc;
        }, { locked: 0, open: 0, cracked: 0 });
        const total = Math.max(0, Number(totals.locked + totals.open + totals.cracked));
        if (total <= 0) {
            securityTarget.innerHTML = '<div class="analytics-chart-empty">No security mix data.</div>';
        } else {
            const lockedPct = Math.round((totals.locked / total) * 100);
            const openPct = Math.round((totals.open / total) * 100);
            const crackedPct = Math.max(0, 100 - lockedPct - openPct);
            securityTarget.innerHTML = `
                <div class="analytics-security-track">
                    <span class="analytics-security-segment analytics-security-segment--locked" style="width:${lockedPct}%"></span>
                    <span class="analytics-security-segment analytics-security-segment--open" style="width:${openPct}%"></span>
                    <span class="analytics-security-segment analytics-security-segment--cracked" style="width:${crackedPct}%"></span>
                </div>
                <div class="analytics-security-legend">
                    <span class="analytics-security-pill analytics-security-pill--locked">LOCKED ${escapeHtml(String(totals.locked))}</span>
                    <span class="analytics-security-pill analytics-security-pill--open">OPEN ${escapeHtml(String(totals.open))}</span>
                    <span class="analytics-security-pill analytics-security-pill--cracked">CRACKED ${escapeHtml(String(totals.cracked))}</span>
                </div>
            `;
        }
    }
}

function renderAnalyticsHotspotsList() {
    const analyticsUi = getAnalyticsUiState();
    const list = document.getElementById('analytics-hotspots-list');
    if (!list) return;

    const hotspots = Array.isArray(analyticsUi.hotspots) ? analyticsUi.hotspots : [];
    if (!hotspots.length) {
        list.innerHTML = '<div style="padding: 10px; color:#777;">No hotspots yet.</div>';
        return;
    }

    list.innerHTML = hotspots.map((item) => {
        const isSelected = String(item.id) === String(analyticsUi.selectedHotspotId || '');
        const score = Number(item.score || 0);
        const networksCount = Number(item.networks_count || 0);
        const lockedCount = Number(item.locked_count || 0);
        const rawId = String(item.id || '').trim();
        const code = rawId
            ? (rawId.toUpperCase().startsWith('H') ? rawId.toUpperCase() : `H${rawId}`)
            : '-';
        return `
            <div class="list-item${isSelected ? ' selected' : ''}" data-hotspot-id="${escapeHtml(String(item.id))}">
                <div class="analytics-hotspot-card">
                    <div class="analytics-hotspot-code">${escapeHtml(code)}</div>
                    <div class="analytics-hotspot-metrics">
                        <span class="analytics-hotspot-metric" title="Score">
                            <i class="fa-solid fa-bullseye"></i>
                            ${escapeHtml(String(score))}
                        </span>
                        <span class="analytics-hotspot-metric" title="Networks">
                            <i class="fa-solid fa-wifi"></i>
                            ${escapeHtml(String(networksCount))}
                        </span>
                        <span class="analytics-hotspot-metric" title="Locked">
                            <i class="fa-solid fa-lock"></i>
                            ${escapeHtml(String(lockedCount))}
                        </span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function renderSelectedHotspotDetails() {
    const target = document.getElementById('analytics-hotspot-details');
    if (!target) return;
    const hotspot = getSelectedAnalyticsHotspot();
    if (!hotspot) {
        target.textContent = 'Select a hotspot to inspect tactical context.';
        return;
    }

    const topChannels = Array.isArray(hotspot.top_channels) ? hotspot.top_channels : [];
    const topSources = Array.isArray(hotspot.top_sources)
        ? hotspot.top_sources.map((value) => mapAnalyticsSourceLabel(value))
        : [];
    const sampleMacs = Array.isArray(hotspot.sample_macs) ? hotspot.sample_macs : [];
    const candidateMacs = Array.isArray(hotspot.candidate_macs) ? hotspot.candidate_macs : sampleMacs;
    const candidateTop = candidateMacs.slice(0, 8);
    const hiddenCount = Math.max(0, candidateMacs.length - candidateTop.length);
    const candidateSummary = hiddenCount > 0
        ? `${candidateTop.length}/${candidateMacs.length} shown`
        : `${candidateTop.length}`;
    const decisionFactors = Array.isArray(hotspot.decision_factors) ? hotspot.decision_factors.slice(0, 5) : [];
    const dominantChannels = topChannels.length ? topChannels.join(', ') : '--';
    const dominantSources = topSources.length ? topSources.join(', ') : '--';
    const actionLabel = String(hotspot.recommended_action || '--')
        .replace(/_/g, ' ')
        .toUpperCase();

    target.innerHTML = `
        <div class="analytics-hotspot-detail-stack">
            <div class="analytics-hotspot-section">
                <div class="analytics-hotspot-section-title">Overview</div>
                <div class="analytics-hotspot-overview-grid">
                    <div class="analytics-hotspot-overview-card"><span>SCORE</span><strong>${escapeHtml(String(hotspot.score ?? 0))}</strong></div>
                    <div class="analytics-hotspot-overview-card"><span>LOCKED</span><strong>${escapeHtml(String(hotspot.locked_count ?? 0))}</strong></div>
                    <div class="analytics-hotspot-overview-card"><span>NETWORKS</span><strong>${escapeHtml(String(hotspot.networks_count ?? 0))}</strong></div>
                    <div class="analytics-hotspot-overview-card"><span>CHANNELS</span><strong>${escapeHtml(dominantChannels)}</strong></div>
                </div>
                <div class="analytics-hotspot-meta-row">
                    <span class="analytics-hotspot-meta-chip">ID ${escapeHtml(String(hotspot.id || '-'))}</span>
                    <span class="analytics-hotspot-meta-chip">SRC ${escapeHtml(dominantSources)}</span>
                    <span class="analytics-hotspot-meta-chip">ACTION ${escapeHtml(actionLabel)}</span>
                </div>
            </div>

            <div class="analytics-hotspot-section">
                <div class="analytics-hotspot-section-title">Why This Hotspot Matters</div>
                <div class="analytics-hotspot-rationale-list">
                    ${decisionFactors.length
        ? decisionFactors.map((item) => `<div class="analytics-hotspot-rationale-item">${escapeHtml(String(item))}</div>`).join('')
        : '<div class="analytics-hotspot-rationale-item">No backend rationale available yet.</div>'}
                </div>
            </div>

            <div class="analytics-hotspot-section">
                <div class="analytics-hotspot-section-title">Priority Targets</div>
                <div class="analytics-hotspot-section-copy">${escapeHtml(candidateSummary)} · add-to-targets keeps the top 8 prioritized MACs.</div>
                <div class="analytics-hotspot-target-list">
                    ${candidateTop.length
        ? candidateTop.map((mac) => `<span class="analytics-hotspot-target-chip">${escapeHtml(String(mac))}</span>`).join('')
        : '<span class="analytics-hotspot-target-empty">No targetable MACs in this hotspot.</span>'}
                </div>
                ${hiddenCount > 0 ? `<div class="analytics-hotspot-section-copy">+${escapeHtml(String(hiddenCount))} more candidates hidden from preview.</div>` : ''}
            </div>
        </div>
    `;
}

export async function refreshAnalyticsPanel(force = false) {
    const panel = document.getElementById('analytics-panel');
    if (!panel) return;
    if (!STATE.modes.analytics && !force) return;

    const analyticsUi = getAnalyticsUiState();
    renderAnalyticsControls();
    try {
        const query = {
            metric: analyticsUi.metric,
            source: analyticsUi.source,
            security: analyticsUi.security,
            device_type: analyticsUi.deviceType,
            time_window: analyticsUi.timeWindow,
            channel: analyticsUi.channel === 'all' ? null : analyticsUi.channel,
        };

        const [heatmap, channelSummary, hotspots] = await Promise.all([
            API.getAnalyticsHeatmap(query),
            API.getAnalyticsChannelSummary(query),
            API.getAnalyticsHotspots({ ...query, limit: 12 }),
        ]);

        analyticsUi.heatmap = heatmap || null;
        analyticsUi.channelSummary = channelSummary || null;
        analyticsUi.hotspots = Array.isArray(hotspots?.hotspots) ? hotspots.hotspots : [];
        if (
            analyticsUi.selectedHotspotId
            && !analyticsUi.hotspots.some((item) => String(item.id) === String(analyticsUi.selectedHotspotId))
        ) {
            analyticsUi.selectedHotspotId = null;
        }

        renderAnalyticsControls();
        renderAnalyticsKpis();
        renderAnalyticsWardriveContext();
        renderAnalyticsChannelSummary();
        renderAnalyticsCharts();
        renderAnalyticsHotspotsList();
        renderSelectedHotspotDetails();
        setAnalyticsHeatmapLayer(heatmap?.cells || [], analyticsUi.metric);
        setAnalyticsHotspotsLayer(analyticsUi.hotspots, analyticsUi.selectedHotspotId);
    } catch (e) {
        renderAnalyticsWardriveContext();
        renderAnalyticsCharts();
        clearAnalyticsHeatmapLayer();
        clearAnalyticsHotspotsLayer();
        log(`Analytics refresh failed: ${e.message}`, 'error');
    }
}

export function setupAnalyticsListeners() {
    const analyticsMetric = document.getElementById('analytics-metric-select');
    const analyticsSource = document.getElementById('analytics-source-select');
    const analyticsSecurity = document.getElementById('analytics-security-select');
    const analyticsDeviceType = document.getElementById('analytics-device-type-select');
    const analyticsTimeWindow = document.getElementById('analytics-time-window-select');
    const analyticsChannel = document.getElementById('analytics-channel-select');
    const btnAnalyticsRefresh = document.getElementById('btn-analytics-refresh');
    const btnAnalyticsAddTargets = document.getElementById('btn-analytics-add-targets');
    const btnAnalyticsOpenWardrive = document.getElementById('btn-analytics-open-wardrive');
    const btnAnalyticsDimensionChannel = document.getElementById('btn-analytics-dimension-channel');
    const btnAnalyticsDimensionDevice = document.getElementById('btn-analytics-dimension-device');
    const analyticsHotspotsList = document.getElementById('analytics-hotspots-list');

    const bindAnalyticsFilter = (el, key) => {
        if (!el) return;
        el.addEventListener('change', () => {
            const analyticsUi = getAnalyticsUiState();
            analyticsUi[key] = (el.value || '').trim() || analyticsUi[key];
            if (key === 'timeWindow') {
                const is24h = String(analyticsUi.timeWindow).toLowerCase() === '24h';
                STATE.filters.time = is24h ? '24H' : 'ALL';
                syncGlobalTimeButtons(analyticsUi.timeWindow);
            }
            persistAnalyticsUi();
            refreshAnalyticsPanel();
        });
    };

    bindAnalyticsFilter(analyticsMetric, 'metric');
    bindAnalyticsFilter(analyticsSource, 'source');
    bindAnalyticsFilter(analyticsSecurity, 'security');
    bindAnalyticsFilter(analyticsDeviceType, 'deviceType');
    bindAnalyticsFilter(analyticsTimeWindow, 'timeWindow');
    bindAnalyticsFilter(analyticsChannel, 'channel');

    if (btnAnalyticsDimensionChannel) {
        btnAnalyticsDimensionChannel.addEventListener('click', () => {
            const analyticsUi = getAnalyticsUiState();
            analyticsUi.dimension = 'channel';
            persistAnalyticsUi();
            renderAnalyticsControls();
            renderAnalyticsChannelSummary();
            renderAnalyticsCharts();
        });
    }

    if (btnAnalyticsDimensionDevice) {
        btnAnalyticsDimensionDevice.addEventListener('click', () => {
            const analyticsUi = getAnalyticsUiState();
            analyticsUi.dimension = 'device';
            persistAnalyticsUi();
            renderAnalyticsControls();
            renderAnalyticsChannelSummary();
            renderAnalyticsCharts();
        });
    }

    if (btnAnalyticsRefresh) {
        btnAnalyticsRefresh.addEventListener('click', () => refreshAnalyticsPanel(true));
    }

    if (analyticsHotspotsList) {
        analyticsHotspotsList.addEventListener('click', (e) => {
            const item = e.target.closest('.list-item');
            if (!item) return;
            const hotspotId = item.getAttribute('data-hotspot-id');
            if (!hotspotId) return;
            const analyticsUi = getAnalyticsUiState();
            analyticsUi.selectedHotspotId = hotspotId;
            renderAnalyticsHotspotsList();
            renderSelectedHotspotDetails();
            setSelectedAnalyticsHotspot(hotspotId);
            const hotspot = getSelectedAnalyticsHotspot();
            if (hotspot) focusAnalyticsHotspot(hotspot);
        });
    }

    if (btnAnalyticsAddTargets) {
        btnAnalyticsAddTargets.addEventListener('click', () => {
            const hotspot = getSelectedAnalyticsHotspot();
            if (!hotspot) {
                log('Select a hotspot first.', 'warn');
                return;
            }
            const candidatesRaw = Array.isArray(hotspot.candidate_macs) && hotspot.candidate_macs.length
                ? hotspot.candidate_macs
                : (Array.isArray(hotspot.sample_macs) ? hotspot.sample_macs : []);
            const candidates = Array.from(
                new Set(
                    candidatesRaw
                        .map((item) => String(item || '').trim().toUpperCase())
                        .filter(Boolean)
                )
            ).slice(0, 8);
            if (!candidates.length) {
                log('Selected hotspot has no sample MAC targets.', 'warn');
                return;
            }
            let added = 0;
            candidates.forEach((mac) => {
                const normalizedMac = String(mac || '').trim().toUpperCase();
                if (!normalizedMac || STATE.lists.targets.includes(normalizedMac)) return;
                STATE.lists.targets.push(normalizedMac);
                added += 1;
            });
            if (added > 0) {
                saveLists();
                document.dispatchEvent(new CustomEvent('listsUpdated'));
                log(`Added ${added} hotspot targets.`, 'success');
            } else {
                log('All hotspot sample targets are already in target list.', 'info');
            }
        });
    }

    if (btnAnalyticsOpenWardrive) {
        btnAnalyticsOpenWardrive.addEventListener('click', () => {
            document.dispatchEvent(new CustomEvent('openWardriveFromAnalytics'));
        });
    }

    renderAnalyticsControls();
}
