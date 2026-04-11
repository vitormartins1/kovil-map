import { STATE } from './state.js';
import { API } from './api.js';
import { log, escapeHtml } from './utils.js';
import { addProcess, updateProcess } from './ui_components/ui_processes.js';
import { openCrackingPanel } from './ui_components/ui_cracking.js';

export function getRawUiState() {
    if (!STATE.rawUi || typeof STATE.rawUi !== 'object') {
        STATE.rawUi = {
            fileSearch: "",
            fileStatus: "all",
            fileSort: "modified_desc",
            networkSearch: "",
            networkSort: "beacon_desc",
        };
    }
    return STATE.rawUi;
}

function ensureRawAnalysisState() {
    if (!STATE.rawAnalysisByKey || typeof STATE.rawAnalysisByKey !== 'object') {
        STATE.rawAnalysisByKey = {};
    }
    if (!Object.prototype.hasOwnProperty.call(STATE, 'rawSelectedRawItemId')) {
        STATE.rawSelectedRawItemId = null;
    }
}

function normalizeRawText(value) {
    return String(value || '').trim().toLowerCase();
}

function isMacAddress(value) {
    return /^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/i.test(String(value || '').trim());
}

function compareTextAsc(a, b) {
    return normalizeRawText(a).localeCompare(normalizeRawText(b));
}

function compareNumberDesc(a, b) {
    return Number(b || 0) - Number(a || 0);
}

function formatBytes(bytes) {
    const n = Number(bytes || 0);
    if (!Number.isFinite(n) || n <= 0) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let idx = 0;
    let val = n;
    while (val >= 1024 && idx < units.length - 1) {
        val /= 1024;
        idx += 1;
    }
    return `${val.toFixed(idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function getRawSubtypeLabel(sourcePathRole) {
    const normalized = String(sourcePathRole || '').trim().toLowerCase();
    if (normalized === 'master_sniffer') return 'MASTER SNIFFER';
    if (normalized === 'rawsniffer') return 'RAWSNIFFER';
    return '';
}

function getRawAnalysisKey(filename, rawItemId = null) {
    const key = String(rawItemId || filename || '').trim();
    return key || null;
}

function createRawAnalysisProcessId() {
    return `raw-analysis-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function getRawFileRecord({ filename = null, rawItemId = null } = {}) {
    const targetFilename = String(filename || STATE.rawSelectedFile || '').trim();
    const targetRawItemId = String(rawItemId || STATE.rawSelectedRawItemId || '').trim();
    const files = Array.isArray(STATE.rawFiles) ? STATE.rawFiles : [];
    if (targetRawItemId) {
        const byItemId = files.find((item) => String(item?.raw_item_id || '').trim() === targetRawItemId);
        if (byItemId) return byItemId;
    }
    if (targetFilename) {
        return files.find((item) => String(item?.filename || '').trim() === targetFilename) || null;
    }
    return null;
}

function setSelectedRawFile(file) {
    if (!file || typeof file !== 'object') {
        STATE.rawSelectedFile = null;
        STATE.rawSelectedRawItemId = null;
        return;
    }
    STATE.rawSelectedFile = String(file.filename || '').trim() || null;
    STATE.rawSelectedRawItemId = String(file.raw_item_id || '').trim() || null;
}

function formatDuration(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) return '-';
    if (value < 60) return `${value.toFixed(value >= 10 ? 0 : 1)}s`;
    const mins = Math.floor(value / 60);
    const secs = Math.round(value % 60);
    if (mins < 60) return `${mins}m ${secs}s`;
    const hours = Math.floor(mins / 60);
    const remMins = mins % 60;
    return `${hours}h ${remMins}m`;
}

function renderRawAnalysis(filename, rawRecord) {
    ensureRawAnalysisState();
    const key = getRawAnalysisKey(
        filename,
        rawRecord?.raw_item_id || STATE.rawSelectedRawItemId || null
    );
    const analysis = key ? STATE.rawAnalysisByKey[key] : null;
    const cachedSummary = rawRecord?.analysis_summary && typeof rawRecord.analysis_summary === 'object'
        ? rawRecord.analysis_summary
        : null;

    if (!analysis) {
        const summaryBits = [];
        if (cachedSummary) {
            if (cachedSummary.duration_s != null) summaryBits.push(`duration ${formatDuration(cachedSummary.duration_s)}`);
            if (cachedSummary.networks_count != null) summaryBits.push(`nets ${Number(cachedSummary.networks_count)}`);
            if (cachedSummary.clients_count != null) summaryBits.push(`clients ${Number(cachedSummary.clients_count)}`);
            if (cachedSummary.handshake_candidate_count != null) summaryBits.push(`handshake cands ${Number(cachedSummary.handshake_candidate_count)}`);
            if (cachedSummary.noisy_capture) summaryBits.push('noisy capture');
        }
        return `
            <div class="raw-analysis-shell">
                <div class="raw-analysis-header">
                    <i class="fa-solid fa-chart-column"></i>
                    <span>RAW ANALYSIS</span>
                </div>
                <div class="raw-analysis-empty">
                    ${rawRecord?.analysis_present
                        ? 'Cached analysis is available. Click ANALYZE SELECTED to load or refresh it.'
                        : 'No RAW analysis cached yet. Click ANALYZE SELECTED to build a capture-wide report.'}
                </div>
                ${summaryBits.length ? `<div class="raw-analysis-summary-strip">${summaryBits.map((item) => `<span>${escapeHtml(item)}</span>`).join('')}</div>` : ''}
            </div>
        `;
    }

    const capture = analysis.capture || {};
    const highlights = analysis.highlights || {};
    const handshakeCandidates = Array.isArray(highlights.handshake_candidates) ? highlights.handshake_candidates : [];
    const topNetworks = Array.isArray(highlights.top_networks) ? highlights.top_networks : [];
    const topClients = Array.isArray(highlights.top_clients) ? highlights.top_clients : [];
    const warnings = Array.isArray(capture.warnings) ? capture.warnings : [];

    const captureBits = [
        `Duration: ${formatDuration(capture.duration_s)}`,
        `Networks: ${Number(capture.networks_count || 0)}`,
        `Clients: ${Number(capture.clients_count || 0)}`,
        `Beacons: ${Number((capture.frame_totals || {}).beacons || 0)}`,
        `EAPOL: ${Number((capture.frame_totals || {}).eapol || 0)}`,
        `Probes: ${Number((capture.frame_totals || {}).probe_requests || 0)}`,
    ];

    const renderList = (items, renderer, emptyText) => {
        if (!Array.isArray(items) || !items.length) {
            return `<div class="raw-analysis-empty raw-analysis-empty--compact">${escapeHtml(emptyText)}</div>`;
        }
        return `<div class="raw-analysis-list">${items.map(renderer).join('')}</div>`;
    };

    return `
        <div class="raw-analysis-shell">
            <div class="raw-analysis-header">
                <i class="fa-solid fa-chart-column"></i>
                <span>RAW ANALYSIS</span>
            </div>
            <div class="raw-analysis-summary-strip">
                ${captureBits.map((item) => `<span>${escapeHtml(item)}</span>`).join('')}
            </div>
            <div class="raw-analysis-grid">
                <div class="raw-analysis-card">
                    <div class="raw-analysis-card-title">Handshake Candidates</div>
                    ${renderList(
                        handshakeCandidates,
                        (item) => `<div class="raw-analysis-row"><b>${escapeHtml(item?.bssid || '-')}</b><span>${escapeHtml(item?.ssid || '<hidden>')} | eapol ${Number(item?.eapol_count || 0)} | ${escapeHtml(item?.tier || 'none')}</span></div>`,
                        'No handshake evidence found.'
                    )}
                </div>
                <div class="raw-analysis-card">
                    <div class="raw-analysis-card-title">Top Networks</div>
                    ${renderList(
                        topNetworks,
                        (item) => `<div class="raw-analysis-row"><b>${escapeHtml(item?.bssid || '-')}</b><span>${escapeHtml(item?.ssid || '<hidden>')} | beacon ${Number(item?.beacon_count || 0)} | clients ${Number(item?.client_count || 0)}</span></div>`,
                        'No network rollup available.'
                    )}
                </div>
                <div class="raw-analysis-card">
                    <div class="raw-analysis-card-title">Top Clients</div>
                    ${renderList(
                        topClients,
                        (item) => `<div class="raw-analysis-row"><b>${escapeHtml(item?.mac || '-')}</b><span>frames ${Number(item?.total_frames || 0)} | nets ${Number(item?.network_count || 0)} | eapol ${Number(item?.eapol_count || 0)}</span></div>`,
                        'No client activity identified.'
                    )}
                </div>
            </div>
            <div class="raw-analysis-footer">
                <div><b>Hidden networks:</b> ${Number(highlights.hidden_network_count || 0)}</div>
                <div><b>Revealed later:</b> ${Number(highlights.revealed_hidden_count || 0)}</div>
                <div><b>Noisy capture:</b> ${highlights.noisy_capture ? 'YES' : 'NO'}</div>
            </div>
            <div class="raw-analysis-card">
                <div class="raw-analysis-card-title">Warnings</div>
                ${warnings.length
                    ? `<ul class="raw-analysis-warnings">${warnings.map((warning) => `<li>${escapeHtml(String(warning))}</li>`).join('')}</ul>`
                    : '<div class="raw-analysis-empty raw-analysis-empty--compact">No warnings.</div>'}
            </div>
        </div>
    `;
}

function getFilteredRawFiles() {
    const rawUi = getRawUiState();
    const sourceFiles = Array.isArray(STATE.rawFiles) ? [...STATE.rawFiles] : [];

    const searched = sourceFiles.filter(file => {
        if (!rawUi.fileSearch) return true;
        return normalizeRawText(file.filename).includes(rawUi.fileSearch);
    });

    const statusFiltered = searched.filter(file => {
        if (rawUi.fileStatus === 'pending') return !file.cached_up_to_date;
        if (rawUi.fileStatus === 'cached') return !!file.cached_up_to_date;
        return true;
    });

    const sorter = rawUi.fileSort || 'modified_desc';
    statusFiltered.sort((a, b) => {
        if (sorter === 'modified_asc') return Number(a.modified || 0) - Number(b.modified || 0);
        if (sorter === 'size_desc') return Number(b.size || 0) - Number(a.size || 0);
        if (sorter === 'size_asc') return Number(a.size || 0) - Number(b.size || 0);
        if (sorter === 'networks_desc') return Number(b.networks_count || 0) - Number(a.networks_count || 0);
        if (sorter === 'name_asc') return compareTextAsc(a.filename, b.filename);
        return Number(b.modified || 0) - Number(a.modified || 0);
    });

    return statusFiltered;
}

export function renderRawFilesList() {
    ensureRawAnalysisState();
    const list = document.getElementById('raw-files-list');
    if (!list) return;
    const countInfo = document.getElementById('raw-files-count-info');

    const rawUi = getRawUiState();
    const fileSearch = document.getElementById('raw-file-search');
    const fileStatus = document.getElementById('raw-file-status');
    const fileSort = document.getElementById('raw-file-sort');
    if (fileSearch && fileSearch.value !== (rawUi.fileSearch || '')) fileSearch.value = rawUi.fileSearch || '';
    if (fileStatus && fileStatus.value !== (rawUi.fileStatus || 'all')) fileStatus.value = rawUi.fileStatus || 'all';
    if (fileSort && fileSort.value !== (rawUi.fileSort || 'modified_desc')) fileSort.value = rawUi.fileSort || 'modified_desc';

    const files = getFilteredRawFiles();
    const totalFiles = Array.isArray(STATE.rawFiles) ? STATE.rawFiles.length : 0;
    if (countInfo) countInfo.textContent = `${files.length}/${totalFiles}`;

    if (!files.length) {
        list.innerHTML = '<div style="padding: 12px; color:#666; font-style: italic;">NO RAW FILES</div>';
        return;
    }

    list.innerHTML = '';
    files.forEach(file => {
        const selected = (
            (STATE.rawSelectedRawItemId && String(file.raw_item_id || '').trim() === String(STATE.rawSelectedRawItemId || '').trim())
            || STATE.rawSelectedFile === file.filename
        );
        const item = document.createElement('div');
        item.className = `list-item${selected ? ' selected' : ''}`;
        item.setAttribute('data-filename', file.filename);
        item.setAttribute('data-raw-item-id', String(file.raw_item_id || ''));
        const modified = Number(file.modified || 0);
        const modifiedLabel = modified > 0 ? new Date(modified * 1000).toLocaleString() : 'N/A';
        const subtypeLabel = getRawSubtypeLabel(file.source_path_role);
        const deviceLabel = String(file.device_label || '').trim();
        const statusTag = file.cached_up_to_date
            ? '<span class="file-type-tag badge-cracked" style="width:auto; padding:1px 6px;">CACHED</span>'
            : '<span class="file-type-tag badge-pcap" style="width:auto; padding:1px 6px;">PENDING</span>';
        const analysisTag = file.analysis_present
            ? '<span class="file-type-tag badge-details" style="width:auto; padding:1px 6px;">ANALYSIS</span>'
            : '';
        item.innerHTML = `
            <div style="display:flex; align-items:center; justify-content:space-between; width:100%; gap:8px;">
                <div style="overflow:hidden;">
                    <div class="item-name" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(file.filename)}</div>
                    <div class="item-meta" style="font-size:0.68em; color:#777;">
                        ${escapeHtml(formatBytes(file.size))} | nets: ${Number(file.networks_count || 0)} | ${escapeHtml(modifiedLabel)}
                    </div>
                    <div class="item-meta" style="font-size:0.66em; color:#6fa9ad; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        ${escapeHtml([deviceLabel, subtypeLabel].filter(Boolean).join(' | ') || 'RAW')}
                    </div>
                </div>
                <div style="display:flex; align-items:center; gap:6px;">
                    ${analysisTag}
                    ${statusTag}
                </div>
            </div>
        `;
        list.appendChild(item);
    });
}

export function renderRawHashesList() {
    const list = document.getElementById('raw-hashes-list');
    if (!list) return;

    const hashes = Array.isArray(STATE.rawHashes) ? STATE.rawHashes : [];
    if (!hashes.length) {
        list.innerHTML = '<div style="padding: 12px; color:#666; font-style: italic;">NO RAW HASHES</div>';
        return;
    }

    if (
        STATE.rawSelectedHash
        && !hashes.some(item => item.filename === STATE.rawSelectedHash)
    ) {
        STATE.rawSelectedHash = null;
    }

    if (!STATE.rawSelectedHash) {
        const firstSelectable = hashes.find(
            item => !!item.has_context && Number(item.valid_hash_lines || 0) > 0
        );
        STATE.rawSelectedHash = firstSelectable ? firstSelectable.filename : null;
    }

    list.innerHTML = '';
    hashes.forEach((hash) => {
        const filename = String(hash.filename || '');
        const hasContext = !!hash.has_context;
        const validHashLines = Number(hash.valid_hash_lines || 0);
        const canOpen = hasContext && validHashLines > 0;
        const selected = STATE.rawSelectedHash === filename;
        const item = document.createElement('div');
        item.className = `list-item${selected ? ' selected' : ''}${canOpen ? '' : ' is-disabled'}`;
        item.setAttribute('data-filename', filename);
        item.setAttribute('data-has-context', hasContext ? 'true' : 'false');
        item.setAttribute('data-valid-hash-lines', String(validHashLines));
        item.setAttribute('data-primary-bssid', String(hash.primary_bssid || ''));
        item.setAttribute('data-primary-ssid', String(hash.primary_ssid || ''));

        const modified = Number(hash.modified || 0);
        const modifiedLabel = modified > 0 ? new Date(modified * 1000).toLocaleString() : 'N/A';
        const contextLabel = hasContext ? 'READY' : 'NO CONTEXT';
        const contextBadgeClass = hasContext ? 'raw-hash-context-badge' : 'raw-hash-context-badge warn';
        const primaryBssid = hasContext ? String(hash.primary_bssid || '-') : '-';
        const sourceRawFile = String(hash.source_raw_file || '-');
        const primarySsid = String(hash.primary_ssid || '').trim();

        item.innerHTML = `
            <div style="display:flex; align-items:center; justify-content:space-between; width:100%; gap:8px;">
                <div style="overflow:hidden;">
                    <div class="item-name" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(filename)}</div>
                    <div class="item-meta" style="font-size:0.68em; color:#777;">
                        lines: ${validHashLines} | bssid: ${escapeHtml(primaryBssid)} | ${escapeHtml(modifiedLabel)}
                    </div>
                    <div class="item-meta" style="font-size:0.66em; color:#6fa9ad; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        from: ${escapeHtml(sourceRawFile)}${primarySsid ? ` | ssid: ${escapeHtml(primarySsid)}` : ''}
                    </div>
                </div>
                <div style="display:flex; align-items:center; gap:6px;">
                    <span class="${contextBadgeClass}">${contextLabel}</span>
                </div>
            </div>
        `;
        list.appendChild(item);
    });
}

function getFilteredRawNetworks(metadata) {
    const rawUi = getRawUiState();
    const sourceNetworks = Array.isArray(metadata?.networks) ? [...metadata.networks] : [];
    const searched = sourceNetworks.filter(net => {
        if (!rawUi.networkSearch) return true;
        const bssid = normalizeRawText(net?.bssid);
        const ssid = normalizeRawText(net?.ssid);
        return bssid.includes(rawUi.networkSearch) || ssid.includes(rawUi.networkSearch);
    });

    const sortKey = rawUi.networkSort || 'beacon_desc';
    searched.sort((a, b) => {
        if (sortKey === 'eapol_desc') return compareNumberDesc(a?.eapol_count, b?.eapol_count);
        if (sortKey === 'probe_desc') return compareNumberDesc(a?.probe_client_count, b?.probe_client_count);
        if (sortKey === 'ssid_asc') return compareTextAsc(a?.ssid, b?.ssid);
        if (sortKey === 'bssid_asc') return compareTextAsc(a?.bssid, b?.bssid);
        return compareNumberDesc(a?.beacon_count, b?.beacon_count);
    });
    return searched;
}

function formatRawValue(value, fallback = '-') {
    if (value === null || value === undefined || value === '') return fallback;
    return String(value);
}

export function renderRawMetadata(filename, metadata) {
    ensureRawAnalysisState();
    const target = document.getElementById('raw-details-view');
    if (!target) return;
    const networkCountInfo = document.getElementById('raw-net-count-info');

    const rawUi = getRawUiState();
    const networkSearch = document.getElementById('raw-network-search');
    const networkSort = document.getElementById('raw-network-sort');
    if (networkSearch && networkSearch.value !== (rawUi.networkSearch || '')) networkSearch.value = rawUi.networkSearch || '';
    if (networkSort && networkSort.value !== (rawUi.networkSort || 'beacon_desc')) networkSort.value = rawUi.networkSort || 'beacon_desc';

    if (!metadata) {
        if (networkCountInfo) networkCountInfo.textContent = '0/0';
        target.innerHTML = `No metadata cached for <b>${escapeHtml(filename || '')}</b>. Click reprocess to extract.`;
        return;
    }

    const rawRecord = getRawFileRecord({ filename });
    const stats = metadata.stats || {};
    const warnings = Array.isArray(metadata.warnings) ? metadata.warnings : [];
    const filteredNetworks = getFilteredRawNetworks(metadata);
    const totalNetworks = Array.isArray(metadata?.networks) ? metadata.networks.length : 0;
    if (networkCountInfo) networkCountInfo.textContent = `${filteredNetworks.length}/${totalNetworks}`;

    const selectedFromState = STATE.rawSelectedNetworkByFile[filename];
    let selectedBssid = selectedFromState;
    if (!selectedBssid || !filteredNetworks.some(n => String(n?.bssid || '').toUpperCase() === String(selectedBssid).toUpperCase())) {
        selectedBssid = filteredNetworks[0]?.bssid || null;
        if (selectedBssid) STATE.rawSelectedNetworkByFile[filename] = selectedBssid;
    }

    const selectedNetwork = filteredNetworks.find(
        n => String(n?.bssid || '').toUpperCase() === String(selectedBssid || '').toUpperCase()
    ) || null;
    const selectedBssidNorm = String(selectedNetwork?.bssid || '').toUpperCase();
    const mapEntry = selectedNetwork
        ? (STATE.allPositions[selectedBssidNorm] || STATE.allPositions[selectedNetwork.bssid])
        : null;

    const rows = filteredNetworks.map(n => {
        const rowBssid = String(n?.bssid || '');
        const selectedClass = selectedBssid && rowBssid.toUpperCase() === String(selectedBssid).toUpperCase()
            ? ' selected'
            : '';
        return `
        <tr class="raw-network-row${selectedClass}" data-bssid="${escapeHtml(rowBssid)}">
            <td style="padding:2px 6px; color:#fff;">${escapeHtml(n.bssid || '')}</td>
            <td style="padding:2px 6px;">${escapeHtml(n.ssid || '<hidden>')}</td>
            <td style="padding:2px 6px; text-align:right;">${n.channel ?? '-'}</td>
            <td style="padding:2px 6px; text-align:right;">${n.beacon_count ?? 0}</td>
            <td style="padding:2px 6px; text-align:right;">${n.eapol_count ?? 0}</td>
            <td style="padding:2px 6px; text-align:right;">${n.probe_client_count ?? 0}</td>
        </tr>
    `;
    }).join('');

    const focusHtml = selectedNetwork
        ? `
        <div class="raw-network-focus">
            <div class="line"><span class="k">BSSID</span><span class="v">${escapeHtml(formatRawValue(selectedNetwork.bssid))}</span></div>
            <div class="line"><span class="k">SSID</span><span class="v">${escapeHtml(formatRawValue(selectedNetwork.ssid || '<hidden>'))}</span></div>
            <div class="line"><span class="k">Channel / Freq</span><span class="v">${escapeHtml(formatRawValue(selectedNetwork.channel))} / ${escapeHtml(formatRawValue(selectedNetwork.frequency_mhz, '-'))} MHz</span></div>
            <div class="line"><span class="k">Beacons / EAPOL</span><span class="v">${escapeHtml(formatRawValue(selectedNetwork.beacon_count, '0'))} / ${escapeHtml(formatRawValue(selectedNetwork.eapol_count, '0'))}</span></div>
            <div class="line"><span class="k">Probe Clients</span><span class="v">${escapeHtml(formatRawValue(selectedNetwork.probe_client_count, '0'))}</span></div>
            <div class="line"><span class="k">Last Seen Offset</span><span class="v">${escapeHtml(formatRawValue(selectedNetwork.last_seen_offset_s, '-'))} s</span></div>
            <div class="line"><span class="k">In Map Dataset</span><span class="v">${mapEntry ? 'YES' : 'NO'}</span></div>
            ${mapEntry ? `<div class="line"><span class="k">Map SSID / Src</span><span class="v">${escapeHtml(formatRawValue(mapEntry.ssid || '<hidden>'))} / ${escapeHtml((mapEntry.sources || []).join(', ') || '-')}</span></div>` : ''}
        </div>
        `
        : '';

    const rowsOrEmpty = rows || `
        <tr>
            <td colspan="6" style="padding:8px; text-align:center; color:#777;">NO NETWORKS FOR CURRENT FILTERS</td>
        </tr>
    `;

    target.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:8px;">
            <div><b>FILE:</b> ${escapeHtml(metadata.source_file || filename || '')}</div>
            ${rawRecord?.device_label ? `<div><b>DEVICE:</b> ${escapeHtml(rawRecord.device_label)}</div>` : ''}
            ${getRawSubtypeLabel(rawRecord?.source_path_role) ? `<div><b>RAW TYPE:</b> ${escapeHtml(getRawSubtypeLabel(rawRecord?.source_path_role))}</div>` : ''}
            <div><b>PROCESSED:</b> ${escapeHtml(metadata.processed_at || 'N/A')}</div>
            <div><b>STATS:</b> networks=${stats.networks_count || 0}, beacons=${stats.beacon_frames || 0}, probes=${stats.probe_requests || 0}, eapol=${stats.eapol_frames || 0}</div>
            ${warnings.length ? `<div><b>WARNINGS:</b><br>${warnings.map(w => `- ${escapeHtml(String(w))}`).join('<br>')}</div>` : '<div><b>WARNINGS:</b> none</div>'}
            <div><b>NETWORKS LIST:</b></div>
            <div class="raw-networks-scroll">
                <table style="width:100%; border-collapse:collapse; font-size:0.9em;">
                    <thead>
                        <tr style="background:rgba(0,243,255,.08);">
                            <th style="text-align:left; padding:3px 6px;">BSSID</th>
                            <th style="text-align:left; padding:3px 6px;">SSID</th>
                            <th style="text-align:right; padding:3px 6px;">CH</th>
                            <th style="text-align:right; padding:3px 6px;">BEACON</th>
                            <th style="text-align:right; padding:3px 6px;">EAPOL</th>
                            <th style="text-align:right; padding:3px 6px;">PROBES</th>
                        </tr>
                    </thead>
                    <tbody>${rowsOrEmpty}</tbody>
                </table>
            </div>
            ${focusHtml}
            ${renderRawAnalysis(filename, rawRecord)}
        </div>
    `;
}

export async function refreshRawFiles() {
    try {
        ensureRawAnalysisState();
        getRawUiState();
        const [filesResult, hashesResult] = await Promise.allSettled([
            API.listRawSnifferFiles(),
            API.getRawSnifferHashes(),
        ]);
        if (filesResult.status !== 'fulfilled') {
            throw filesResult.reason || new Error('Failed to load RAW files');
        }
        STATE.rawFiles = filesResult.value || [];
        if (hashesResult.status === 'fulfilled') {
            STATE.rawHashes = hashesResult.value || [];
        } else {
            STATE.rawHashes = [];
            console.warn("Failed to load raw hashes", hashesResult.reason);
        }
        if (
            STATE.rawSelectedFile
            && !STATE.rawFiles.some(f => f.filename === STATE.rawSelectedFile)
        ) {
            STATE.rawSelectedFile = null;
            STATE.rawSelectedRawItemId = null;
        }
        const filteredFiles = getFilteredRawFiles();
        if (!filteredFiles.length) {
            STATE.rawSelectedFile = null;
            STATE.rawSelectedRawItemId = null;
        } else if (!STATE.rawSelectedFile || !filteredFiles.some(f => f.filename === STATE.rawSelectedFile)) {
            setSelectedRawFile(filteredFiles[0]);
        } else {
            const current = filteredFiles.find((item) => item.filename === STATE.rawSelectedFile);
            if (current) setSelectedRawFile(current);
        }

        renderRawFilesList();
        renderRawHashesList();
        if (STATE.rawSelectedFile) {
            const selectedRecord = getRawFileRecord();
            await loadRawMetadata(
                STATE.rawSelectedFile,
                false,
                selectedRecord?.raw_item_id || STATE.rawSelectedRawItemId || null
            );
        } else {
            renderRawMetadata(null, null);
        }
    } catch (e) {
        console.error("Failed to load raw files", e);
    }
}

export async function loadRawMetadata(filename, refresh = false, rawItemId = null) {
    if (!filename) return;
    try {
        ensureRawAnalysisState();
        const data = await API.getRawSnifferMetadata(filename, refresh, rawItemId);
        const metadata = data && data.status === 'success' && data.data ? data.data : data;
        STATE.rawMetadataByFile[filename] = metadata;
        renderRawMetadata(filename, metadata);
        const rawRecord = getRawFileRecord({ filename, rawItemId });
        const analysisKey = getRawAnalysisKey(filename, rawItemId || rawRecord?.raw_item_id || null);
        const analysisItemId = String(rawItemId || rawRecord?.raw_item_id || '').trim();
        if (analysisItemId && (rawRecord?.analysis_present || (analysisKey && STATE.rawAnalysisByKey[analysisKey]))) {
            try {
                const analysis = await API.getRawSnifferAnalysis(analysisItemId);
                if (analysisKey) STATE.rawAnalysisByKey[analysisKey] = analysis;
                renderRawMetadata(filename, metadata);
            } catch (_e) {
                // Cached analysis is optional; ignore missing analysis here.
            }
        }
    } catch (e) {
        STATE.rawMetadataByFile[filename] = null;
        renderRawMetadata(filename, null);
    }
}

async function loadRawAnalysis(rawItemId, { force = false, build = false, filename = null } = {}) {
    const targetRawItemId = String(rawItemId || '').trim();
    if (!targetRawItemId) return null;
    ensureRawAnalysisState();
    const key = getRawAnalysisKey(filename, targetRawItemId);
    const call = build
        ? API.analyzeRawSniffer(targetRawItemId, !!force)
        : API.getRawSnifferAnalysis(targetRawItemId);
    const analysis = await call;
    if (key) {
        STATE.rawAnalysisByKey[key] = analysis && analysis.status === 'success' && analysis.data
            ? analysis.data
            : analysis;
    }
    return key ? STATE.rawAnalysisByKey[key] : analysis;
}

export function setupRawListeners() {
    const btnRawRefresh = document.getElementById('btn-raw-refresh');
    if (btnRawRefresh) btnRawRefresh.addEventListener('click', refreshRawFiles);

    const btnRawAnalyzeSelected = document.getElementById('btn-raw-analyze-selected');
    if (btnRawAnalyzeSelected) {
        btnRawAnalyzeSelected.addEventListener('click', async () => {
            const selectedRecord = getRawFileRecord();
            if (!selectedRecord?.raw_item_id || !STATE.rawSelectedFile) {
                log("Select a RAW file first.", "warn");
                return;
            }
            btnRawAnalyzeSelected.disabled = true;
            const originalHtml = btnRawAnalyzeSelected.innerHTML;
            btnRawAnalyzeSelected.innerHTML = 'ANALYZING...';
            const processId = createRawAnalysisProcessId();
            addProcess(
                processId,
                'RAW ANALYSIS',
                STATE.rawSelectedFile,
                'STARTING'
            );
            updateProcess(
                processId,
                15,
                'RUNNING',
                'Building capture-wide report',
                true
            );
            try {
                await loadRawAnalysis(selectedRecord.raw_item_id, {
                    build: true,
                    force: false,
                    filename: STATE.rawSelectedFile,
                });
                const refreshedRecord = getRawFileRecord();
                if (refreshedRecord) refreshedRecord.analysis_present = true;
                renderRawMetadata(
                    STATE.rawSelectedFile,
                    STATE.rawMetadataByFile[STATE.rawSelectedFile] || null
                );
                updateProcess(
                    processId,
                    100,
                    'COMPLETED',
                    'RAW analysis ready',
                    false
                );
                log(`RAW analysis ready for ${STATE.rawSelectedFile}.`, 'success');
            } catch (e) {
                updateProcess(
                    processId,
                    100,
                    'ERROR',
                    e.message || 'RAW analysis failed',
                    false
                );
                log(`Failed to analyze RAW capture: ${e.message}`, 'error');
            } finally {
                btnRawAnalyzeSelected.disabled = false;
                btnRawAnalyzeSelected.innerHTML = originalHtml || 'ANALYZE SELECTED';
            }
        });
    }

    const rawFileSearch = document.getElementById('raw-file-search');
    if (rawFileSearch) {
        rawFileSearch.addEventListener('input', () => {
            const rawUi = getRawUiState();
            rawUi.fileSearch = (rawFileSearch.value || '').trim().toLowerCase();
            renderRawFilesList();
        });
    }

    const rawFileStatus = document.getElementById('raw-file-status');
    if (rawFileStatus) {
        rawFileStatus.addEventListener('change', () => {
            const rawUi = getRawUiState();
            rawUi.fileStatus = rawFileStatus.value || 'all';
            renderRawFilesList();
        });
    }

    const rawFileSort = document.getElementById('raw-file-sort');
    if (rawFileSort) {
        rawFileSort.addEventListener('change', () => {
            const rawUi = getRawUiState();
            rawUi.fileSort = rawFileSort.value || 'modified_desc';
            renderRawFilesList();
        });
    }

    const rawNetworkSearch = document.getElementById('raw-network-search');
    if (rawNetworkSearch) {
        rawNetworkSearch.addEventListener('input', () => {
            const rawUi = getRawUiState();
            rawUi.networkSearch = (rawNetworkSearch.value || '').trim().toLowerCase();
            if (STATE.rawSelectedFile) {
                renderRawMetadata(STATE.rawSelectedFile, STATE.rawMetadataByFile[STATE.rawSelectedFile] || null);
            }
        });
    }

    const rawNetworkSort = document.getElementById('raw-network-sort');
    if (rawNetworkSort) {
        rawNetworkSort.addEventListener('change', () => {
            const rawUi = getRawUiState();
            rawUi.networkSort = rawNetworkSort.value || 'beacon_desc';
            if (STATE.rawSelectedFile) {
                renderRawMetadata(STATE.rawSelectedFile, STATE.rawMetadataByFile[STATE.rawSelectedFile] || null);
            }
        });
    }

    const btnRawReprocessSelected = document.getElementById('btn-raw-reprocess-selected');
    if (btnRawReprocessSelected) {
        btnRawReprocessSelected.addEventListener('click', async () => {
            if (!STATE.rawSelectedFile) {
                log("Select a RAW file first.", "warn");
                return;
            }
            try {
                const out = await API.extractRawSniffer({
                    filename: STATE.rawSelectedFile,
                    force: true,
                });
                if (out.status === 'started' && out.job_id) {
                    addProcess(out.job_id, "RAW SNIFFER", STATE.rawSelectedFile, "STARTING");
                    log(`Raw extraction started for ${STATE.rawSelectedFile}.`, 'info');
                } else {
                    log(out.message || "No raw files to process.", "info");
                }
            } catch (e) {
                log(`Failed to start raw extraction: ${e.message}`, 'error');
            }
        });
    }

    const btnRawDeleteSelected = document.getElementById('btn-raw-delete-selected');
    if (btnRawDeleteSelected) {
        btnRawDeleteSelected.addEventListener('click', async () => {
            const selectedFile = STATE.rawSelectedFile;
            if (!selectedFile) {
                log("Select a RAW file first.", "warn");
                return;
            }

            const confirmed = window.confirm(
                `Delete ${selectedFile}? This will remove the RAW .pcap, cached metadata, and related .22000 if it exists.`
            );
            if (!confirmed) return;

            try {
                const res = await API.deleteRawSnifferFile(selectedFile);
                delete STATE.rawMetadataByFile[selectedFile];
                delete STATE.rawAnalysisByKey[getRawAnalysisKey(selectedFile, STATE.rawSelectedRawItemId)];
                delete STATE.rawSelectedNetworkByFile[selectedFile];
                if (STATE.rawSelectedHash === selectedFile.replace(/\.pcap$/i, '.22000')) {
                    STATE.rawSelectedHash = null;
                }
                STATE.rawSelectedFile = null;
                STATE.rawSelectedRawItemId = null;
                await refreshRawFiles();
                const deletedNames = Array.isArray(res?.deleted) ? res.deleted.join(', ') : selectedFile;
                log(`RAW file deleted: ${deletedNames}`, 'success');
            } catch (e) {
                log(`Failed to delete RAW file: ${e.message}`, 'error');
            }
        });
    }

    const btnRawReprocessPending = document.getElementById('btn-raw-reprocess-pending');
    if (btnRawReprocessPending) {
        btnRawReprocessPending.addEventListener('click', async () => {
            try {
                const out = await API.extractRawSniffer({ only_pending: true, force: false });
                if (out.status === 'started' && out.job_id) {
                    addProcess(out.job_id, "RAW SNIFFER", `Pending (${out.total_files} files)`, "STARTING");
                    log(`Raw extraction started for ${out.total_files} pending files.`, 'info');
                } else {
                    log(out.message || "No pending raw files to process.", "info");
                }
            } catch (e) {
                log(`Failed to start raw extraction: ${e.message}`, 'error');
            }
        });
    }

    const rawFilesList = document.getElementById('raw-files-list');
    if (rawFilesList) {
        rawFilesList.addEventListener('click', async (e) => {
            const row = e.target.closest('.list-item');
            if (!row) return;
            const filename = row.getAttribute('data-filename');
            const rawItemId = row.getAttribute('data-raw-item-id') || null;
            if (!filename) return;
            setSelectedRawFile({ filename, raw_item_id: rawItemId });
            renderRawFilesList();
            await loadRawMetadata(filename, false, rawItemId);
        });
    }

    const rawHashesList = document.getElementById('raw-hashes-list');
    if (rawHashesList) {
        rawHashesList.addEventListener('click', async (e) => {
            const row = e.target.closest('.list-item');
            if (!row) return;
            const filename = row.getAttribute('data-filename');
            if (!filename) return;

            const hasContext = row.getAttribute('data-has-context') === 'true';
            const validHashLines = Number(row.getAttribute('data-valid-hash-lines') || 0);
            if (!hasContext || validHashLines <= 0) {
                log(`RAW hash ${filename} has no usable context yet.`, 'warn');
                return;
            }

            const primaryBssid = row.getAttribute('data-primary-bssid') || '';
            if (!isMacAddress(primaryBssid)) {
                log(`RAW hash ${filename} has no valid primary BSSID.`, 'warn');
                return;
            }
            const rawDisplayTarget = `RAW HASH ${filename}`;

            STATE.rawSelectedHash = filename;
            renderRawHashesList();
            await openCrackingPanel(primaryBssid, rawDisplayTarget, filename, { scope: 'raw_hash' });
        });
    }

    const rawDetailsView = document.getElementById('raw-details-view');
    if (rawDetailsView) {
        rawDetailsView.addEventListener('click', (e) => {
            const row = e.target.closest('.raw-network-row');
            if (!row || !STATE.rawSelectedFile) return;
            const bssid = row.getAttribute('data-bssid');
            if (!bssid) return;
            STATE.rawSelectedNetworkByFile[STATE.rawSelectedFile] = bssid;
            renderRawMetadata(
                STATE.rawSelectedFile,
                STATE.rawMetadataByFile[STATE.rawSelectedFile] || null
            );
        });
    }

    if (!document.__kovilRawAnalysisListenerBound) {
        document.__kovilRawAnalysisListenerBound = true;
        document.addEventListener('kovil:open-raw-analysis', async (event) => {
            const detail = event?.detail || {};
            const rawItemId = String(detail.rawItemId || '').trim();
            const filename = String(detail.filename || '').trim();
            if (!rawItemId && !filename) return;
            const btnRawView = document.getElementById('btn-raw-view');
            if (btnRawView) btnRawView.click();

            if (filename) {
                STATE.rawSelectedFile = filename;
            }
            if (rawItemId) {
                STATE.rawSelectedRawItemId = rawItemId;
            }

            if (filename) {
                await loadRawMetadata(filename, false, rawItemId || null);
            }
            if (rawItemId) {
                try {
                    await loadRawAnalysis(rawItemId, { filename: filename || STATE.rawSelectedFile });
                    renderRawMetadata(
                        filename || STATE.rawSelectedFile,
                        STATE.rawMetadataByFile[filename || STATE.rawSelectedFile] || null
                    );
                } catch (_e) {
                    // If no analysis exists yet, leave the workspace on metadata view.
                }
            }
        });
    }
}
