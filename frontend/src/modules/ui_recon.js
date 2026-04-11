import { STATE, saveLists } from './state.js';
import { API } from './api.js';
import { log, escapeHtml } from './utils.js';
import { addProcess } from './ui_components/ui_processes.js';
import { openCrackingPanel } from './ui_components/ui_cracking.js';
import {
    applyReconCacheManifest,
    clearReconPayloadCaches,
    clearReconRuntimeCache,
    clearTabCache as _tdc_clear,
    ensureReconCacheManifest as _ensureReconCacheManifest,
    getCachedReconRow as _getCachedReconRow,
    getCachedReconRowsByMacs as _getCachedReconRowsByMacs,
    getDetailCacheEntry as _detailCacheGet,
    getReconCacheScope as _getReconCacheScope,
    getTabCacheEntry as _tdc_get,
    primeReconCacheManifest,
    rememberReconRows as _rememberReconRows,
    setDetailCacheEntry as _detailCacheSet,
    setTabCacheEntry as _tdc_set,
} from './recon/cache.js';
import {
    formatReconDeviceLabel as _formatReconDeviceLabel,
    formatReconSourceLabel as _formatReconSourceLabel,
    getReconSecurityEntries as _getReconSecurityEntries,
    normalizeReconSecurityLabel as _normalizeReconSecurityLabel,
    reconHintLabel as _reconHintLabel,
    renderReconDeviceMiniBar as _renderReconDeviceMiniBar,
    renderReconFindingsPanel as _renderReconFindingsPanel,
    renderReconSecurityMiniBar as _renderReconSecurityMiniBar,
    renderReconSourceMiniBar as _renderReconSourceMiniBar,
} from './recon/ui_helpers.js';
import {
    bindSigintGeocorrelationActions as _bindSigintGeocorrelationActions,
    formatSigintGeoWindow as _formatSigintGeoWindow,
    formatSigintVendor as _formatSigintVendor,
    renderSigintGeocorrelationPanel as _renderSigintGeocorrelationPanel,
} from './recon/sigint_graph_helpers.js';
import { createAttackSurfaceRenderer } from './recon/attack_surface_tab.js';
import {
    createCommsRenderer,
    renderCommsClusters as _renderCommsClusters,
    renderCommsDeviceIntel as _renderCommsDeviceIntel,
    renderCommsGraph as _renderCommsGraph,
    renderCommsTopVendors as _renderCommsTopVendors,
} from './recon/comms_tab.js';
import { createSigintRenderer, renderSigintData as _renderSigintData } from './recon/sigint_tab.js';
import { createOperationsRenderer } from './recon/operations_tab.js';
import { createReportsRenderer } from './recon/reports_tab.js';
import { createGeointRenderer } from './recon/geoint_tab.js';
import { createTargetIntelRenderer } from './recon/target_intel_tab.js';
import { createTargetDetailController } from './recon/target_detail_flow.js';

export { clearReconRuntimeCache, primeReconCacheManifest };

// ─── Recon UI local state ───────────────────────────────────────────
const _reconState = {
    surfaceStageFilter: null,       // S-L1: active stage filter
    surfaceSearch: '',              // S-L3: search text
    surfaceExpanded: new Set(),     // S-L2: expanded stage blocks
    surfaceBulk: new Set(),         // S-F4: bulk-selected MACs
    surfaceStageLoading: {},        // S-L: lazy member loading per stage/search
    intelSort: { col: 'attack_score', dir: 'desc' }, // I-L1
    intelFilter: { encryption: 'all', stage: 'all', severity: 'all' }, // I-L2
    intelPage: { offset: 0, limit: 50 },              // I-L6
    intelCompare: [],               // I-F5: MACs selected for comparison (max 4)
    intelDetailMac: null,           // Intel details focus follows selection context
    surfaceCollapsed: new Set(),    // S-L3: Surface sections collapsed state
    reportCollapsed: new Set(),     // R-L3
    reportChecklist: null,          // R-F4: compliance checklist state (from localStorage)
    sigintSearch: '',               // SI-L1
    sigintExpanded: new Set(),      // SI-L4
    sigintCollapsed: new Set(),     // SI sections collapsed state
    opsPeriod: 'all',               // O-L4: time filter
    opsCollapsed: new Set(),        // OPS sections collapsed state
    geoCollapsed: new Set(),        // GEO sections collapsed state
    commsSearch: '',                // C-L1: COMMS search text
    commsCollapsed: new Set(),      // C-L2: COMMS collapsed sections
    commsLoading: {},               // C-L: per-section lazy loading state
    commsResizeObserver: null,      // C-L: disconnect observers across rerenders
    deepPollTimer: null,            // I-F: deep analysis polling interval
    opsPollTimer: null,             // O-F1: ops active jobs polling interval
};

const _SURFACE_STAGE_PREVIEW_LIMIT = 20;
const _SURFACE_STAGE_PAGE_LIMIT = 50;

// ─── Utilities ─────────────────────────────────────────────────────

function _debounce(fn, delay) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

/** Set up a canvas for HiDPI displays. Returns {ctx, W, H} in logical pixels. */
function _hiDpiCanvas(canvas) {
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    const W = rect.width || canvas.width;
    const H = rect.height || canvas.height;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    canvas.style.width = W + 'px';
    canvas.style.height = H + 'px';
    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    return { ctx, W, H };
}

/** Attach hover tooltip to a canvas. hitRegions: [{x, y, w, h, label}] */
function _attachCanvasTooltip(canvas, hitRegions) {
    if (!canvas) return;
    const wrap = canvas.parentElement;
    if (!wrap) return;
    wrap.style.position = 'relative';
    let tip = wrap.querySelector('.recon-canvas-tooltip');
    if (!tip) {
        tip = document.createElement('div');
        tip.className = 'recon-canvas-tooltip';
        tip.style.display = 'none';
        wrap.appendChild(tip);
    }
    canvas.onmousemove = (e) => {
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const hit = hitRegions.find(r => mx >= r.x && mx <= r.x + r.w && my >= r.y && my <= r.y + r.h);
        if (hit) {
            tip.textContent = hit.label;
            tip.style.display = 'block';
            tip.style.left = Math.min(mx + 12, rect.width - tip.offsetWidth - 4) + 'px';
            tip.style.top = (my - 28) + 'px';
        } else {
            tip.style.display = 'none';
        }
    };
    canvas.onmouseleave = () => { tip.style.display = 'none'; };
}

function _formatReconChannels(channels, limit = 3) {
    const entries = Object.entries(channels || {})
        .map(([channel, count]) => ({ channel, count: Number(count) || 0 }))
        .filter((entry) => entry.count > 0)
        .sort((a, b) => b.count - a.count || Number(a.channel) - Number(b.channel))
        .slice(0, limit);
    if (!entries.length) return '—';
    return entries.map((entry) => `CH${entry.channel} (${entry.count})`).join(' · ');
}

function _formatReconRssiStat(value) {
    return value == null ? '—' : String(value);
}

// ─── Panel visibility ───────────────────────────────────────────────

export function setReconWorkspaceActive(active) {
    const enabled = !!active;
    if (!STATE.ui || typeof STATE.ui !== 'object') STATE.ui = {};
    STATE.ui.analyticsWorkspaceActive = enabled;

    const panel = document.getElementById('analytics-panel');
    if (panel) panel.style.display = enabled ? 'flex' : 'none';
}

// ─── Main refresh ───────────────────────────────────────────────────

let _refreshing = false;

export async function refreshReconPanel() {
    if (_refreshing) return;
    _refreshing = true;
    try {
        const tab = getActiveTab();
        const previousScope = _getReconCacheScope();
        await renderTab(tab);
        void _ensureReconCacheManifest()
            .then((manifest) => {
                const nextScope = String(manifest?.scope || '').trim();
                if (!nextScope || nextScope === previousScope) return;
                if (!STATE.modes?.analytics) return;
                if (getActiveTab() !== tab) return;
                renderTab(tab);
            })
            .catch(() => null);
    } catch (e) {
        log('recon', `Error refreshing: ${e.message}`);
    } finally {
        _refreshing = false;
    }
}

// ─── Tabs ───────────────────────────────────────────────────────────

// Tabs that use the right-panel Target Details column
const TABS_WITH_RIGHT_PANEL = new Set([]);

// Tabs that use the bottom drawer for Target Details
const TABS_WITH_DRAWER = new Set(['attack-surface', 'target-intel']);

function getActiveTab() {
    if (!STATE.reconUi) STATE.reconUi = { activeTab: 'attack-surface' };
    return STATE.reconUi.activeTab || 'attack-surface';
}

function setActiveTab(name) {
    if (!STATE.reconUi) STATE.reconUi = { activeTab: name };
    else STATE.reconUi.activeTab = name;

    document.querySelectorAll('.recon-tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === name);
    });
}

function _syncReconLayoutState(tab) {
    const splitContent = document.getElementById('recon-tab-content')?.closest('.panel-split-content');
    if (splitContent) {
        splitContent.classList.toggle('recon-right-hidden', !TABS_WITH_RIGHT_PANEL.has(tab));
        splitContent.classList.toggle('recon-drawer-active', TABS_WITH_DRAWER.has(tab));
    }

    const drawer = document.getElementById('recon-drawer');
    if (drawer) {
        if (TABS_WITH_DRAWER.has(tab) && STATE.reconUi?.selectedMac) {
            drawer.classList.remove('recon-drawer--hidden');
            drawer.classList.remove('recon-drawer--collapsed');
        } else {
            drawer.classList.add('recon-drawer--hidden');
            drawer.classList.remove('recon-drawer--collapsed');
        }
    }
}

async function renderTab(tab) {
    const container = document.getElementById('recon-tab-content');
    if (!container) return;

    // Clear any active polling timers from previous tab
    if (_reconState.deepPollTimer) { clearInterval(_reconState.deepPollTimer); _reconState.deepPollTimer = null; }
    if (_reconState.opsPollTimer) { clearInterval(_reconState.opsPollTimer); _reconState.opsPollTimer = null; }

    _syncReconLayoutState(tab);

    // Show loading spinner only when there is no fresh cached data for this tab.
    // This preserves stale content on screen while fresh data is fetched.
    const cacheKey = tab === 'operations' ? `ops:${_reconState.opsPeriod}` : tab;
    const useShellLoading = tab === 'attack-surface' || tab === 'comms';
    if (!useShellLoading && !_tdc_get(cacheKey)) {
        container.innerHTML = '<div class="recon-loading">Loading…</div>';
    }

    try {
        switch (tab) {
            case 'attack-surface': await renderAttackSurface(container); break;
            case 'target-intel':   await renderTargetIntel(container); break;
            case 'operations':     await renderOperations(container); break;
            case 'geoint':         await renderGeoint(container); break;
            case 'sigint':         await renderSigint(container); break;
            case 'reports':        await renderReports(container); break;
            case 'comms':          await renderComms(container); break;
            default:               await renderAttackSurface(container); break;
        }
    } catch (e) {
        container.innerHTML = `<div class="recon-error"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHtml(e.message)}</div>`;
    }
}

const { renderAttackSurface } = createAttackSurfaceRenderer({
    API,
    escapeHtml,
    reconState: _reconState,
    surfaceStagePreviewLimit: _SURFACE_STAGE_PREVIEW_LIMIT,
    surfaceStagePageLimit: _SURFACE_STAGE_PAGE_LIMIT,
    tdcGet: _tdc_get,
    tdcSet: _tdc_set,
    rememberReconRows: _rememberReconRows,
    getCachedReconRow: _getCachedReconRow,
    detailCacheGet: _detailCacheGet,
    downloadFile: _downloadFile,
    showQuickAttackPopup: (...args) => _showQuickAttackPopup(...args),
    syncSelectedHighlight: (...args) => _syncSelectedHighlight(...args),
    enableDynamicSectionCollapse: _enableDynamicSectionCollapse,
    selectTarget: (...args) => selectTarget(...args),
    reconHintLabel: _reconHintLabel,
    getActiveTab,
    debounce: _debounce,
});

function _buildKnownReconSsidsFromState() {
    const knownSsids = new Set();
    Object.values(STATE.allPositions || {}).forEach((net) => {
        const ssid = String(net?.ssid || '').trim().toLowerCase();
        if (ssid) knownSsids.add(ssid);
    });
    return knownSsids;
}

function _normalizeSectionKey(prefix, raw, index) {
    const cleaned = String(raw || '')
        .toLowerCase()
        .replace(/\d+/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    const base = cleaned || `section-${index}`;
    return `${prefix}-${base}`;
}

function _enableDynamicSectionCollapse(container, opts) {
    const { titleSelector, stateSet, keyPrefix, dataAttr, rerender } = opts || {};
    if (!container || !titleSelector || !stateSet || !dataAttr || typeof rerender !== 'function') return;

    const titles = Array.from(container.querySelectorAll(titleSelector));
    for (let i = 0; i < titles.length; i++) {
        const titleEl = titles[i];
        if (!titleEl || !titleEl.parentElement) continue;

        const rawText = titleEl.textContent || '';
        const key = _normalizeSectionKey(keyPrefix || 'section', rawText, i);
        const isCollapsed = stateSet.has(key);
        const titleHtml = titleEl.innerHTML;

        titleEl.classList.add('recon-section-toggle');
        titleEl.setAttribute(`data-${dataAttr}`, key);
        titleEl.innerHTML = `<span class="recon-section-arrow">${isCollapsed ? '▸' : '▾'}</span> ${titleHtml}`;

        const block = document.createElement('div');
        block.className = `recon-report-block${isCollapsed ? ' recon-collapsed' : ''}`;
        let sib = titleEl.nextElementSibling;
        while (sib && !sib.matches(titleSelector)) {
            const next = sib.nextElementSibling;
            block.appendChild(sib);
            sib = next;
        }
        titleEl.parentElement.insertBefore(block, sib);

        titleEl.addEventListener('click', () => {
            if (stateSet.has(key)) stateSet.delete(key);
            else stateSet.add(key);
            rerender();
        });
    }
}

// ─── Right panel: target detail ─────────────────────────────────────

const {
    syncSelectedHighlight: _syncSelectedHighlight,
    selectTarget,
} = createTargetDetailController({
    STATE,
    saveLists,
    API,
    log,
    escapeHtml,
    openCrackingPanel,
    setReconWorkspaceActive,
    normalizeReconSecurityLabel: _normalizeReconSecurityLabel,
    detailCacheGet: _detailCacheGet,
    detailCacheSet: _detailCacheSet,
    tabCacheGet: _tdc_get,
    getCachedReconRow: _getCachedReconRow,
    rememberReconRows: _rememberReconRows,
    getActiveTab,
    tabsWithDrawer: TABS_WITH_DRAWER,
    reconState: _reconState,
});

const { renderTargetIntel } = createTargetIntelRenderer({
    API,
    log,
    escapeHtml,
    addProcess,
    reconHintLabel: _reconHintLabel,
    reconState: _reconState,
    tdcGet: _tdc_get,
    tdcSet: _tdc_set,
    tdcClear: _tdc_clear,
    detailCacheSet: _detailCacheSet,
    rememberReconRows: _rememberReconRows,
    downloadFile: _downloadFile,
    formatTime,
    selectTarget: (...args) => selectTarget(...args),
});

const { renderOperations } = createOperationsRenderer({
    STATE,
    saveLists,
    API,
    log,
    escapeHtml,
    openCrackingPanel,
    reconState: _reconState,
    reconHintLabel: _reconHintLabel,
    tdcGet: _tdc_get,
    tdcSet: _tdc_set,
    tdcClear: _tdc_clear,
    detailCacheSet: _detailCacheSet,
    enableDynamicSectionCollapse: _enableDynamicSectionCollapse,
    formatSize: _formatSize,
    formatRelativeTime: _formatRelativeTime,
    formatTime,
});

const { renderReports } = createReportsRenderer({
    API,
    log,
    escapeHtml,
    reconState: _reconState,
    reconHintLabel: _reconHintLabel,
    tdcGet: _tdc_get,
    tdcSet: _tdc_set,
    renderReconFindingsPanel: _renderReconFindingsPanel,
    downloadFile: _downloadFile,
});

const { renderGeoint } = createGeointRenderer({
    API,
    escapeHtml,
    reconHintLabel: _reconHintLabel,
    tdcGet: _tdc_get,
    tdcSet: _tdc_set,
    enableDynamicSectionCollapse: _enableDynamicSectionCollapse,
    reconState: _reconState,
});

// ─── Helpers ────────────────────────────────────────────────────────

// S-F1: Quick Attack popup
function _showQuickAttackPopup(anchorEl, mac, ssid) {
    let popup = document.getElementById('recon-quick-attack-popup');
    if (popup) popup.remove();
    popup = document.createElement('div');
    popup.id = 'recon-quick-attack-popup';
    popup.className = 'recon-popup';
    const macClean = (mac || '').replace(/:/g, '').toLowerCase();
    popup.innerHTML = `<div class="recon-popup-title">Attack: ${escapeHtml(ssid || mac)}</div>
        <button class="recon-popup-opt" data-action="hashcat">
            <i class="fa-solid fa-microchip"></i> Hashcat (Dictionary)
        </button>
        <button class="recon-popup-opt" data-action="hashcat-brute">
            <i class="fa-solid fa-key"></i> Hashcat (Brute Force)
        </button>
        <button class="recon-popup-opt" data-action="pmk">
            <i class="fa-solid fa-database"></i> PMK Attack
        </button>
        <div class="recon-popup-plan"></div>
        <button class="recon-popup-opt recon-popup-opt--close" data-action="close">Close</button>`;
    document.body.appendChild(popup);
    const rect = anchorEl.getBoundingClientRect();
    popup.style.top = `${rect.bottom + 4}px`;
    popup.style.left = `${rect.left}px`;

    const strategyMap = { hashcat: 'dictionary', 'hashcat-brute': 'bruteforce', pmk: 'pmk' };
    const planDiv = popup.querySelector('.recon-popup-plan');
    popup.querySelectorAll('.recon-popup-opt').forEach(opt => {
        opt.addEventListener('click', async () => {
            if (opt.dataset.action === 'close') { popup.remove(); return; }
            const strategy = strategyMap[opt.dataset.action];
            if (!strategy) return;
            planDiv.textContent = 'Planning…';
            try {
                const op = await API.createReconAttackPlan({ targets: [mac], strategy });
                planDiv.innerHTML = op
                    ? `Mode: ${escapeHtml(op.mode || '—')}<br>Wordlist: ${escapeHtml(op.wordlist || '—')}`
                    : 'No plan returned.';
            } catch (e) {
                planDiv.textContent = `Error: ${e.message}`;
            }
        });
    });
    // Close on outside click
    const closeHandler = (e) => {
        if (!popup.contains(e.target)) { popup.remove(); document.removeEventListener('click', closeHandler, true); }
    };
    setTimeout(() => document.addEventListener('click', closeHandler, true), 0);
}

function _downloadFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// ─── TAB: COMMS Intelligence ────────────────────────────────────────
const { renderComms } = createCommsRenderer({
    API,
    reconState: _reconState,
    tdcGet: _tdc_get,
    tdcSet: _tdc_set,
    getActiveTab,
    debounce: _debounce,
    hiDpiCanvas: _hiDpiCanvas,
    attachCanvasTooltip: _attachCanvasTooltip,
});

const { renderSigint } = createSigintRenderer({
    API,
    addProcess,
    log,
    escapeHtml,
    reconState: _reconState,
    tdcGet: _tdc_get,
    tdcSet: _tdc_set,
    buildKnownReconSsidsFromState: _buildKnownReconSsidsFromState,
    bindSigintGeocorrelationActions: _bindSigintGeocorrelationActions,
    renderSigintGeocorrelationPanel: _renderSigintGeocorrelationPanel,
    formatSigintGeoWindow: _formatSigintGeoWindow,
    formatSigintVendor: _formatSigintVendor,
    reconHintLabel: _reconHintLabel,
    normalizeReconSecurityLabel: _normalizeReconSecurityLabel,
    formatReconDeviceLabel: _formatReconDeviceLabel,
    formatReconSourceLabel: _formatReconSourceLabel,
    enableDynamicSectionCollapse: _enableDynamicSectionCollapse,
    debounce: _debounce,
    downloadFile: _downloadFile,
});

function _renderSigintDataCompat(container, data, knownSsids) {
    const loadSigintExtensions = async () => {
        const deWrap = document.getElementById('sigint-derandom');
        if (deWrap) {
            try {
                const dr = await API.getReconProbeDerandom();
                const groups = (dr && dr.groups) || [];
                if (!groups.length) {
                    deWrap.innerHTML = '<span class="recon-muted">No likely device groups detected from shared probe fingerprints.</span>';
                } else {
                    let h = '<div class="recon-derandom-grid">';
                    for (const g of groups) {
                        const badge = g.confidence === 'high' ? 'recon-mini-badge--pmkid' : '';
                        const timeWindow = _formatSigintGeoWindow(g);
                        const memberRows = (g.members || []).map((m) => `
                            <div class="recon-derandom-member">
                                <div class="recon-derandom-member-main">
                                    <span class="recon-sigint-mac${m.is_random ? ' recon-random-mac' : ''}">${escapeHtml(m.mac)}</span>
                                    <span class="recon-sigint-match-pill${m.is_random ? ' recon-sigint-match-pill--warn' : ' recon-sigint-match-pill--known'}">${m.is_random ? 'Randomized' : 'Global'}</span>
                                </div>
                                <div class="recon-derandom-member-meta">
                                    <span>${escapeHtml(m.vendor || 'Unknown vendor')}</span>
                                    <span>${m.probe_count || 0} probes</span>
                                    <span>${m.avg_signal != null ? `${m.avg_signal} dBm` : 'No RSSI'}</span>
                                </div>
                            </div>
                        `).join('');
                        h += `<div class="recon-derandom-card">
                            <div class="recon-derandom-header">
                                <div>
                                    <div class="recon-derandom-title">${escapeHtml(g.group_label || 'Likely Device')}</div>
                                    <div class="recon-derandom-summary">${escapeHtml(g.rule_summary || 'Shared probe fingerprint detected.')}</div>
                                </div>
                                <div class="recon-derandom-badges">
                                    <span class="recon-mini-badge ${badge}">${escapeHtml(g.confidence)}</span>
                                    <span class="recon-badge recon-badge--dim">${g.total_macs} MACs</span>
                                </div>
                            </div>
                            <div class="recon-derandom-window">${escapeHtml(timeWindow)}</div>
                            <div class="recon-derandom-sub">Shared fingerprint</div>
                            <div class="recon-derandom-ssids">${(g.ssid_fingerprint || []).map((s) => `<span class="recon-chip">${escapeHtml(s)}</span>`).join(' ')}</div>
                            <div class="recon-derandom-sub">Known matches</div>
                            <div class="recon-derandom-known">${g.known_ssid_count ? (g.known_ssid_preview || []).map((s) => `<span class="recon-chip recon-chip--geo">${escapeHtml(s)}</span>`).join(' ') : '<span class="recon-muted">No known network matches in the current Recon dataset.</span>'}</div>
                            <div class="recon-derandom-sub">Observed MACs</div>
                            <div class="recon-derandom-members">${memberRows}</div>
                        </div>`;
                    }
                    h += '</div>';
                    deWrap.innerHTML = h;
                }
            } catch (_) {
                deWrap.innerHTML = '<span class="recon-muted">Error loading data</span>';
            }
        }

        const geoWrap = document.getElementById('sigint-geocorr');
        if (geoWrap) {
            try {
                const gc = await API.getReconProbeGeocorrelation();
                const clients = (gc && gc.clients) || [];
                geoWrap.innerHTML = _renderSigintGeocorrelationPanel(gc || {});
                if (clients.length) _bindSigintGeocorrelationActions(geoWrap, clients);
            } catch (_) {
                geoWrap.innerHTML = '<span class="recon-muted">Error loading data</span>';
            }
        }
    };

    return _renderSigintData({
        escapeHtml,
        reconState: _reconState,
        reconHintLabel: _reconHintLabel,
        normalizeReconSecurityLabel: _normalizeReconSecurityLabel,
        formatReconDeviceLabel: _formatReconDeviceLabel,
        formatReconSourceLabel: _formatReconSourceLabel,
        formatSigintVendor: _formatSigintVendor,
        enableDynamicSectionCollapse: _enableDynamicSectionCollapse,
        loadSigintExtensions,
        debounce: _debounce,
        downloadFile: _downloadFile,
    }, container, data, knownSsids);
}

function formatTime(seconds) {
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${(seconds / 3600).toFixed(1)}h`;
}

function _formatRelativeTime(ts) {
    if (!ts) return 'unknown';
    const parsed = new Date(ts).getTime();
    if (!Number.isFinite(parsed) || parsed <= 0) return 'unknown';
    const diffSec = Math.max(0, Math.round((Date.now() - parsed) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    const mins = Math.floor(diffSec / 60);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
}

function _formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`;
    return `${(bytes / 1073741824).toFixed(1)} GB`;
}

// ─── Listeners ──────────────────────────────────────────────────────

export function setupReconListeners() {
    // Tab clicks
    document.querySelectorAll('.recon-tab').forEach(btn => {
        btn.addEventListener('click', () => {
            // Reset selected target when switching tabs to avoid cross-tab confusion
            if (STATE.reconUi) STATE.reconUi.selectedMac = null;
            const rightPanel = document.getElementById('recon-right-content');
            if (rightPanel) rightPanel.innerHTML = '<div class="recon-right-empty">Select a target to view details</div>';

            // Reset drawer content when switching tabs
            const drawerContent = document.getElementById('recon-drawer-content');
            if (drawerContent) drawerContent.innerHTML = '<div class="recon-right-empty">Select a target for detailed intel.</div>';

            setActiveTab(btn.dataset.tab);
            renderTab(btn.dataset.tab);
        });
    });

    // Drawer toggle (click on handle bar to collapse/expand)
    const drawerToggle = document.getElementById('recon-drawer-toggle');
    if (drawerToggle) {
        drawerToggle.addEventListener('click', (e) => {
            // Ignore if the close button was clicked
            if (e.target.closest('.recon-drawer-close')) return;
            const drawer = document.getElementById('recon-drawer');
            if (drawer) drawer.classList.toggle('recon-drawer--collapsed');
        });
    }

    // Drawer close button
    const drawerClose = document.getElementById('recon-drawer-close');
    if (drawerClose) {
        drawerClose.addEventListener('click', () => {
            const drawer = document.getElementById('recon-drawer');
            if (drawer) drawer.classList.add('recon-drawer--hidden');
            if (STATE.reconUi) STATE.reconUi.selectedMac = null;
            _syncSelectedHighlight();
        });
    }

    // Refresh button
    const btnRefresh = document.getElementById('btn-recon-refresh');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', () => {
            clearReconRuntimeCache();
            refreshReconPanel();
        });
    }
}

export const __test = {
    _applyReconCacheManifest: applyReconCacheManifest,
    _clearReconPayloadCaches: clearReconPayloadCaches,
    _syncReconLayoutState,
    _tdc_get,
    _tdc_set,
    _normalizeReconSecurityLabel,
    _getReconSecurityEntries,
    _renderReconSecurityMiniBar,
    _renderReconFindingsPanel,
    _renderSigintData: _renderSigintDataCompat,
    _renderCommsDeviceIntel,
    _renderCommsTopVendors,
    _renderCommsClusters,
    _renderCommsGraph,
    renderAttackSurface,
    selectTarget,
};
