import { STATE, saveModes } from './state.js';
import { API } from './api.js';
import { log, escapeHtml } from './utils.js';
import {
    calculateDiscoveredZones,
    calculateIntelligenceZones,
    calculateToConquerZones,
    calculateZones,
    clearClassicMapOverlays,
    clearAnalyticsHeatmapLayer,
    clearAnalyticsHotspotsLayer,
    clearWardriveLayers,
    focusWardriveTrack,
    focusWardriveReplayPlayhead,
    focusWardriveBBox,
    focusWardriveZone,
    getMapInstance,
    getWardriveSessionPalette,
    renderMarkers,
    renderWardriveRegion,
    renderWardriveSessionTracks,
    renderWardriveZones,
    setWardriveReplayPlayhead,
} from './map.js';
import { setReconWorkspaceActive } from './ui_recon.js';
import { buildHintTrigger } from './ui_components/ui_hints.js';
import {
    buildWardriveLoadingBlocks,
    buildWardriveLoadingKpiCards,
    buildWardriveLoadingRows,
    buildWardriveSessionLoadingCards,
    yieldWardriveUiPaint,
} from './wardrive/loading.js';
import { createWardriveRouteReplayRenderer } from './wardrive/route_replay.js';

const DEFAULT_DBSCAN_EPS = 200;
const DEFAULT_DBSCAN_MIN_SAMPLES = 3;
const WORKSPACE_TAB_MAIN = 'workspace';
const WORKSPACE_TAB_INVENTORY = 'inventory';
const WORKSPACE_EXPLORER_PANE_REGIONS = 'regions';
const WORKSPACE_EXPLORER_PANE_ZONES = 'zones';
const LEVEL_WEIGHT = { state: 1, city: 2, neighborhood: 3, sector: 4, unmapped: 999 };
const LEVEL_LABEL = {
    state: 'State',
    city: 'City',
    neighborhood: 'Neighborhood',
    sector: 'Sector',
    unmapped: 'Unmapped',
};
const TRANSPORT_MODE_META = {
    walk: { icon: 'fa-person-walking', label: 'Walk' },
    bike: { icon: 'fa-bicycle', label: 'Bike' },
    motorcycle: { icon: 'fa-motorcycle', label: 'Motorcycle' },
    boat: { icon: 'fa-ship', label: 'Boat' },
    plane: { icon: 'fa-plane', label: 'Plane' },
    helicopter: { icon: 'fa-helicopter', label: 'Helicopter' },
    car: { icon: 'fa-car', label: 'Car' },
    bus: { icon: 'fa-bus', label: 'Bus' },
    train: { icon: 'fa-train', label: 'Train' },
    metro: { icon: 'fa-subway', label: 'Metro' },
};
const TRANSPORT_MODE_ORDER = Object.keys(TRANSPORT_MODE_META);
const REPLAY_SPEED_OPTIONS = [0.05, 0.1, 0.25, 0.5, 1, 1.5, 2, 2.5, 4, 8];
const REPLAY_TIMING_MODE_OPTIONS = [
    { value: 'real_time', label: 'Real Time', description: 'Keeps the original timing between captured points.' },
    { value: 'compress_idle', label: 'Compress Idle', description: 'Caps long stops so replay keeps moving.' },
    { value: 'uniform_path', label: 'Uniform Path', description: 'Ignores raw timestamps and distributes movement across the route.' },
];
const REPLAY_TIMING_MODE_ALLOWED = new Set(REPLAY_TIMING_MODE_OPTIONS.map((item) => item.value));
const REPLAY_FOLLOW_ZOOM_OPTIONS = [
    { value: 'current', label: 'Current' },
    { value: '13', label: 'City (13)' },
    { value: '15', label: 'Street (15)' },
    { value: '17', label: 'Close (17)' },
    { value: '19', label: 'Very Close (19)' },
];
const REPLAY_FOLLOW_ZOOM_ALLOWED = new Set(REPLAY_FOLLOW_ZOOM_OPTIONS.map((item) => item.value));
const REPLAY_IDLE_DISTANCE_THRESHOLD_METERS = 25;
const REPLAY_IDLE_MAX_SECONDS = 3;
const WARDRIVE_SESSIONS_UI_STORAGE_KEY = 'pwn_wardrive_sessions_ui';
const WARDRIVE_SESSION_SORT_OPTIONS = new Set(['none', 'date', 'duration', 'distance', 'nets']);
const WARDRIVE_COMPARISON_SECONDARY_SESSION_ID = '__comparison_secondary__';
const WARDRIVE_FILTERED_ZONE_SESSION_ID = '__session_filtered__';
const WARDRIVE_UI_CONFIG_DEFAULTS = {
    replaySpeed: 1,
    replayAutoplay: false,
    replayAutoFocus: true,
    replayFollowCamera: false,
    replayFollowZoom: 'current',
    replayTimingMode: 'real_time',
    sessionsSortBy: 'none',
    sessionsSortDirection: 'desc',
    mergeConfirmation: true,
};

let wardriveHierarchy = [];
let wardriveMapsSummary = {};
let wardriveInventory = {};
let wardriveSessions = [];
let wardriveSessionsSummary = {};
let wardriveSelectedRegionId = null;
let wardriveSelectedSessionIds = [];
let wardriveHierarchyReq = 0;
let wardriveZonesReq = 0;
let wardriveInventoryReq = 0;
let wardriveSessionsReq = 0;
let suspendedMapModes = null;
let sourceBeforeSessionOverride = null;
let wardriveWorkspaceWarm = false;
let wardriveWorkspaceDirty = true;
let wardriveLastRegionPayload = null;
let wardriveLastRegionStats = null;
let wardriveLastZones = [];
let wardriveLastZoneComparison = null;
let wardriveInventoryLoaded = false;
let wardriveWorkspaceTab = WORKSPACE_TAB_MAIN;
let wardriveWorkspaceExplorerPane = WORKSPACE_EXPLORER_PANE_REGIONS;
let wardriveSessionTagSavingIds = new Set();
let wardriveTagPopoverCloseBound = false;
let wardriveOpenFromAnalyticsBound = false;
let wardriveSessionsUiFilters = loadWardriveSessionsUiFilters();
let wardriveCollapsedRegionIds = new Set();
let wardriveSessionTracks = [];
let wardriveReplayLoading = false;
let wardriveHierarchyLoading = false;
let wardriveZonesLoading = false;
let wardriveSessionsLoading = false;
let wardriveInventoryLoading = false;
let wardriveWorkspaceBooting = false;
let wardriveReplayReq = 0;
let wardriveReplayTimer = null;
let wardriveReplayProgress = 0;
let wardriveActiveReplaySessionId = null;
let wardriveReplaySpeed = WARDRIVE_UI_CONFIG_DEFAULTS.replaySpeed;
let wardriveReplayFollowCamera = WARDRIVE_UI_CONFIG_DEFAULTS.replayFollowCamera;
let wardriveReplayFollowZoom = WARDRIVE_UI_CONFIG_DEFAULTS.replayFollowZoom;
let wardriveReplayTimingMode = WARDRIVE_UI_CONFIG_DEFAULTS.replayTimingMode;
let wardriveReplayFollowZoomSnapshot = null;
let wardriveReplayLockedMapHandlers = null;
let wardrivePrewarmReq = 0;
let wardriveSessionMergeLoading = false;
let wardriveUiConfig = { ...WARDRIVE_UI_CONFIG_DEFAULTS };
let wardriveConfigEventBound = false;

function byLevelName(a, b) {
    const levelA = getLevelWeight(a);
    const levelB = getLevelWeight(b);
    if (levelA !== levelB) return levelA - levelB;
    return String(a?.name || '').localeCompare(String(b?.name || ''), 'en');
}

function getLevelWeight(region) {
    const depth = Number(region?.depth);
    if (Number.isFinite(depth)) return depth;
    return LEVEL_WEIGHT[String(region?.level_key || region?.level || '').toLowerCase()] || 99;
}

function getNode(id) {
    return document.getElementById(id);
}

function applyWardriveExplorerPaneUi() {
    const panes = [
        [WORKSPACE_EXPLORER_PANE_REGIONS, getNode('wardrive-explorer-pane-regions'), getNode('btn-wardrive-pane-regions')],
        [WORKSPACE_EXPLORER_PANE_ZONES, getNode('wardrive-explorer-pane-zones'), getNode('btn-wardrive-pane-zones')],
    ];
    panes.forEach(([pane, container, button]) => {
        const active = wardriveWorkspaceExplorerPane === pane;
        if (container) container.style.display = active ? 'flex' : 'none';
        if (button) {
            button.classList.toggle('active', active);
            button.setAttribute('aria-selected', active ? 'true' : 'false');
        }
    });
}

function setWardriveExplorerPane(pane) {
    wardriveWorkspaceExplorerPane = pane === WORKSPACE_EXPLORER_PANE_ZONES
        ? WORKSPACE_EXPLORER_PANE_ZONES
        : WORKSPACE_EXPLORER_PANE_REGIONS;
    applyWardriveExplorerPaneUi();
}

function openWardriveExplorerPane(pane) {
    setWardriveExplorerPane(pane);
    const target = pane === WORKSPACE_EXPLORER_PANE_ZONES
        ? (getNode('wardrive-zones-summary') || getNode('wardrive-zones-list'))
        : getNode('wardrive-regions-list');
    if (target && typeof target.scrollIntoView === 'function') {
        try {
            target.scrollIntoView({ block: 'nearest' });
        } catch (err) {
            target.scrollIntoView();
        }
    }
}

function normalizeWardriveSessionSortBy(value) {
    const normalized = String(value || 'none').trim().toLowerCase();
    return WARDRIVE_SESSION_SORT_OPTIONS.has(normalized) ? normalized : 'none';
}

function normalizeWardriveSessionSortDirection(value) {
    return String(value || 'desc').trim().toLowerCase() === 'asc' ? 'asc' : 'desc';
}

function loadWardriveSessionsUiFilters() {
    try {
        const raw = localStorage.getItem(WARDRIVE_SESSIONS_UI_STORAGE_KEY);
        if (!raw) {
            return {
                sortBy: WARDRIVE_UI_CONFIG_DEFAULTS.sessionsSortBy,
                sortDirection: WARDRIVE_UI_CONFIG_DEFAULTS.sessionsSortDirection,
            };
        }
        const parsed = JSON.parse(raw);
        return {
            sortBy: normalizeWardriveSessionSortBy(parsed?.sortBy),
            sortDirection: normalizeWardriveSessionSortDirection(parsed?.sortDirection),
        };
    } catch (_) {
        return {
            sortBy: WARDRIVE_UI_CONFIG_DEFAULTS.sessionsSortBy,
            sortDirection: WARDRIVE_UI_CONFIG_DEFAULTS.sessionsSortDirection,
        };
    }
}

function persistWardriveSessionsUiFilters() {
    try {
        localStorage.setItem(WARDRIVE_SESSIONS_UI_STORAGE_KEY, JSON.stringify({
            sortBy: normalizeWardriveSessionSortBy(wardriveSessionsUiFilters.sortBy),
            sortDirection: normalizeWardriveSessionSortDirection(wardriveSessionsUiFilters.sortDirection),
        }));
    } catch (_) {
        // Ignore storage errors and keep the in-memory preference.
    }
}

function applyWardriveUiConfig(config = {}) {
    wardriveUiConfig = {
        replaySpeed: normalizeWardriveReplaySpeed(
            config?.ui_wardrive_replay_speed_default ?? wardriveUiConfig.replaySpeed
        ),
        replayAutoplay: Boolean(
            config?.ui_wardrive_replay_autoplay ?? wardriveUiConfig.replayAutoplay
        ),
        replayAutoFocus: Boolean(
            config?.ui_wardrive_replay_auto_focus ?? wardriveUiConfig.replayAutoFocus
        ),
        replayFollowCamera: Boolean(
            config?.ui_wardrive_replay_follow_camera_default ?? wardriveUiConfig.replayFollowCamera
        ),
        replayFollowZoom: normalizeWardriveReplayFollowZoom(
            config?.ui_wardrive_replay_follow_zoom_default ?? wardriveUiConfig.replayFollowZoom
        ),
        replayTimingMode: normalizeWardriveReplayTimingMode(
            config?.ui_wardrive_replay_timing_mode_default ?? wardriveUiConfig.replayTimingMode
        ),
        sessionsSortBy: normalizeWardriveSessionSortBy(
            config?.ui_wardrive_sessions_sort_by ?? wardriveUiConfig.sessionsSortBy
        ),
        sessionsSortDirection: normalizeWardriveSessionSortDirection(
            config?.ui_wardrive_sessions_sort_direction ?? wardriveUiConfig.sessionsSortDirection
        ),
        mergeConfirmation: Boolean(
            config?.ui_wardrive_merge_confirmation ?? wardriveUiConfig.mergeConfirmation
        ),
    };

    wardriveReplaySpeed = wardriveUiConfig.replaySpeed;
    wardriveReplayFollowCamera = wardriveUiConfig.replayFollowCamera;
    wardriveReplayFollowZoom = wardriveUiConfig.replayFollowZoom;
    wardriveReplayTimingMode = wardriveUiConfig.replayTimingMode;
    wardriveSessionsUiFilters = {
        sortBy: wardriveUiConfig.sessionsSortBy,
        sortDirection: wardriveUiConfig.sessionsSortDirection,
    };
    persistWardriveSessionsUiFilters();
    syncWardriveReplayCameraLock();
    syncSessionsUiFiltersDomFromState();
    syncWardriveReplayLiveUi();
    renderWardriveRouteReplaySection();
    renderSessionsPanel();
}

function bindWardriveConfigEvents() {
    if (wardriveConfigEventBound || typeof window === 'undefined') return;
    window.addEventListener('kovil:config-applied', (event) => {
        applyWardriveUiConfig(event?.detail?.config || {});
    });
    wardriveConfigEventBound = true;
}

function getRegionLevelLabel(region) {
    return String(region?.level_label || LEVEL_LABEL[String(region?.level_key || region?.level || '').toLowerCase()] || 'Region');
}

function getRegionDisplayPath(region) {
    const explicit = String(region?.display_path || '').trim();
    if (explicit) return explicit;
    const lineage = Array.isArray(region?.lineage) ? region.lineage : [];
    if (lineage.length) {
        return lineage.map((item) => String(item?.name || '').trim()).filter(Boolean).join(' > ');
    }
    return String(region?.name || '').trim();
}

function formatSessionDateTime(timestampSeconds) {
    const timestamp = Number(timestampSeconds || 0);
    if (!timestamp) return '--';
    try {
        return new Date(timestamp * 1000).toLocaleString('en', {
            dateStyle: 'short',
            timeStyle: 'short',
        });
    } catch (_) {
        return new Date(timestamp * 1000).toLocaleString();
    }
}

function formatDuration(startedAtSeconds, endedAtSeconds) {
    const startedAt = Number(startedAtSeconds || 0);
    const endedAt = Number(endedAtSeconds || 0);
    const diff = Math.max(0, endedAt - startedAt);
    if (!diff) return '--';

    const hours = Math.floor(diff / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    const seconds = diff % 60;
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
}

function getSessionDurationSeconds(startedAtSeconds, endedAtSeconds) {
    return Math.max(0, Number(endedAtSeconds || 0) - Number(startedAtSeconds || 0));
}

function formatDistanceMeters(distanceMeters) {
    const value = Number(distanceMeters);
    if (!Number.isFinite(value) || value < 0) return '--';
    if (value >= 1000) return `${(value / 1000).toFixed(2)} km`;
    return `${Math.round(value)} m`;
}

function formatWardriveSessionDisplayName(value) {
    const label = String(value || '').trim();
    if (!label) return 'wardrive';
    return label
        .replace(/\.csv$/i, '')
        .replace(/^m5evil__/i, '');
}

function formatAccuracyMeters(accuracyMeters) {
    const value = Number(accuracyMeters);
    if (!Number.isFinite(value) || value <= 0) return '--';
    return `${value.toFixed(1)} m`;
}

function clearWardriveReplayTimer() {
    if (wardriveReplayTimer) {
        clearInterval(wardriveReplayTimer);
        wardriveReplayTimer = null;
    }
    syncWardriveReplayCameraLock();
}

function normalizeTransportMode(value) {
    const mode = String(value || '').trim().toLowerCase();
    return TRANSPORT_MODE_META[mode] ? mode : null;
}

function getTransportMeta(mode) {
    const normalized = normalizeTransportMode(mode);
    if (!normalized) {
        return {
            mode: null,
            icon: 'fa-route',
            label: 'Set transport mode',
        };
    }
    return {
        mode: normalized,
        icon: TRANSPORT_MODE_META[normalized].icon,
        label: TRANSPORT_MODE_META[normalized].label,
    };
}

function summarizeTransportModes(sessions) {
    const buckets = {};
    (sessions || []).forEach((session) => {
        const mode = normalizeTransportMode(session?.transport_mode);
        if (!mode) return;
        if (!buckets[mode]) {
            buckets[mode] = {
                transport_mode: mode,
                sessions_count: 0,
                networks_count: 0,
                points_count: 0,
            };
        }
        buckets[mode].sessions_count += 1;
        buckets[mode].networks_count += Number(session?.networks_count || 0);
        buckets[mode].points_count += Number(session?.points_count || 0);
    });
    return Object.values(buckets).sort((a, b) => {
        const netsDiff = Number(b.networks_count || 0) - Number(a.networks_count || 0);
        if (netsDiff !== 0) return netsDiff;
        const sessionsDiff = Number(b.sessions_count || 0) - Number(a.sessions_count || 0);
        if (sessionsDiff !== 0) return sessionsDiff;
        return String(a.transport_mode || '').localeCompare(String(b.transport_mode || ''), 'en');
    });
}

function normalizeWardriveReplaySpeed(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return 1;
    return REPLAY_SPEED_OPTIONS.find((item) => item === numeric) || 1;
}

function normalizeWardriveReplayTimingMode(value) {
    const normalized = String(value || 'real_time').trim().toLowerCase();
    return REPLAY_TIMING_MODE_ALLOWED.has(normalized) ? normalized : 'real_time';
}

function normalizeWardriveReplayFollowZoom(value) {
    const normalized = String(value || 'current').trim().toLowerCase();
    return REPLAY_FOLLOW_ZOOM_ALLOWED.has(normalized) ? normalized : 'current';
}

function formatWardriveReplaySpeed(value) {
    const normalized = normalizeWardriveReplaySpeed(value);
    const labels = {
        0.05: '0.05x · Very Slow',
        0.1: '0.1x · Slow',
        0.25: '0.25x · Leisure',
        0.5: '0.5x · Half',
        1: '1x · Normal',
        1.5: '1.5x · Fast',
        2: '2x · Faster',
        2.5: '2.5x · Very Fast',
        4: '4x · Max',
        8: '8x · Ultra',
    };
    return labels[normalized] || `${normalized}x`;
}

function haversineMeters(lat1, lng1, lat2, lng2) {
    const toRad = (value) => (value * Math.PI) / 180;
    const earthRadius = 6371000;
    const dLat = toRad(lat2 - lat1);
    const dLng = toRad(lng2 - lng1);
    const a = Math.sin(dLat / 2) ** 2
        + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return earthRadius * c;
}

function getWardriveReplayPoints(track) {
    return Array.isArray(track?.points) ? track.points : [];
}

function getWardriveReplayRealTimeWeights(track) {
    const points = getWardriveReplayPoints(track);
    const weights = [];
    for (let index = 0; index < Math.max(0, points.length - 1); index += 1) {
        const current = points[index];
        const next = points[index + 1];
        const delta = Number(next?.ts_last) - Number(current?.ts_last);
        weights.push(Number.isFinite(delta) && delta > 0 ? delta : 1);
    }
    return weights;
}

function getWardriveReplayUniformPathWeights(track) {
    const points = getWardriveReplayPoints(track);
    const distances = [];
    let hasMovement = false;
    for (let index = 0; index < Math.max(0, points.length - 1); index += 1) {
        const current = points[index];
        const next = points[index + 1];
        const currentLat = Number(current?.lat);
        const currentLng = Number(current?.lng);
        const nextLat = Number(next?.lat);
        const nextLng = Number(next?.lng);
        const distance = (
            Number.isFinite(currentLat)
            && Number.isFinite(currentLng)
            && Number.isFinite(nextLat)
            && Number.isFinite(nextLng)
        ) ? haversineMeters(currentLat, currentLng, nextLat, nextLng) : 0;
        if (distance > 0.5) hasMovement = true;
        distances.push(Math.max(distance, 5));
    }
    if (!hasMovement) {
        return distances.map(() => 1);
    }
    return distances;
}

function getWardriveReplayCompressIdleWeights(track) {
    const points = getWardriveReplayPoints(track);
    const baseWeights = getWardriveReplayRealTimeWeights(track);
    const nextWeights = [...baseWeights];
    let idleStart = null;

    function flushIdleRun(endIndexInclusive) {
        if (idleStart === null || endIndexInclusive < idleStart) return;
        const runLength = endIndexInclusive - idleStart + 1;
        const idleWeight = baseWeights
            .slice(idleStart, endIndexInclusive + 1)
            .reduce((sum, weight) => sum + Number(weight || 0), 0);
        const cappedWeight = Math.max(1, Math.min(idleWeight, REPLAY_IDLE_MAX_SECONDS));
        const distributed = cappedWeight / Math.max(1, runLength);
        for (let index = idleStart; index <= endIndexInclusive; index += 1) {
            nextWeights[index] = distributed;
        }
        idleStart = null;
    }

    for (let index = 0; index < Math.max(0, points.length - 1); index += 1) {
        const current = points[index];
        const next = points[index + 1];
        const currentLat = Number(current?.lat);
        const currentLng = Number(current?.lng);
        const nextLat = Number(next?.lat);
        const nextLng = Number(next?.lng);
        const distance = (
            Number.isFinite(currentLat)
            && Number.isFinite(currentLng)
            && Number.isFinite(nextLat)
            && Number.isFinite(nextLng)
        ) ? haversineMeters(currentLat, currentLng, nextLat, nextLng) : 0;
        const isIdle = distance <= REPLAY_IDLE_DISTANCE_THRESHOLD_METERS;
        if (isIdle) {
            if (idleStart === null) idleStart = index;
        } else {
            flushIdleRun(index - 1);
        }
    }
    flushIdleRun(points.length - 2);
    return nextWeights;
}

function getWardriveReplaySegmentWeights(track, timingMode = wardriveReplayTimingMode) {
    const points = getWardriveReplayPoints(track);
    if (points.length <= 1) return [];
    const normalizedTimingMode = normalizeWardriveReplayTimingMode(timingMode);
    if (normalizedTimingMode === 'uniform_path') {
        return getWardriveReplayUniformPathWeights(track);
    }
    if (normalizedTimingMode === 'compress_idle') {
        return getWardriveReplayCompressIdleWeights(track);
    }
    return getWardriveReplayRealTimeWeights(track);
}

function getWardriveReplayTimingModeMeta(value = wardriveReplayTimingMode) {
    const normalized = normalizeWardriveReplayTimingMode(value);
    return REPLAY_TIMING_MODE_OPTIONS.find((item) => item.value === normalized) || REPLAY_TIMING_MODE_OPTIONS[0];
}

const {
    renderWardriveReplayLoadingState,
    renderWardriveRouteReplaySection,
    syncWardriveReplayLiveUi,
} = createWardriveRouteReplayRenderer({
    getNode,
    escapeHtml,
    buildHintTrigger,
    buildWardriveLoadingBlocks,
    buildWardriveLoadingKpiCards,
    buildWardriveLoadingRows,
    formatDistanceMeters,
    formatDuration,
    formatAccuracyMeters,
    formatWardriveReplaySpeed,
    getTransportMeta,
    getWardriveReplayTimingModeMeta,
    getWardriveSelectedSessions,
    getWardriveReplayTracks,
    getActiveWardriveReplayTrack,
    replayTimingModeOptions: REPLAY_TIMING_MODE_OPTIONS,
    replayFollowZoomOptions: REPLAY_FOLLOW_ZOOM_OPTIONS,
    getReplayState: () => ({
        workspaceBooting: wardriveWorkspaceBooting,
        replayLoading: wardriveReplayLoading,
        replayTimer: wardriveReplayTimer,
        replayProgress: wardriveReplayProgress,
        sessionMergeLoading: wardriveSessionMergeLoading,
        replayFollowCamera: wardriveReplayFollowCamera,
        replayFollowZoom: wardriveReplayFollowZoom,
        replayTimingMode: wardriveReplayTimingMode,
        replaySpeed: wardriveReplaySpeed,
        replaySpeedOptions: REPLAY_SPEED_OPTIONS,
    }),
});

function captureWardriveReplayMapZoomSnapshot() {
    if (wardriveReplayFollowZoom !== 'current' || wardriveReplayFollowZoomSnapshot !== null) return;
    const map = getMapInstance();
    const currentZoom = Number(map?.getZoom?.());
    wardriveReplayFollowZoomSnapshot = Number.isFinite(currentZoom) ? currentZoom : null;
}

function resolveWardriveReplayCameraZoom() {
    if (wardriveReplayFollowZoom === 'current') {
        return wardriveReplayFollowZoomSnapshot !== null
            && Number.isFinite(Number(wardriveReplayFollowZoomSnapshot))
            ? Number(wardriveReplayFollowZoomSnapshot)
            : null;
    }
    const numeric = Number(wardriveReplayFollowZoom);
    return Number.isFinite(numeric) ? numeric : null;
}

function lockWardriveReplayMapInteractions() {
    const map = getMapInstance();
    if (!map || wardriveReplayLockedMapHandlers) return;
    const handlerNames = ['dragging', 'scrollWheelZoom', 'doubleClickZoom', 'touchZoom', 'boxZoom', 'keyboard'];
    wardriveReplayLockedMapHandlers = handlerNames.reduce((snapshot, name) => {
        const handler = map?.[name];
        const wasEnabled = Boolean(handler && typeof handler.enabled === 'function' ? handler.enabled() : false);
        snapshot[name] = wasEnabled;
        if (wasEnabled && typeof handler.disable === 'function') {
            handler.disable();
        }
        return snapshot;
    }, {});
}

function unlockWardriveReplayMapInteractions() {
    const map = getMapInstance();
    const snapshot = wardriveReplayLockedMapHandlers;
    wardriveReplayLockedMapHandlers = null;
    wardriveReplayFollowZoomSnapshot = null;
    if (!map || !snapshot) return;
    Object.entries(snapshot).forEach(([name, wasEnabled]) => {
        const handler = map?.[name];
        if (wasEnabled && handler && typeof handler.enable === 'function') {
            handler.enable();
        }
    });
}

function shouldFollowWardriveReplayCamera() {
    return Boolean(wardriveReplayFollowCamera && wardriveReplayTimer);
}

function syncWardriveReplayCameraLock() {
    if (shouldFollowWardriveReplayCamera()) {
        captureWardriveReplayMapZoomSnapshot();
        lockWardriveReplayMapInteractions();
        return;
    }
    unlockWardriveReplayMapInteractions();
}

function getWardriveSelectedSessions() {
    const selectedIds = new Set(
        wardriveSelectedSessionIds.map((item) => String(item || '').trim()).filter(Boolean)
    );
    return wardriveSessions.filter((session) => selectedIds.has(String(session?.session_id || '').trim()));
}

function getWardriveReplayTracks() {
    const selectedIds = new Set(
        wardriveSelectedSessionIds.map((item) => String(item || '').trim()).filter(Boolean)
    );
    return wardriveSessionTracks.filter((track) => selectedIds.has(String(track?.session_id || '').trim()));
}

function getActiveWardriveReplayTrack() {
    const tracks = getWardriveReplayTracks();
    if (!tracks.length) return null;
    return tracks.find((track) => String(track?.session_id || '') === String(wardriveActiveReplaySessionId || '')) || tracks[0];
}

function getFiniteWardriveNumber(...values) {
    for (const value of values) {
        const numeric = Number(value);
        if (Number.isFinite(numeric)) return numeric;
    }
    return null;
}

function getWardriveZoneOverlaySessionIds() {
    const normalized = wardriveSelectedSessionIds
        .map((item) => String(item || '').trim())
        .filter(Boolean);
    return normalized.length > 0 && normalized.length <= 3 ? normalized : [];
}

function getWardriveFocusComparisonSessionIds() {
    const normalized = wardriveSelectedSessionIds
        .map((item) => String(item || '').trim())
        .filter(Boolean);
    return normalized.length >= 2 && normalized.length <= 3 ? normalized : [];
}

function getWardriveStandardZoneScope(selectedSessionsById = new Map()) {
    const selectedSessionIds = wardriveSelectedSessionIds
        .map((item) => String(item || '').trim())
        .filter(Boolean);
    if (!selectedSessionIds.length) return null;

    if (selectedSessionIds.length === 1) {
        const sessionId = selectedSessionIds[0];
        const session = selectedSessionsById.get(sessionId);
        const sessionLabel = String(
            session?.label
            || session?.source_file
            || sessionId
        ).trim() || sessionId;
        return {
            sessionId,
            sessionLabel,
            sessionIds: [sessionId],
            activeSessionId: sessionId,
        };
    }

    return {
        sessionId: WARDRIVE_FILTERED_ZONE_SESSION_ID,
        sessionLabel: 'SELECTED SESSIONS',
        sessionIds: [WARDRIVE_FILTERED_ZONE_SESSION_ID],
        activeSessionId: WARDRIVE_FILTERED_ZONE_SESSION_ID,
    };
}

function getWardriveComparisonActiveSessionId(comparison = wardriveLastZoneComparison) {
    const sessionIds = Array.isArray(comparison?.sessionIds) ? comparison.sessionIds : [];
    const activeSessionId = String(wardriveActiveReplaySessionId || '').trim();
    if (activeSessionId && sessionIds.includes(activeSessionId)) {
        return activeSessionId;
    }
    const comparisonActive = String(comparison?.activeSessionId || '').trim();
    if (comparisonActive && sessionIds.includes(comparisonActive)) {
        return comparisonActive;
    }
    return sessionIds[0] || null;
}

function normalizeWardriveComparisonZone(zone, {
    sessionId = null,
    sessionLabel = null,
    zoneRole = null,
} = {}) {
    const normalizedRole = String(zoneRole || zone?.zone_role || 'primary').trim().toLowerCase() || 'primary';
    const effectiveSessionId = (
        normalizedRole === 'secondary'
            ? WARDRIVE_COMPARISON_SECONDARY_SESSION_ID
            : (sessionId || zone?.session_id || null)
    );
    const effectiveSessionLabel = (
        sessionLabel
        || zone?.session_label
        || (normalizedRole === 'secondary' ? 'OTHER SELECTED SESSIONS' : null)
    );
    const [decorated] = decorateWardriveZones([{
        ...zone,
        session_id: effectiveSessionId,
        session_label: effectiveSessionLabel,
        zone_role: normalizedRole,
    }], {
        sessionId: effectiveSessionId,
        sessionLabel: effectiveSessionLabel,
    });
    return decorated || null;
}

function normalizeWardriveComparisonPayload(comparison = null, selectedSessionsById = new Map()) {
    if (!comparison || String(comparison?.mode || '').trim() !== 'focus_active') {
        return null;
    }

    const sessionIds = Array.from(new Set(
        (Array.isArray(comparison?.session_ids) ? comparison.session_ids : [])
            .map((item) => String(item || '').trim())
            .filter(Boolean)
    ));
    if (!sessionIds.length) return null;

    const normalizedLayersByActiveSession = {};
    sessionIds.forEach((sessionId) => {
        const layer = comparison?.layers_by_active_session?.[sessionId] || {};
        const sessionMeta = selectedSessionsById.get(sessionId);
        const sessionLabel = String(
            sessionMeta?.label
            || sessionMeta?.source_file
            || sessionId
        ).trim() || sessionId;
        const primaryZones = (Array.isArray(layer?.primary_zones) ? layer.primary_zones : [])
            .map((zone) => normalizeWardriveComparisonZone(zone, {
                sessionId,
                sessionLabel,
                zoneRole: 'primary',
            }))
            .filter(Boolean);
        const secondaryZone = layer?.secondary_zone
            ? normalizeWardriveComparisonZone(layer.secondary_zone, {
                sessionId: WARDRIVE_COMPARISON_SECONDARY_SESSION_ID,
                sessionLabel: 'OTHER SELECTED SESSIONS',
                zoneRole: 'secondary',
            })
            : null;
        normalizedLayersByActiveSession[sessionId] = {
            primary_zones: primaryZones,
            secondary_zone: secondaryZone,
        };
    });

    const activeSessionId = (
        sessionIds.includes(String(comparison?.active_session_id || '').trim())
            ? String(comparison.active_session_id || '').trim()
            : sessionIds[0]
    );
    return {
        mode: 'focus_active',
        sessionIds,
        activeSessionId,
        layersByActiveSession: normalizedLayersByActiveSession,
    };
}

function buildWardriveComparisonPreset(comparison = null, activeSessionId = null) {
    const sessionIds = Array.isArray(comparison?.sessionIds) ? comparison.sessionIds : [];
    if (!sessionIds.length) return [];
    const effectiveActiveSessionId = (
        sessionIds.includes(String(activeSessionId || '').trim())
            ? String(activeSessionId || '').trim()
            : getWardriveComparisonActiveSessionId(comparison)
    );
    const activeLayer = comparison?.layersByActiveSession?.[effectiveActiveSessionId] || {};
    const primaryZones = Array.isArray(activeLayer?.primary_zones) ? activeLayer.primary_zones : [];
    const secondaryZone = activeLayer?.secondary_zone || null;
    return [
        ...primaryZones.map((zone) => ({ ...zone })),
        ...(secondaryZone ? [{ ...secondaryZone }] : []),
    ];
}

function syncWardriveComparisonPreset(activeSessionId = null) {
    if (!wardriveLastZoneComparison) return false;
    const effectiveActiveSessionId = getWardriveComparisonActiveSessionId({
        ...wardriveLastZoneComparison,
        activeSessionId: activeSessionId || wardriveLastZoneComparison.activeSessionId,
    });
    wardriveLastZoneComparison = {
        ...wardriveLastZoneComparison,
        activeSessionId: effectiveActiveSessionId,
    };
    wardriveLastZones = buildWardriveComparisonPreset(
        wardriveLastZoneComparison,
        effectiveActiveSessionId
    );
    return true;
}

function getWardriveZoneRenderContext() {
    if (wardriveLastZoneComparison?.mode === 'focus_active') {
        const activeSessionId = getWardriveComparisonActiveSessionId(wardriveLastZoneComparison);
        return {
            sessionIds: [
                ...wardriveLastZoneComparison.sessionIds,
                WARDRIVE_COMPARISON_SECONDARY_SESSION_ID,
            ],
            activeSessionId,
            comparisonMode: 'focus_active',
            comparison: wardriveLastZoneComparison,
        };
    }
    const standardZoneScope = getWardriveStandardZoneScope();
    if (standardZoneScope) {
        return {
            sessionIds: standardZoneScope.sessionIds,
            activeSessionId: standardZoneScope.activeSessionId,
            comparisonMode: 'standard',
            comparison: null,
        };
    }
    return {
        sessionIds: [],
        activeSessionId: null,
        comparisonMode: 'standard',
        comparison: null,
    };
}

function decorateWardriveZones(zones = [], { sessionId = null, sessionLabel = null } = {}) {
    return (Array.isArray(zones) ? zones : []).map((zone, index) => ({
        ...zone,
        session_id: sessionId || zone?.session_id || null,
        session_label: sessionLabel || zone?.session_label || null,
        zone_uid: `${sessionId || 'all'}:${String(zone?.id ?? index)}:${index}`,
    }));
}

function renderCurrentWardriveZones() {
    if (wardriveLastZoneComparison?.mode === 'focus_active') {
        syncWardriveComparisonPreset(wardriveActiveReplaySessionId);
    }
    const zones = Array.isArray(wardriveLastZones) ? wardriveLastZones : [];
    const context = getWardriveZoneRenderContext();
    renderWardriveZones(zones, context);
    renderZonesList(zones, context);
}

function closeAllSessionTagPopovers() {
    document.querySelectorAll('.wardrive-session-transport-popover').forEach((node) => {
        node.classList.remove('is-open');
        node.setAttribute('aria-hidden', 'true');
    });
}

function getWardriveFilters() {
    const timeSelect = getNode('wardrive-time-window');
    const sourceSelect = getNode('wardrive-source');
    const timeWindow = (timeSelect?.value || (STATE.filters.time === '24H' ? '24h' : 'all')).toLowerCase();
    const forceWard = wardriveSelectedSessionIds.length > 0;
    const source = forceWard ? 'ward' : (sourceSelect?.value || 'all').toLowerCase();
    return {
        time_window: timeWindow,
        source,
        session_ids: [...wardriveSelectedSessionIds],
    };
}

function hasWarmWorkspaceSnapshot() {
    return (
        wardriveWorkspaceWarm
        && !wardriveWorkspaceDirty
        && (Array.isArray(wardriveHierarchy) && wardriveHierarchy.length > 0)
    );
}

function ensureWardriveFilterDefaults() {
    const timeSelect = getNode('wardrive-time-window');
    const sourceSelect = getNode('wardrive-source');
    if (timeSelect && !timeSelect.value) {
        timeSelect.value = STATE.filters.time === '24H' ? '24h' : 'all';
    }
    if (sourceSelect && !sourceSelect.value) {
        sourceSelect.value = 'all';
    }
    syncWardriveSourceLock();
}

function syncWardriveSourceLock() {
    const sourceSelect = getNode('wardrive-source');
    if (!sourceSelect) return;

    const hasSessionFilter = wardriveSelectedSessionIds.length > 0;
    if (hasSessionFilter) {
        if (sourceSelect.value !== 'ward') {
            sourceBeforeSessionOverride = sourceSelect.value || 'all';
        }
        sourceSelect.value = 'ward';
        sourceSelect.disabled = true;
        return;
    }

    sourceSelect.disabled = false;
    if (sourceBeforeSessionOverride) {
        sourceSelect.value = sourceBeforeSessionOverride;
        sourceBeforeSessionOverride = null;
    }
}

function setMapViewOnly() {
    STATE.modes.noGps = false;
    STATE.modes.multi = false;
    STATE.modes.raw = false;
    STATE.modes.analytics = false;

    const btnMap = getNode('btn-map-view');
    const btnNoGps = getNode('btn-no-gps-view');
    const btnMulti = getNode('btn-multi-view');
    const btnRaw = getNode('btn-raw-view');
    const btnAnalytics = getNode('btn-analytics-view');

    if (btnMap) btnMap.classList.add('active');
    if (btnNoGps) btnNoGps.classList.remove('active');
    if (btnMulti) btnMulti.classList.remove('active');
    if (btnRaw) btnRaw.classList.remove('active');
    if (btnAnalytics) btnAnalytics.classList.remove('active');

    const noGpsPanel = getNode('no-gps-panel');
    const multiPanel = getNode('multi-panel');
    const rawPanel = getNode('raw-panel');
    const analyticsPanel = getNode('analytics-panel');
    if (noGpsPanel) noGpsPanel.style.display = 'none';
    if (multiPanel) multiPanel.style.display = 'none';
    if (rawPanel) rawPanel.style.display = 'none';
    if (analyticsPanel) analyticsPanel.style.display = 'none';

    setReconWorkspaceActive(false);
    clearAnalyticsHeatmapLayer();
    clearAnalyticsHotspotsLayer();
}

function suspendButtons(ids, suspend) {
    ids.forEach((id) => {
        const btn = getNode(id);
        if (!btn) return;
        btn.disabled = !!suspend;
        btn.classList.toggle('suspended', !!suspend);
    });
}

function suspendLeftPanels(suspend) {
    suspendButtons(['btn-zones', 'btn-targets', 'btn-favs'], suspend);
}

function suspendRightPanels(suspend) {
    suspendButtons(['btn-toggle-cracking', 'btn-process', 'btn-logs'], suspend);
}

function syncMapModeButton(id, active) {
    const btn = getNode(id);
    if (!btn) return;
    btn.classList.toggle('active', !!active);
}

function suspendMapModeButtons(suspend) {
    suspendButtons(['btn-conquered', 'btn-to-conquer', 'btn-discovered', 'btn-intelligence', 'btn-heat'], suspend);
}

function syncHudHeaderHeights() {
    const left = document.querySelector('.controls-row');
    const right = document.querySelector('.stats-container-wrapper');
    if (!left || !right) return;
    left.style.height = 'auto';
    right.style.height = 'auto';
    const targetHeight = Math.max(left.offsetHeight, right.offsetHeight);
    if (targetHeight > 0) {
        left.style.height = `${targetHeight}px`;
        right.style.height = `${targetHeight}px`;
    }
}

function applyWardriveWorkspaceTabUi() {
    const mainView = getNode('wardrive-workspace-main');
    const inventoryView = getNode('wardrive-workspace-inventory');
    const btnMain = getNode('btn-wardrive-tab-workspace');
    const btnInventory = getNode('btn-wardrive-tab-inventory');

    const isInventory = wardriveWorkspaceTab === WORKSPACE_TAB_INVENTORY;
    if (mainView) mainView.style.display = isInventory ? 'none' : 'flex';
    if (inventoryView) inventoryView.style.display = isInventory ? 'flex' : 'none';
    if (btnMain) btnMain.classList.toggle('active', !isInventory);
    if (btnInventory) btnInventory.classList.toggle('active', isInventory);
    if (!isInventory) {
        applyWardriveExplorerPaneUi();
    }
}

async function setWardriveWorkspaceTab(tab) {
    wardriveWorkspaceTab = tab === WORKSPACE_TAB_INVENTORY ? WORKSPACE_TAB_INVENTORY : WORKSPACE_TAB_MAIN;
    applyWardriveWorkspaceTabUi();
    if (wardriveWorkspaceTab === WORKSPACE_TAB_INVENTORY && !wardriveInventoryLoaded) {
        await refreshWardriveInventory();
    }
}

function applyWardriveWorkspaceVisibility(active) {
    const hud = getNode('hud-layer');
    if (hud) hud.classList.toggle('wardrive-workspace-active', !!active);

    const wardrivePanel = getNode('wardrive-panel');
    const sessionsPanel = getNode('wardrive-right-sessions-panel');
    if (wardrivePanel) wardrivePanel.style.display = active ? 'flex' : 'none';
    if (sessionsPanel) sessionsPanel.style.display = active ? 'flex' : 'none';

    const zonesPanel = getNode('zones-panel');
    const targetsPanel = getNode('targets-panel');
    const favoritesPanel = getNode('favorites-panel');
    const crackingPanel = getNode('cracking-panel');
    const processPanel = getNode('process-panel');
    const logPanel = getNode('log-panel');

    if (active) {
        if (zonesPanel) zonesPanel.style.display = 'none';
        if (targetsPanel) targetsPanel.style.display = 'none';
        if (favoritesPanel) favoritesPanel.style.display = 'none';
        if (crackingPanel) crackingPanel.style.display = 'none';
        if (processPanel) processPanel.style.display = 'none';
        if (logPanel) logPanel.style.display = 'none';
        syncHudHeaderHeights();
        return;
    }

    if (zonesPanel) zonesPanel.style.display = STATE.modes.zones ? 'flex' : 'none';
    if (targetsPanel) targetsPanel.style.display = STATE.modes.targets ? 'flex' : 'none';
    if (favoritesPanel) favoritesPanel.style.display = STATE.modes.favs ? 'flex' : 'none';
    if (crackingPanel) crackingPanel.style.display = STATE.modes.cracking ? 'flex' : 'none';
    if (processPanel) processPanel.style.display = STATE.modes.process ? 'flex' : 'none';
    if (logPanel) logPanel.style.display = STATE.modes.logs ? 'block' : 'none';
    syncHudHeaderHeights();
}

function syncSessionsUiFiltersFromDom() {
    const sortBy = getNode('wardrive-sessions-sort-by');
    wardriveSessionsUiFilters = {
        sortBy: normalizeWardriveSessionSortBy(sortBy?.value),
        sortDirection: normalizeWardriveSessionSortDirection(wardriveSessionsUiFilters.sortDirection),
    };
    persistWardriveSessionsUiFilters();
}

function syncSessionsUiFiltersDomFromState() {
    const sortBy = getNode('wardrive-sessions-sort-by');
    if (sortBy) {
        sortBy.value = normalizeWardriveSessionSortBy(wardriveSessionsUiFilters.sortBy);
    }
}

function getFilteredAndSortedWardriveSessions() {
    const { sortBy, sortDirection } = wardriveSessionsUiFilters;
    const filtered = [...wardriveSessions];

    if (sortBy === 'none') return filtered;

    const direction = sortDirection === 'asc' ? 1 : -1;
    const getPrimary = (session) => {
        if (sortBy === 'date') return Number(session?.started_at || 0);
        if (sortBy === 'duration') return getSessionDurationSeconds(session?.started_at, session?.ended_at);
        if (sortBy === 'distance') return Number(session?.distance_m || 0);
        if (sortBy === 'nets') return Number(session?.networks_count || 0);
        return 0;
    };

    return filtered
        .map((session, index) => ({ session, index }))
        .sort((a, b) => {
            const primaryA = getPrimary(a.session);
            const primaryB = getPrimary(b.session);
            if (primaryA !== primaryB) return (primaryA - primaryB) * direction;

            const startedDiff = Number(b.session?.started_at || 0) - Number(a.session?.started_at || 0);
            if (startedDiff !== 0) return startedDiff;

            const fileA = String(a.session?.source_file || a.session?.label || a.session?.session_id || '');
            const fileB = String(b.session?.source_file || b.session?.label || b.session?.session_id || '');
            const fileCmp = fileA.localeCompare(fileB, 'pt-BR');
            if (fileCmp !== 0) return fileCmp;

            return a.index - b.index;
        })
        .map((entry) => entry.session);
}

function selectRegionRow(regionId) {
    const list = getNode('wardrive-regions-list');
    if (!list) return;
    list.querySelectorAll('.wardrive-region-item').forEach((node) => {
        node.classList.toggle('active', node.getAttribute('data-region-id') === regionId);
    });
}

function buildWardriveHierarchyIndex(regions) {
    const byId = new Map();
    const byParent = new Map();

    (Array.isArray(regions) ? regions : []).forEach((region) => {
        if (!region?.id) return;
        byId.set(region.id, region);
    });

    (Array.isArray(regions) ? regions : []).forEach((region) => {
        if (!region?.id) return;
        const rawParentId = String(region.parent_id || '').trim();
        const parentId = rawParentId && byId.has(rawParentId) ? rawParentId : '__root__';
        if (!byParent.has(parentId)) byParent.set(parentId, []);
        byParent.get(parentId).push(region);
    });

    byParent.forEach((items) => items.sort(byLevelName));
    return { byId, byParent };
}

function reconcileCollapsedWardriveRegions(regions = wardriveHierarchy) {
    const { byId, byParent } = buildWardriveHierarchyIndex(regions);
    wardriveCollapsedRegionIds = new Set(
        Array.from(wardriveCollapsedRegionIds).filter((regionId) => {
            const normalizedId = String(regionId || '').trim();
            return normalizedId && byId.has(normalizedId) && (byParent.get(normalizedId)?.length || 0) > 0;
        })
    );
}

function expandWardriveRegionAncestors(regionId, regions = wardriveHierarchy) {
    const normalizedId = String(regionId || '').trim();
    if (!normalizedId) return;
    const { byId } = buildWardriveHierarchyIndex(regions);
    let current = byId.get(normalizedId) || null;
    while (current && current.parent_id) {
        const parentId = String(current.parent_id || '').trim();
        if (!parentId || !byId.has(parentId)) break;
        wardriveCollapsedRegionIds.delete(parentId);
        current = byId.get(parentId) || null;
    }
}

function toggleWardriveRegionCollapse(regionId) {
    const normalizedId = String(regionId || '').trim();
    if (!normalizedId) return;
    if (wardriveCollapsedRegionIds.has(normalizedId)) {
        wardriveCollapsedRegionIds.delete(normalizedId);
    } else {
        wardriveCollapsedRegionIds.add(normalizedId);
    }
    renderRegionsList();
}

function renderRegionSummary(region = null, stats = null) {
    const box = getNode('wardrive-region-summary');
    if (!box) return;
    if (!region) {
        if (wardriveHierarchyLoading || wardriveWorkspaceBooting) {
            box.innerHTML = `
                <div class="wardrive-region-summary-shell">
                    <div class="wardrive-region-summary-top">
                        <span class="wardrive-selected-meta">${wardriveWorkspaceBooting ? 'Preparing workspace' : 'Loading hierarchy'}</span>
                        <div class="wardrive-region-status is-loading">Loading</div>
                    </div>
                    <div class="wardrive-summary-loading">
                        ${buildWardriveLoadingRows(2)}
                    </div>
                    <div class="wardrive-kpi-grid wardrive-kpi-grid--summary wardrive-loading-kpi-grid">
                        ${buildWardriveLoadingKpiCards(4)}
                    </div>
                </div>
            `;
            return;
        }
        box.innerHTML = `
            <div class="wardrive-region-summary-shell">
                <div class="wardrive-region-summary-top">
                    <span class="wardrive-selected-meta">${wardriveHierarchyLoading ? 'Loading hierarchy' : 'No region selected'}</span>
                </div>
                <div class="wardrive-empty">
                    ${wardriveHierarchyLoading ? 'Loading region hierarchy...' : 'Select a region to inspect zones.'}
                </div>
            </div>
        `;
        return;
    }

    const rowStats = stats || region.stats || {};
    const total = Number(rowStats.networks_count || 0);
    const cracked = Number(rowStats.cracked || 0);
    const open = Number(rowStats.open || 0);
    const locked = Number(rowStats.locked || 0);
    const levelLabel = getRegionLevelLabel(region);
    const displayPath = getRegionDisplayPath(region);
    const zoneCount = Array.isArray(wardriveLastZones) ? wardriveLastZones.length : 0;
    const statusCopy = wardriveZonesLoading
        ? 'Loading zones'
        : `Open ${zoneCount} zone${zoneCount === 1 ? '' : 's'}`;

    box.innerHTML = `
        <div class="wardrive-region-summary-shell">
            <div class="wardrive-region-summary-top">
                <div class="wardrive-selected-head">
                    <div class="wardrive-selected-title">${escapeHtml(region.name || 'UNMAPPED')}</div>
                    <div class="wardrive-selected-meta wardrive-selected-meta--chip">${escapeHtml(levelLabel)}</div>
                </div>
                <button
                    type="button"
                    class="wardrive-region-status wardrive-region-status--action${wardriveZonesLoading ? ' is-loading' : ''}"
                    data-action="wardrive-open-zones"
                    title="Open zones explorer for the active region"
                >
                    ${escapeHtml(statusCopy)}
                </button>
            </div>
            <div class="wardrive-selected-path wardrive-selected-path--wrap">${escapeHtml(displayPath)}</div>
            <div class="wardrive-kpi-grid wardrive-kpi-grid--summary">
                <div class="wardrive-kpi-card"><span>NETS</span><strong>${total}</strong></div>
                <div class="wardrive-kpi-card"><span>CRACKED</span><strong>${cracked}</strong></div>
                <div class="wardrive-kpi-card"><span>OPEN</span><strong>${open}</strong></div>
                <div class="wardrive-kpi-card"><span>LOCKED</span><strong>${locked}</strong></div>
            </div>
        </div>
    `;
}

function renderWardriveZonesSummary(zones = [], options = {}) {
    const box = getNode('wardrive-zones-summary');
    const count = getNode('wardrive-zone-count');
    if (count) {
        count.textContent = wardriveZonesLoading ? '...' : String(Array.isArray(zones) ? zones.length : 0);
    }
    if (!box) return;

    const region = wardriveLastRegionPayload || wardriveHierarchy.find((item) => item.id === wardriveSelectedRegionId) || null;
    const zoneCount = Array.isArray(zones) ? zones.length : 0;
    const selectedSessions = getWardriveSelectedSessions();
    const scopeCopy = String(options?.comparisonMode || '') === 'focus_active'
        ? 'Focus compare across selected sessions'
        : (selectedSessions.length
            ? `${selectedSessions.length} selected session${selectedSessions.length === 1 ? '' : 's'}`
            : 'Full workspace scope');

    if (!region) {
        if (wardriveZonesLoading || wardriveWorkspaceBooting) {
            box.innerHTML = `
                <div class="wardrive-region-summary-shell">
                    <div class="wardrive-zones-summary-head">
                        <div>
                            <div class="wardrive-zones-summary-title">Preparing zones...</div>
                            <div class="wardrive-zones-summary-copy">DBSCAN summaries will appear here as soon as the active region finishes loading.</div>
                        </div>
                        <div class="wardrive-region-status is-loading">Loading</div>
                    </div>
                    <div class="wardrive-summary-loading">
                        ${buildWardriveLoadingRows(2)}
                    </div>
                </div>
            `;
            return;
        }
        box.innerHTML = `
            <div class="wardrive-empty">
                ${wardriveZonesLoading ? 'Loading zones...' : 'Select a region to inspect DBSCAN zones.'}
            </div>
        `;
        return;
    }

    box.innerHTML = `
        <div class="wardrive-zones-summary-head">
            <div>
                <div class="wardrive-zones-summary-title">${escapeHtml(region.name || 'UNMAPPED')}</div>
                <div class="wardrive-zones-summary-copy">${escapeHtml(scopeCopy)}</div>
            </div>
            <div class="wardrive-region-status${wardriveZonesLoading ? ' is-loading' : ''}">${wardriveZonesLoading ? 'Loading' : `${zoneCount} zones`}</div>
        </div>
    `;
}

function renderMapsSummary() {
    const target = getNode('wardrive-maps-summary');
    if (!target) return;
    if (wardriveWorkspaceBooting && !Object.keys(wardriveMapsSummary || {}).length) {
        target.textContent = 'Preparing WarDrive workspace...';
        return;
    }
    const loadedFiles = Number(wardriveMapsSummary.loaded_files || 0);
    const loadedDatasets = Number(
        wardriveMapsSummary.loaded_datasets ||
        (Array.isArray(wardriveMapsSummary.active_datasets) ? wardriveMapsSummary.active_datasets.length : 0)
    );
    const regionsCount = Number(wardriveMapsSummary.regions_count || 0);
    const legacyCount = Array.isArray(wardriveMapsSummary.legacy_ignored) ? wardriveMapsSummary.legacy_ignored.length : 0;
    const incompatibleCrs = Array.isArray(wardriveMapsSummary.incompatible_crs) ? wardriveMapsSummary.incompatible_crs.length : 0;
    const errors = Array.isArray(wardriveMapsSummary.errors) ? wardriveMapsSummary.errors.length : 0;
    target.textContent = `Files: ${loadedFiles} | Datasets: ${loadedDatasets} | Regions: ${regionsCount}${legacyCount ? ` | Legacy: ${legacyCount}` : ''}${incompatibleCrs ? ` | CRS: ${incompatibleCrs}` : ''}${errors ? ` | Errors: ${errors}` : ''}`;
}

function renderWardriveRegionsLoadingState(message = 'Loading region hierarchy...') {
    const list = getNode('wardrive-regions-list');
    if (!list) return;
    list.innerHTML = `
        <div class="wardrive-pane-loading">
            <div class="wardrive-route-replay-note">${escapeHtml(message)}</div>
            <div class="wardrive-route-replay-loading">${buildWardriveLoadingRows(4)}</div>
        </div>
    `;
}

function renderWardriveSessionsLoadingState(message = 'Loading sessions...') {
    const summary = getNode('wardrive-sessions-summary');
    const list = getNode('wardrive-sessions-list');
    const clearBtn = getNode('btn-wardrive-sessions-clear');
    const sortDirectionBtn = getNode('btn-wardrive-sessions-sort-dir');
    if (clearBtn) clearBtn.disabled = true;
    if (sortDirectionBtn) {
        sortDirectionBtn.disabled = true;
        sortDirectionBtn.classList.remove('active');
    }
    if (summary) {
        summary.innerHTML = `
            <div class="wardrive-session-kpi-grid wardrive-loading-kpi-grid">
                ${buildWardriveLoadingKpiCards(4)}
            </div>
        `;
    }
    if (list) {
        list.innerHTML = `
            <div class="wardrive-session-skeleton-list">
                <div class="wardrive-route-replay-note">${escapeHtml(message)}</div>
                ${buildWardriveSessionLoadingCards(4)}
            </div>
        `;
    }
}

function renderWardriveInventoryLoadingState(message = 'Loading inventory...') {
    const target = getNode('wardrive-inventory-content');
    if (!target) return;
    target.innerHTML = `
        <div class="wardrive-pane-loading">
            <div class="wardrive-route-replay-note">${escapeHtml(message)}</div>
            <div class="wardrive-inventory-grid wardrive-loading-kpi-grid">
                ${buildWardriveLoadingKpiCards(4)}
            </div>
            <div class="wardrive-route-replay-loading">${buildWardriveLoadingRows(4)}</div>
        </div>
    `;
}

function showWardriveBootLoadingState() {
    wardriveWorkspaceBooting = true;
    wardriveHierarchyLoading = true;
    wardriveZonesLoading = true;
    wardriveSessionsLoading = true;
    renderMapsSummary();
    renderWardriveReplayLoadingState({
        headline: 'Preparing workspace...',
        note: 'Loading region hierarchy, sessions and replay shell...',
    });
    renderWardriveSessionsLoadingState('Loading sessions...');
    renderWardriveRegionsLoadingState('Loading region hierarchy...');
    renderRegionSummary(null, null);
    showWardriveZonesLoadingState();
}

function renderSessionFilterSummary() {
    renderWardriveRouteReplaySection();
}

function applyWardriveReplayMapState(options = {}) {
    const { renderTracks = true } = options;
    const tracks = getWardriveReplayTracks();
    if (renderTracks) {
        renderWardriveSessionTracks(tracks, wardriveActiveReplaySessionId);
    }
    const activeTrack = getActiveWardriveReplayTrack();
    if (!activeTrack || !Array.isArray(activeTrack.points) || !activeTrack.points.length) {
        setWardriveReplayPlayhead(null);
        return;
    }
    const segmentWeights = getWardriveReplaySegmentWeights(activeTrack);
    setWardriveReplayPlayhead(activeTrack, wardriveReplayProgress, { segmentWeights });
    if (shouldFollowWardriveReplayCamera()) {
        focusWardriveReplayPlayhead(activeTrack, wardriveReplayProgress, {
            zoom: resolveWardriveReplayCameraZoom(),
            segmentWeights,
        });
    }
}

function setWardriveReplayProgress(progress) {
    wardriveReplayProgress = Math.max(0, Math.min(1, Number(progress || 0)));
    syncWardriveReplayLiveUi();
    applyWardriveReplayMapState({ renderTracks: false });
}

function setWardriveActiveReplaySession(sessionId) {
    const nextId = String(sessionId || '').trim();
    if (!nextId) return;
    wardriveActiveReplaySessionId = nextId;
    syncWardriveComparisonPreset(nextId);
    clearWardriveReplayTimer();
    wardriveReplayProgress = 0;
    renderWardriveRouteReplaySection();
    renderCurrentWardriveZones();
    applyWardriveReplayMapState();
    const activeTrack = getActiveWardriveReplayTrack();
    if (wardriveUiConfig.replayAutoFocus && activeTrack) {
        focusWardriveTrack(activeTrack);
    }
    if (wardriveUiConfig.replayAutoplay) {
        toggleWardriveReplayPlayback();
    }
}

function resetWardriveReplayPlayback() {
    clearWardriveReplayTimer();
    wardriveReplayProgress = 0;
    syncWardriveReplayLiveUi();
    applyWardriveReplayMapState({ renderTracks: false });
}

function getWardriveReplayDurationMs(track) {
    const points = Array.isArray(track?.points) ? track.points : [];
    const segments = Math.max(1, points.length - 1);
    const baseDuration = Math.max(2600, Math.min(45000, segments * 320));
    return Math.max(900, Math.min(240000, baseDuration / Math.max(0.05, wardriveReplaySpeed)));
}

function setWardriveReplaySpeed(speed) {
    const nextSpeed = normalizeWardriveReplaySpeed(speed);
    if (nextSpeed === wardriveReplaySpeed) return;
    const wasPlaying = Boolean(wardriveReplayTimer);
    clearWardriveReplayTimer();
    wardriveReplaySpeed = nextSpeed;
    syncWardriveReplayLiveUi();
    applyWardriveReplayMapState({ renderTracks: false });
    if (wasPlaying) {
        toggleWardriveReplayPlayback();
    }
}

function setWardriveReplayFollowCamera(enabled) {
    wardriveReplayFollowCamera = !!enabled;
    syncWardriveReplayCameraLock();
    syncWardriveReplayLiveUi();
    if (shouldFollowWardriveReplayCamera()) {
        applyWardriveReplayMapState({ renderTracks: false });
    }
}

function setWardriveReplayFollowZoom(value) {
    const nextZoom = normalizeWardriveReplayFollowZoom(value);
    if (nextZoom === wardriveReplayFollowZoom) return;
    wardriveReplayFollowZoom = nextZoom;
    wardriveReplayFollowZoomSnapshot = null;
    syncWardriveReplayCameraLock();
    syncWardriveReplayLiveUi();
    if (shouldFollowWardriveReplayCamera()) {
        applyWardriveReplayMapState({ renderTracks: false });
    }
}

function setWardriveReplayTimingMode(value) {
    const nextMode = normalizeWardriveReplayTimingMode(value);
    if (nextMode === wardriveReplayTimingMode) return;
    wardriveReplayTimingMode = nextMode;
    renderWardriveRouteReplaySection();
    applyWardriveReplayMapState({ renderTracks: false });
}

function toggleWardriveReplayPlayback() {
    const activeTrack = getActiveWardriveReplayTrack();
    const points = Array.isArray(activeTrack?.points) ? activeTrack.points : [];
    if (points.length <= 1) {
        clearWardriveReplayTimer();
        syncWardriveReplayLiveUi();
        return;
    }
    if (wardriveReplayTimer) {
        clearWardriveReplayTimer();
        syncWardriveReplayLiveUi();
        return;
    }

    if (wardriveReplayProgress >= 1) {
        wardriveReplayProgress = 0;
        syncWardriveReplayLiveUi();
        applyWardriveReplayMapState({ renderTracks: false });
    }

    const tickMs = 40;
    const playbackDurationMs = getWardriveReplayDurationMs(activeTrack);
    captureWardriveReplayMapZoomSnapshot();
    wardriveReplayTimer = setInterval(() => {
        const step = tickMs / Math.max(tickMs, playbackDurationMs);
        const nextProgress = Math.min(1, wardriveReplayProgress + step);
        wardriveReplayProgress = nextProgress;
        syncWardriveReplayLiveUi();
        applyWardriveReplayMapState({ renderTracks: false });
        if (nextProgress >= 1) {
            clearWardriveReplayTimer();
            syncWardriveReplayLiveUi();
        }
    }, tickMs);
    syncWardriveReplayCameraLock();
    syncWardriveReplayLiveUi();
}

async function refreshWardriveSessionTracks() {
    clearWardriveReplayTimer();
    const selectedIds = wardriveSelectedSessionIds.map((item) => String(item || '').trim()).filter(Boolean);
    if (!STATE.modes.wardrive || !selectedIds.length) {
        wardriveReplayLoading = false;
        wardriveSessionTracks = [];
        wardriveActiveReplaySessionId = null;
        wardriveReplayProgress = 0;
        renderWardriveRouteReplaySection();
        applyWardriveReplayMapState();
        return;
    }

    if (selectedIds.length > 3) {
        wardriveReplayLoading = false;
        wardriveSessionTracks = [];
        wardriveActiveReplaySessionId = null;
        wardriveReplayProgress = 0;
        renderWardriveRouteReplaySection();
        applyWardriveReplayMapState();
        return;
    }

    wardriveReplayLoading = true;
    renderWardriveRouteReplaySection();
    const requestId = ++wardriveReplayReq;
    try {
        const payload = await API.getWardriveSessionTracks(selectedIds);
        if (requestId !== wardriveReplayReq) return;
        wardriveSessionTracks = Array.isArray(payload?.tracks) ? payload.tracks : [];
        const previousActiveReplaySessionId = wardriveActiveReplaySessionId;
        if (!wardriveSessionTracks.some((track) => String(track?.session_id || '') === String(wardriveActiveReplaySessionId || ''))) {
            wardriveActiveReplaySessionId = wardriveSessionTracks[0]?.session_id || null;
            wardriveReplayProgress = 0;
        }
        if (
            wardriveLastZoneComparison?.mode === 'focus_active'
            && previousActiveReplaySessionId !== wardriveActiveReplaySessionId
        ) {
            syncWardriveComparisonPreset(wardriveActiveReplaySessionId);
        }
        wardriveReplayLoading = false;
        renderWardriveRouteReplaySection();
        if (
            wardriveLastZoneComparison?.mode === 'focus_active'
            && previousActiveReplaySessionId !== wardriveActiveReplaySessionId
        ) {
            renderCurrentWardriveZones();
        }
        applyWardriveReplayMapState();
    } catch (err) {
        if (requestId !== wardriveReplayReq) return;
        wardriveReplayLoading = false;
        wardriveSessionTracks = [];
        wardriveActiveReplaySessionId = null;
        wardriveReplayProgress = 0;
        renderWardriveRouteReplaySection();
        applyWardriveReplayMapState();
        log(`WarDrive route replay unavailable: ${err.message || err}`, 'warn');
    }
}

function renderZonesList(zones = [], options = {}) {
    const list = getNode('wardrive-zones-list');
    const countEl = getNode('wardrive-zone-count');
    if (!list) return;

    list.innerHTML = '';
    if (countEl) countEl.textContent = wardriveZonesLoading ? '...' : String(zones.length);
    renderWardriveZonesSummary(zones, options);
    if (!zones.length) {
        list.innerHTML = '<div class="wardrive-empty">No zones found for the current region/filters.</div>';
        return;
    }

    const palette = getWardriveSessionPalette(
        options?.sessionIds || zones.map((zone) => zone?.session_id),
        options?.activeSessionId || null,
        { comparisonMode: options?.comparisonMode || 'standard' }
    );

    function createZoneItem(zone, idx, labelOverride = null) {
        const count = Number(zone?.count || 0);
        const sessionId = String(zone?.session_id || '').trim();
        const sessionStyle = palette[sessionId];
        const zoneAccent = sessionStyle?.zoneColor || sessionStyle?.innerColor || 'var(--theme-color)';
        const isActive = Boolean(sessionStyle?.isActive);
        const sessionLabel = String(zone?.session_label || zone?.session_id || '').trim();
        const zoneName = String(
            labelOverride || `ZONE-${String(idx + 1).padStart(3, '0')}`
        ).trim();
        const item = document.createElement('button');
        item.type = 'button';
        item.className = `wardrive-zone-item${isActive ? ' active' : ''}${sessionId && !isActive ? ' muted' : ''}`;
        item.style.setProperty('--wardrive-zone-accent', zoneAccent);
        item.innerHTML = `
            <span class="wardrive-zone-copy">
                <span class="wardrive-zone-name-row">
                    <span class="wardrive-zone-swatch" aria-hidden="true"></span>
                    <span class="wardrive-zone-name">${escapeHtml(zoneName)}</span>
                </span>
                ${sessionLabel ? `<span class="wardrive-zone-session">${escapeHtml(sessionLabel)}</span>` : ''}
            </span>
            <span class="wardrive-zone-meta">${count} APs</span>
        `;
        item.addEventListener('click', () => {
            focusWardriveZone(zone);
        });
        return item;
    }

    function appendSection(title, sectionZones, labelResolver = null) {
        const header = document.createElement('div');
        header.className = 'wardrive-zone-section-title';
        header.textContent = title;
        list.appendChild(header);

        if (!sectionZones.length) {
            const empty = document.createElement('div');
            empty.className = 'wardrive-zone-section-empty';
            empty.textContent = 'No zones in this layer.';
            list.appendChild(empty);
            return;
        }

        sectionZones.forEach((zone, idx) => {
            const labelOverride = typeof labelResolver === 'function' ? labelResolver(zone, idx) : null;
            list.appendChild(createZoneItem(zone, idx, labelOverride));
        });
    }

    if (String(options?.comparisonMode || '') === 'focus_active') {
        const primaryZones = zones.filter((zone) => String(zone?.zone_role || '').trim().toLowerCase() !== 'secondary');
        const secondaryZones = zones.filter((zone) => String(zone?.zone_role || '').trim().toLowerCase() === 'secondary');
        appendSection('ACTIVE SESSION', primaryZones, (_zone, idx) => `ZONE-${String(idx + 1).padStart(3, '0')}`);
        appendSection('OTHER SELECTED SESSIONS', secondaryZones, () => 'MERGED COVERAGE');
        return;
    }

    zones.forEach((zone, idx) => {
        list.appendChild(createZoneItem(zone, idx));
    });
}

function buildHierarchyRows(regions) {
    const rows = [];
    const { byId, byParent } = buildWardriveHierarchyIndex(regions);

    const visited = new Set();
    function walk(parentId, depth) {
        const children = byParent.get(parentId || '__root__') || [];
        children.forEach((child) => {
            if (visited.has(child.id)) return;
            visited.add(child.id);
            const childCount = Number((byParent.get(child.id) || []).length);
            const isCollapsed = childCount > 0 && wardriveCollapsedRegionIds.has(String(child.id || '').trim());
            rows.push({
                region: child,
                depth,
                hasChildren: childCount > 0,
                isCollapsed,
            });
            if (!isCollapsed) {
                walk(child.id, depth + 1);
            }
        });
    }

    walk(null, 0);
    regions.forEach((region) => {
        if (visited.has(region.id)) return;
        const parentId = String(region?.parent_id || '').trim();
        if (parentId && byId.has(parentId)) return;
        const childCount = Number((byParent.get(region.id) || []).length);
        const isCollapsed = childCount > 0 && wardriveCollapsedRegionIds.has(String(region.id || '').trim());
        rows.push({
            region,
            depth: 0,
            hasChildren: childCount > 0,
            isCollapsed,
        });
        if (!isCollapsed) {
            walk(region.id, 1);
        }
    });

    return rows;
}

function renderRegionsList() {
    const list = getNode('wardrive-regions-list');
    if (!list) return;
    list.innerHTML = '';

    if (!wardriveHierarchy.length) {
        list.innerHTML = '<div class="wardrive-empty">No classified regions for the current filters.</div>';
        return;
    }

    reconcileCollapsedWardriveRegions(wardriveHierarchy);
    const rows = buildHierarchyRows(wardriveHierarchy);
    rows.forEach(({ region, depth, hasChildren, isCollapsed }) => {
        const stats = region.stats || {};
        const count = Number(stats.networks_count || 0);
        const levelLabel = getRegionLevelLabel(region);
        const displayPath = getRegionDisplayPath(region);
        const wrapper = document.createElement('div');
        wrapper.className = 'wardrive-region-row';
        wrapper.style.setProperty('--wardrive-depth', String(depth));

        if (hasChildren) {
            const toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'wardrive-region-toggle';
            toggle.setAttribute('data-action', 'wardrive-region-toggle');
            toggle.setAttribute('data-region-id', region.id);
            toggle.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
            toggle.setAttribute(
                'aria-label',
                isCollapsed ? `Expand ${region.name || region.id}` : `Collapse ${region.name || region.id}`
            );
            toggle.innerHTML = `<i class="fa-solid ${isCollapsed ? 'fa-chevron-right' : 'fa-chevron-down'}" aria-hidden="true"></i>`;
            toggle.addEventListener('click', (event) => {
                event.preventDefault();
                event.stopPropagation();
                toggleWardriveRegionCollapse(region.id);
            });
            wrapper.appendChild(toggle);
        } else {
            const spacer = document.createElement('span');
            spacer.className = 'wardrive-region-toggle-spacer';
            spacer.setAttribute('aria-hidden', 'true');
            wrapper.appendChild(spacer);
        }

        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'wardrive-region-item';
        row.setAttribute('data-region-id', region.id);
        row.innerHTML = `
            <span class="wardrive-region-copy">
                <span class="wardrive-region-name">${escapeHtml(region.name || region.id)}</span>
                <span class="wardrive-region-path">${escapeHtml(displayPath)}</span>
            </span>
            <span class="wardrive-region-meta">${escapeHtml(levelLabel)} · ${count}</span>
        `;
        row.addEventListener('click', () => {
            selectWardriveRegion(region.id, true);
        });
        wrapper.appendChild(row);
        list.appendChild(wrapper);
    });

    selectRegionRow(wardriveSelectedRegionId);
}

function renderInventoryPanel() {
    const target = getNode('wardrive-inventory-content');
    if (!target) return;
    if (wardriveInventoryLoading) {
        renderWardriveInventoryLoadingState();
        return;
    }

    const activeDatasets = Array.isArray(wardriveInventory.active_datasets) ? wardriveInventory.active_datasets : [];
    const legacy = Array.isArray(wardriveInventory.legacy_ignored) ? wardriveInventory.legacy_ignored : [];
    const incompatible = Array.isArray(wardriveInventory.incompatible_crs) ? wardriveInventory.incompatible_crs : [];
    const errors = Array.isArray(wardriveInventory.errors) ? wardriveInventory.errors : [];
    const coverage = wardriveInventory.coverage_by_level || {};
    const formats = wardriveInventory.formats || {};
    const coverageRows = Object.entries(coverage).flatMap(([countryCode, levels]) =>
        Object.entries(levels || {}).map(([levelKey, info]) => ({
            countryCode,
            levelKey,
            depth: Number(info?.depth || 0),
            hierarchyCount: Number(info?.hierarchy_regions_count || 0),
            totalCount: Number(info?.regions_count || 0),
        }))
    );
    const healthLabel = errors.length
        ? 'Attention required'
        : incompatible.length
            ? 'CRS review'
            : 'Operational';

    target.innerHTML = `
        <div class="wardrive-inventory-hero">
            <div class="wardrive-inventory-eyebrow">Country Packs</div>
            <div class="wardrive-inventory-hero-title">${activeDatasets.length} datasets active across ${Object.keys(coverage).length || 0} country pack(s)</div>
            <div class="wardrive-inventory-hero-copy">Inventory health: <strong>${escapeHtml(healthLabel)}</strong>. Legacy packs, CRS mismatches and ingest errors stay visible here so the WarDrive workspace keeps a clear map-readiness picture.</div>
        </div>
        <div class="wardrive-inventory-grid">
            <div class="wardrive-inventory-card"><span>ACTIVE DATASETS</span><strong>${activeDatasets.length}</strong></div>
            <div class="wardrive-inventory-card"><span>LOADED FILES</span><strong>${Number(wardriveInventory.loaded_files || 0)}</strong></div>
            <div class="wardrive-inventory-card"><span>SUPPORTED FILES</span><strong>${Number(wardriveInventory.supported_files || 0)}</strong></div>
            <div class="wardrive-inventory-card"><span>REGIONS</span><strong>${Number(wardriveInventory.regions_count || 0)}</strong></div>
        </div>
        <div class="wardrive-inventory-section">
            <div class="wardrive-inventory-title">FORMATS</div>
            <div class="wardrive-inventory-chip-row">
                <span class="wardrive-inventory-chip">GEOJSON ${Number(formats.geojson || 0)}</span>
                <span class="wardrive-inventory-chip">SHP ${Number(formats.shp || 0)}</span>
                <span class="wardrive-inventory-chip">KMZ ${Number(formats.kmz || 0)}</span>
            </div>
        </div>
        <div class="wardrive-inventory-section">
            <div class="wardrive-inventory-title">DATASETS</div>
            <div class="wardrive-inventory-dataset-list">
                ${activeDatasets.length ? activeDatasets.map((item) => `
                    <div class="wardrive-inventory-dataset-row">
                        <div class="wardrive-inventory-dataset-head">
                            <span class="wardrive-inventory-dataset-title">${escapeHtml(item.dataset_id || 'dataset')}</span>
                            <span class="wardrive-inventory-dataset-meta">${escapeHtml(item.country_code || '--').toUpperCase()} · ${escapeHtml(item.level_label || item.level_key || 'Region')}</span>
                        </div>
                        <div class="wardrive-inventory-dataset-copy">Depth ${Number(item.depth || 0)} · files ${Number(item.loaded_files || 0)} · regions ${Number(item.regions_count || 0)}</div>
                    </div>
                `).join('') : '<span class="wardrive-empty">No active dataset.</span>'}
            </div>
        </div>
        <div class="wardrive-inventory-section">
            <div class="wardrive-inventory-title">COVERAGE</div>
            <div class="wardrive-inventory-coverage-list">
                ${coverageRows.length ? coverageRows.map((item) => `
                    <div class="wardrive-inventory-coverage-row">
                        <div class="wardrive-inventory-coverage-head">
                            <span class="wardrive-inventory-coverage-title">${escapeHtml(item.countryCode.toUpperCase())} · ${escapeHtml(item.levelKey)}</span>
                            <span class="wardrive-inventory-coverage-meta">depth ${item.depth}</span>
                        </div>
                        <div class="wardrive-inventory-coverage-copy">Hierarchy regions ${item.hierarchyCount} · Total polygons ${item.totalCount}</div>
                    </div>
                `).join('') : '<span class="wardrive-empty">Sem cobertura carregada.</span>'}
            </div>
        </div>
        <div class="wardrive-inventory-section">
            <div class="wardrive-inventory-title">STATUS</div>
            <div class="wardrive-inventory-chip-row">
                <span class="wardrive-inventory-chip">LEGACY ${legacy.length}</span>
                <span class="wardrive-inventory-chip">CRS ${incompatible.length}</span>
                <span class="wardrive-inventory-chip">ERRORS ${errors.length}</span>
            </div>
        </div>
    `;
}

function reconcileSelectedSessions() {
    const available = new Set(wardriveSessions.map((item) => String(item?.session_id || '')));
    wardriveSelectedSessionIds = wardriveSelectedSessionIds.filter((item) => available.has(String(item)));
    if (
        wardriveActiveReplaySessionId
        && !wardriveSelectedSessionIds.includes(String(wardriveActiveReplaySessionId))
    ) {
        wardriveActiveReplaySessionId = null;
        wardriveReplayProgress = 0;
    }
    syncWardriveSourceLock();
    renderSessionFilterSummary();
}

async function saveWardriveSessionTag(sessionId, transportMode) {
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) return;
    if (wardriveSessionTagSavingIds.has(normalizedSessionId)) return;

    wardriveSessionTagSavingIds.add(normalizedSessionId);
    renderSessionsPanel();
    try {
        const payload = await API.setWardriveSessionTag(normalizedSessionId, transportMode);
        const updatedSession = payload?.session && typeof payload.session === 'object' ? payload.session : null;
        if (updatedSession) {
            const updatedId = String(updatedSession?.session_id || normalizedSessionId);
            let found = false;
            wardriveSessions = wardriveSessions.map((item) => {
                if (String(item?.session_id || '') !== updatedId) return item;
                found = true;
                return { ...item, ...updatedSession };
            });
            if (!found) {
                wardriveSessions = [...wardriveSessions, updatedSession];
            }
        } else {
            const mode = normalizeTransportMode(transportMode);
            wardriveSessions = wardriveSessions.map((item) => (
                String(item?.session_id || '') === normalizedSessionId
                    ? { ...item, transport_mode: mode }
                    : item
            ));
        }
        if (payload?.summary && typeof payload.summary === 'object') {
            wardriveSessionsSummary = payload.summary;
        } else {
            wardriveSessionsSummary = {
                ...wardriveSessionsSummary,
                transport_modes: summarizeTransportModes(wardriveSessions),
                top_transport_modes: summarizeTransportModes(wardriveSessions).slice(0, 8),
            };
        }
    } catch (err) {
        log(`WarDrive session tag update failed: ${err.message || err}`, 'warn');
    } finally {
        wardriveSessionTagSavingIds.delete(normalizedSessionId);
        closeAllSessionTagPopovers();
        renderSessionsPanel();
        renderSessionFilterSummary();
    }
}

async function mergeSelectedWardriveSessions() {
    const selectedIds = getWardriveSelectedSessions()
        .map((session) => String(session?.session_id || '').trim())
        .filter(Boolean);
    if (wardriveSessionMergeLoading) return;
    if (selectedIds.length < 2 || selectedIds.length > 3) return;
    if (
        wardriveUiConfig.mergeConfirmation
        && !window.confirm(`Merge ${selectedIds.length} selected WarDrive sessions into a single active session?`)
    ) {
        return;
    }

    wardriveSessionMergeLoading = true;
    renderWardriveRouteReplaySection();
    try {
        const payload = await API.mergeWardriveSessions(selectedIds);
        const mergedSessionId = String(payload?.session?.session_id || '').trim();
        if (mergedSessionId) {
            wardriveSelectedSessionIds = [mergedSessionId];
            wardriveActiveReplaySessionId = mergedSessionId;
        } else {
            wardriveSelectedSessionIds = [];
            wardriveActiveReplaySessionId = null;
        }
        wardriveReplayProgress = 0;
        wardriveSessionTracks = [];
        wardriveLastZones = [];
        wardriveLastZoneComparison = null;
        closeAllSessionTagPopovers();
        await refreshWardriveWorkspace({
            keepSelection: true,
            reloadInventory: false,
            reloadSessions: true,
        });
    } catch (err) {
        log(`WarDrive merge failed: ${err.message || err}`, 'warn');
    } finally {
        wardriveSessionMergeLoading = false;
        renderWardriveRouteReplaySection();
    }
}

function renderSessionsPanel() {
    const summary = getNode('wardrive-sessions-summary');
    const list = getNode('wardrive-sessions-list');
    const clearBtn = getNode('btn-wardrive-sessions-clear');
    const sortDirectionBtn = getNode('btn-wardrive-sessions-sort-dir');
    if (!summary || !list) return;

    if (wardriveSessionsLoading) {
        renderWardriveSessionsLoadingState();
        return;
    }

    syncSessionsUiFiltersDomFromState();
    const filteredSessions = getFilteredAndSortedWardriveSessions();
    const totalNetworks = wardriveSessions.reduce((acc, item) => acc + Number(item?.networks_count || 0), 0);
    const totalPoints = wardriveSessions.reduce((acc, item) => acc + Number(item?.points_count || 0), 0);
    const filteredNetworks = filteredSessions.reduce((acc, item) => acc + Number(item?.networks_count || 0), 0);
    const filteredPoints = filteredSessions.reduce((acc, item) => acc + Number(item?.points_count || 0), 0);
    const selectedCount = wardriveSelectedSessionIds.length;
    const hasSort = wardriveSessionsUiFilters.sortBy !== 'none';
    const filtersActive = hasSort;

    if (clearBtn) {
        clearBtn.disabled = selectedCount === 0;
    }
    if (sortDirectionBtn) {
        const direction = wardriveSessionsUiFilters.sortDirection === 'asc' ? 'ASC' : 'DESC';
        sortDirectionBtn.textContent = direction;
        sortDirectionBtn.disabled = !hasSort;
        sortDirectionBtn.classList.toggle('active', hasSort);
        sortDirectionBtn.setAttribute('aria-label', `Sort direction ${direction}`);
        sortDirectionBtn.title = `Sort direction ${direction}`;
    }
    summary.innerHTML = `
        <div class="wardrive-session-kpi-grid">
            <div class="wardrive-session-kpi-card"><span>LOADED</span><strong>${filteredSessions.length}${filtersActive ? `/${wardriveSessions.length}` : ''}</strong></div>
            <div class="wardrive-session-kpi-card"><span>SELECTED</span><strong>${selectedCount}</strong></div>
            <div class="wardrive-session-kpi-card"><span>NETWORKS</span><strong>${filtersActive ? filteredNetworks : totalNetworks}</strong></div>
            <div class="wardrive-session-kpi-card"><span>POINTS</span><strong>${filtersActive ? filteredPoints : totalPoints}</strong></div>
        </div>
    `;

    list.innerHTML = '';
    if (!filteredSessions.length) {
        if (wardriveSessions.length && filtersActive) {
            list.innerHTML = '<div class="wardrive-empty">No sessions match the current filters.</div>';
            return;
        }
        list.innerHTML = '<div class="wardrive-empty">No WarDrive sessions found.</div>';
        return;
    }

    filteredSessions.forEach((session) => {
        const sessionId = String(session?.session_id || '');
        const item = document.createElement('div');
        item.className = 'wardrive-session-item';
        item.setAttribute('role', 'button');
        item.setAttribute('tabindex', '0');
        item.classList.toggle('active', wardriveSelectedSessionIds.includes(sessionId));

        const startedAt = Number(session?.started_at || 0);
        const endedAt = Number(session?.ended_at || 0);
        const networksCount = Number(session?.networks_count || 0);
        const startedLabel = formatSessionDateTime(startedAt);
        const durationLabel = formatDuration(startedAt, endedAt);
        const distanceLabel = formatDistanceMeters(session?.distance_m);
        const fileLabel = formatWardriveSessionDisplayName(
            session?.source_file || session?.label || sessionId || 'wardrive'
        );
        const sessionType = String(session?.session_type || 'original').trim().toLowerCase();
        const mergedFromSessionIds = Array.isArray(session?.merged_from_session_ids)
            ? session.merged_from_session_ids.filter(Boolean)
            : [];
        const transportMeta = getTransportMeta(session?.transport_mode);
        const isTagSaving = wardriveSessionTagSavingIds.has(sessionId);
        const transportModeOptions = TRANSPORT_MODE_ORDER.map((modeKey) => {
            const modeMeta = getTransportMeta(modeKey);
            const isActive = modeKey === transportMeta.mode;
            return `
                <button type="button" class="wardrive-session-transport-option${isActive ? ' active' : ''}" data-mode="${modeKey}">
                    <i class="fa-solid ${escapeHtml(modeMeta.icon)}"></i>
                    <span>${escapeHtml(modeMeta.label)}</span>
                </button>
            `;
        }).join('');

        item.innerHTML = `
            <div class="wardrive-session-head">
                <div class="wardrive-session-title-row">
                    <button
                        type="button"
                        class="wardrive-session-transport-btn${transportMeta.mode ? ' tagged' : ''}"
                        data-action="session-transport-toggle"
                        title="${escapeHtml(transportMeta.label)}"
                        aria-label="${escapeHtml(transportMeta.label)}"
                        ${isTagSaving ? 'disabled' : ''}
                    >
                        <i class="fa-solid ${escapeHtml(transportMeta.icon)}"></i>
                    </button>
                    <span class="wardrive-session-title">${escapeHtml(fileLabel)}</span>
                    ${sessionType === 'merged' ? '<span class="wardrive-session-badge">MERGED</span>' : ''}
                </div>
                <div class="wardrive-session-transport-popover" aria-hidden="true">
                    <div class="wardrive-session-transport-grid">
                        ${transportModeOptions}
                    </div>
                    <button type="button" class="wardrive-session-transport-clear" data-mode="">
                        <i class="fa-solid fa-ban"></i>
                        <span>CLEAR TAG</span>
                    </button>
                </div>
            </div>
            <div class="wardrive-session-time-row">
                <span class="wardrive-session-time-item">
                    <i class="fa-regular fa-calendar"></i>
                    <span class="wardrive-session-time-label">START</span>
                    <strong>${escapeHtml(startedLabel)}</strong>
                </span>
                <span class="wardrive-session-time-separator">•</span>
                <span class="wardrive-session-time-item">
                    <i class="fa-solid fa-road"></i>
                    <span class="wardrive-session-time-label">DIST</span>
                    <strong>${escapeHtml(distanceLabel)}</strong>
                </span>
            </div>
            <div class="wardrive-session-detail-row">
                <span class="wardrive-session-detail-item">
                    <i class="fa-regular fa-hourglass-half"></i>
                    <span class="wardrive-session-detail-label">DURATION</span>
                    <strong>${escapeHtml(durationLabel)}</strong>
                </span>
                <span class="wardrive-session-detail-dot">•</span>
                <span class="wardrive-session-detail-item">
                    <i class="fa-solid fa-wifi"></i>
                    <span class="wardrive-session-detail-label">NETS</span>
                    <strong>${networksCount}</strong>
                </span>
                ${sessionType === 'merged' ? `
                    <span class="wardrive-session-detail-dot">•</span>
                    <span class="wardrive-session-detail-item">
                        <i class="fa-solid fa-code-merge"></i>
                        <span class="wardrive-session-detail-label">MERGED</span>
                        <strong>${mergedFromSessionIds.length}</strong>
                    </span>
                ` : ''}
            </div>
        `;
        const transportToggle = item.querySelector('[data-action="session-transport-toggle"]');
        const transportPopover = item.querySelector('.wardrive-session-transport-popover');
        if (transportToggle && transportPopover) {
            transportToggle.addEventListener('click', (event) => {
                event.preventDefault();
                event.stopPropagation();
                const shouldOpen = !transportPopover.classList.contains('is-open');
                closeAllSessionTagPopovers();
                if (shouldOpen) {
                    transportPopover.classList.add('is-open');
                    transportPopover.setAttribute('aria-hidden', 'false');
                }
            });

            transportPopover.querySelectorAll('[data-mode]').forEach((option) => {
                option.addEventListener('click', async (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const modeValue = String(option.getAttribute('data-mode') || '').trim();
                    const nextMode = modeValue ? modeValue : null;
                    await saveWardriveSessionTag(sessionId, nextMode);
                });
            });
        }

        const handleSessionSelection = async () => {
            toggleWardriveSession(sessionId);
            await refreshWardriveHierarchy(true);
        };

        item.addEventListener('click', async () => {
            await handleSessionSelection();
        });
        item.addEventListener('keydown', async (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            await handleSessionSelection();
        });
        list.appendChild(item);
    });
}

function toggleWardriveSession(sessionId) {
    const normalized = String(sessionId || '').trim();
    if (!normalized) return;
    if (wardriveSelectedSessionIds.includes(normalized)) {
        wardriveSelectedSessionIds = wardriveSelectedSessionIds.filter((item) => item !== normalized);
    } else {
        wardriveSelectedSessionIds = [...wardriveSelectedSessionIds, normalized];
    }
    syncWardriveSourceLock();
    renderSessionFilterSummary();
    renderSessionsPanel();
    renderWardriveRouteReplaySection();
}

async function clearWardriveSessionsSelection() {
    if (!wardriveSelectedSessionIds.length) {
        renderSessionsPanel();
        return;
    }
    wardriveSelectedSessionIds = [];
    syncWardriveSourceLock();
    renderSessionFilterSummary();
    renderSessionsPanel();
    renderWardriveRouteReplaySection();
    await refreshWardriveHierarchy(true);
    applyWardriveSessionMapFilter({ forceFullRestore: true });
}

function buildWardriveSessionDataset() {
    const selectedIds = new Set(wardriveSelectedSessionIds.map((item) => String(item || '').trim()).filter(Boolean));
    if (!selectedIds.size) return STATE.allPositions || {};

    const filtered = {};
    Object.values(STATE.allPositions || {}).forEach((item) => {
        if (!item || typeof item !== 'object') return;
        const observations = (item.wardrive_sessions || []).filter((obs) => selectedIds.has(String(obs?.session_id || '')));
        if (!observations.length) return;

        observations.sort((a, b) => {
            const tsDiff = Number(b?.ts_last || 0) - Number(a?.ts_last || 0);
            if (tsDiff !== 0) return tsDiff;
            return Number(a?.acc || 999999) - Number(b?.acc || 999999);
        });
        const selected = observations[0] || {};
        const mac = String(item.mac || '').trim();
        if (!mac) return;

        const displayLat = getFiniteWardriveNumber(
            selected.displayLatitude,
            selected.lat,
            item.displayLatitude,
            item.lat
        );
        const displayLng = getFiniteWardriveNumber(
            selected.displayLongitude,
            selected.lng,
            item.displayLongitude,
            item.lng
        );
        const rawLat = getFiniteWardriveNumber(
            selected.rawLatitude,
            selected.lat,
            item.rawLatitude,
            item.lat
        );
        const rawLng = getFiniteWardriveNumber(
            selected.rawLongitude,
            selected.lng,
            item.rawLongitude,
            item.lng
        );
        const rawAcc = getFiniteWardriveNumber(
            selected.rawAccuracy,
            selected.acc,
            item.rawAccuracy,
            item.acc,
            0
        );

        filtered[mac] = {
            ...item,
            lat: displayLat,
            lng: displayLng,
            acc: rawAcc,
            rawLatitude: rawLat,
            rawLongitude: rawLng,
            rawAccuracy: rawAcc,
            displayLatitude: displayLat,
            displayLongitude: displayLng,
            ts_last: Number(selected.ts_last ?? item.ts_last ?? 0),
            ts_first: Number(selected.ts_first ?? item.ts_first ?? 0),
            channel: selected.channel ?? item.channel,
            frequency: selected.frequency ?? item.frequency,
            rssi: selected.rssi ?? item.rssi,
            altitude: selected.altitude ?? item.altitude,
            encryption: selected.encryption || item.encryption,
            ssid: selected.ssid || item.ssid,
            sessionId: selected.session_id || item.sessionId,
            sessionSourceFile: selected.source_file || item.sessionSourceFile,
            sources: ['wardrive'],
            wardrive_sessions: observations,
        };
    });
    return filtered;
}

function applyWardriveSessionMapFilter({ forceFullRestore = false } = {}) {
    if (!STATE.modes.wardrive) return;
    const hasSessionFilter = wardriveSelectedSessionIds.length > 0;
    if (!hasSessionFilter && !forceFullRestore) return;
    const dataset = hasSessionFilter ? buildWardriveSessionDataset() : (STATE.allPositions || {});
    renderMarkers(dataset, false);
}

function showWardriveZonesLoadingState() {
    const list = getNode('wardrive-zones-list');
    wardriveZonesLoading = true;
    if (list) {
        list.innerHTML = `
            <div class="wardrive-pane-loading">
                <div class="wardrive-route-replay-note">Loading zones...</div>
                <div class="wardrive-route-replay-loading">${buildWardriveLoadingRows(4)}</div>
            </div>
        `;
    }
    renderWardriveZonesSummary([], getWardriveZoneRenderContext());
    renderWardriveZones([]);
}

function restoreWorkspaceFromSnapshot() {
    wardriveWorkspaceBooting = false;
    wardriveHierarchyLoading = false;
    wardriveSessionsLoading = false;
    wardriveInventoryLoading = false;
    renderMapsSummary();
    renderInventoryPanel();
    reconcileSelectedSessions();
    renderSessionsPanel();
    renderSessionFilterSummary();
    renderWardriveRouteReplaySection();

    if (!wardriveHierarchy.length) {
        renderRegionsList();
        wardriveSelectedRegionId = null;
        wardriveZonesLoading = false;
        renderRegionSummary(null, null);
        renderZonesList([]);
        clearWardriveLayers();
        applyWardriveSessionMapFilter();
        applyWardriveReplayMapState();
        return;
    }

    const selectedRegion = wardriveHierarchy.find((item) => item.id === wardriveSelectedRegionId) || wardriveHierarchy[0];
    wardriveSelectedRegionId = selectedRegion?.id || null;
    expandWardriveRegionAncestors(wardriveSelectedRegionId, wardriveHierarchy);
    renderRegionsList();
    selectRegionRow(wardriveSelectedRegionId);

    if (wardriveLastRegionPayload && wardriveSelectedRegionId && String(wardriveLastRegionPayload.id) === String(wardriveSelectedRegionId)) {
        wardriveZonesLoading = false;
        renderRegionSummary(wardriveLastRegionPayload, wardriveLastRegionStats);
        renderWardriveRegion(wardriveLastRegionPayload);
        renderCurrentWardriveZones();
    } else {
        wardriveZonesLoading = false;
        renderRegionSummary(selectedRegion, selectedRegion?.stats || null);
        renderWardriveRegion(selectedRegion || null);
        renderWardriveZones([]);
        renderZonesList([]);
    }

    if (
        wardriveSelectedRegionId
        && wardriveSelectedRegionId !== 'unmapped'
        && (!Array.isArray(wardriveLastZones) || wardriveLastZones.length === 0)
    ) {
        showWardriveZonesLoadingState();
        void loadWardriveZones(wardriveSelectedRegionId, false);
    }

    applyWardriveSessionMapFilter();
    applyWardriveReplayMapState();
}

async function loadWardriveZones(regionId, shouldFitBounds) {
    const requestId = ++wardriveZonesReq;
    const filters = getWardriveFilters();
    try {
        const focusComparisonSessionIds = getWardriveFocusComparisonSessionIds();
        const selectedSessionsById = new Map(
            getWardriveSelectedSessions().map((session) => [
                String(session?.session_id || '').trim(),
                session,
            ])
        );
        let payload = null;
        let region = null;
        let stats = null;
        let zones = [];
        payload = await API.getWardriveZones({
            region_id: regionId,
            eps_m: DEFAULT_DBSCAN_EPS,
            min_samples: DEFAULT_DBSCAN_MIN_SAMPLES,
            ...filters,
            ...(focusComparisonSessionIds.length
                ? {
                    session_ids: focusComparisonSessionIds,
                    comparison_mode: 'focus_active',
                    active_session_id: (
                        focusComparisonSessionIds.includes(String(wardriveActiveReplaySessionId || '').trim())
                            ? String(wardriveActiveReplaySessionId || '').trim()
                            : focusComparisonSessionIds[0]
                    ),
                }
                : {}),
        });
        if (requestId !== wardriveZonesReq) return;
        if (!STATE.modes.wardrive) return;

        region = payload?.region || wardriveHierarchy.find((item) => item.id === regionId) || null;
        stats = (
            wardriveHierarchy.find((item) => item.id === regionId)?.stats
            || wardriveLastRegionStats
            || payload?.stats
            || null
        );
        wardriveLastZoneComparison = normalizeWardriveComparisonPayload(
            payload?.comparison,
            selectedSessionsById
        );
        if (wardriveLastZoneComparison?.mode === 'focus_active') {
            zones = buildWardriveComparisonPreset(
                wardriveLastZoneComparison,
                getWardriveComparisonActiveSessionId(wardriveLastZoneComparison)
            );
        } else {
            wardriveLastZoneComparison = null;
            const standardZoneScope = getWardriveStandardZoneScope(selectedSessionsById);
            zones = decorateWardriveZones(payload?.zones || [], {
                sessionId: standardZoneScope?.sessionId || null,
                sessionLabel: standardZoneScope?.sessionLabel || null,
            });
        }
        wardriveLastRegionPayload = region;
        wardriveLastRegionStats = stats;
        wardriveLastZones = zones;
        wardriveZonesLoading = false;
        renderRegionSummary(region, stats);
        renderWardriveRegion(region);
        renderCurrentWardriveZones();
        if (shouldFitBounds && region?.bbox) {
            focusWardriveBBox(region.bbox);
        }
    } catch (err) {
        if (requestId !== wardriveZonesReq) return;
        wardriveLastRegionPayload = null;
        wardriveLastRegionStats = null;
        wardriveLastZones = [];
        wardriveLastZoneComparison = null;
        wardriveZonesLoading = false;
        renderWardriveRegion(null);
        renderWardriveZones([]);
        renderZonesList([]);
        log(`WarDrive zones unavailable: ${err.message || err}`, 'warn');
    }
}

async function selectWardriveRegion(regionId, shouldFitBounds) {
    wardriveSelectedRegionId = regionId;
    selectRegionRow(regionId);
    setWardriveExplorerPane(WORKSPACE_EXPLORER_PANE_ZONES);
    const selected = wardriveHierarchy.find((item) => String(item?.id || '') === String(regionId || '')) || null;
    wardriveLastRegionPayload = selected || null;
    wardriveLastRegionStats = selected?.stats || null;
    renderRegionSummary(selected, selected?.stats || null);
    showWardriveZonesLoadingState();
    await loadWardriveZones(regionId, shouldFitBounds);
}

function mergeHierarchyWithUnmapped(payload) {
    const regions = Array.isArray(payload?.regions) ? [...payload.regions] : [];
    const unmapped = payload?.unmapped_summary || {};
    const unmappedCount = Number(unmapped.networks_count || 0);
    if (unmappedCount > 0) {
        regions.push({
            id: 'unmapped',
            level: 'unmapped',
            level_key: 'unmapped',
            level_label: 'Sem mapa',
            depth: 999,
            parent_id: null,
            name: 'UNMAPPED',
            code: 'UNMAPPED',
            bbox: null,
            center: null,
            stats: unmapped,
            source_format: 'fallback',
            display_path: 'UNMAPPED',
            lineage: [],
        });
    }
    return regions.sort(byLevelName);
}

async function refreshWardriveHierarchy(keepSelection = true) {
    const requestId = ++wardriveHierarchyReq;
    const filters = getWardriveFilters();
    wardriveHierarchyLoading = true;
    renderWardriveRegionsLoadingState('Loading region hierarchy...');
    renderRegionSummary(keepSelection ? wardriveLastRegionPayload : null, keepSelection ? wardriveLastRegionStats : null);

    try {
        const payload = await API.getWardriveHierarchy(filters);
        if (requestId !== wardriveHierarchyReq) return;
        if (!STATE.modes.wardrive) return;

        wardriveMapsSummary = payload?.maps_summary || {};
        wardriveHierarchy = mergeHierarchyWithUnmapped(payload);
        wardriveHierarchyLoading = false;
        renderMapsSummary();
        renderSessionFilterSummary();

        if (!wardriveHierarchy.length) {
            renderRegionsList();
            wardriveSelectedRegionId = null;
            wardriveZonesLoading = false;
            renderRegionSummary(null, null);
            renderZonesList([]);
            clearWardriveLayers();
            applyWardriveSessionMapFilter();
            void refreshWardriveSessionTracks();
            return;
        }

        const preferredId = keepSelection ? wardriveSelectedRegionId : null;
        const selected = wardriveHierarchy.find((region) => region.id === preferredId) || wardriveHierarchy[0];
        wardriveSelectedRegionId = selected?.id || null;
        expandWardriveRegionAncestors(wardriveSelectedRegionId, wardriveHierarchy);
        renderRegionsList();
        selectRegionRow(wardriveSelectedRegionId);
        wardriveLastRegionPayload = selected || null;
        wardriveLastRegionStats = selected?.stats || null;
        wardriveLastZones = [];
        wardriveLastZoneComparison = null;
        renderRegionSummary(selected, selected?.stats || null);
        renderWardriveRegion(selected || null);
        if (selected?.id === 'unmapped') {
            wardriveZonesLoading = false;
            renderWardriveZones([]);
            renderZonesList([]);
        } else {
            showWardriveZonesLoadingState();
            void loadWardriveZones(selected.id, !keepSelection);
        }
        applyWardriveSessionMapFilter();
        void refreshWardriveSessionTracks();
    } catch (err) {
        if (requestId !== wardriveHierarchyReq) return;
        wardriveHierarchy = [];
        wardriveSelectedRegionId = null;
        wardriveLastZoneComparison = null;
        wardriveHierarchyLoading = false;
        wardriveZonesLoading = false;
        renderRegionsList();
        renderRegionSummary(null, null);
        renderZonesList([]);
        clearWardriveLayers();
        applyWardriveSessionMapFilter();
        void refreshWardriveSessionTracks();
        log(`WarDrive hierarchy unavailable: ${err.message || err}`, 'warn');
    }
}

async function refreshWardriveInventory() {
    const requestId = ++wardriveInventoryReq;
    wardriveInventoryLoading = true;
    renderInventoryPanel();

    try {
        const payload = await API.getWardriveInventory();
        if (requestId !== wardriveInventoryReq) return;
        wardriveInventory = payload || {};
        wardriveInventoryLoaded = true;
        wardriveInventoryLoading = false;
        renderInventoryPanel();
    } catch (err) {
        if (requestId !== wardriveInventoryReq) return;
        wardriveInventoryLoaded = false;
        wardriveInventoryLoading = false;
        const target = getNode('wardrive-inventory-content');
        if (target) target.innerHTML = '<div class="wardrive-empty">Failed to load inventory.</div>';
        log(`WarDrive inventory unavailable: ${err.message || err}`, 'warn');
    }
}

async function refreshWardriveSessions() {
    const requestId = ++wardriveSessionsReq;
    wardriveSessionsLoading = true;
    renderSessionsPanel();

    try {
        const payload = await API.getWardriveSessions({ time_window: getWardriveFilters().time_window });
        if (requestId !== wardriveSessionsReq) return;
        wardriveSessions = Array.isArray(payload?.sessions) ? payload.sessions : [];
        wardriveSessionsSummary = payload?.summary && typeof payload.summary === 'object' ? payload.summary : {};
        wardriveSessionsLoading = false;
        reconcileSelectedSessions();
        renderSessionsPanel();
    } catch (err) {
        if (requestId !== wardriveSessionsReq) return;
        wardriveSessions = [];
        wardriveSessionsSummary = {};
        wardriveSessionsLoading = false;
        reconcileSelectedSessions();
        renderSessionsPanel();
        log(`WarDrive sessions unavailable: ${err.message || err}`, 'warn');
    }
}

async function refreshWardriveWorkspace({ keepSelection = true, reloadInventory = false, reloadSessions = false } = {}) {
    const jobs = [refreshWardriveHierarchy(keepSelection)];
    if (reloadSessions) {
        jobs.push(refreshWardriveSessions());
    }
    if (reloadInventory) jobs.push(refreshWardriveInventory());
    await Promise.all(jobs);
    const booting = wardriveWorkspaceBooting;
    wardriveWorkspaceBooting = false;
    if (booting) {
        renderMapsSummary();
        renderSessionFilterSummary();
    }
    wardriveWorkspaceWarm = true;
    wardriveWorkspaceDirty = false;
}

function hasActiveClassicMapModes(modes = suspendedMapModes) {
    return !!(
        modes
        && (
            modes.conquered
            || modes.toConquer
            || modes.discovered
            || modes.intelligence
            || modes.heat
            || modes.radar
        )
    );
}

function suspendClassicMapModes() {
    suspendedMapModes = {
        conquered: !!STATE.modes.conquered,
        toConquer: !!STATE.modes.toConquer,
        discovered: !!STATE.modes.discovered,
        intelligence: !!STATE.modes.intelligence,
        heat: !!STATE.modes.heat,
        radar: !!STATE.modes.radar,
    };
    STATE.modes.conquered = false;
    STATE.modes.toConquer = false;
    STATE.modes.discovered = false;
    STATE.modes.intelligence = false;
    STATE.modes.heat = false;
    STATE.modes.radar = false;
    // Preserve the previous visual toggle state while WarDrive is active,
    // matching the same suspended behavior used by other toolbar buttons.
    syncMapModeButton('btn-conquered', suspendedMapModes.conquered);
    syncMapModeButton('btn-to-conquer', suspendedMapModes.toConquer);
    syncMapModeButton('btn-discovered', suspendedMapModes.discovered);
    syncMapModeButton('btn-intelligence', suspendedMapModes.intelligence);
    syncMapModeButton('btn-heat', suspendedMapModes.heat);
    if (hasActiveClassicMapModes(suspendedMapModes)) {
        clearClassicMapOverlays();
    }
}

function restoreClassicMapModes() {
    if (!suspendedMapModes) return;
    const restoreModes = { ...suspendedMapModes };
    STATE.modes.conquered = restoreModes.conquered;
    STATE.modes.toConquer = restoreModes.toConquer;
    STATE.modes.discovered = restoreModes.discovered;
    STATE.modes.intelligence = restoreModes.intelligence;
    STATE.modes.heat = restoreModes.heat;
    STATE.modes.radar = restoreModes.radar;
    syncMapModeButton('btn-conquered', STATE.modes.conquered);
    syncMapModeButton('btn-to-conquer', STATE.modes.toConquer);
    syncMapModeButton('btn-discovered', STATE.modes.discovered);
    syncMapModeButton('btn-intelligence', STATE.modes.intelligence);
    syncMapModeButton('btn-heat', STATE.modes.heat);
    suspendedMapModes = null;
    if (restoreModes.heat || restoreModes.radar) {
        renderMarkers(STATE.allPositions || {}, false);
    }
    if (restoreModes.conquered) calculateZones(STATE.allPositions || {});
    if (restoreModes.toConquer) calculateToConquerZones(STATE.allPositions || {});
    if (restoreModes.discovered) calculateDiscoveredZones(STATE.allPositions || {});
    if (restoreModes.intelligence) calculateIntelligenceZones();
}

export async function activateWardriveMode() {
    if (STATE.modes.wardrive) return;
    STATE.modes.wardrive = true;
    saveModes();

    const btn = getNode('btn-wardrive');
    if (btn) btn.classList.add('active');

    ensureWardriveFilterDefaults();
    setMapViewOnly();
    suspendLeftPanels(true);
    suspendRightPanels(true);
    suspendMapModeButtons(true);
    wardriveWorkspaceTab = WORKSPACE_TAB_MAIN;
    applyWardriveWorkspaceVisibility(true);
    applyWardriveWorkspaceTabUi();

    const hasWarmSnapshot = hasWarmWorkspaceSnapshot();
    if (!hasWarmSnapshot) {
        showWardriveBootLoadingState();
    }
    await yieldWardriveUiPaint();
    suspendClassicMapModes();

    if (hasWarmSnapshot) {
        restoreWorkspaceFromSnapshot();
        return;
    }
    await refreshWardriveWorkspace({ keepSelection: false, reloadInventory: false, reloadSessions: true });
}

export function deactivateWardriveMode() {
    if (!STATE.modes.wardrive) return;
    STATE.modes.wardrive = false;

    const btn = getNode('btn-wardrive');
    if (btn) btn.classList.remove('active');

    restoreClassicMapModes();
    clearWardriveReplayTimer();
    wardriveWorkspaceBooting = false;
    wardriveSessionsLoading = false;
    wardriveInventoryLoading = false;
    applyWardriveWorkspaceVisibility(false);
    suspendLeftPanels(false);
    suspendRightPanels(false);
    suspendMapModeButtons(false);
    syncWardriveSourceLock();
    clearWardriveLayers();
    saveModes();
}

export async function refreshWardriveIfActive(keepSelection = true) {
    if (!STATE.modes.wardrive) return;
    await refreshWardriveWorkspace({ keepSelection, reloadInventory: false, reloadSessions: false });
}

export async function prewarmWardriveWorkspace() {
    if (STATE.modes.wardrive) return;

    const requestId = ++wardrivePrewarmReq;
    const filters = getWardriveFilters();
    try {
        const [sessionsPayload, hierarchyPayload] = await Promise.all([
            API.getWardriveSessions({ time_window: filters.time_window }),
            API.getWardriveHierarchy(filters),
        ]);
        if (requestId !== wardrivePrewarmReq) return;
        if (STATE.modes.wardrive) return;

        wardriveSessions = Array.isArray(sessionsPayload?.sessions) ? sessionsPayload.sessions : [];
        wardriveSessionsSummary = sessionsPayload?.summary && typeof sessionsPayload.summary === 'object'
            ? sessionsPayload.summary
            : {};
        reconcileSelectedSessions();

        wardriveMapsSummary = hierarchyPayload?.maps_summary || {};
        wardriveHierarchy = mergeHierarchyWithUnmapped(hierarchyPayload);
        const preferredId = wardriveSelectedRegionId;
        const selected = wardriveHierarchy.find((region) => region.id === preferredId) || wardriveHierarchy[0] || null;
        wardriveSelectedRegionId = selected?.id || null;
        wardriveLastRegionPayload = selected;
        wardriveLastRegionStats = selected?.stats || null;
        wardriveLastZones = [];
        wardriveLastZoneComparison = null;
        wardriveWorkspaceWarm = Array.isArray(wardriveHierarchy) && wardriveHierarchy.length > 0;
        wardriveWorkspaceDirty = false;
    } catch (_err) {
        if (requestId !== wardrivePrewarmReq) return;
    }
}

export function markWardriveDirty({ clearWarm = false } = {}) {
    wardriveWorkspaceDirty = true;
    wardriveInventoryLoaded = false;
    if (clearWarm) {
        wardriveWorkspaceWarm = false;
    }
}

export function setupWardriveListeners() {
    bindWardriveConfigEvents();
    const btn = getNode('btn-wardrive');
    if (btn && !btn.dataset.boundWardrive) {
        btn.addEventListener('click', async () => {
            if (STATE.modes.wardrive) {
                deactivateWardriveMode();
                return;
            }
            await activateWardriveMode();
        });
        btn.dataset.boundWardrive = '1';
    }

    const btnRefresh = getNode('btn-wardrive-refresh');
    if (btnRefresh && !btnRefresh.dataset.boundWardrive) {
        btnRefresh.addEventListener('click', async () => {
            try {
                await API.refreshWardriveRuntime({ reload_data: true, reload_maps: true });
            } catch (err) {
                log(`WarDrive refresh endpoint unavailable: ${err.message || err}`, 'warn');
            }
            markWardriveDirty({ clearWarm: true });
            await refreshWardriveWorkspace({
                keepSelection: true,
                reloadInventory: true,
                reloadSessions: true,
            });
        });
        btnRefresh.dataset.boundWardrive = '1';
    }

    const btnTabWorkspace = getNode('btn-wardrive-tab-workspace');
    if (btnTabWorkspace && !btnTabWorkspace.dataset.boundWardrive) {
        btnTabWorkspace.addEventListener('click', () => {
            setWardriveWorkspaceTab(WORKSPACE_TAB_MAIN);
        });
        btnTabWorkspace.dataset.boundWardrive = '1';
    }

    const btnTabInventory = getNode('btn-wardrive-tab-inventory');
    if (btnTabInventory && !btnTabInventory.dataset.boundWardrive) {
        btnTabInventory.addEventListener('click', () => {
            setWardriveWorkspaceTab(WORKSPACE_TAB_INVENTORY);
        });
        btnTabInventory.dataset.boundWardrive = '1';
    }

    const btnPaneRegions = getNode('btn-wardrive-pane-regions');
    if (btnPaneRegions && !btnPaneRegions.dataset.boundWardrive) {
        btnPaneRegions.addEventListener('click', () => {
            setWardriveExplorerPane(WORKSPACE_EXPLORER_PANE_REGIONS);
        });
        btnPaneRegions.dataset.boundWardrive = '1';
    }

    const btnPaneZones = getNode('btn-wardrive-pane-zones');
    if (btnPaneZones && !btnPaneZones.dataset.boundWardrive) {
        btnPaneZones.addEventListener('click', () => {
            setWardriveExplorerPane(WORKSPACE_EXPLORER_PANE_ZONES);
        });
        btnPaneZones.dataset.boundWardrive = '1';
    }

    const regionSummary = getNode('wardrive-region-summary');
    if (regionSummary && !regionSummary.dataset.boundWardrive) {
        regionSummary.addEventListener('click', (event) => {
            const actionEl = event.target.closest('[data-action]');
            if (!actionEl) return;
            const action = String(actionEl.getAttribute('data-action') || '').trim();
            if (action === 'wardrive-open-zones') {
                event.preventDefault();
                openWardriveExplorerPane(WORKSPACE_EXPLORER_PANE_ZONES);
            }
        });
        regionSummary.dataset.boundWardrive = '1';
    }

    const btnSessionsClear = getNode('btn-wardrive-sessions-clear');
    if (btnSessionsClear && !btnSessionsClear.dataset.boundWardrive) {
        btnSessionsClear.addEventListener('click', () => clearWardriveSessionsSelection());
        btnSessionsClear.dataset.boundWardrive = '1';
    }

    const sessionsSortBy = getNode('wardrive-sessions-sort-by');
    if (sessionsSortBy && !sessionsSortBy.dataset.boundWardrive) {
        sessionsSortBy.addEventListener('change', () => {
            syncSessionsUiFiltersFromDom();
            renderSessionsPanel();
        });
        sessionsSortBy.dataset.boundWardrive = '1';
    }

    const sessionsSortDirection = getNode('btn-wardrive-sessions-sort-dir');
    if (sessionsSortDirection && !sessionsSortDirection.dataset.boundWardrive) {
        sessionsSortDirection.addEventListener('click', () => {
            wardriveSessionsUiFilters.sortDirection = wardriveSessionsUiFilters.sortDirection === 'asc' ? 'desc' : 'asc';
            persistWardriveSessionsUiFilters();
            renderSessionsPanel();
        });
        sessionsSortDirection.dataset.boundWardrive = '1';
    }

    const timeSelect = getNode('wardrive-time-window');
    if (timeSelect && !timeSelect.dataset.boundWardrive) {
        timeSelect.addEventListener('change', () => {
            refreshWardriveWorkspace({ keepSelection: true, reloadInventory: false, reloadSessions: true });
        });
        timeSelect.dataset.boundWardrive = '1';
    }

    const sourceSelect = getNode('wardrive-source');
    if (sourceSelect && !sourceSelect.dataset.boundWardrive) {
        sourceSelect.addEventListener('change', () => refreshWardriveHierarchy(true));
        sourceSelect.dataset.boundWardrive = '1';
    }

    const routeReplay = getNode('wardrive-route-replay');
    if (routeReplay && !routeReplay.dataset.boundWardrive) {
        routeReplay.addEventListener('click', (event) => {
            const actionEl = event.target.closest('[data-action]');
            if (!actionEl) return;
            const action = String(actionEl.getAttribute('data-action') || '').trim();
            if (!action) return;
            event.preventDefault();

            if (action === 'wardrive-replay-toggle') {
                toggleWardriveReplayPlayback();
                return;
            }
            if (action === 'wardrive-replay-reset') {
                resetWardriveReplayPlayback();
                return;
            }
            if (action === 'wardrive-replay-focus') {
                const activeTrack = getActiveWardriveReplayTrack();
                if (activeTrack) focusWardriveTrack(activeTrack);
                return;
            }
            if (action === 'wardrive-replay-follow-camera') {
                setWardriveReplayFollowCamera(!wardriveReplayFollowCamera);
                return;
            }
            if (action === 'wardrive-replay-merge') {
                void mergeSelectedWardriveSessions();
                return;
            }
            if (action === 'wardrive-replay-track') {
                const sessionId = actionEl.getAttribute('data-session-id');
                setWardriveActiveReplaySession(sessionId);
            }
        });

        routeReplay.addEventListener('input', (event) => {
            const scrubber = event.target;
            if (!scrubber || scrubber.getAttribute('data-action') !== 'wardrive-replay-scrub') return;
            clearWardriveReplayTimer();
            const nextValue = Number(scrubber.value || 0) / 1000;
            setWardriveReplayProgress(nextValue);
        });
        routeReplay.addEventListener('change', (event) => {
            const select = event.target;
            const action = select?.getAttribute?.('data-action');
            if (action === 'wardrive-replay-speed') {
                setWardriveReplaySpeed(select.value);
                return;
            }
            if (action === 'wardrive-replay-timing-mode') {
                setWardriveReplayTimingMode(select.value);
                return;
            }
            if (action === 'wardrive-replay-follow-zoom') {
                setWardriveReplayFollowZoom(select.value);
            }
        });
        routeReplay.dataset.boundWardrive = '1';
    }

    if (!wardriveTagPopoverCloseBound) {
        document.addEventListener('click', (event) => {
            const target = event.target;
            if (target && typeof target.closest === 'function' && target.closest('.wardrive-session-head')) {
                return;
            }
            closeAllSessionTagPopovers();
        });
        wardriveTagPopoverCloseBound = true;
    }

    if (!wardriveOpenFromAnalyticsBound) {
        document.addEventListener('openWardriveFromAnalytics', async () => {
            setWardriveWorkspaceTab(WORKSPACE_TAB_MAIN);
            if (STATE.modes.wardrive) return;
            await activateWardriveMode();
        });
        wardriveOpenFromAnalyticsBound = true;
    }

    applyWardriveWorkspaceTabUi();
}

export function __testSetWardriveState(partial = {}) {
    if (Object.prototype.hasOwnProperty.call(partial, 'selectedSessionIds')) {
        wardriveSelectedSessionIds = Array.isArray(partial.selectedSessionIds)
            ? [...partial.selectedSessionIds]
            : [];
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'sessions')) {
        wardriveSessions = Array.isArray(partial.sessions) ? [...partial.sessions] : [];
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'sessionTracks')) {
        wardriveSessionTracks = Array.isArray(partial.sessionTracks) ? [...partial.sessionTracks] : [];
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'activeReplaySessionId')) {
        wardriveActiveReplaySessionId = partial.activeReplaySessionId || null;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'lastZoneComparison')) {
        wardriveLastZoneComparison = partial.lastZoneComparison || null;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'hierarchy')) {
        wardriveHierarchy = Array.isArray(partial.hierarchy) ? [...partial.hierarchy] : [];
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'workspaceWarm')) {
        wardriveWorkspaceWarm = !!partial.workspaceWarm;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'workspaceDirty')) {
        wardriveWorkspaceDirty = !!partial.workspaceDirty;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'workspaceTab')) {
        wardriveWorkspaceTab = partial.workspaceTab || WORKSPACE_TAB_MAIN;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'sourceBeforeSessionOverride')) {
        sourceBeforeSessionOverride = partial.sourceBeforeSessionOverride || null;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'replaySpeed')) {
        wardriveReplaySpeed = normalizeWardriveReplaySpeed(partial.replaySpeed);
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'replayTimingMode')) {
        wardriveReplayTimingMode = normalizeWardriveReplayTimingMode(partial.replayTimingMode);
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'replayFollowCamera')) {
        wardriveReplayFollowCamera = !!partial.replayFollowCamera;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'replayFollowZoom')) {
        wardriveReplayFollowZoom = normalizeWardriveReplayFollowZoom(partial.replayFollowZoom);
    }
}

export function __testResetWardriveState() {
    wardriveSessions = [];
    wardriveSelectedSessionIds = [];
    wardriveSessionTracks = [];
    wardriveActiveReplaySessionId = null;
    wardriveLastZoneComparison = null;
    wardriveHierarchy = [];
    wardriveWorkspaceWarm = false;
    wardriveWorkspaceDirty = true;
    wardriveWorkspaceBooting = false;
    wardriveWorkspaceTab = WORKSPACE_TAB_MAIN;
    wardriveSessionsLoading = false;
    wardriveInventoryLoading = false;
    sourceBeforeSessionOverride = null;
    wardriveReplaySpeed = WARDRIVE_UI_CONFIG_DEFAULTS.replaySpeed;
    wardriveReplayTimingMode = WARDRIVE_UI_CONFIG_DEFAULTS.replayTimingMode;
    wardriveReplayFollowCamera = WARDRIVE_UI_CONFIG_DEFAULTS.replayFollowCamera;
    wardriveReplayFollowZoom = WARDRIVE_UI_CONFIG_DEFAULTS.replayFollowZoom;
    wardriveReplayFollowZoomSnapshot = null;
    wardriveReplayLockedMapHandlers = null;
}

export const __testWardriveHelpers = {
    byLevelName,
    getLevelWeight,
    normalizeWardriveSessionSortBy,
    normalizeWardriveSessionSortDirection,
    loadWardriveSessionsUiFilters,
    getRegionLevelLabel,
    getRegionDisplayPath,
    formatSessionDateTime,
    formatDuration,
    getSessionDurationSeconds,
    formatDistanceMeters,
    formatWardriveSessionDisplayName,
    formatAccuracyMeters,
    normalizeTransportMode,
    getTransportMeta,
    summarizeTransportModes,
    normalizeWardriveReplaySpeed,
    normalizeWardriveReplayTimingMode,
    normalizeWardriveReplayFollowZoom,
    formatWardriveReplaySpeed,
    getWardriveReplaySegmentWeights,
    getWardriveReplayTimingModeMeta,
    resolveWardriveReplayCameraZoom,
    getWardriveSelectedSessions,
    getWardriveReplayTracks,
    getActiveWardriveReplayTrack,
    getFiniteWardriveNumber,
    getWardriveZoneOverlaySessionIds,
    getWardriveFocusComparisonSessionIds,
    getWardriveStandardZoneScope,
    getWardriveComparisonActiveSessionId,
    normalizeWardriveComparisonZone,
    normalizeWardriveComparisonPayload,
    buildWardriveComparisonPreset,
    mergeHierarchyWithUnmapped,
    getWardriveZoneRenderContext,
    decorateWardriveZones,
    getWardriveFilters,
    hasWarmWorkspaceSnapshot,
    ensureWardriveFilterDefaults,
    syncWardriveSourceLock,
    setMapViewOnly,
    suspendButtons,
    suspendLeftPanels,
    suspendRightPanels,
    syncMapModeButton,
    suspendMapModeButtons,
    applyWardriveWorkspaceTabUi,
    applyWardriveWorkspaceVisibility,
};
