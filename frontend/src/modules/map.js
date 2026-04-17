import { CONFIG } from './config.js';
import { STATE, saveLists } from './state.js';
import { escapeHtml, copyToClipboard, log, safeText } from './utils.js';
import { API } from './api.js';
import { openCrackingPanel } from './ui_components/ui_cracking.js';
import { getHudAutoPanPadding } from './layout.js';
import {
    boundsFromBBox,
    buildWardriveSessionStyle,
    circlePolygonPoints,
    getDeviceTypeLabel,
    getWardrivePlayheadIcon,
    getWardriveReplayPosition,
    haversineMeters,
    lightenHexColor,
    mapColocationClusterToZone,
    normalizePolygonRings,
    pointInPolygon,
    resolveWardriveAccentColor,
} from './map_wardrive_helpers.js';
import { getRawSummaryFromPosition, insertRawSummaryFallbackRow } from './map_raw.js';
import { getSourceBadges, getSourceFlags } from './source_tags.js';

let map, markers, radarLayer, zonesLayer, toConquerLayer, discoveredLayer, intelligenceLayer, wardriveRegionLayer, wardriveZonesLayer, wardriveTracksLayer, wardriveReplayMarkerLayer, heatLayer, analyticsHeatLayer, analyticsHotspotsLayer;
let analyticsHeatCellsCache = [];
let analyticsHeatMetricCache = 'opportunity';
let analyticsHeatRedrawTimer = null;
let analyticsHotspotsCache = [];
let analyticsSelectedHotspotId = null;
const markerIndex = new Map();
const iconCache = new Map();
let currentTileLayer = null;
let currentClusterConfig = 'performance'; // Default (aggressive grouping)
let currentIconPwned = 'fa-skull';
let currentIconLocked = 'fa-shield-halved';
let currentIconOpen = 'fa-bolt';
let currentIconWardrive = 'fa-tower-broadcast';
let currentWardriveStyle = 'icon';
let zonesRequestId = 0;
let toConquerRequestId = 0;
let discoveredRequestId = 0;
let intelligenceRequestId = 0;
const DISCOVERED_ZONE_MIN_SAMPLES = 5;
const PERFORMANCE_DEBUG = false;
const passVisibilityByMac = new Map();
const detailsCache = new Map();
const WARDRIVE_COMPARE_SECONDARY_COLOR = '#ffd27e';
const WARDRIVE_REPLAY_PLAYHEAD_PANE = 'wardriveReplayPlayheadPane';
const WARDRIVE_REPLAY_PLAYHEAD_Z_INDEX = 690;
const WARDRIVE_REPLAY_PLAYHEAD_Z_OFFSET = 20_000;
const DEFAULT_WARDRIVE_PALETTE_CONFIG = {
    routeAccentColor: 'theme',
    primaryZoneAccentColor: 'theme',
    secondaryAccentColor: 'amber',
};
let wardrivePaletteConfig = { ...DEFAULT_WARDRIVE_PALETTE_CONFIG };
let wardrivePaletteConfigBound = false;

export function clearDetailsCache() {
    detailsCache.clear();
}

function getAnalyticsHotspots() {
    const ui = STATE.analyticsUi || {};
    return Array.isArray(ui.hotspots) ? ui.hotspots : [];
}

function getMatchingHotspotForPosition(pos) {
    if (!pos || !STATE.modes.analytics) return null;
    const lat = Number(pos.lat);
    const lng = Number(pos.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;

    const hotspots = getAnalyticsHotspots();
    if (!hotspots.length) return null;

    const selectedId = STATE.analyticsUi?.selectedHotspotId;
    if (!selectedId) return null;
    const candidates = hotspots.filter((item) => String(item.id) === String(selectedId));

    let best = null;
    candidates.forEach((hotspot) => {
        const mesh = Array.isArray(hotspot?.mesh) ? hotspot.mesh : [];
        const meshMatches = mesh.length >= 3 ? pointInPolygon(lat, lng, mesh) : false;
        if (!meshMatches) {
            const centerLat = Number(hotspot.center_lat);
            const centerLng = Number(hotspot.center_lng);
            const radius = Number(hotspot.radius_m || 0);
            if (!Number.isFinite(centerLat) || !Number.isFinite(centerLng) || radius <= 0) {
                return;
            }
            const distance = haversineMeters(lat, lng, centerLat, centerLng);
            if (distance > radius) return;
        }
        if (!best || Number(hotspot.score || 0) > Number(best.score || 0)) {
            best = hotspot;
        }
    });

    return best;
}

export function getAreaContextForMac(mac) {
    const key = String(mac || '').trim().toUpperCase();
    if (!key || !STATE.allPositions || !STATE.allPositions[key]) return null;
    const pos = STATE.allPositions[key];
    const hotspot = getMatchingHotspotForPosition(pos);
    if (!hotspot) return null;
    return {
        hotspot_id: hotspot.id,
        score: Number(hotspot.score || 0),
        dominant_channel: Array.isArray(hotspot.top_channels) && hotspot.top_channels.length
            ? hotspot.top_channels[0]
            : null,
        nearby_locked: Number(hotspot.locked_count || 0),
    };
}

const TILE_PROVIDERS = {
    'carto_dark': 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    'carto_dark_nolabels': 'https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png',
    'osm': 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
    'opentopomap': 'https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
    'esri_sat': 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    'carto_light': 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
};

const CLUSTER_CONFIGS = {
    // PRIMARY MODE: Aggressive grouping (proven to work well)
    'performance': {
        maxClusterRadius: 80,
        disableClusteringAtZoom: null,
        spiderfyOnMaxZoom: true,
        spiderfyDistanceMultiplier: 1,
        animate: true
    },
    // APPROVED EXPERIMENTAL MODES
    'ultra': {
        maxClusterRadius: 120,
        disableClusteringAtZoom: null,
        spiderfyOnMaxZoom: true,
        spiderfyDistanceMultiplier: 1,
        animate: true
    },
    'spread': {
        maxClusterRadius: 100,
        disableClusteringAtZoom: null,
        spiderfyOnMaxZoom: true,
        spiderfyDistanceMultiplier: 1,
        animate: true
    },
    'tight': {
        maxClusterRadius: 35,
        disableClusteringAtZoom: null,
        spiderfyOnMaxZoom: true,
        spiderfyDistanceMultiplier: 3,
        animate: true
    }
};

export function initMap() {
    bindWardrivePaletteConfigEvents();
    map = L.map('map', { zoomControl: false, attributionControl: false })
        .setView([CONFIG.MAP.DEFAULT_LAT, CONFIG.MAP.DEFAULT_LNG], CONFIG.MAP.DEFAULT_ZOOM);

    ensureWardriveReplayPlayheadPane();

    // Inicializa com o tile padrão, será atualizado se houver config salva
    setTileLayer('carto_dark');

    // Inicializa markers com config padrão (performance - aggressive grouping)
    createMarkerClusterGroup();

    radarLayer = L.layerGroup().addTo(map);
    zonesLayer = L.layerGroup().addTo(map);
    toConquerLayer = L.layerGroup().addTo(map);
    discoveredLayer = L.layerGroup().addTo(map);
    intelligenceLayer = L.layerGroup().addTo(map);
    wardriveRegionLayer = L.layerGroup().addTo(map);
    wardriveZonesLayer = L.layerGroup().addTo(map);
    wardriveTracksLayer = L.layerGroup().addTo(map);
    wardriveReplayMarkerLayer = L.layerGroup().addTo(map);
    analyticsHotspotsLayer = L.layerGroup().addTo(map);
    
    map.addLayer(markers);

    if (map && typeof map.on === 'function') {
        map.on('zoomend', scheduleAnalyticsHeatRedraw);
        map.on('moveend', scheduleAnalyticsHeatRedraw);
    }
    
    window.setTileLayer = setTileLayer;
    window.setClusterConfig = setClusterConfig;
}

function ensureWardriveReplayPlayheadPane() {
    if (!map) return null;

    let pane = typeof map.getPane === 'function'
        ? map.getPane(WARDRIVE_REPLAY_PLAYHEAD_PANE)
        : null;
    if (!pane && typeof map.createPane === 'function') {
        pane = map.createPane(WARDRIVE_REPLAY_PLAYHEAD_PANE);
    }
    if (!pane) return null;

    if (pane.style) {
        pane.style.zIndex = String(WARDRIVE_REPLAY_PLAYHEAD_Z_INDEX);
    }
    return pane;
}

function getAnalyticsHeatVisualParams() {
    const zoom = Number(map?.getZoom?.() || 13);
    const radius = Math.max(16, Math.min(56, Math.round(52 - (zoom - 10) * 3)));
    const blur = Math.max(12, Math.min(32, Math.round(radius * 0.62)));
    return { radius, blur };
}

function normalizeAnalyticsHeatPoints(cells = []) {
    const values = cells.map((cell) => Number(cell?.value || 0));
    const minValue = values.length ? Math.min(...values) : 0;
    const maxValue = values.length ? Math.max(...values) : 0;
    return cells
        .map((cell) => {
            const lat = Number(cell?.lat);
            const lng = Number(cell?.lng);
            const value = Number(cell?.value || 0);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
            let intensity = 0.65;
            if (maxValue > minValue) {
                intensity = (value - minValue) / (maxValue - minValue);
            } else if (value > 0) {
                intensity = 1;
            }
            intensity = Math.max(0.12, Math.min(1, intensity));
            return [lat, lng, intensity];
        })
        .filter(Boolean);
}

function getVisibleAnalyticsCells(cells = []) {
    if (!map || !Array.isArray(cells) || !cells.length) return [];
    const bounds = typeof map.getBounds === 'function' ? map.getBounds() : null;
    if (!bounds || typeof bounds.pad !== 'function') return [...cells];

    const padded = bounds.pad(0.25);
    if (!padded || typeof padded.contains !== 'function') return [...cells];

    const visible = cells.filter((cell) => {
        const lat = Number(cell?.lat);
        const lng = Number(cell?.lng);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) return false;
        return padded.contains([lat, lng]);
    });

    // If viewport is too small and leaves no points, keep full dataset to avoid "vanishing" layer.
    return visible.length >= 3 ? visible : [...cells];
}

function renderAnalyticsHeatmapFromCache() {
    if (!map || !window.L || !L.heatLayer) return;

    if (analyticsHeatLayer) {
        map.removeLayer(analyticsHeatLayer);
        analyticsHeatLayer = null;
    }

    if (!Array.isArray(analyticsHeatCellsCache) || !analyticsHeatCellsCache.length) return;

    const sourceCells = getVisibleAnalyticsCells(analyticsHeatCellsCache);
    const points = normalizeAnalyticsHeatPoints(sourceCells);
    if (!points.length) return;

    const gradientByMetric = {
        opportunity: { 0.2: '#1e90ff', 0.55: '#00f3ff', 0.8: '#fcee0a', 1: '#ff003c' },
        density: { 0.2: '#1e90ff', 0.5: '#00f3ff', 0.85: '#ff8c00', 1: '#ff003c' },
        eapol: { 0.2: '#00f3ff', 0.6: '#fcee0a', 1: '#ff003c' },
        beacon: { 0.2: '#1e90ff', 0.6: '#00f3ff', 1: '#ff8c00' },
        probe: { 0.2: '#1e90ff', 0.6: '#bc13fe', 1: '#ff003c' },
    };
    const gradient = gradientByMetric[analyticsHeatMetricCache] || gradientByMetric.opportunity;
    const visual = getAnalyticsHeatVisualParams();

    analyticsHeatLayer = L.heatLayer(points, {
        radius: visual.radius,
        blur: visual.blur,
        maxZoom: 19,
        gradient,
    }).addTo(map);

    if (analyticsHeatLayer && analyticsHeatLayer.bringToBack) {
        analyticsHeatLayer.bringToBack();
    }
}

function scheduleAnalyticsHeatRedraw() {
    if (!STATE.modes.analytics) return;
    if (!Array.isArray(analyticsHeatCellsCache) || !analyticsHeatCellsCache.length) return;

    if (analyticsHeatRedrawTimer) clearTimeout(analyticsHeatRedrawTimer);
    analyticsHeatRedrawTimer = setTimeout(() => {
        analyticsHeatRedrawTimer = null;
        renderAnalyticsHeatmapFromCache();
    }, 40);
}

function getThemeColor() {
    try {
        const root = window?.getComputedStyle?.(document.documentElement);
        const value = String(root?.getPropertyValue('--theme-color') || '').trim();
        return value || '#00f3ff';
    } catch (_e) {
        return '#00f3ff';
    }
}

function applyWardrivePaletteConfig(config = {}) {
    wardrivePaletteConfig = {
        routeAccentColor: String(
            config?.ui_wardrive_route_accent_color
            || wardrivePaletteConfig.routeAccentColor
            || DEFAULT_WARDRIVE_PALETTE_CONFIG.routeAccentColor
        ).trim().toLowerCase() || DEFAULT_WARDRIVE_PALETTE_CONFIG.routeAccentColor,
        primaryZoneAccentColor: String(
            config?.ui_wardrive_primary_zone_accent_color
            || wardrivePaletteConfig.primaryZoneAccentColor
            || DEFAULT_WARDRIVE_PALETTE_CONFIG.primaryZoneAccentColor
        ).trim().toLowerCase() || DEFAULT_WARDRIVE_PALETTE_CONFIG.primaryZoneAccentColor,
        secondaryAccentColor: String(
            config?.ui_wardrive_secondary_accent_color
            || wardrivePaletteConfig.secondaryAccentColor
            || DEFAULT_WARDRIVE_PALETTE_CONFIG.secondaryAccentColor
        ).trim().toLowerCase() || DEFAULT_WARDRIVE_PALETTE_CONFIG.secondaryAccentColor,
    };
}

function bindWardrivePaletteConfigEvents() {
    if (wardrivePaletteConfigBound || typeof window === 'undefined') return;
    window.addEventListener('kovil:config-applied', (event) => {
        applyWardrivePaletteConfig(event?.detail?.config || {});
    });
    wardrivePaletteConfigBound = true;
}

function renderAnalyticsHotspotsFromCache() {
    if (!map || !analyticsHotspotsLayer || !window.L) return;
    if (!L.polygon) return;

    analyticsHotspotsLayer.clearLayers();
    if (!STATE.modes.analytics) return;
    if (!Array.isArray(analyticsHotspotsCache) || !analyticsHotspotsCache.length) return;
    if (!analyticsSelectedHotspotId) return;

    const themeColor = getThemeColor();

    const selectedStyle = {
        color: themeColor,
        weight: 2,
        opacity: 0.9,
        fillColor: themeColor,
        fillOpacity: 0.2,
        dashArray: '6, 4',
    };

    analyticsHotspotsCache.forEach((hotspot) => {
        const isSelected = String(hotspot?.id || '') === String(analyticsSelectedHotspotId);
        if (!isSelected) return;
        const mesh = Array.isArray(hotspot?.mesh) ? hotspot.mesh : [];
        const ring = mesh
            .map((point) => [Number(point?.lat), Number(point?.lng)])
            .filter((point) => Number.isFinite(point[0]) && Number.isFinite(point[1]));
        const layer = ring.length >= 3 ? L.polygon(ring, selectedStyle) : null;
        if (!layer) return;

        if (typeof layer.bindTooltip === 'function') {
            const label = `Hotspot ${String(hotspot?.id || '-')} | score ${Number(hotspot?.score || 0)} | locked ${Number(hotspot?.locked_count || 0)}`;
            layer.bindTooltip(label, {
                direction: 'top',
                className: 'analytics-hotspot-tooltip',
                sticky: true,
            });
        }
        analyticsHotspotsLayer.addLayer(layer);
    });

    if (typeof analyticsHotspotsLayer.bringToFront === 'function') {
        analyticsHotspotsLayer.bringToFront();
    }
}

function createMarkerClusterGroup() {
    const config = CLUSTER_CONFIGS[currentClusterConfig] || CLUSTER_CONFIGS['surgical'];
    
    const options = {
        maxClusterRadius: config.maxClusterRadius,
        spiderfyOnMaxZoom: config.spiderfyOnMaxZoom,
        spiderfyDistanceMultiplier: config.spiderfyDistanceMultiplier,
        animate: config.animate,
        showCoverageOnHover: false,
        zoomToBoundsOnClick: true,
        iconCreateFunction: function(cluster) {
            const count = cluster.getChildCount();
            const children = cluster.getAllChildMarkers();
            
            let hasTarget = false;
            let hasCracked = false;

            for (let i = 0; i < children.length; i++) {
                const pos = children[i].options.posData;
                if (pos) {
                    if (STATE.lists.targets.includes(pos.mac)) {
                        hasTarget = true;
                        break; 
                    }
                    if (pos.pass) {
                        hasCracked = true;
                    }
                }
            }

            let className = 'cyber-cluster';
            if (hasTarget) {
                className += ' cluster-target';
            } else if (hasCracked) {
                className += ' cluster-cracked';
            }

            return L.divIcon({
                html: count,
                className: className,
                iconSize: L.point(40, 40)
            });
        }
    };

    if (config.disableClusteringAtZoom !== null) {
        options.disableClusteringAtZoom = config.disableClusteringAtZoom;
    }

    markers = L.markerClusterGroup(options);
}

export function setClusterConfig(mode) {
    if (!map || !CLUSTER_CONFIGS[mode]) return;
    if (currentClusterConfig === mode) return;

    currentClusterConfig = mode;
    const currentView = { center: map.getCenter(), zoom: map.getZoom() };
    
    // Remove grupo antigo
    if (markers) {
        map.removeLayer(markers);
        markers.clearLayers();
    }

    // Cria novo grupo com nova config
    createMarkerClusterGroup();
    map.addLayer(markers);

    // Re-renderiza os dados atuais
    if (STATE.allPositions) {
        renderMarkers(STATE.allPositions, false);
    }

    if (currentView) {
        map.setView(currentView.center, currentView.zoom, { animate: false });
    }
}

export function setTileLayer(providerKey) {
    if (!map) return;
    
    if (currentTileLayer) {
        map.removeLayer(currentTileLayer);
    }

    const url = TILE_PROVIDERS[providerKey] || TILE_PROVIDERS['carto_dark'];
    
    // Ajustes específicos para alguns provedores se necessário
    let options = {
        maxZoom: 20,
        subdomains: 'abcd',
        opacity: 1,
        attribution: '' 
    };

    if (providerKey === 'osm' || providerKey === 'opentopomap') {
        options.subdomains = 'abc';
    } else if (providerKey === 'esri_sat') {
        delete options.subdomains;
    }

    currentTileLayer = L.tileLayer(url, options).addTo(map);
    currentTileLayer.bringToBack(); // Garante que fique atrás de tudo
}

export function setMarkerIcons(pwnedIcon, lockedIcon, wardriveIcon = null, wardriveStyle = null, openIcon = null) {
    currentIconPwned = pwnedIcon;
    currentIconLocked = lockedIcon;
    if (wardriveIcon) currentIconWardrive = wardriveIcon;
    if (wardriveStyle) currentWardriveStyle = wardriveStyle;
    if (openIcon) currentIconOpen = openIcon;
    iconCache.clear();
    
    // Re-renderiza se já houver dados
    if (STATE.allPositions && Object.keys(STATE.allPositions).length > 0) {
        renderMarkers(STATE.allPositions, false);
    }
}

export function getMapInstance() { return map; }

export function toggleTarget(mac) {
    if (STATE.lists.targets.includes(mac)) {
        STATE.lists.targets = STATE.lists.targets.filter(t => t !== mac);
    } else {
        STATE.lists.targets.push(mac);
    }
    saveLists();
    renderMarkers(STATE.allPositions, false);
    document.dispatchEvent(new CustomEvent('listsUpdated'));
}

export function toggleFav(mac) {
    if (STATE.lists.favs.includes(mac)) {
        STATE.lists.favs = STATE.lists.favs.filter(t => t !== mac);
    } else {
        STATE.lists.favs.push(mac);
    }
    saveLists();
    renderMarkers(STATE.allPositions, false);
    document.dispatchEvent(new CustomEvent('listsUpdated'));
}

function getCrackingInfo(pos) {
    if (!pos || !pos.mac) return { crackingStatus: null, crackingType: null };
    const info = STATE.crackingByMac[pos.mac];
    if (!info) return { crackingStatus: null, crackingType: null };
    return { crackingStatus: info.status, crackingType: info.type };
}

function isWardriveOnlySource(sourceFlags) {
    return (
        sourceFlags.hasWardrive
        && !sourceFlags.hasPwnagotchi
        && !sourceFlags.hasBrucegotchi
        && !sourceFlags.hasM5evil
        && !sourceFlags.hasRawsniffer
    );
}

function hasGpsFix(pos) {
    const lat = Number(pos?.lat);
    const lng = Number(pos?.lng);
    return Number.isFinite(lat) && Number.isFinite(lng) && !(lat === 0 && lng === 0);
}

function getArtifactFlags(pos = {}) {
    const handshakeFiles = Array.isArray(pos?.handshake_files) ? pos.handshake_files : [];
    return {
        handshakeFiles,
        hasPcap: handshakeFiles.some((file) => typeof file === 'string' && file.toLowerCase().endsWith('.pcap')),
        has22000: handshakeFiles.some((file) => typeof file === 'string' && file.toLowerCase().endsWith('.22000')),
        hasRawHash: Number(pos?.raw_pmkid_count || 0) > 0 || Number(pos?.raw_eapol_count || 0) > 0,
    };
}

function getNormalizedNetworkState(pos = {}) {
    const normalized = String(pos?.network_state || '').trim().toLowerCase();
    if (normalized) return normalized;

    const { hasPcap, has22000, hasRawHash } = getArtifactFlags(pos);
    const enc = String(pos?.encryption || '').trim().toUpperCase();
    const openLike = enc === 'OPEN' || enc === 'WEP';
    const gpsBacked = String(pos?.type || '').trim().toLowerCase() !== 'no-gps' && hasGpsFix(pos);
    const wardriveOnly = isWardriveOnlySource(getSourceFlags(pos?.sources));

    if (pos?.pass) return 'cracked';
    if (openLike) return 'open';
    if (hasPcap || has22000) return gpsBacked ? 'locked' : 'no_gps_locked';
    if (hasRawHash) return 'not_ready';
    if (wardriveOnly || gpsBacked) return 'gps_only';
    return 'no_gps_only';
}

function isLockedState(state) {
    return state === 'locked' || state === 'no_gps_locked';
}

function isGpsOnlyState(state) {
    return state === 'gps_only';
}

function getNormalizedMacSearchValue(mac) {
    return String(mac || '').replace(/[:-]/g, '').toLowerCase();
}

function buildSearchableText(pos, vendor, tags) {
    const normalizedMac = getNormalizedMacSearchValue(pos?.mac);
    return `${pos?.ssid || ''} ${pos?.mac || ''} ${normalizedMac} ${vendor || ''} ${tags || ''}`.toLowerCase();
}

function getMarkerHtml(pos) {
    let cssClass = 'm-locked';
    let iconClass = currentIconLocked; // Use dynamic icon

    // Verifica se está sendo crackeada e obtém o status
    const { crackingStatus, crackingType } = getCrackingInfo(pos);
    const state = getNormalizedNetworkState(pos);
    const isWardriveOnly = isGpsOnlyState(state);
    const isOpen = state === 'open';
    let badgeHtml = '';

    if (state === 'cracked') {
        cssClass = 'm-cracked';
        iconClass = `${currentIconPwned} cyber-glitch-1`; // Use dynamic icon
    } else if (isOpen) {
        cssClass = 'm-open';
        iconClass = currentIconOpen;
    } else if (isWardriveOnly) {
        cssClass = 'm-wardrive';
        iconClass = currentIconWardrive;
        if (currentWardriveStyle === 'pulse') {
            cssClass = `m-wardrive-pulse ${cssClass}`;
        }
        if (currentWardriveStyle === 'badge') {
            badgeHtml = '<span class="wardrive-badge">W</span>';
        }
    } else if (crackingStatus) {
        if (crackingStatus === 'QUEUED') {
            cssClass = 'm-cracking-queued';
            iconClass = 'fa-solid fa-clock m-open'; // Default queued icon
        } else {
            cssClass = 'm-cracking';
            iconClass = 'fa-solid fa-shield-cat cyber-glitch-4'; // Default cracking icon
        }

        // Determine specific icon based on tool type
        if (crackingType) {
            if (crackingType.includes("HASHCAT") || crackingType.includes("22000")) {
                iconClass = 'fa-solid fa-cat';
            } else if (crackingType.includes("AIRCRACK")) {
                iconClass = 'fa-solid fa-wind';
            }
            
            if (crackingStatus !== 'QUEUED') {
                iconClass += ' cyber-glitch-4';
            } else {
                iconClass += ' m-open';
            }
        }
    } else if (!pos.ssid) {
        cssClass = 'm-hidden';
        iconClass = 'fa-solid fa-ghost cyber-glitch-2';
    }

    if (STATE.lists.targets.includes(pos.mac)) cssClass = 'm-target ' + cssClass;
    if (STATE.lists.favs.includes(pos.mac)) cssClass = 'm-favorite ' + cssClass;

    // Ensure fa-solid is present if not included in the config string (it usually is)
    if (!iconClass.includes('fa-')) {
        iconClass = 'fa-solid ' + iconClass;
    } else if (!iconClass.includes('fa-solid') && !iconClass.includes('fa-regular') && !iconClass.includes('fa-brands')) {
         iconClass = 'fa-solid ' + iconClass;
    }

    return `<div class="icon-wrapper ${cssClass}"><i class="${iconClass}"></i>${badgeHtml}</div>`;
}

function getMarkerIcon(pos) {
    const html = getMarkerHtml(pos);
    const cached = iconCache.get(html);
    if (cached) return cached;
    const icon = L.divIcon({
        className: 'cyber-marker',
        html: html,
        iconSize: [32, 32],
        iconAnchor: [16, 16],
        popupAnchor: [0, -28]
    });
    iconCache.set(html, icon);
    return icon;
}

function getThemeClass(pos) {
    const state = getNormalizedNetworkState(pos);
    if (state === 'cracked') return 'theme-cracked';
    if (!pos.ssid) return 'theme-hidden';
    if (state === 'open') return 'theme-open';
    if (isGpsOnlyState(state)) return 'theme-wardrive';
    return 'theme-locked';
}

function getAccuracyColor(pos) {
    const { crackingStatus } = getCrackingInfo(pos);
    const state = getNormalizedNetworkState(pos);

    if (state === 'cracked') return 'var(--theme-color)';
    if (crackingStatus === 'QUEUED') return 'var(--neon-yellow)';
    if (crackingStatus) return 'var(--theme-color)';
    if (!pos.ssid) return 'var(--neon-purple)';
    if (state === 'open') return 'var(--neon-yellow)';
    if (isGpsOnlyState(state)) return 'var(--wardrive-color)';
    return 'var(--neon-red)';
}

function maskPassword(pass) {
    if (!pass) return '';
    const length = Math.max(4, String(pass).length);
    return '*'.repeat(length);
}

function isPassVisible(mac) {
    if (passVisibilityByMac.has(mac)) return passVisibilityByMac.get(mac);
    return !STATE.ui.hidePasswords;
}

function setPassVisibility(mac, visible) {
    passVisibilityByMac.set(mac, visible);
    const passEl = document.getElementById(`pass-val-${mac.replace(/:/g, '')}`);
    const eyeEl = document.getElementById(`pass-eye-${mac.replace(/:/g, '')}`);
    const passRaw = passEl ? passEl.getAttribute('data-pass') : null;
    if (passEl && passRaw != null) {
        passEl.textContent = visible ? passRaw : maskPassword(passRaw);
    }
    if (eyeEl) {
        eyeEl.classList.toggle('fa-eye', visible);
        eyeEl.classList.toggle('fa-eye-slash', !visible);
    }
}

function escapeAttribute(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function buildPopupRow(label, valueHtml, options = {}) {
    const rowClass = options.rowClass ? ` ${options.rowClass}` : '';
    const rowId = options.id ? ` id="${options.id}"` : '';
    const labelClass = options.labelClass ? ` ${options.labelClass}` : '';
    const valueClass = options.valueClass ? ` ${options.valueClass}` : '';
    return `
        <div class="data-row${rowClass}"${rowId}>
            <span class="d-label${labelClass}">${label}</span>
            <span class="d-val${valueClass}">${valueHtml}</span>
        </div>
    `;
}

function formatPopupAccuracyValue(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric) || numeric <= 0) return null;
    if (numeric >= 100) return `${Math.round(numeric)}m`;
    return `${numeric.toFixed(1)}m`;
}

function buildPopupSection(title, innerHtml, options = {}) {
    const sectionClass = options.sectionClass ? ` ${options.sectionClass}` : '';
    const sectionId = options.sectionId ? ` id="${options.sectionId}"` : '';
    const sectionAttrs = options.sectionAttrs ? ` ${options.sectionAttrs}` : '';
    const rowsId = options.rowsId ? ` id="${options.rowsId}"` : '';
    return `
        <section class="popup-section${sectionClass}"${sectionId}${sectionAttrs}>
            <div class="popup-section-title">${title}</div>
            <div class="popup-section-rows"${rowsId}>
                ${innerHtml}
            </div>
        </section>
    `;
}

function getPopupStateChips(pos, flags = {}) {
    const chips = [];
    const enc = escapeHtml(pos.encryption || 'UNK');
    const state = getNormalizedNetworkState(pos);
    const hasPcap = Boolean(flags.hasPcap);
    const has22000 = Boolean(flags.has22000);
    const hasRawHash = Boolean(flags.hasRawHash);

    if (state === 'cracked') {
        chips.push('<span class="popup-chip popup-chip-status popup-chip-cracked">CRACKED</span>');
    } else if (state === 'open') {
        chips.push(`<span class="popup-chip popup-chip-status popup-chip-open">${escapeHtml(pos.encryption)}</span>`);
    } else if (state === 'not_ready') {
        chips.push('<span class="popup-chip popup-chip-status popup-chip-hidden">NOT READY</span>');
    } else if (isGpsOnlyState(state)) {
        chips.push('<span class="popup-chip popup-chip-status popup-chip-wardrive">GPS ONLY</span>');
    } else {
        chips.push('<span class="popup-chip popup-chip-status popup-chip-locked">LOCKED</span>');
    }

    if (!pos.ssid) {
        chips.push('<span class="popup-chip popup-chip-status popup-chip-hidden">HIDDEN</span>');
    }

    chips.push(`<span class="popup-chip popup-chip-security">${enc}</span>`);

    if (hasPcap && state !== 'cracked') {
        chips.push('<span class="popup-chip popup-chip-capture">PCAP</span>');
    }

    if (has22000 && state !== 'cracked') {
        chips.push('<span class="popup-chip popup-chip-handshake">HANDSHAKE</span>');
    }
    if (hasRawHash && state === 'not_ready') {
        chips.push('<span class="popup-chip popup-chip-capture">RAW</span>');
    }

    return chips.join('');
}

function getAccessCtaLabel(flags = {}, pos = {}) {
    const state = getNormalizedNetworkState(pos);
    if (state === 'cracked') return 'OPEN ARTIFACTS';
    if (state === 'not_ready') return 'INSPECT // PREP';
    return 'HASH // CRACK';
}

function revealPopupSection(sectionEl) {
    if (sectionEl) {
        sectionEl.classList.remove('popup-section-empty');
    }
}

function triggerCrack(mac, encodedSsid) {
    const decodedSsid = decodeURIComponent(encodedSsid || '');
    openCrackingPanel(mac, decodedSsid);
}

function bindPopupActionHandlers(pos) {
    const macKey = pos.mac.replace(/:/g, '');
    const rowsContainer = document.getElementById(`data-rows-${macKey}`);
    const popupRoot = rowsContainer?.closest('.data-card');
    if (!popupRoot || popupRoot.dataset.actionsBound === '1') return;

    popupRoot.dataset.actionsBound = '1';
    popupRoot.addEventListener('click', (event) => {
        const actionEl = event.target.closest('[data-action]');
        if (!actionEl) return;

        const action = actionEl.getAttribute('data-action');
        const mac = actionEl.getAttribute('data-mac') || pos.mac;

        if (action === 'copy') {
            event.stopPropagation();
            copyToClipboard(actionEl.getAttribute('data-copy') || '');
            return;
        }

        if (action === 'toggle-target') {
            toggleTarget(mac);
            return;
        }

        if (action === 'toggle-fav') {
            toggleFav(mac);
            return;
        }

        if (action === 'trigger-crack') {
            triggerCrack(mac, actionEl.getAttribute('data-ssid') || '');
            return;
        }

        if (action === 'toggle-pass-visibility') {
            event.stopPropagation();
            setPassVisibility(mac, !isPassVisible(mac));
        }
    });
}


// Test-only helper to validate popup action wiring without depending on Leaflet runtime.
export function __testBindPopupActionHandlers(pos) {
    bindPopupActionHandlers(pos);
}

// Test-only helper for popup details sanitization.
export function __testInjectDetailsIntoPopup(mac, details) {
    injectDetailsIntoPopup(mac, details);
}

export function updateMarkersStatus() {
    if (!markers) return;

    const startTs = PERFORMANCE_DEBUG ? performance.now() : 0;
    markers.eachLayer(marker => {
        if (marker.options.posData) {
            const pos = marker.options.posData;
            marker.setIcon(getMarkerIcon(pos));
        }
    });

    if (PERFORMANCE_DEBUG) {
        const elapsed = performance.now() - startTs;
        console.log(`[perf] updateMarkersStatus ${elapsed.toFixed(1)}ms`);
    }
}

export function updateMarkerStatusByMac(mac) {
    const marker = markerIndex.get(mac);
    if (!marker || !marker.options || !marker.options.posData) return;

    const pos = marker.options.posData;
    marker.setIcon(getMarkerIcon(pos));
}

export function renderMarkers(data, forceRender = false) {
    const renderStart = PERFORMANCE_DEBUG ? performance.now() : 0;
    // Se estivermos no meio de uma interação programática, abortamos para não destruir o popup
    if (STATE.isProgrammaticInteraction) {
        return;
    }

    // 1. Tenta preservar o popup aberto
    let currentOpenMac = STATE.openPopupMac;

    // Se não tivermos um estado salvo, tentamos descobrir se há algum popup aberto no mapa
    if (!currentOpenMac) {
        map.eachLayer(layer => {
            if (layer.getPopup && typeof layer.getPopup === 'function') {
                const popup = layer.getPopup();
                if (popup && popup.isOpen() && layer.options.posData) {
                    currentOpenMac = layer.options.posData.mac;
                }
            }
        });
    }
    
    // Persiste a intenção
    STATE.openPopupMac = currentOpenMac;

    // Define flag para ignorar o evento popupclose durante a limpeza
    STATE.ignorePopupClose = true;
    markers.clearLayers();
    markerIndex.clear();
    STATE.ignorePopupClose = false;

    radarLayer.clearLayers();
    if (heatLayer) { map.removeLayer(heatLayer); heatLayer = null; }
    if (STATE.map.hoverCircle) { map.removeLayer(STATE.map.hoverCircle); STATE.map.hoverCircle = null; }
    
    let stats = { 
        total: 0, cracked: 0, locked: 0, open: 0, hidden: 0, wardrive: 0,
        noGpsTotal: 0, noGpsCracked: 0, noGpsLocked: 0
    };
    const bounds = L.latLngBounds();
    const now = Date.now() / 1000;
    
    let heatPoints = [];
    let markerToOpen = null; 

    Object.values(data).forEach(pos => {
        if (STATE.filters.time === '24H') {
            if (pos.ts_last < (now - 86400)) return;
        }

        const vendor = pos.vendor || "Loading...";
        
        let tags = "";
        if (pos.pass) tags += " #cracked";
        if (!pos.ssid) tags += " #hidden";
        if (pos.encryption === 'OPEN') tags += " #open";
        if (STATE.lists.targets.includes(pos.mac)) tags += " #target";
        if (STATE.lists.favs.includes(pos.mac)) tags += " #fav";
        const sourceFlags = getSourceFlags(pos?.sources);
        if (sourceFlags.hasWardrive) tags += " #wardrive";
        if (sourceFlags.hasPwnagotchi) tags += " #pwnagotchi";
        if (sourceFlags.hasBrucegotchi) tags += " #brucegotchi";
        if (sourceFlags.hasM5evil) tags += " #m5evil";
        if (sourceFlags.hasRawsniffer) tags += " #rawsniffer";
        
        const searchable = buildSearchableText(pos, vendor, tags);
        if (STATE.filters.search && !searchable.includes(STATE.filters.search)) return;

        // Contabiliza redes sem GPS
        if (pos.type === 'no-gps') {
            const state = getNormalizedNetworkState(pos);
            stats.noGpsTotal++;
            if (state === 'cracked') stats.noGpsCracked++;
            if (state === 'no_gps_locked') stats.noGpsLocked = (stats.noGpsLocked || 0) + 1;
            return; // Não renderiza no mapa
        }

        if (pos.lat && pos.lng && pos.lat !== 0 && pos.lng !== 0) {
            stats.total++;
            const { handshakeFiles, hasPcap, has22000, hasRawHash } = getArtifactFlags(pos);
            const state = getNormalizedNetworkState(pos);
            if (state === 'cracked') {
                stats.cracked++;
            } else if (!pos.ssid) {
                stats.hidden++;
            } else if (state === 'open') {
                stats.open++;
            } else if (isGpsOnlyState(state)) {
                stats.wardrive++;
            } else if (state === 'locked') {
                stats.locked++; 
            }

            if (STATE.modes.heat) {
                heatPoints.push([pos.lat, pos.lng, 0.5]); 
            }

            const marker = L.marker([pos.lat, pos.lng], {
                icon: getMarkerIcon(pos),
                posData: pos 
            });

            // Verifica se este é o marker que deve ser reaberto
            if (currentOpenMac === pos.mac) {
                markerToOpen = marker;
            }

            marker.on('mouseover', function() {
                if (STATE.modes.radar) return; 
                if (STATE.map.hoverCircle) map.removeLayer(STATE.map.hoverCircle);
                const accColor = getAccuracyColor(pos);
                STATE.map.hoverCircle = L.circle([pos.lat, pos.lng], {
                    radius: pos.acc || 20,
                    color: accColor,
                    fillColor: accColor,
                    fillOpacity: 0.05,
                    weight: 1,
                    dashArray: '5, 5'
                }).addTo(map);
            });

            marker.on('mouseout', function() {
                if (STATE.map.hoverCircle) {
                    map.removeLayer(STATE.map.hoverCircle);
                    STATE.map.hoverCircle = null;
                }
            });

            marker.on('popupopen', () => handlePopupOpen(pos));
            marker.on('popupclose', () => {
                if (STATE.ignorePopupClose) return;
                // Só limpa se for o popup atual
                if (STATE.openPopupMac === pos.mac) {
                    // Pequeno delay para permitir cliques rápidos ou trocas
                    setTimeout(() => {
                        if (STATE.openPopupMac === pos.mac) {
                            STATE.openPopupMac = null;
                        }
                    }, 100);
                }
            });

            const ssidDisplay = pos.ssid ? escapeHtml(pos.ssid) : '[HIDDEN]';
            const targetClass = STATE.lists.targets.includes(pos.mac) ? 'active' : '';
            const favClass = STATE.lists.favs.includes(pos.mac) ? 'active' : '';
            const encodedSsid = encodeURIComponent(pos.ssid || '');
            const escapedMac = escapeAttribute(pos.mac);
            const escapedPass = escapeAttribute(pos.pass || '');

            const canTarget = state !== 'cracked' && state !== 'open' && !isGpsOnlyState(state);
            const canAccess = !isGpsOnlyState(state) && (canTarget || state === 'cracked' || state === 'not_ready');
            const targetBtnHtml = canTarget 
                ? `<i class="fa-solid fa-bullseye header-btn target ${targetClass}" data-action="toggle-target" data-mac="${escapedMac}" title="Toggle Target"></i>`
                : '';
            const favBtnHtml = `<i class="fa-solid fa-star header-btn fav ${favClass}" data-action="toggle-fav" data-mac="${escapedMac}" title="Toggle Favorite"></i>`;

            const accessCtaLabel = getAccessCtaLabel({ hasPcap, has22000 }, pos);
            const accessCtaHtml = canAccess
                ? `
                    <div class="popup-access-stack popup-access-stack--cta">
                        <div class="popup-access-main">
                            <div class="pass-box popup-crack-cta"
                                 data-action="trigger-crack" data-mac="${escapedMac}" data-ssid="${escapeAttribute(encodedSsid)}">
                                ${accessCtaLabel}
                            </div>
                        </div>
                    </div>
                `
                : '';

            const macKey = pos.mac.replace(/:/g, '');
            const sourceBadges = getSourceBadges(pos?.sources).map(
                (badge) => `<span class="${badge.className}">${badge.label}</span>`
            );
            const sourceBadge = sourceBadges.join(' ');

            const signalRows = [];
            if (pos.channel !== null && pos.channel !== undefined && pos.channel !== '') {
                signalRows.push(buildPopupRow('CH', escapeHtml(String(pos.channel))));
            }
            if (pos.frequency !== null && pos.frequency !== undefined && pos.frequency !== '') {
                signalRows.push(buildPopupRow('FREQ', `${escapeHtml(String(pos.frequency))} MHz`));
            }
            const hasDetailsFile = handshakeFiles.some((file) => typeof file === 'string' && file.endsWith('.details'));
            const rawSummary = getRawSummaryFromPosition(pos);
            const analyticsHotspot = getMatchingHotspotForPosition(pos);
            if (analyticsHotspot) {
                signalRows.push(
                    buildPopupRow(
                        'AREA',
                        `Hotspot ${escapeHtml(String(analyticsHotspot.id || '-'))} | score ${escapeHtml(String(analyticsHotspot.score ?? 0))}`
                    )
                );
            }
            if (pos.rssi !== null && pos.rssi !== undefined && pos.rssi !== '') {
                signalRows.push(buildPopupRow('RSSI', `${escapeHtml(String(pos.rssi))} dBm`));
            }
            if (pos.altitude !== null && pos.altitude !== undefined && pos.altitude !== '') {
                const altVal = Math.round(pos.altitude * 10) / 10;
                signalRows.push(buildPopupRow('ALT', `${escapeHtml(String(altVal))} m`));
            }
            if (pos.ts_first) {
                signalRows.push(buildPopupRow('FIRST SEEN', new Date(pos.ts_first * 1000).toLocaleDateString()));
            }

            const operationalAcc = formatPopupAccuracyValue(pos.acc);
            if (operationalAcc) {
                signalRows.push(buildPopupRow('ACC', operationalAcc));
            }
            const sourceAcc = Number(pos.sourceAccuracyMeters);
            const operationalAccValue = Number(pos.acc);
            if (
                Number.isFinite(sourceAcc)
                && sourceAcc > 0
                && (
                    !Number.isFinite(operationalAccValue)
                    || Math.abs(sourceAcc - operationalAccValue) >= 1
                )
            ) {
                const rawAccLabel = formatPopupAccuracyValue(sourceAcc);
                if (rawAccLabel) {
                    signalRows.push(buildPopupRow('RAW ACC', rawAccLabel));
                }
            }
            signalRows.push(buildPopupRow('SEEN', new Date(pos.ts_last * 1000).toLocaleDateString()));

            const overviewRowsHtml = [
                buildPopupRow(
                    'MAC',
                    `${pos.mac} <i class="fa-regular fa-copy copy-icon"></i>`,
                    {
                        valueClass: ' popup-copy-value',
                        rowClass: ' popup-overview-row',
                    }
                ).replace(
                    '<span class="d-val popup-copy-value">',
                    `<span class="d-val popup-copy-value" data-action="copy" data-copy="${escapedMac}" title="Click to Copy">`
                ),
                buildPopupRow('VENDOR 1', `<span id="vendor-${macKey}" class="popup-dynamic-value">Loading...</span>`, {
                    rowClass: ' popup-overview-row',
                }),
                buildPopupRow('VENDOR 2', `<span id="vendor-alt-${macKey}" class="popup-dynamic-subtle">Loading...</span>`, {
                    rowClass: ' popup-overview-row',
                }),
                buildPopupRow(
                    'SOURCE',
                    `<span class="popup-source-row">${sourceBadge || '<span class="popup-chip popup-chip-muted">UNKNOWN</span>'}</span>`,
                    { rowClass: ' popup-overview-row', valueClass: ' popup-source-value' }
                ),
            ].join('');

            const securityRowsHtml = buildPopupRow('SEC', pos.encryption || 'UNK', {
                id: `sec-row-${macKey}`,
                rowClass: ' popup-security-row',
            });

            const rawRowsHtml = (!hasDetailsFile && rawSummary)
                ? buildPopupRow('RAW', escapeHtml(rawSummary.summaryText), {
                    rowClass: ' raw-summary-row popup-static-row',
                })
                : '';

            const accessSectionHtml = canAccess
                ? buildPopupSection(
                    'Access',
                    [
                        pos.pass ? `
                            <div class="data-row popup-access-row popup-access-row-cracked" id="pass-row-${macKey}">
                                <div class="popup-access-stack popup-access-stack--cracked">
                                    <div class="popup-access-main">
                                        <div class="pass-box popup-pass-box" data-action="trigger-crack" data-mac="${escapedMac}" data-ssid="${escapeAttribute(encodedSsid)}" title="Open in Cracking Operations">
                                            <span id="pass-val-${macKey}" data-pass="${escapedPass}" class="popup-pass-value">${isPassVisible(pos.mac) ? escapeHtml(pos.pass) : maskPassword(pos.pass)}</span>
                                            <i id="pass-eye-${macKey}" class="fa-solid ${isPassVisible(pos.mac) ? 'fa-eye' : 'fa-eye-slash'} popup-pass-eye" data-action="toggle-pass-visibility" data-mac="${escapedMac}"></i>
                                        </div>
                                    </div>
                                    <div class="popup-access-main">
                                        <div class="pass-box popup-crack-cta"
                                             data-action="trigger-crack" data-mac="${escapedMac}" data-ssid="${escapeAttribute(encodedSsid)}">
                                            ${accessCtaLabel}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ` : accessCtaHtml,
                    ].join(''),
                    {
                        sectionClass: ' popup-section-access',
                        sectionAttrs: 'data-popup-section="access"',
                        rowsId: `access-rows-${macKey}`,
                    }
                )
                : '';

            const popupContent = `
                <div class="data-card">
                    <div class="card-header popup-card-header">
                        <div class="popup-header-main">
                            <div class="popup-header-actions">
                                ${favBtnHtml}
                                ${targetBtnHtml}
                            </div>
                            <div class="popup-title-block popup-title-block-full">
                                <div class="popup-title">${ssidDisplay}</div>
                            </div>
                        </div>
                        <div class="popup-header-meta">
                            <div class="popup-chip-row">
                                ${getPopupStateChips(pos, { hasPcap, has22000, hasRawHash })}
                            </div>
                        </div>
                    </div>
                    <div id="data-rows-${macKey}" class="popup-sections">
                        ${buildPopupSection('Overview', overviewRowsHtml, {
                            sectionClass: ' popup-section-overview',
                            sectionAttrs: 'data-popup-section="overview"',
                        })}
                        ${buildPopupSection('Signal // Capture', signalRows.join(''), {
                            sectionClass: ' popup-section-signal',
                            sectionAttrs: 'data-popup-section="signal"',
                            rowsId: `signal-rows-${macKey}`,
                        })}
                        ${buildPopupSection('Security // Fingerprint', securityRowsHtml, {
                            sectionClass: ' popup-section-security',
                            sectionAttrs: 'data-popup-section="security"',
                            rowsId: `security-rows-${macKey}`,
                        })}
                        ${buildPopupSection('Raw Sniffer', rawRowsHtml, {
                            sectionClass: ` popup-section-raw${rawRowsHtml ? '' : ' popup-section-empty'}`,
                            sectionId: `raw-section-${macKey}`,
                            sectionAttrs: 'data-popup-section="raw"',
                            rowsId: `raw-rows-${macKey}`,
                        })}
                        ${accessSectionHtml}
                    </div>
                </div>
            `;

            marker.bindPopup(popupContent, {
                className: getThemeClass(pos),
                maxWidth: 460,
                autoPanPaddingTopLeft: getHudAutoPanPadding().topLeft,
                autoPanPaddingBottomRight: getHudAutoPanPadding().bottomRight
            });

            marker.on('popupclose', () => {
                const rowsContainer = document.getElementById(`data-rows-${macKey}`);
                if (rowsContainer) {
                    delete rowsContainer.dataset.detailsApplied;
                    Array.from(rowsContainer.querySelectorAll('.detail-row')).forEach((el) => el.remove());
                }
            });

            markers.addLayer(marker);
            markerIndex.set(pos.mac, marker);
            bounds.extend([pos.lat, pos.lng]);
        }
    });

    if (STATE.modes.heat && !STATE.isCrackingActive && heatPoints.length > 0) {
        heatLayer = L.heatLayer(heatPoints, {
            radius: 35, blur: 20, maxZoom: 17,
            gradient: {0.4: 'blue', 0.65: 'lime', 1: 'red'}
        }).addTo(map);
        heatLayer.bringToBack();
    }

    if (STATE.modes.radar) updateRadarCircles();

    document.dispatchEvent(new CustomEvent('statsUpdated', { detail: stats }));

    // Lógica de Zoom Automático (FitBounds)
    // Só executa se NÃO houver intenção de popup aberto
    if ((STATE.isFirstLoad || forceRender) && stats.total > 0 && !STATE.filters.search && !STATE.openPopupMac && !STATE.isProgrammaticInteraction) {
        map.fitBounds(bounds);
    }

    if (markerToOpen) {
        // Garante que o estado persista
        STATE.openPopupMac = currentOpenMac;
        
        // Usa setTimeout para garantir que o cluster manager processou a adição
        setTimeout(() => {
            // Se estivermos em interação programática, não usamos zoomToShowLayer aqui para não conflitar
            // Apenas abrimos o popup se ele já estiver visível
            if (!STATE.isProgrammaticInteraction) {
                const visibleParent = markers.getVisibleParent(markerToOpen);
                if (visibleParent === markerToOpen) {
                    markerToOpen.openPopup();
                } else {
                    markers.zoomToShowLayer(markerToOpen, () => {
                        markerToOpen.openPopup();
                    });
                }
            } else {
                // Se for interação programática, deixamos o focusAndOpenPopup lidar com o zoom
                // mas garantimos que o popup abra se o marker estiver lá
                markerToOpen.openPopup();
            }
        }, 100);
    }

    if (PERFORMANCE_DEBUG) {
        const elapsed = performance.now() - renderStart;
        console.log(`[perf] renderMarkers ${elapsed.toFixed(1)}ms`);
    }
}

export function clearAnalyticsHeatmapLayer() {
    if (analyticsHeatRedrawTimer) {
        clearTimeout(analyticsHeatRedrawTimer);
        analyticsHeatRedrawTimer = null;
    }
    analyticsHeatCellsCache = [];
    if (!map || !analyticsHeatLayer) return;
    map.removeLayer(analyticsHeatLayer);
    analyticsHeatLayer = null;
}

export function clearAnalyticsHotspotsLayer() {
    analyticsHotspotsCache = [];
    analyticsSelectedHotspotId = null;
    if (!analyticsHotspotsLayer) return;
    analyticsHotspotsLayer.clearLayers();
}

export function setAnalyticsHotspotsLayer(hotspots = [], selectedId = null) {
    if (!map || !analyticsHotspotsLayer) return;
    analyticsHotspotsCache = Array.isArray(hotspots) ? [...hotspots] : [];
    analyticsSelectedHotspotId = selectedId === null || selectedId === undefined
        ? null
        : String(selectedId);
    renderAnalyticsHotspotsFromCache();
}

export function setSelectedAnalyticsHotspot(id) {
    analyticsSelectedHotspotId = id === null || id === undefined ? null : String(id);
    renderAnalyticsHotspotsFromCache();
}

export function setAnalyticsHeatmapLayer(cells = [], metric = 'opportunity') {
    if (!map || !window.L || !L.heatLayer) return;
    analyticsHeatMetricCache = String(metric || 'opportunity');
    analyticsHeatCellsCache = Array.isArray(cells) ? [...cells] : [];
    renderAnalyticsHeatmapFromCache();
}

export function focusAnalyticsHotspot(hotspot) {
    if (!map || !hotspot) return;

    const mesh = Array.isArray(hotspot?.mesh) ? hotspot.mesh : [];
    const meshBounds = mesh
        .map((point) => [Number(point?.lat), Number(point?.lng)])
        .filter((point) => Number.isFinite(point[0]) && Number.isFinite(point[1]));
    const bboxBounds = boundsFromBBox(hotspot?.extent_bbox);
    let bounds = null;
    if (meshBounds.length >= 3) {
        bounds = meshBounds;
    } else if (bboxBounds) {
        bounds = bboxBounds;
    } else {
        const lat = Number(hotspot.center_lat);
        const lng = Number(hotspot.center_lng);
        const radius = Number(hotspot.radius_m || 0);
        if (!Number.isFinite(lat) || !Number.isFinite(lng) || radius <= 0) return;
        const latDelta = radius / 111_320;
        const lngDelta = radius / (111_320 * Math.max(0.2, Math.cos((lat * Math.PI) / 180)));
        bounds = [
            [lat - latDelta, lng - lngDelta],
            [lat + latDelta, lng + lngDelta],
        ];
    }

    map.fitBounds(bounds, {
        animate: true,
        paddingTopLeft: getHudAutoPanPadding().topLeft,
        paddingBottomRight: getHudAutoPanPadding().bottomRight,
    });
}

function fitBoundsWithHud(bounds) {
    if (!map || !bounds) return;
    map.fitBounds(bounds, {
        animate: true,
        paddingTopLeft: getHudAutoPanPadding().topLeft,
        paddingBottomRight: getHudAutoPanPadding().bottomRight,
    });
}

export function focusReconGeoHypothesis({ points = [], center = null, radius_m = null } = {}) {
    if (!map) return false;

    const coords = [];
    if (Array.isArray(points)) {
        points.forEach((point) => {
            const lat = Number(point?.lat);
            const lng = Number(point?.lng);
            if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;
            coords.push([lat, lng]);
        });
    }

    const centerLat = Number(center?.lat);
    const centerLng = Number(center?.lng);
    const radiusM = Number(radius_m);
    if (coords.length === 0 && Number.isFinite(centerLat) && Number.isFinite(centerLng)) {
        if (Number.isFinite(radiusM) && radiusM > 0) {
            const ring = circlePolygonPoints(centerLat, centerLng, Math.max(40, radiusM), 20);
            ring.forEach((point) => coords.push([point.lat, point.lng]));
        } else {
            coords.push([centerLat, centerLng]);
        }
    }

    if (!coords.length) return false;

    if (coords.length === 1) {
        map.panTo(coords[0], { animate: true });
        return true;
    }

    fitBoundsWithHud(coords);
    return true;
}

export function clearWardriveLayers() {
    if (wardriveRegionLayer) wardriveRegionLayer.clearLayers();
    if (wardriveZonesLayer) wardriveZonesLayer.clearLayers();
    if (wardriveTracksLayer) wardriveTracksLayer.clearLayers();
    if (wardriveReplayMarkerLayer) wardriveReplayMarkerLayer.clearLayers();
}

export function clearClassicMapOverlays() {
    if (zonesLayer) zonesLayer.clearLayers();
    if (toConquerLayer) toConquerLayer.clearLayers();
    if (discoveredLayer) discoveredLayer.clearLayers();
    if (intelligenceLayer) intelligenceLayer.clearLayers();
    if (radarLayer) radarLayer.clearLayers();
    if (heatLayer && map) {
        map.removeLayer(heatLayer);
        heatLayer = null;
    }
    if (STATE.map?.hoverCircle && map) {
        map.removeLayer(STATE.map.hoverCircle);
        STATE.map.hoverCircle = null;
    }
    document.dispatchEvent(new CustomEvent('zonesUpdated', { detail: [] }));
    document.dispatchEvent(new CustomEvent('toConquerZonesUpdated', { detail: [] }));
    document.dispatchEvent(new CustomEvent('discoveredZonesUpdated', { detail: [] }));
    document.dispatchEvent(new CustomEvent('intelligenceZonesUpdated', { detail: [] }));
}

export function __testSetMapState(partial = {}) {
    if (Object.prototype.hasOwnProperty.call(partial, 'analyticsUi')) {
        STATE.analyticsUi = partial.analyticsUi;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'allPositions')) {
        STATE.allPositions = partial.allPositions;
    }
    if (Object.prototype.hasOwnProperty.call(partial, 'modes')) {
        STATE.modes = { ...STATE.modes, ...(partial.modes || {}) };
    }
}

export const __testMapHelpers = {
    haversineMeters,
    getAnalyticsHotspots,
    pointInPolygon,
    getMatchingHotspotForPosition,
    getDeviceTypeLabel,
    isWardriveOnlySource,
    getNormalizedMacSearchValue,
    buildSearchableText,
    maskPassword,
    escapeAttribute,
    boundsFromBBox,
    normalizePolygonRings,
    buildWardriveSessionStyle,
    getWardriveReplayPosition,
    focusWardriveReplayPlayhead,
    focusReconGeoHypothesis,
};

export function renderWardriveRegion(region) {
    if (!wardriveRegionLayer || !window.L) return;
    wardriveRegionLayer.clearLayers();

    const themeColor = getThemeColor();
    const parts = Array.isArray(region?.outline) ? region.outline : [];
    parts.forEach((part) => {
        const rings = normalizePolygonRings(part);
        if (!rings.length) return;
        L.polygon(
            rings.length === 1
                ? rings[0].map((p) => [Number(p.lat), Number(p.lng)])
                : rings.map((ring) => ring.map((p) => [Number(p.lat), Number(p.lng)])),
            {
                color: themeColor,
                fillColor: themeColor,
                fillOpacity: 0,
                weight: 2,
                dashArray: '5, 3',
                opacity: 0.95,
            }
        ).addTo(wardriveRegionLayer);
    });
}

export function renderWardriveZones(zones = [], options = {}) {
    if (!wardriveZonesLayer || !window.L) return;
    wardriveZonesLayer.clearLayers();

    const normalizedZones = Array.isArray(zones) ? [...zones] : [];
    const palette = getWardriveSessionPalette(
        options?.sessionIds || normalizedZones.map((zone) => zone?.session_id),
        options?.activeSessionId || null,
        { comparisonMode: options?.comparisonMode || 'standard' }
    );
    normalizedZones.sort((left, right) => {
        const leftActive = palette[String(left?.session_id || '').trim()]?.isActive ? 1 : 0;
        const rightActive = palette[String(right?.session_id || '').trim()]?.isActive ? 1 : 0;
        return leftActive - rightActive;
    });

    normalizedZones.forEach((zone) => {
        const sessionStyle = palette[String(zone?.session_id || '').trim()];
        const zoneColor = sessionStyle?.zoneColor || sessionStyle?.innerColor || '#00ffd0';
        const zoneOpacity = sessionStyle?.zoneOpacity ?? 0.9;
        const zoneFillOpacity = sessionStyle?.zoneFillOpacity ?? 0.12;
        const zoneWeight = sessionStyle?.zoneWeight ?? 1;
        const zoneDashArray = sessionStyle?.zoneDashArray ?? '3, 4';
        const zoneParts = Array.isArray(zone?.parts) ? zone.parts : [];
        zoneParts.forEach((part) => {
            const rings = normalizePolygonRings(part);
            if (!rings.length) return;
            L.polygon(
                rings.length === 1
                    ? rings[0].map((p) => [Number(p.lat), Number(p.lng)])
                    : rings.map((ring) => ring.map((p) => [Number(p.lat), Number(p.lng)])),
                {
                    color: zoneColor,
                    fillColor: zoneColor,
                    fillOpacity: zoneFillOpacity,
                    opacity: zoneOpacity,
                    weight: zoneWeight,
                    dashArray: zoneDashArray,
                }
            ).addTo(wardriveZonesLayer);
        });
    });

    if (typeof wardriveZonesLayer.bringToFront === 'function') {
        wardriveZonesLayer.bringToFront();
    }
}

export function focusWardriveBBox(bbox) {
    const bounds = boundsFromBBox(bbox);
    if (!bounds) return;
    fitBoundsWithHud(bounds);
}

export function focusWardriveZone(zone) {
    const parts = Array.isArray(zone?.parts) ? zone.parts : [];
    const coords = [];
    parts.forEach((part) => {
        const rings = normalizePolygonRings(part);
        rings.forEach((ring) => {
            ring.forEach((p) => {
                const lat = Number(p?.lat);
                const lng = Number(p?.lng);
                if (Number.isFinite(lat) && Number.isFinite(lng)) {
                    coords.push([lat, lng]);
                }
            });
        });
    });
    if (!coords.length) return;
    fitBoundsWithHud(coords);
}

export function getWardriveSessionPalette(sessionIds = [], activeSessionId = null, options = {}) {
    const orderedIds = Array.from(
        new Set(
            (Array.isArray(sessionIds) ? sessionIds : [])
                .map((item) => String(item || '').trim())
                .filter(Boolean)
        )
    );
    const fallbackActiveId = orderedIds[0] || null;
    const effectiveActiveId = String(activeSessionId || fallbackActiveId || '').trim();
    const theme = getThemeColor();
    const normalizedComparisonMode = String(
        options?.comparisonMode
        || ((orderedIds.length >= 2 && orderedIds.length <= 3) ? 'focus_active' : 'standard')
    ).trim().toLowerCase();
    const comparisonMode = normalizedComparisonMode === 'focus_active' ? 'focus_active' : 'standard';
    const themeLight = lightenHexColor(theme, 0.22);
    const standardRouteAccent = resolveWardriveAccentColor(
        wardrivePaletteConfig.routeAccentColor,
        { fallback: theme, themeColor: theme }
    );
    const standardZoneAccent = resolveWardriveAccentColor(
        wardrivePaletteConfig.primaryZoneAccentColor,
        { fallback: theme, themeColor: theme }
    );
    const secondaryAccent = resolveWardriveAccentColor(
        wardrivePaletteConfig.secondaryAccentColor,
        { fallback: WARDRIVE_COMPARE_SECONDARY_COLOR, themeColor: theme }
    );
    const accents = [
        standardRouteAccent,
        lightenHexColor(standardRouteAccent, 0.2),
        themeLight,
        secondaryAccent,
    ];
    return orderedIds.reduce((palette, sessionId, index) => {
        const isActive = sessionId === effectiveActiveId;
        const trackColor = comparisonMode === 'focus_active'
            ? (isActive ? standardRouteAccent : secondaryAccent)
            : accents[index % accents.length];
        const zoneColor = comparisonMode === 'focus_active'
            ? (isActive ? standardZoneAccent : secondaryAccent)
            : standardZoneAccent;
        palette[sessionId] = {
            sessionId,
            isActive,
            ...buildWardriveSessionStyle(trackColor, zoneColor, isActive, comparisonMode),
        };
        return palette;
    }, {});
}

function getWardriveTrackPalette(index, isActive) {
    const fallback = getWardriveSessionPalette(
        ['fallback', 'inactive-fallback'],
        isActive ? 'fallback' : 'inactive-fallback',
        { comparisonMode: 'focus_active' }
    )[isActive ? 'fallback' : 'inactive-fallback'];
    return {
        ...fallback,
        innerColor: fallback?.innerColor || (isActive ? getThemeColor() : WARDRIVE_COMPARE_SECONDARY_COLOR),
        trackColor: fallback?.trackColor || fallback?.innerColor || (isActive ? getThemeColor() : WARDRIVE_COMPARE_SECONDARY_COLOR),
        zoneColor: fallback?.zoneColor || fallback?.innerColor || (isActive ? getThemeColor() : WARDRIVE_COMPARE_SECONDARY_COLOR),
    };
}

export function renderWardriveSessionTracks(tracks = [], activeSessionId = null) {
    if (!wardriveTracksLayer || !window.L || !L.polyline) return;
    wardriveTracksLayer.clearLayers();

    const normalizedTracks = Array.isArray(tracks) ? tracks : [];
    const palette = getWardriveSessionPalette(
        normalizedTracks.map((track) => track?.session_id),
        activeSessionId,
        {
            comparisonMode: normalizedTracks.length >= 2 && normalizedTracks.length <= 3
                ? 'focus_active'
                : 'standard',
        }
    );

    normalizedTracks.forEach((track, index) => {
        const points = Array.isArray(track?.points) ? track.points : [];
        const coords = points
            .map((point) => [Number(point?.lat), Number(point?.lng)])
            .filter((point) => Number.isFinite(point[0]) && Number.isFinite(point[1]));
        if (coords.length < 2) return;
        const sessionId = String(track?.session_id || '').trim();
        const isActive = sessionId === String(activeSessionId || sessionId || '').trim();
        const style = palette[sessionId] || getWardriveTrackPalette(index, isActive);
        const outerLayer = L.polyline(coords, {
            color: style.outerColor,
            opacity: style.outerOpacity,
            weight: style.outerWeight,
            dashArray: style.dashArray,
            lineCap: 'round',
            lineJoin: 'round',
        });
        outerLayer.addTo(wardriveTracksLayer);

        const innerLayer = L.polyline(coords, {
            color: style.trackColor || style.innerColor,
            opacity: style.innerOpacity,
            weight: style.innerWeight,
            dashArray: style.dashArray,
            lineCap: 'round',
            lineJoin: 'round',
        });
        if (typeof innerLayer.bindTooltip === 'function') {
            innerLayer.bindTooltip(String(track?.label || track?.session_id || 'Track'), {
                direction: 'top',
                className: 'analytics-hotspot-tooltip',
                sticky: true,
            });
        }
        innerLayer.addTo(wardriveTracksLayer);
    });

    if (typeof wardriveTracksLayer.bringToFront === 'function') {
        wardriveTracksLayer.bringToFront();
    }
}


export function setWardriveReplayPlayhead(track = null, progress = 0, options = {}) {
    if (!wardriveReplayMarkerLayer || !window.L) return;
    wardriveReplayMarkerLayer.clearLayers();
    if (!track) return;
    const points = Array.isArray(track?.points) ? track.points : [];
    if (!points.length) return;

    const point = getWardriveReplayPosition(points, progress, options?.segmentWeights || null);
    const lat = Number(point?.lat);
    const lng = Number(point?.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;
    const themeColor = getThemeColor();
    const transportMode = String(track?.transport_mode || '').trim().toLowerCase();
    const iconClass = getWardrivePlayheadIcon(transportMode);
    const markerLabel = String(track?.label || track?.session_id || 'Replay');
    ensureWardriveReplayPlayheadPane();

    if (L.divIcon && L.marker) {
        const icon = L.divIcon({
            className: 'wardrive-replay-playhead-icon-wrap',
            html: `
                <div class="wardrive-replay-playhead-icon" style="--wardrive-replay-color:${escapeHtml(themeColor)};">
                    <i class="fa-solid ${escapeHtml(iconClass)}"></i>
                </div>
            `,
            iconSize: [32, 32],
            iconAnchor: [16, 16],
        });
        const marker = L.marker([lat, lng], {
            icon,
            pane: WARDRIVE_REPLAY_PLAYHEAD_PANE,
            zIndexOffset: WARDRIVE_REPLAY_PLAYHEAD_Z_OFFSET,
        });
        if (typeof marker.setZIndexOffset === 'function') {
            marker.setZIndexOffset(WARDRIVE_REPLAY_PLAYHEAD_Z_OFFSET);
        }
        if (typeof marker.bindTooltip === 'function') {
            marker.bindTooltip(markerLabel, {
                direction: 'top',
                className: 'analytics-hotspot-tooltip',
                sticky: true,
            });
        }
        if (typeof marker.addTo === 'function') {
            marker.addTo(wardriveReplayMarkerLayer);
        } else if (typeof wardriveReplayMarkerLayer.addLayer === 'function') {
            wardriveReplayMarkerLayer.addLayer(marker);
        }
        return;
    }

    if (L.circleMarker) {
        L.circleMarker([lat, lng], {
            radius: 9,
            color: '#ffffff',
            weight: 2,
            fillColor: themeColor,
            fillOpacity: 0.95,
            pane: WARDRIVE_REPLAY_PLAYHEAD_PANE,
        }).addTo(wardriveReplayMarkerLayer);
    }
}

export function focusWardriveReplayPlayhead(track = null, progress = 0, options = {}) {
    if (!map || !track) return;
    const points = Array.isArray(track?.points) ? track.points : [];
    if (!points.length) return;

    const point = getWardriveReplayPosition(points, progress, options?.segmentWeights || null);
    const lat = Number(point?.lat);
    const lng = Number(point?.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;

    const requestedZoom = Number(options?.zoom);
    const currentZoom = Number(map?.getZoom?.());
    const nextZoom = Number.isFinite(requestedZoom)
        ? requestedZoom
        : (Number.isFinite(currentZoom) ? currentZoom : undefined);
    map.setView([lat, lng], nextZoom, { animate: false });
}

export function focusWardriveTrack(track) {
    const bbox = boundsFromBBox(track?.bbox);
    if (bbox) {
        fitBoundsWithHud(bbox);
        return;
    }
    const coords = (Array.isArray(track?.points) ? track.points : [])
        .map((point) => [Number(point?.lat), Number(point?.lng)])
        .filter((point) => Number.isFinite(point[0]) && Number.isFinite(point[1]));
    if (coords.length) fitBoundsWithHud(coords);
}

function handlePopupOpen(pos) {
    STATE.openPopupMac = pos.mac;
    bindPopupActionHandlers(pos);
    
    const vendorSpan = document.getElementById(`vendor-${pos.mac.replace(/:/g, '')}`);
    const vendorAltSpan = document.getElementById(`vendor-alt-${pos.mac.replace(/:/g, '')}`);
    
    if (vendorSpan && vendorSpan.innerText === "Loading...") {
        API.getVendor(pos.mac)
            .then(vData => { if(vendorSpan) vendorSpan.innerText = vData.vendor; })
            .catch(() => { if(vendorSpan) vendorSpan.innerText = "Err"; });

        API.getVendorAlt(pos.mac)
            .then(vData => { if(vendorAltSpan) vendorAltSpan.innerText = vData.vendor; })
            .catch(() => { if(vendorAltSpan) vendorAltSpan.innerText = "Err"; });
    }

    const hasDetails = (pos.handshake_files || []).some(f => f.endsWith('.details'));
    if (hasDetails) {
        const cacheKey = pos.mac;
        if (detailsCache.has(cacheKey)) {
            injectDetailsIntoPopup(pos.mac, detailsCache.get(cacheKey));
        } else {
            const detailsFile = (pos.handshake_files || []).find(f => f.endsWith('.details'));
            API.getFingerprintDetails({ filename: detailsFile })
                .then(data => {
                    detailsCache.set(cacheKey, data);
                    injectDetailsIntoPopup(pos.mac, data);
                })
                .catch(() => {
                    insertRawSummaryFallbackRow(pos);
                });
        }
    }
}

export function updateRadarCircles() {
    radarLayer.clearLayers();
    if (!STATE.modes.radar || STATE.isCrackingActive) return;

    markers.eachLayer(function(layer) {
            if (map.hasLayer(layer) && layer.options.posData) {
                const accColor = getAccuracyColor(layer.options.posData);
                L.circle([layer.options.posData.lat, layer.options.posData.lng], {
                    radius: layer.options.posData.acc || 20,
                    color: accColor,
                    fillColor: accColor,
                    fillOpacity: 0.05,
                    weight: 1,
                    dashArray: '2, 4'
            }).addTo(radarLayer);
        }
    });
}

function injectDetailsIntoPopup(mac, details) {
    if (!details) return;
    const macKey = mac.replace(/:/g, '');
    const rowsContainer = document.getElementById(`data-rows-${macKey}`);
    if (!rowsContainer) return;
    if (rowsContainer.dataset.detailsApplied === "1") return;

    const sec = details.security || {};
    const wps = details.wps || {};
    const cls = details.classification || {};
    const radio = details.radio || {};
    const rates = details.rates || {};
    const phy = details.phy || {};
    const caps = details.capabilities || {};
    const qbss = details.qbss || {};
    const raw = details.raw_sniffer || {};
    const showClass = (cls.confidence || 0) >= 0.6;
    const meta = details.meta || {};
    const securityRowsContainer = document.getElementById(`security-rows-${macKey}`) || rowsContainer;
    const signalRowsContainer = document.getElementById(`signal-rows-${macKey}`) || rowsContainer;
    const rawRowsContainer = document.getElementById(`raw-rows-${macKey}`) || rowsContainer;
    const rawSection = document.getElementById(`raw-section-${macKey}`) || rowsContainer.querySelector('[data-popup-section="raw"]');
    const modernLayout = securityRowsContainer !== rowsContainer
        || signalRowsContainer !== rowsContainer
        || rawRowsContainer !== rowsContainer;

    // Atualiza linha SEC existente
    const secRow = document.getElementById(`sec-row-${macKey}`);
    const akmShort = (sec.akm || [])[0] || "";
    const pairShort = (sec.pairwise_ciphers || [])[0] || "";
    if (secRow) {
        const valSpan = secRow.querySelector('.d-val');
        if (valSpan) {
            valSpan.textContent = '';
            const secChipValues = [sec.wpa_version || "Unknown", akmShort, pairShort].filter(Boolean);
            if (secChipValues.length > 0) {
                secChipValues.forEach((chipValue, idx) => {
                    const chip = document.createElement('span');
                    chip.className = 'sec-chip';
                    chip.textContent = safeText(chipValue);
                    valSpan.appendChild(chip);
                    if (idx < secChipValues.length - 1) {
                        valSpan.appendChild(document.createTextNode(' '));
                    }
                });
            } else {
                valSpan.textContent = safeText(details.security?.group_cipher || "Unknown");
            }
        }
    }

    // remove previous detail rows if any
    Array.from(rowsContainer.querySelectorAll('.detail-row')).forEach((el) => el.remove());

    const makeRowEl = (label, value, rowClass = '', valueClass = '') => {
        const wrap = document.createElement('div');
        wrap.className = 'data-row detail-row';
        if (rowClass) {
            wrap.classList.add(rowClass);
        }
        const labelSpan = document.createElement('span');
        labelSpan.className = 'd-label';
        labelSpan.textContent = safeText(label);

        const valueSpan = document.createElement('span');
        valueSpan.className = 'd-val';
        if (valueClass) {
            valueSpan.classList.add(valueClass);
        }
        valueSpan.textContent = safeText(value);

        wrap.appendChild(labelSpan);
        wrap.appendChild(valueSpan);
        return wrap;
    };

    const securityRowsToAdd = [];
    const signalRowsToAdd = [];
    const rawRowsToAdd = [];

    securityRowsToAdd.push(makeRowEl("PMF", sec.pmf || "Unknown"));
    securityRowsToAdd.push(makeRowEl("WPS", wps.present ? `${(wps.manufacturer || "")} ${(wps.model_name || "")} ${(wps.device_name || "")}`.trim() || "Present" : "Not present"));

    const channelParts = [];
    if (radio.channel !== null && radio.channel !== undefined && radio.channel !== "") {
        channelParts.push(`${radio.channel}`);
    }
    if (radio.band) {
        channelParts.push(`${radio.band}GHz`);
    }
    const channelVal = channelParts.join(" / ");
    if (channelVal) signalRowsToAdd.push(makeRowEl("CHANNEL / BAND", channelVal));

    if (radio.frequency_mhz !== null && radio.frequency_mhz !== undefined && radio.frequency_mhz !== "") {
        signalRowsToAdd.push(makeRowEl("FREQ", `${radio.frequency_mhz} MHz`));
    }

    const signalParts = [];
    if (radio.signal_dbm_avg !== null && radio.signal_dbm_avg !== undefined) {
        signalParts.push(`avg ${radio.signal_dbm_avg} dBm`);
    }
    if (radio.signal_dbm_min !== null && radio.signal_dbm_min !== undefined) {
        signalParts.push(`min ${radio.signal_dbm_min}`);
    }
    if (radio.signal_dbm_max !== null && radio.signal_dbm_max !== undefined) {
        signalParts.push(`max ${radio.signal_dbm_max}`);
    }
    const signalVal = signalParts.join(" | ");
    if (signalVal) signalRowsToAdd.push(makeRowEl("SIGNAL", signalVal));

    const rateBits = [];
    const allRates = (Array.isArray(rates.all) && rates.all.length > 0)
        ? rates.all
        : (rates.supported || []);
    if (allRates.length > 0) rateBits.push(allRates.join(", "));
    if (rates.max_rate_mbps !== null && rates.max_rate_mbps !== undefined) {
        rateBits.push(`max ${rates.max_rate_mbps} Mbps`);
    }
    if (radio.datarate_mbps_avg !== null && radio.datarate_mbps_avg !== undefined) {
        rateBits.push(`tx avg ${radio.datarate_mbps_avg} Mbps`);
    }
    if (radio.datarate_mbps_max !== null && radio.datarate_mbps_max !== undefined) {
        rateBits.push(`tx max ${radio.datarate_mbps_max} Mbps`);
    }
    const ratesVal = rateBits.join(" | ");
    if (ratesVal) securityRowsToAdd.push(makeRowEl("RATES", ratesVal));

    const phyParts = [];
    if (phy.ht_present) {
        phyParts.push(`HT${phy.ht_width_code ? ` w=${phy.ht_width_code}` : ""}`);
    } else if (phy.ht_width_code) {
        phyParts.push(`HT w=${phy.ht_width_code}`);
    }
    if (phy.vht_present) {
        phyParts.push(`VHT${phy.vht_width_code ? ` w=${phy.vht_width_code}` : ""}`);
    } else if (phy.vht_width_code) {
        phyParts.push(`VHT w=${phy.vht_width_code}`);
    }
    const phyVal = phyParts.join(" | ");
    if (phyVal) securityRowsToAdd.push(makeRowEl("PHY", phyVal));

    const capFlags = (caps.flags && caps.flags.length)
        ? caps.flags
        : [
            caps.privacy ? "PRIVACY" : "",
            caps.short_preamble ? "SHORT_PREAMBLE" : "",
            caps.short_slot_time ? "SHORT_SLOT" : "",
            caps.qos ? "QOS" : "",
            caps.spectrum_mgmt ? "SPECTRUM_MGMT" : "",
        ].filter(Boolean);
    if (capFlags.length > 0) securityRowsToAdd.push(makeRowEl("CAPS", capFlags.join(", ")));

    const qbssParts = [];
    if (qbss.station_count !== null && qbss.station_count !== undefined) {
        qbssParts.push(`stations ${qbss.station_count}`);
    }
    if (qbss.channel_utilization !== null && qbss.channel_utilization !== undefined) {
        qbssParts.push(`util ${qbss.channel_utilization}`);
    }
    if (qbss.available_capacity !== null && qbss.available_capacity !== undefined) {
        qbssParts.push(`cap ${qbss.available_capacity}`);
    }
    const qbssVal = qbssParts.join(" | ");
    if (qbssVal) securityRowsToAdd.push(makeRowEl("QBSS", qbssVal));

    if (raw.present) {
        const aggregate = raw.aggregate || {};
        const filesCount = Number(raw.files_count || 0);
        const beaconTotal = Number(aggregate.beacon_count_total || 0);
        const eapolTotal = Number(aggregate.eapol_count_total || 0);
        const probePeak = Number(aggregate.probe_client_count_peak || 0);
        rawRowsToAdd.push(
            makeRowEl(
                "RAW FILES",
                String(filesCount),
                "popup-raw-detail-row",
                "popup-raw-detail-val"
            )
        );
        rawRowsToAdd.push(
            makeRowEl(
                "RAW STATS",
                `b ${beaconTotal} | e ${eapolTotal} | p ${probePeak}`,
                "popup-raw-detail-row",
                "popup-raw-detail-val"
            )
        );
    }

    if (showClass) {
        const tier = cls.tier ? ` | ${cls.tier}` : '';
        securityRowsToAdd.push(
            makeRowEl(
                "DEVICE",
                `${getDeviceTypeLabel(cls.type || "unknown")} (${(cls.confidence || 0).toFixed(2)}${tier})`
            )
        );
    }
    // source/ts omitido a pedido do usuário

    if (modernLayout) {
        securityRowsToAdd.forEach((row) => securityRowsContainer.appendChild(row));
        signalRowsToAdd.forEach((row) => signalRowsContainer.appendChild(row));
        if (rawRowsToAdd.length > 0) {
            revealPopupSection(rawSection);
            rawRowsToAdd.forEach((row) => rawRowsContainer.appendChild(row));
        }
    } else {
        const rowsToAdd = [...securityRowsToAdd, ...signalRowsToAdd, ...rawRowsToAdd];
        const anchorRow = rowsContainer.querySelector('.data-row .vault-btn')?.closest('.data-row');
        if (anchorRow) {
            rowsToAdd.reverse().forEach(r => rowsContainer.insertBefore(r, anchorRow));
        } else {
            rowsToAdd.forEach(r => rowsContainer.appendChild(r));
        }

        const passRow = document.getElementById(`pass-row-${macKey}`);
        if (passRow) {
            rowsContainer.appendChild(passRow);
        }
    }

    rowsContainer.dataset.detailsApplied = "1";
}

// Expose helper for external refresh (e.g., after re-extract)
window.refreshPopupDetails = (mac, details) => {
    const rowsContainer = document.getElementById(`data-rows-${mac.replace(/:/g, '')}`);
    if (rowsContainer) {
        delete rowsContainer.dataset.detailsApplied;
        Array.from(rowsContainer.querySelectorAll('.detail-row')).forEach((el) => el.remove());
    }
    injectDetailsIntoPopup(mac, details);
};

export async function calculateZones(data) {
    zonesLayer.clearLayers();
    if (!STATE.modes.conquered) {
        document.dispatchEvent(new CustomEvent('zonesUpdated', { detail: [] }));
        return;
    }

    const now = Date.now() / 1000;
    const points = [];

    Object.values(data).forEach(pos => {
        if (!pos.pass) return;
        if (!pos.lat || !pos.lng || pos.lat === 0 || pos.lng === 0) return;
        if (STATE.filters.time === '24H' && pos.ts_last < (now - 86400)) return;

        const vendor = pos.vendor || "Loading...";
        const tags = " #cracked";
        const searchable = buildSearchableText(pos, vendor, tags);
        if (STATE.filters.search && !searchable.includes(STATE.filters.search)) return;

        points.push({ lat: pos.lat, lng: pos.lng, acc: pos.acc || 0 });
    });

    if (points.length === 0) {
        document.dispatchEvent(new CustomEvent('zonesUpdated', { detail: [] }));
        return;
    }

    const requestId = ++zonesRequestId;
    try {
        const res = await API.getZones({ points, eps_m: 200, min_samples: 3 });
        if (requestId !== zonesRequestId) return;

    const zones = (res && res.zones) ? res.zones : [];
    let partsCount = 0;
    zones.forEach(zone => {
        if (!zone.parts || zone.parts.length === 0) return;
        zone.parts.forEach((part, pi) => {
            if (!part || part.length < 3) return;
            partsCount++;
            const rings = [part.map(p => [p.lat, p.lng])];
            if (zone.holes && zone.holes[pi]) {
                zone.holes[pi].forEach(h => rings.push(h.map(p => [p.lat, p.lng])));
            }
            L.polygon(rings, {
                color: '#00ff41',
                fillColor: '#00ff41',
                fillOpacity: 0.08,
                weight: 1,
                dashArray: '5, 5'
            }).addTo(zonesLayer);
        });
    });
    log(`Zones: ${zones.length} zones, ${partsCount} parts`, 'info');
        document.dispatchEvent(new CustomEvent('zonesUpdated', { detail: zones }));
    } catch (err) {
        if (requestId !== zonesRequestId) return;
        document.dispatchEvent(new CustomEvent('zonesUpdated', { detail: [] }));
        log(`Zones unavailable: ${err.message || err}`, 'warn');
    }
}

export async function calculateToConquerZones(data) {
    toConquerLayer.clearLayers();
    if (!STATE.modes.toConquer) {
        document.dispatchEvent(new CustomEvent('toConquerZonesUpdated', { detail: [] }));
        return;
    }

    const now = Date.now() / 1000;
    const conqueredPoints = [];
    const toConquerPoints = [];

    Object.values(data).forEach(pos => {
        if (!pos.lat || !pos.lng || pos.lat === 0 || pos.lng === 0) return;
        if (STATE.filters.time === '24H' && pos.ts_last < (now - 86400)) return;

        const vendor = pos.vendor || "Loading...";
        let tags = "";
        if (pos.pass) tags += " #cracked";
        if (!pos.ssid) tags += " #hidden";
        if (pos.encryption === 'OPEN') tags += " #open";
        if (STATE.lists.targets.includes(pos.mac)) tags += " #target";
        if (STATE.lists.favs.includes(pos.mac)) tags += " #fav";

        const searchable = buildSearchableText(pos, vendor, tags);
        if (STATE.filters.search && !searchable.includes(STATE.filters.search)) return;

        const point = { lat: pos.lat, lng: pos.lng, acc: pos.acc || 0 };
        const state = getNormalizedNetworkState(pos);
        if (state === 'cracked') {
            conqueredPoints.push(point);
        } else if (state === 'locked') {
            toConquerPoints.push(point);
        }
    });

    if (toConquerPoints.length === 0) {
        document.dispatchEvent(new CustomEvent('toConquerZonesUpdated', { detail: [] }));
        return;
    }

    const requestId = ++toConquerRequestId;
    try {
        const res = await API.getToConquerZones({
            conquered_points: conqueredPoints,
            to_conquer_points: toConquerPoints,
            eps_m: 200,
            min_samples: 3,
            acc_segments: 8
        });
        if (requestId !== toConquerRequestId) return;

        const zones = (res && res.zones) ? res.zones : [];
        let partsCount = 0;
        zones.forEach(zone => {
            (zone.parts || []).forEach((part, pi) => {
                if (part.length < 3) return;
                partsCount++;
                const rings = [part.map(p => [p.lat, p.lng])];
                if (zone.holes && zone.holes[pi]) {
                    zone.holes[pi].forEach(h => rings.push(h.map(p => [p.lat, p.lng])));
                }
                L.polygon(rings, {
                    color: 'var(--neon-red)',
                    fillColor: 'var(--neon-red)',
                    fillOpacity: 0.08,
                    weight: 1,
                    dashArray: '5, 5'
                }).addTo(toConquerLayer);
            });
        });
        log(`To-conquer: ${zones.length} zones, ${partsCount} parts`, 'info');
        document.dispatchEvent(new CustomEvent('toConquerZonesUpdated', { detail: zones }));
    } catch (err) {
        if (requestId !== toConquerRequestId) return;
        document.dispatchEvent(new CustomEvent('toConquerZonesUpdated', { detail: [] }));
        log(`To-conquer zones unavailable: ${err.message || err}`, 'warn');
    }
}

export async function calculateDiscoveredZones(data) {
    discoveredLayer.clearLayers();
    if (!STATE.modes.discovered) {
        document.dispatchEvent(new CustomEvent('discoveredZonesUpdated', { detail: [] }));
        return;
    }

    const now = Date.now() / 1000;
    const higherPriorityPoints = [];
    const discoveredPoints = [];

    Object.values(data).forEach(pos => {
        if (!pos.lat || !pos.lng || pos.lat === 0 || pos.lng === 0) return;
        if (STATE.filters.time === '24H' && pos.ts_last < (now - 86400)) return;

        const vendor = pos.vendor || "Loading...";
        let tags = "";
        if (pos.pass) tags += " #cracked";
        if (!pos.ssid) tags += " #hidden";
        if (pos.encryption === 'OPEN') tags += " #open";
        if (STATE.lists.targets.includes(pos.mac)) tags += " #target";
        if (STATE.lists.favs.includes(pos.mac)) tags += " #fav";
        const sourceFlags = getSourceFlags(pos?.sources);
        if (sourceFlags.hasWardrive) tags += " #wardrive";

        const searchable = buildSearchableText(pos, vendor, tags);
        if (STATE.filters.search && !searchable.includes(STATE.filters.search)) return;

        const point = { lat: pos.lat, lng: pos.lng, acc: pos.acc || 0 };
        if (pos.pass) {
            higherPriorityPoints.push(point);
            return;
        }
        if (pos.ssid && pos.encryption !== 'OPEN' && pos.encryption !== 'WEP' && !isWardriveOnlySource(sourceFlags)) {
            higherPriorityPoints.push(point);
            return;
        }
        if (isWardriveOnlySource(sourceFlags)) {
            discoveredPoints.push(point);
        }
    });

    if (discoveredPoints.length === 0) {
        document.dispatchEvent(new CustomEvent('discoveredZonesUpdated', { detail: [] }));
        return;
    }

    const requestId = ++discoveredRequestId;
    try {
        const res = await API.getToConquerZones({
            // Reuse the generic subtractive zone route: discovered areas must be
            // cropped by every higher-priority zone (conquered first, then locked).
            conquered_points: higherPriorityPoints,
            to_conquer_points: discoveredPoints,
            eps_m: 200,
            min_samples: DISCOVERED_ZONE_MIN_SAMPLES,
            acc_segments: 8,
            min_zone_points: DISCOVERED_ZONE_MIN_SAMPLES
        });
        if (requestId !== discoveredRequestId) return;

        const zones = (res && res.zones) ? res.zones : [];
        let partsCount = 0;
        zones.forEach(zone => {
            (zone.parts || []).forEach((part, pi) => {
                if (part.length < 3) return;
                partsCount++;
                const rings = [part.map(p => [p.lat, p.lng])];
                if (zone.holes && zone.holes[pi]) {
                    zone.holes[pi].forEach(h => rings.push(h.map(p => [p.lat, p.lng])));
                }
                L.polygon(rings, {
                    color: 'var(--wardrive-color)',
                    fillColor: 'var(--wardrive-color)',
                    fillOpacity: 0.08,
                    weight: 1,
                    dashArray: '5, 5'
                }).addTo(discoveredLayer);
            });
        });
        log(`Discovered zones: ${zones.length} zones, ${partsCount} parts`, 'info');
        document.dispatchEvent(new CustomEvent('discoveredZonesUpdated', { detail: zones }));
    } catch (err) {
        if (requestId !== discoveredRequestId) return;
        document.dispatchEvent(new CustomEvent('discoveredZonesUpdated', { detail: [] }));
        log(`Discovered zones unavailable: ${err.message || err}`, 'warn');
    }
}

export async function calculateIntelligenceZones() {
    if (intelligenceLayer) intelligenceLayer.clearLayers();
    if (!STATE.modes.intelligence) {
        document.dispatchEvent(new CustomEvent('intelligenceZonesUpdated', { detail: [] }));
        return;
    }

    const requestId = ++intelligenceRequestId;
    try {
        const res = await API.getReconCommsColocation();
        if (requestId !== intelligenceRequestId) return;

        const zones = ((res && res.clusters) ? res.clusters : [])
            .map((cluster, idx) => mapColocationClusterToZone(cluster, idx))
            .filter(Boolean);

        let partsCount = 0;
        zones.forEach((zone) => {
            (zone.parts || []).forEach((part, pi) => {
                if (!part || part.length < 3) return;
                partsCount++;
                const rings = [part.map((point) => [point.lat, point.lng])];
                if (zone.holes && zone.holes[pi]) {
                    zone.holes[pi].forEach((hole) => rings.push(hole.map((point) => [point.lat, point.lng])));
                }
                L.polygon(rings, {
                    color: 'var(--neon-purple)',
                    fillColor: 'var(--neon-purple)',
                    fillOpacity: 0.06,
                    weight: 1,
                    dashArray: '3, 6'
                }).addTo(intelligenceLayer);
            });
        });

        log(`Intelligence zones: ${zones.length} zones, ${partsCount} parts`, 'info');
        document.dispatchEvent(new CustomEvent('intelligenceZonesUpdated', { detail: zones }));
    } catch (err) {
        if (requestId !== intelligenceRequestId) return;
        document.dispatchEvent(new CustomEvent('intelligenceZonesUpdated', { detail: [] }));
        log(`Intelligence zones unavailable: ${err.message || err}`, 'warn');
    }
}

// Função para focar e abrir popup de um MAC específico
export function focusAndOpenPopup(mac) {
    let targetLayer = null;
    
    // Procura o marker correspondente
    markers.eachLayer(layer => {
        if (layer.options.posData && layer.options.posData.mac === mac) {
            targetLayer = layer;
        }
    });

    if (targetLayer) {
        // Ativa flag para impedir que o renderMarkers interfira
        STATE.isProgrammaticInteraction = true;
        STATE.openPopupMac = mac;
        
        const visibleParent = markers.getVisibleParent(targetLayer);
        
        // Se o marker já estiver visível (não clusterizado)
        if (visibleParent === targetLayer) {
            // Garante que o marker esteja na área visível (entre painéis)
            map.panInside(targetLayer.getLatLng(), {
                paddingTopLeft: getHudAutoPanPadding().topLeft,
                paddingBottomRight: getHudAutoPanPadding().bottomRight,
                animate: true
            });

            targetLayer.openPopup();
            setTimeout(() => { STATE.isProgrammaticInteraction = false; }, 500);
        } else {
            // Marker está dentro de um cluster
            // zoomToShowLayer cuida de dar zoom e abrir o cluster
            markers.zoomToShowLayer(targetLayer, () => {
                // Callback chamado quando o marker se torna visível
                
                // Garante que o marker esteja na área visível
                map.panInside(targetLayer.getLatLng(), {
                    paddingTopLeft: getHudAutoPanPadding().topLeft,
                    paddingBottomRight: getHudAutoPanPadding().bottomRight,
                    animate: true
                });

                targetLayer.openPopup();
                setTimeout(() => { STATE.isProgrammaticInteraction = false; }, 1000);
            });
        }
    }
}
