export const WARDRIVE_PLAYHEAD_ICON_MAP = {
    walk: 'fa-person-walking',
    bike: 'fa-bicycle',
    motorcycle: 'fa-motorcycle',
    boat: 'fa-ship',
    plane: 'fa-plane',
    helicopter: 'fa-helicopter',
    car: 'fa-car',
    bus: 'fa-bus',
    train: 'fa-train',
    metro: 'fa-subway',
};

export const WARDRIVE_ACCENT_COLORS = {
    teal: '#00ffd0',
    cyan: '#00f3ff',
    purple: '#bc13fe',
    yellow: '#fcee0a',
    green: '#00ff41',
    orange: '#ff8c00',
    pink: '#ff4fd8',
    amber: '#ffd27e',
    red: '#ff5c74',
    white: '#f5fbff',
};

export function haversineMeters(lat1, lng1, lat2, lng2) {
    const toRad = (value) => (value * Math.PI) / 180;
    const earthRadius = 6371000;
    const dLat = toRad(lat2 - lat1);
    const dLng = toRad(lng2 - lng1);
    const a = Math.sin(dLat / 2) ** 2
        + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return earthRadius * c;
}

export function circlePolygonPoints(lat, lng, radiusM, segments = 28) {
    const points = [];
    const safeRadius = Math.max(20, Number(radiusM) || 0);
    const latRad = (lat * Math.PI) / 180;
    const metersPerDegLat = 111320;
    const metersPerDegLng = metersPerDegLat * Math.max(Math.cos(latRad), 0.0001);
    for (let index = 0; index < segments; index++) {
        const angle = (index / segments) * Math.PI * 2;
        const dLat = (Math.sin(angle) * safeRadius) / metersPerDegLat;
        const dLng = (Math.cos(angle) * safeRadius) / metersPerDegLng;
        points.push({ lat: lat + dLat, lng: lng + dLng });
    }
    return points;
}

export function pointInPolygon(lat, lng, polygon) {
    if (!Array.isArray(polygon) || polygon.length < 3) return false;
    let inside = false;
    for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
        const latI = Number(polygon[i]?.lat);
        const lngI = Number(polygon[i]?.lng);
        const latJ = Number(polygon[j]?.lat);
        const lngJ = Number(polygon[j]?.lng);
        if (![latI, lngI, latJ, lngJ].every(Number.isFinite)) continue;
        const intersects = ((latI > lat) !== (latJ > lat))
            && (lng < (((lngJ - lngI) * (lat - latI)) / ((latJ - latI) || Number.EPSILON)) + lngI);
        if (intersects) inside = !inside;
    }
    return inside;
}

export function mapColocationClusterToZone(cluster, idx) {
    const centerLat = Number(cluster?.center?.lat);
    const centerLng = Number(cluster?.center?.lng);
    if (!Number.isFinite(centerLat) || !Number.isFinite(centerLng)) return null;
    const radiusM = Math.max(30, Number(cluster?.radius_m) || 0);
    const parts = Array.isArray(cluster?.parts) && cluster.parts.length > 0
        ? cluster.parts
        : [circlePolygonPoints(centerLat, centerLng, radiusM)];
    const label = String(cluster?.label || 'Cluster').trim();
    return {
        id: 7000 + idx,
        count: Number(cluster?.count) || 0,
        center: { lat: centerLat, lng: centerLng },
        parts,
        holes: Array.isArray(cluster?.holes) ? cluster.holes : undefined,
        points: Array.isArray(cluster?.points) ? cluster.points : parts.flat(),
        zoneLabel: `INTEL-${String(idx + 1).padStart(3, '0')} · ${label}`,
        dominant_encryption: cluster?.dominant_encryption || null,
        radius_m: radiusM,
    };
}

export function getDeviceTypeLabel(deviceType) {
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

export function lightenHexColor(color, amount = 0.18) {
    const raw = String(color || '').trim();
    const normalized = raw.startsWith('#') ? raw.slice(1) : raw;
    if (!/^[\da-fA-F]{6}$/.test(normalized)) return raw || '#00f3ff';

    const clamp = (value) => Math.max(0, Math.min(255, value));
    const mixChannel = (channel) => clamp(Math.round(channel + ((255 - channel) * amount)));
    const r = mixChannel(parseInt(normalized.slice(0, 2), 16));
    const g = mixChannel(parseInt(normalized.slice(2, 4), 16));
    const b = mixChannel(parseInt(normalized.slice(4, 6), 16));
    return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${b.toString(16).padStart(2, '0')}`;
}

export function resolveWardriveAccentColor(choice, {
    fallback = '#00f3ff',
    themeColor = '#00f3ff',
} = {}) {
    const normalized = String(choice || '').trim().toLowerCase();
    if (!normalized || normalized === 'theme') {
        return themeColor;
    }
    return WARDRIVE_ACCENT_COLORS[normalized] || fallback;
}

export function getWardrivePlayheadIcon(transportMode) {
    const key = String(transportMode || '').trim().toLowerCase();
    return WARDRIVE_PLAYHEAD_ICON_MAP[key] || 'fa-route';
}

export function boundsFromBBox(bbox) {
    if (!bbox) return null;
    const minLat = Number(bbox.min_lat);
    const minLng = Number(bbox.min_lng);
    const maxLat = Number(bbox.max_lat);
    const maxLng = Number(bbox.max_lng);
    if (![minLat, minLng, maxLat, maxLng].every((n) => Number.isFinite(n))) return null;
    return [[minLat, minLng], [maxLat, maxLng]];
}

export function normalizePolygonRings(part) {
    if (!Array.isArray(part) || !part.length) return [];
    if (Array.isArray(part[0])) {
        return part.filter((ring) => Array.isArray(ring) && ring.length >= 3);
    }
    return part.length >= 3 ? [part] : [];
}

export function buildWardriveSessionStyle(trackColor, zoneColor, isActive, comparisonMode = 'standard') {
    if (comparisonMode === 'focus_active') {
        return {
            color: trackColor,
            outerColor: 'rgba(2, 10, 14, 0.88)',
            innerColor: trackColor,
            trackColor,
            zoneColor,
            outerOpacity: isActive ? 0.92 : 0.52,
            innerOpacity: isActive ? 0.98 : 0.72,
            outerWeight: isActive ? 8 : 5,
            innerWeight: isActive ? 4 : 2,
            dashArray: isActive ? null : '7, 5',
            zoneOpacity: isActive ? 0.96 : 0.44,
            zoneFillOpacity: isActive ? 0.18 : 0.045,
            zoneWeight: isActive ? 2 : 1,
            zoneDashArray: isActive ? null : '6, 6',
        };
    }

    return {
        color: trackColor,
        outerColor: 'rgba(2, 10, 14, 0.88)',
        innerColor: trackColor,
        trackColor,
        zoneColor,
        outerOpacity: isActive ? 0.9 : 0.65,
        innerOpacity: isActive ? 0.98 : 0.78,
        outerWeight: isActive ? 8 : 5,
        innerWeight: isActive ? 4 : 2,
        dashArray: isActive ? null : '7, 5',
        zoneOpacity: isActive ? 0.95 : 0.68,
        zoneFillOpacity: isActive ? 0.18 : 0.08,
        zoneWeight: isActive ? 2 : 1,
        zoneDashArray: isActive ? null : '5, 5',
    };
}

export function getWardriveReplayPosition(points = [], progress = 0, segmentWeights = null) {
    const validPoints = (Array.isArray(points) ? points : [])
        .map((point) => ({
            lat: Number(point?.lat),
            lng: Number(point?.lng),
            ts_last: Number(point?.ts_last || 0),
        }))
        .filter((point) => Number.isFinite(point.lat) && Number.isFinite(point.lng));

    if (!validPoints.length) return null;
    if (validPoints.length === 1) return validPoints[0];

    const clampedProgress = Math.max(0, Math.min(1, Number(progress || 0)));
    const expectedWeightCount = validPoints.length - 1;
    const providedWeights = Array.isArray(segmentWeights) && segmentWeights.length === expectedWeightCount
        ? segmentWeights
        : null;
    const weights = [];
    let totalWeight = 0;
    for (let index = 0; index < expectedWeightCount; index += 1) {
        const current = validPoints[index];
        const next = validPoints[index + 1];
        const delta = Number(next.ts_last) - Number(current.ts_last);
        const fallbackWeight = Number.isFinite(delta) && delta > 0 ? delta : 1;
        const providedWeight = Number(providedWeights?.[index]);
        const weight = Number.isFinite(providedWeight) && providedWeight > 0 ? providedWeight : fallbackWeight;
        weights.push(weight);
        totalWeight += weight;
    }

    if (totalWeight <= 0) return validPoints[0];
    const target = clampedProgress * totalWeight;
    let traversed = 0;
    for (let index = 0; index < weights.length; index += 1) {
        const weight = weights[index];
        const nextTraversed = traversed + weight;
        if (target <= nextTraversed || index === weights.length - 1) {
            const ratio = weight > 0 ? (target - traversed) / weight : 0;
            const current = validPoints[index];
            const next = validPoints[index + 1];
            return {
                lat: current.lat + ((next.lat - current.lat) * ratio),
                lng: current.lng + ((next.lng - current.lng) * ratio),
                ts_last: current.ts_last + ((next.ts_last - current.ts_last) * ratio),
            };
        }
        traversed = nextTraversed;
    }

    return validPoints[validPoints.length - 1];
}
