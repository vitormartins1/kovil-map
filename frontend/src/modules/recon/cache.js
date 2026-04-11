import { STATE } from '../state.js';
import { API } from '../api.js';
import {
    readSessionStorageJson,
    removeSessionStorageKeysByPrefix,
    writeSessionStorageJson,
} from '../cache_store.js';

const TAB_CACHE_TTL = 300_000;
const RECON_SESSION_CACHE_PREFIX = 'pwn.recon.cache.';
const RECON_SESSION_CACHE_VERSION = 'v2';
const RECON_SESSION_CACHE_MAX_BYTES = 900_000;
const RECON_MANIFEST_SESSION_KEY = `${RECON_SESSION_CACHE_PREFIX}manifest`;
const RECON_MANIFEST_TTL = 30_000;

const tabDataCache = {};
const reconRowCache = {};
const detailDataCache = {};
const reconManifestState = {
    manifest: null,
    scope: '',
    ts: 0,
    promise: null,
};

function fallbackReconScope() {
    const raw = String(STATE.lastDataHash || '');
    if (!raw) {
        return `noscope:${Object.keys(STATE.allPositions || {}).length}`;
    }
    const len = raw.length;
    const middleStart = Math.max(0, Math.floor(len / 2) - 48);
    const sample = `${raw.slice(0, 96)}|${raw.slice(middleStart, middleStart + 96)}|${raw.slice(-96)}`;
    let hash = 2166136261;
    for (let i = 0; i < sample.length; i++) {
        hash ^= sample.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
    }
    return `${RECON_SESSION_CACHE_VERSION}:${len}:${(hash >>> 0).toString(16)}`;
}

function readStoredReconManifest() {
    const parsed = readSessionStorageJson(RECON_MANIFEST_SESSION_KEY);
    if (!parsed || !parsed.manifest || !parsed.manifest.scope) return null;
    return parsed;
}

function writeStoredReconManifest(manifest) {
    writeSessionStorageJson(RECON_MANIFEST_SESSION_KEY, {
        ts: Date.now(),
        manifest,
    });
}

export function getReconCacheScope() {
    return reconManifestState.scope
        || String(readStoredReconManifest()?.manifest?.scope || '').trim()
        || fallbackReconScope();
}

function readSessionReconCache(key) {
    const parsed = readSessionStorageJson(`${RECON_SESSION_CACHE_PREFIX}${key}`);
    if (!parsed || parsed.scope !== getReconCacheScope()) return null;
    const ttl = Number(parsed.ttl || TAB_CACHE_TTL);
    if (Date.now() - Number(parsed.ts || 0) >= ttl) return null;
    return parsed.data ?? null;
}

function writeSessionReconCache(key, data, { ttl = TAB_CACHE_TTL, kind = 'tab' } = {}) {
    writeSessionStorageJson(`${RECON_SESSION_CACHE_PREFIX}${key}`, {
        scope: getReconCacheScope(),
        ts: Date.now(),
        ttl,
        kind,
        data,
    }, { maxBytes: RECON_SESSION_CACHE_MAX_BYTES });
}

export function clearReconPayloadCaches({ clearSession = true, clearManifest = false } = {}) {
    for (const key of Object.keys(tabDataCache)) delete tabDataCache[key];
    for (const key of Object.keys(detailDataCache)) delete detailDataCache[key];
    for (const key of Object.keys(reconRowCache)) delete reconRowCache[key];
    if (clearSession) {
        removeSessionStorageKeysByPrefix(RECON_SESSION_CACHE_PREFIX, {
            except: clearManifest ? [] : [RECON_MANIFEST_SESSION_KEY],
        });
    }
    if (clearManifest) {
        reconManifestState.manifest = null;
        reconManifestState.scope = '';
        reconManifestState.ts = 0;
    }
}

export function applyReconCacheManifest(manifest) {
    const nextScope = String(manifest?.scope || '').trim();
    const previousScope = reconManifestState.scope
        || String(readStoredReconManifest()?.manifest?.scope || '').trim()
        || '';

    reconManifestState.manifest = manifest || null;
    reconManifestState.scope = nextScope;
    reconManifestState.ts = Date.now();

    if (manifest && nextScope) writeStoredReconManifest(manifest);
    if (previousScope && nextScope && previousScope !== nextScope) {
        clearReconPayloadCaches({ clearSession: true, clearManifest: false });
    }
}

export async function ensureReconCacheManifest({ force = false } = {}) {
    const now = Date.now();
    if (!force && reconManifestState.manifest && (now - reconManifestState.ts) < RECON_MANIFEST_TTL) {
        return reconManifestState.manifest;
    }

    if (!force) {
        const stored = readStoredReconManifest();
        if (stored?.manifest?.scope) {
            reconManifestState.manifest = stored.manifest;
            reconManifestState.scope = String(stored.manifest.scope || '');
            reconManifestState.ts = Number(stored.ts || now);
        }
        if (reconManifestState.promise) return reconManifestState.promise;
    }

    reconManifestState.promise = API.getReconCacheManifest()
        .then((manifest) => {
            applyReconCacheManifest(manifest);
            return manifest;
        })
        .catch((error) => {
            if (reconManifestState.manifest) return reconManifestState.manifest;
            throw error;
        })
        .finally(() => {
            reconManifestState.promise = null;
        });
    return reconManifestState.promise;
}

export function getTabCacheEntry(key) {
    const entry = tabDataCache[key];
    if (entry && Date.now() - entry.ts < TAB_CACHE_TTL) return entry.data;
    const sessionData = readSessionReconCache(key);
    if (sessionData != null) {
        tabDataCache[key] = { data: sessionData, ts: Date.now() };
        return sessionData;
    }
    return null;
}

export function setTabCacheEntry(key, data) {
    tabDataCache[key] = { data, ts: Date.now() };
    writeSessionReconCache(key, data, { ttl: TAB_CACHE_TTL, kind: 'tab' });
}

export function clearTabCache(prefix) {
    for (const key of Object.keys(tabDataCache)) {
        if (key.startsWith(prefix)) delete tabDataCache[key];
    }
    removeSessionStorageKeysByPrefix(`${RECON_SESSION_CACHE_PREFIX}${prefix}`);
}

export function getDetailCacheEntry(key) {
    const entry = detailDataCache[key];
    if (entry && Date.now() - entry.ts < TAB_CACHE_TTL) return entry.data;
    const sessionData = readSessionReconCache(`detail:${key}`);
    if (sessionData != null) {
        detailDataCache[key] = { data: sessionData, ts: Date.now() };
        return sessionData;
    }
    return null;
}

export function setDetailCacheEntry(key, data) {
    detailDataCache[key] = { data, ts: Date.now() };
    writeSessionReconCache(`detail:${key}`, data, { ttl: TAB_CACHE_TTL, kind: 'detail' });
}

export function rememberReconRows(rows) {
    for (const row of Array.isArray(rows) ? rows : []) {
        const mac = String(row?.mac || '').trim().toUpperCase();
        if (!mac) continue;
        reconRowCache[mac] = { ...row };
    }
}

export function getCachedReconRow(mac) {
    const key = String(mac || '').trim().toUpperCase();
    return key ? (reconRowCache[key] || null) : null;
}

export function getCachedReconRowsByMacs(macs) {
    return (Array.isArray(macs) ? macs : [])
        .map((mac) => getCachedReconRow(mac))
        .filter(Boolean);
}

export function clearReconRuntimeCache() {
    clearReconPayloadCaches({ clearSession: true, clearManifest: true });
}

export async function primeReconCacheManifest({ force = false } = {}) {
    try {
        return await ensureReconCacheManifest({ force });
    } catch (_) {
        return null;
    }
}

export const __test = {
    applyReconCacheManifest,
    clearReconPayloadCaches,
    getTabCacheEntry,
    setTabCacheEntry,
};
