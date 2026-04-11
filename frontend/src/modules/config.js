export const API_BASE = "http://127.0.0.1:8000";

export const CONFIG = {
    API_BASE,
    URLS: {
        MAP_DATA: `${API_BASE}/api/map/data`,
        SYNC: `${API_BASE}/api/sync`,
        SYNC_TRUST_HOST_KEY: `${API_BASE}/api/sync/trust-host-key`,
        SYNC_PWNAGOTCHI_PROBE: `${API_BASE}/api/sync/pwnagotchi/probe`,
        SYNC_M5EVIL_PROBE: `${API_BASE}/api/sync/m5evil/probe`,
        SYNC_BRUCE_PROBE: `${API_BASE}/api/sync/bruce/probe`,
        VENDOR: `${API_BASE}/api/vendors`,
        STATUS: `${API_BASE}/api/health`
    },
    MAP: {
        DEFAULT_LAT: -23.5505,
        DEFAULT_LNG: -46.6333,
        DEFAULT_ZOOM: 13
    }
};
