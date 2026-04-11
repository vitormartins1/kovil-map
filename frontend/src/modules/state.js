export const STATE = {
    allPositions: [],
    lastDataHash: "",
    isFirstLoad: true,
    openPopupMac: null,
    retryCount: 0,
    isProgrammaticInteraction: false, // Flag para evitar conflitos de eventos
    activeCrackingStatus: {}, // Mapa de arquivos sendo crackeados: { "filename": { status: "STATUS", type: "TYPE" } }
    crackingByMac: {}, // Mapa rápido mac -> { status, type }
    isCrackingActive: false,
    
    filters: {
        time: 'ALL', // 'ALL' or '24H'
        search: ''
    },
    
    modes: {
        radar: false,
        heat: false,
        zones: JSON.parse(localStorage.getItem('pwn_mode_zones') || 'false'),
        conquered: JSON.parse(localStorage.getItem('pwn_mode_conquered') || localStorage.getItem('pwn_mode_zones') || 'false'),
        toConquer: JSON.parse(localStorage.getItem('pwn_mode_to_conquer') || 'false'),
        discovered: JSON.parse(localStorage.getItem('pwn_mode_discovered') || 'false'),
        intelligence: JSON.parse(localStorage.getItem('pwn_mode_intelligence') || 'false'),
        targets: JSON.parse(localStorage.getItem('pwn_mode_targets') || 'false'),
        favs: JSON.parse(localStorage.getItem('pwn_mode_favs') || 'false'),
        wardrive: false,
        
        // Right Panels
        cracking: JSON.parse(localStorage.getItem('pwn_mode_cracking') || 'false'),
        process: JSON.parse(localStorage.getItem('pwn_mode_process') || 'false'),
        logs: JSON.parse(localStorage.getItem('pwn_mode_logs') || 'true'), // Logs default to true
        
        noGps: false, // No-GPS view state (not persisted usually, but could be)
        multi: false,
        raw: false,
        analytics: false
    },
    
    lists: {
        targets: JSON.parse(localStorage.getItem('pwn_targets') || '[]'),
        favs: JSON.parse(localStorage.getItem('pwn_favs') || '[]')
    },
    
    map: {
        hoverCircle: null,
        userLocationMarker: null,
        watchId: null
    },

    ui: {
        hidePasswords: false,
        analyticsWorkspaceActive: false
    },

    multiSelection: [],
    multiFiles: [],
    multiSelectedFile: null,
    multiFileContents: {},
    multiItemStatus: {},
    multiFilter: "all",
    multiUi: {
        search: "",
        status: "all",
        location: "all",
        source: "all",
        artifact: "all"
    },
    multiLastClickedMac: null,

    rawFiles: [],
    rawSelectedFile: null,
    rawSelectedRawItemId: null,
    rawHashes: [],
    rawSelectedHash: null,
    rawMetadataByFile: {},
    rawAnalysisByKey: {},
    rawSelectedNetworkByFile: {},
    rawUi: {
        fileSearch: "",
        fileStatus: "all",
        fileSort: "modified_desc",
        filePage: 1,
        filePageSize: 12,
        networkSearch: "",
        networkSort: "beacon_desc",
        networkPage: 1,
        networkPageSize: 15
    },
    noGpsUi: {
        search: "",
        device: "all",
        status: "all",
        visibility: "all",
        artifact: "all"
    },
    analyticsUi: {
        metric: localStorage.getItem('pwn_analytics_metric') || 'opportunity',
        source: localStorage.getItem('pwn_analytics_source') || 'all',
        security: localStorage.getItem('pwn_analytics_security') || 'all',
        deviceType: localStorage.getItem('pwn_analytics_device_type') || 'all',
        dimension: localStorage.getItem('pwn_analytics_dimension') || 'channel',
        timeWindow: localStorage.getItem('pwn_analytics_time_window') || 'all',
        channel: localStorage.getItem('pwn_analytics_channel') || 'all',
        heatmap: null,
        channelSummary: null,
        hotspots: [],
        selectedHotspotId: null
    },
    reconUi: {
        activeTab: 'attack-surface',
        selectedMac: null
    }
};

export function saveLists() {
    localStorage.setItem('pwn_targets', JSON.stringify(STATE.lists.targets));
    localStorage.setItem('pwn_favs', JSON.stringify(STATE.lists.favs));
}

export function saveModes() {
    localStorage.setItem('pwn_mode_zones', JSON.stringify(STATE.modes.zones));
    localStorage.setItem('pwn_mode_conquered', JSON.stringify(STATE.modes.conquered));
    localStorage.setItem('pwn_mode_to_conquer', JSON.stringify(STATE.modes.toConquer));
    localStorage.setItem('pwn_mode_discovered', JSON.stringify(STATE.modes.discovered));
    localStorage.setItem('pwn_mode_intelligence', JSON.stringify(STATE.modes.intelligence));
    localStorage.setItem('pwn_mode_targets', JSON.stringify(STATE.modes.targets));
    localStorage.setItem('pwn_mode_favs', JSON.stringify(STATE.modes.favs));
    localStorage.setItem('pwn_mode_wardrive', JSON.stringify(false));
    
    // Save Right Panels
    localStorage.setItem('pwn_mode_cracking', JSON.stringify(STATE.modes.cracking));
    localStorage.setItem('pwn_mode_process', JSON.stringify(STATE.modes.process));
    localStorage.setItem('pwn_mode_logs', JSON.stringify(STATE.modes.logs));
}
