const mockState = {
  filters: { time: "ALL" },
  allPositions: {},
  modes: {
    radar: true,
    intelligence: true,
    heat: true,
    zones: true,
    toConquer: true,
    targets: true,
    favs: true,
    wardrive: false,
    cracking: true,
    process: true,
    logs: true,
    noGps: false,
    multi: false,
    raw: false,
    analytics: false,
  },
};

const mockSaveModes = jest.fn();

const mockAPI = {
  getWardriveHierarchy: jest.fn(),
  getWardriveInventory: jest.fn(),
  getWardriveSessions: jest.fn(),
  getWardriveSessionTracks: jest.fn(),
  mergeWardriveSessions: jest.fn(),
  setWardriveSessionTag: jest.fn(),
  getWardriveZones: jest.fn(),
  refreshWardriveRuntime: jest.fn(),
};

function createMapInteractionHandler(initiallyEnabled = true) {
  let enabledState = initiallyEnabled;
  return {
    enabled: jest.fn(() => enabledState),
    disable: jest.fn(() => {
      enabledState = false;
    }),
    enable: jest.fn(() => {
      enabledState = true;
    }),
    __setEnabled(value) {
      enabledState = !!value;
    },
  };
}

const mockReplayMapInstance = {
  getZoom: jest.fn(() => 13),
  dragging: createMapInteractionHandler(true),
  scrollWheelZoom: createMapInteractionHandler(true),
  doubleClickZoom: createMapInteractionHandler(true),
  touchZoom: createMapInteractionHandler(true),
  boxZoom: createMapInteractionHandler(true),
  keyboard: createMapInteractionHandler(true),
};

function buildWardriveSessionPalette(sessionIds = [], activeSessionId = null) {
  const ordered = Array.from(new Set((sessionIds || []).filter(Boolean)));
  const effectiveActive = activeSessionId || ordered[0] || null;
  return ordered.reduce((acc, sessionId, index) => {
    const color = ["#11ffaa", "#ffcc66", "#66c2ff"][index % 3];
    acc[sessionId] = {
      sessionId,
      isActive: sessionId === effectiveActive,
      innerColor: color,
      zoneFillOpacity: sessionId === effectiveActive ? 0.18 : 0.08,
      zoneOpacity: sessionId === effectiveActive ? 0.95 : 0.68,
      zoneWeight: sessionId === effectiveActive ? 2 : 1,
      zoneDashArray: sessionId === effectiveActive ? null : "5, 5",
    };
    return acc;
  }, {});
}

const mockMap = {
  calculateZones: jest.fn(),
  calculateToConquerZones: jest.fn(),
  calculateDiscoveredZones: jest.fn(),
  calculateIntelligenceZones: jest.fn(),
  clearClassicMapOverlays: jest.fn(),
  clearAnalyticsHeatmapLayer: jest.fn(),
  clearAnalyticsHotspotsLayer: jest.fn(),
  clearWardriveLayers: jest.fn(),
  focusWardriveTrack: jest.fn(),
  focusWardriveReplayPlayhead: jest.fn(),
  focusWardriveBBox: jest.fn(),
  focusWardriveZone: jest.fn(),
  getMapInstance: jest.fn(() => mockReplayMapInstance),
  getWardriveSessionPalette: jest.fn((sessionIds = [], activeSessionId = null) =>
    buildWardriveSessionPalette(sessionIds, activeSessionId)
  ),
  renderMarkers: jest.fn(),
  renderWardriveRegion: jest.fn(),
  renderWardriveSessionTracks: jest.fn(),
  renderWardriveZones: jest.fn(),
  setWardriveReplayPlayhead: jest.fn(),
  updateRadarCircles: jest.fn(),
};

const mockAnalytics = {
  setAnalyticsWorkspaceActive: jest.fn(),
};

const mockLog = jest.fn();

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
  saveModes: (...args) => mockSaveModes(...args),
}));

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/map.js", () => ({
  calculateZones: (...args) => mockMap.calculateZones(...args),
  calculateToConquerZones: (...args) => mockMap.calculateToConquerZones(...args),
  calculateDiscoveredZones: (...args) => mockMap.calculateDiscoveredZones(...args),
  calculateIntelligenceZones: (...args) => mockMap.calculateIntelligenceZones(...args),
  clearClassicMapOverlays: (...args) => mockMap.clearClassicMapOverlays(...args),
  clearAnalyticsHeatmapLayer: (...args) => mockMap.clearAnalyticsHeatmapLayer(...args),
  clearAnalyticsHotspotsLayer: (...args) => mockMap.clearAnalyticsHotspotsLayer(...args),
  clearWardriveLayers: (...args) => mockMap.clearWardriveLayers(...args),
  focusWardriveTrack: (...args) => mockMap.focusWardriveTrack(...args),
  focusWardriveReplayPlayhead: (...args) => mockMap.focusWardriveReplayPlayhead(...args),
  focusWardriveBBox: (...args) => mockMap.focusWardriveBBox(...args),
  focusWardriveZone: (...args) => mockMap.focusWardriveZone(...args),
  getMapInstance: (...args) => mockMap.getMapInstance(...args),
  getWardriveSessionPalette: (...args) => mockMap.getWardriveSessionPalette(...args),
  renderMarkers: (...args) => mockMap.renderMarkers(...args),
  renderWardriveRegion: (...args) => mockMap.renderWardriveRegion(...args),
  renderWardriveSessionTracks: (...args) => mockMap.renderWardriveSessionTracks(...args),
  renderWardriveZones: (...args) => mockMap.renderWardriveZones(...args),
  setWardriveReplayPlayhead: (...args) => mockMap.setWardriveReplayPlayhead(...args),
  updateRadarCircles: (...args) => mockMap.updateRadarCircles(...args),
}));

jest.mock("../../src/modules/ui_analytics.js", () => ({
  setAnalyticsWorkspaceActive: (...args) => mockAnalytics.setAnalyticsWorkspaceActive(...args),
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
  escapeHtml: (value) => String(value ?? ""),
}));

function createNode(tag, id) {
  const node = document.createElement(tag);
  if (id) node.id = id;
  document.body.appendChild(node);
  return node;
}

function mountDom() {
  document.body.innerHTML = "";
  createNode("div", "hud-layer");

  [
    "btn-wardrive",
    "btn-map-view",
    "btn-no-gps-view",
    "btn-multi-view",
    "btn-raw-view",
    "btn-analytics-view",
    "btn-zones",
    "btn-conquered",
    "btn-to-conquer",
    "btn-heat",
    "btn-intelligence",
    "btn-targets",
    "btn-favs",
    "btn-toggle-cracking",
    "btn-process",
    "btn-logs",
    "btn-wardrive-refresh",
    "btn-wardrive-tab-workspace",
    "btn-wardrive-tab-inventory",
    "btn-wardrive-pane-regions",
    "btn-wardrive-pane-zones",
    "btn-wardrive-sessions-clear",
    "btn-wardrive-sessions-sort-dir",
  ].forEach((id) => createNode("button", id));

  [
    "no-gps-panel",
    "multi-panel",
    "raw-panel",
    "analytics-panel",
    "wardrive-panel",
    "wardrive-workspace-main",
    "wardrive-workspace-inventory",
    "wardrive-right-sessions-panel",
    "wardrive-route-replay",
    "zones-panel",
    "targets-panel",
    "favorites-panel",
    "cracking-panel",
    "process-panel",
    "log-panel",
  ].forEach((id) => createNode("div", id));

  createNode("div", "wardrive-maps-summary");
  createNode("div", "wardrive-explorer-pane-regions");
  createNode("div", "wardrive-explorer-pane-zones");
  createNode("div", "wardrive-regions-list");
  createNode("div", "wardrive-region-summary");
  createNode("div", "wardrive-zones-summary");
  createNode("div", "wardrive-zones-list");
  createNode("span", "wardrive-zone-count");
  createNode("div", "wardrive-inventory-content");
  createNode("div", "wardrive-sessions-summary");
  createNode("div", "wardrive-sessions-list");
  const sessionsSortBy = createNode("select", "wardrive-sessions-sort-by");
  sessionsSortBy.innerHTML = '<option value="none">NONE</option><option value="date">DATE</option><option value="duration">DURATION</option><option value="distance">DISTANCE</option><option value="nets">NETS</option>';
  sessionsSortBy.value = "none";

  const time = createNode("select", "wardrive-time-window");
  time.innerHTML = '<option value="all">ALL</option><option value="24h">24H</option>';
  time.value = "all";
  const source = createNode("select", "wardrive-source");
  source.innerHTML = '<option value="all">ALL</option><option value="ward">WARD</option><option value="pwn">PWN</option>';
  source.value = "all";
}

function resetState() {
  mockState.filters = { time: "ALL" };
  mockState.allPositions = {};
  mockState.modes = {
    radar: true,
    intelligence: true,
    heat: true,
    zones: true,
    conquered: true,
    toConquer: true,
    targets: true,
    favs: true,
    wardrive: false,
    cracking: true,
    process: true,
    logs: true,
    noGps: false,
    multi: false,
    raw: false,
    analytics: false,
  };
}

function resetMocks() {
  resetState();
  mockSaveModes.mockReset();
  Object.values(mockAPI).forEach((fn) => fn.mockReset());
  Object.values(mockMap).forEach((fn) => {
    if (typeof fn?.mockReset === "function") fn.mockReset();
  });
  mockMap.getMapInstance.mockImplementation(() => mockReplayMapInstance);
  mockMap.getWardriveSessionPalette.mockImplementation((sessionIds = [], activeSessionId = null) =>
    buildWardriveSessionPalette(sessionIds, activeSessionId)
  );
  mockReplayMapInstance.getZoom.mockReset().mockReturnValue(13);
  [
    mockReplayMapInstance.dragging,
    mockReplayMapInstance.scrollWheelZoom,
    mockReplayMapInstance.doubleClickZoom,
    mockReplayMapInstance.touchZoom,
    mockReplayMapInstance.boxZoom,
    mockReplayMapInstance.keyboard,
  ].forEach((handler) => {
    handler.enabled.mockClear();
    handler.disable.mockClear();
    handler.enable.mockClear();
    handler.__setEnabled(true);
  });
  Object.values(mockAnalytics).forEach((fn) => fn.mockReset());
  mockLog.mockReset();

  mockAPI.getWardriveHierarchy.mockResolvedValue({
    maps_summary: {
      loaded_files: 1,
      loaded_datasets: 2,
      regions_count: 1,
      errors: [],
      legacy_ignored: [{ path: "/tmp/legacy" }],
      incompatible_crs: [],
    },
    regions: [
      {
        id: "city:3304557",
        level: "city",
        level_key: "city",
        level_label: "Cidade",
        depth: 2,
        parent_id: null,
        name: "Rio de Janeiro",
        code: "3304557",
        display_path: "Brasil > RJ > Rio de Janeiro",
        lineage: [
          { id: "br:country", name: "Brasil", level_key: "country", level_label: "Pais", depth: 0 },
          { id: "br:state:rj", name: "RJ", level_key: "state", level_label: "Estado", depth: 1 },
          { id: "city:3304557", name: "Rio de Janeiro", level_key: "city", level_label: "Cidade", depth: 2 },
        ],
        bbox: { min_lat: -23, min_lng: -43.5, max_lat: -22.8, max_lng: -43.1 },
        stats: { networks_count: 2, cracked: 0, open: 1, locked: 1 },
      },
    ],
    unmapped_summary: { networks_count: 0, cracked: 0, open: 0, locked: 0 },
  });

  mockAPI.getWardriveZones.mockResolvedValue({
    region: {
      id: "city:3304557",
      level: "city",
      level_key: "city",
      level_label: "Cidade",
      depth: 2,
      name: "Rio de Janeiro",
      display_path: "Brasil > RJ > Rio de Janeiro",
      bbox: { min_lat: -23, min_lng: -43.5, max_lat: -22.8, max_lng: -43.1 },
      outline: [[{ lat: -23, lng: -43.5 }, { lat: -23, lng: -43.1 }, { lat: -22.8, lng: -43.1 }]],
    },
    zones: [
      {
        id: 1,
        count: 2,
        parts: [[{ lat: -22.91, lng: -43.2 }, { lat: -22.91, lng: -43.18 }, { lat: -22.9, lng: -43.19 }]],
      },
    ],
    stats: { networks_count: 2, cracked: 0, open: 1, locked: 1 },
  });

  mockAPI.getWardriveInventory.mockResolvedValue({
    loaded_files: 3,
    supported_files: 3,
    regions_count: 5,
    formats: { geojson: 1, shp: 1, kmz: 1 },
    active_datasets: [
      { country_code: "br", level_label: "Cidade", dataset_id: "city-demo" },
    ],
    coverage_by_level: {
      br: {
        city: { hierarchy_regions_count: 1, regions_count: 1 },
      },
    },
    legacy_ignored: [],
    incompatible_crs: [],
    errors: [],
  });

  mockAPI.getWardriveSessions.mockResolvedValue({
    time_window: "all",
    sessions: [
      {
        session_id: "session-a",
        label: "session-a",
        source_file: "session-a.csv",
        started_at: 1710000000,
        ended_at: 1710000600,
        networks_count: 2,
        points_count: 4,
        distance_m: 650,
        transport_mode: null,
      },
    ],
    summary: {
      sessions_count: 1,
      networks_count: 2,
      points_count: 4,
      transport_modes: [],
      top_transport_modes: [],
    },
  });
  mockAPI.getWardriveSessionTracks.mockResolvedValue({
    tracks: [
      {
        session_id: "session-a",
        label: "session-a",
        source_file: "session-a.csv",
        transport_mode: "car",
        bbox: { min_lat: -22.91, min_lng: -43.2, max_lat: -22.9, max_lng: -43.19 },
        center: { lat: -22.905, lng: -43.195 },
        points: [
          { lat: -22.91, lng: -43.2, ts_last: 1710000000, acc: 8 },
          { lat: -22.905, lng: -43.195, ts_last: 1710000300, acc: 9 },
        ],
        distance_m: 650,
        duration_s: 300,
        points_count: 2,
        avg_accuracy_m: 8.5,
      },
      {
        session_id: "session-b",
        label: "session-b",
        source_file: "session-b.csv",
        transport_mode: "bike",
        bbox: { min_lat: -22.93, min_lng: -43.23, max_lat: -22.91, max_lng: -43.21 },
        center: { lat: -22.92, lng: -43.22 },
        points: [
          { lat: -22.93, lng: -43.23, ts_last: 1710086400, acc: 10 },
          { lat: -22.91, lng: -43.21, ts_last: 1710087000, acc: 11 },
        ],
        distance_m: 920,
        duration_s: 600,
        points_count: 2,
        avg_accuracy_m: 10.5,
      },
      {
        session_id: "session-c",
        label: "session-c",
        source_file: "session-c.csv",
        transport_mode: "walk",
        bbox: null,
        center: null,
        points: [{ lat: -22.95, lng: -43.25, ts_last: 1710100000, acc: 12 }],
        distance_m: 0,
        duration_s: 0,
        points_count: 1,
        avg_accuracy_m: 12,
      },
    ],
    summary: { requested_sessions: 1, returned_tracks: 3 },
  });
  mockAPI.mergeWardriveSessions.mockResolvedValue({
    session: {
      session_id: "merged-20260326-120000",
      label: "merged-20260326-120000",
      source_file: "merged/merged-20260326-120000.csv",
      started_at: 1710000000,
      ended_at: 1710001200,
      networks_count: 3,
      points_count: 8,
      distance_m: 1570,
      session_type: "merged",
      merged_from_session_ids: ["session-a", "session-b"],
      merged_at: 1710001200,
      transport_mode: null,
    },
    summary: {
      sessions_count: 1,
      networks_count: 3,
      points_count: 8,
      transport_modes: [],
      top_transport_modes: [],
    },
    time_window: "all",
  });
  mockAPI.setWardriveSessionTag.mockResolvedValue({
    session: {
      session_id: "session-a",
      label: "session-a",
      source_file: "session-a.csv",
      started_at: 1710000000,
      ended_at: 1710000600,
      networks_count: 2,
      points_count: 4,
      distance_m: 650,
      transport_mode: "car",
    },
    summary: {
      sessions_count: 1,
      networks_count: 2,
      points_count: 4,
      transport_modes: [
        {
          transport_mode: "car",
          sessions_count: 1,
          networks_count: 2,
          points_count: 4,
        },
      ],
      top_transport_modes: [
        {
          transport_mode: "car",
          sessions_count: 1,
          networks_count: 2,
          points_count: 4,
        },
      ],
    },
    time_window: "all",
  });
  mockAPI.refreshWardriveRuntime.mockResolvedValue({
    status: "ok",
    reload_data: true,
    reload_maps: false,
    sessions_count: 1,
    maps_revision: 1,
    data_revision: 1,
  });
}

function loadModule() {
  jest.resetModules();
  return require("../../src/modules/ui_wardrive.js");
}

async function flushAsync() {
  await Promise.resolve();
  await new Promise((resolve) => {
    if (typeof MessageChannel !== "undefined") {
      const channel = new MessageChannel();
      channel.port1.onmessage = () => resolve();
      channel.port2.postMessage(null);
      return;
    }
    Promise.resolve().then(resolve);
  });
  await Promise.resolve();
  await Promise.resolve();
}

function getReplayToggleLabel() {
  return document.querySelector('[data-action="wardrive-replay-toggle"]')?.getAttribute("aria-label") || "";
}

async function settleWardriveUi() {
  await flushAsync();
  await flushAsync();
  await new Promise((resolve) => setTimeout(resolve, 0));
  await flushAsync();
}

describe("ui_wardrive module", () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.confirm = jest.fn(() => true);
    resetMocks();
    mountDom();
  });

  test("activates workspace, takes left/right panels and loads hierarchy/zones", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(mockState.modes.wardrive).toBe(true);
    expect(mockSaveModes).toHaveBeenCalled();
    expect(document.getElementById("btn-map-view").classList.contains("active")).toBe(true);
    expect(document.getElementById("wardrive-panel").style.display).toBe("flex");
    expect(document.getElementById("wardrive-right-sessions-panel").style.display).toBe("flex");
    expect(document.getElementById("zones-panel").style.display).toBe("none");
    expect(document.getElementById("cracking-panel").style.display).toBe("none");
    expect(document.getElementById("btn-zones").disabled).toBe(true);
    expect(document.getElementById("btn-to-conquer").disabled).toBe(true);
    expect(document.getElementById("btn-heat").disabled).toBe(true);
    expect(document.getElementById("btn-intelligence").disabled).toBe(true);
    expect(document.getElementById("btn-toggle-cracking").disabled).toBe(true);
    expect(mockState.modes.toConquer).toBe(false);
    expect(mockState.modes.heat).toBe(false);
    expect(mockState.modes.intelligence).toBe(false);
    expect(mockState.modes.radar).toBe(false);
    expect(mockAPI.getWardriveSessions).toHaveBeenCalledWith({ time_window: "all" });
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalledWith({ time_window: "all", source: "all", session_ids: [] });
    expect(mockAPI.getWardriveSessionTracks).not.toHaveBeenCalled();
    expect(mockAPI.getWardriveInventory).not.toHaveBeenCalled();
    expect(mockAPI.getWardriveZones).toHaveBeenCalledWith(
      expect.objectContaining({ region_id: "city:3304557", eps_m: 200, min_samples: 3, session_ids: [] })
    );
    expect(mockMap.renderWardriveRegion).toHaveBeenCalled();
    expect(mockMap.renderWardriveZones).toHaveBeenCalled();
    expect(mockMap.clearClassicMapOverlays).toHaveBeenCalled();
    expect(mockMap.calculateZones).not.toHaveBeenCalled();
    expect(mockMap.calculateToConquerZones).not.toHaveBeenCalled();
    expect(mockMap.renderMarkers).not.toHaveBeenCalled();
    expect(document.querySelector("#wardrive-region-summary .wardrive-region-summary-top .wardrive-selected-head")?.textContent).toContain("Rio de Janeiro");
    expect(document.querySelector("#wardrive-region-summary .wardrive-region-summary-top .wardrive-selected-head")?.textContent).toContain("Cidade");
    expect(document.getElementById("wardrive-region-summary").textContent).toContain("Brasil > RJ > Rio de Janeiro");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("session-a");
    expect(document.getElementById("wardrive-sessions-summary").textContent).toContain("LOADED");
    expect(document.getElementById("wardrive-sessions-summary").textContent).toContain("NETWORKS");
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("Select 1-3 sessions");
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("ALL DATA");
    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Route Replay"]')).not.toBeNull();
    expect(document.getElementById("btn-wardrive-sessions-clear").disabled).toBe(true);
  });

  test("shows wardrive boot skeleton before heavy map work kicks in", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    document.getElementById("btn-wardrive").click();

    expect(document.getElementById("wardrive-route-replay").textContent).toContain("Preparing workspace");
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("LOADING");
    expect(document.querySelector("#wardrive-route-replay .wardrive-route-replay-loading-grid")).not.toBeNull();
    expect(document.querySelectorAll("#wardrive-route-replay .wardrive-loading-row").length).toBeGreaterThan(0);
    expect(document.querySelectorAll("#wardrive-sessions-list .wardrive-session-skeleton-card").length).toBeGreaterThan(0);
    expect(document.getElementById("wardrive-region-summary").textContent).toContain("Preparing workspace");
    expect(document.getElementById("wardrive-zones-summary").textContent).toContain("Preparing zones");
    expect(mockMap.calculateZones).not.toHaveBeenCalled();
    expect(mockMap.renderMarkers).not.toHaveBeenCalled();
    expect(mockAPI.getWardriveHierarchy).not.toHaveBeenCalled();
    expect(mockAPI.getWardriveSessions).not.toHaveBeenCalled();

    await settleWardriveUi();

    expect(mockMap.clearClassicMapOverlays).toHaveBeenCalled();
    expect(mockMap.calculateZones).not.toHaveBeenCalled();
    expect(mockMap.renderMarkers).not.toHaveBeenCalled();
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalledWith({ time_window: "all", source: "all", session_ids: [] });
    expect(mockAPI.getWardriveSessions).toHaveBeenCalledWith({ time_window: "all" });
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("Select 1-3 sessions");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("session-a");
  });

  test("deactivates workspace and restores previous left/right panel states", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    document.getElementById("btn-wardrive").click();
    await flushAsync();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(mockState.modes.wardrive).toBe(false);
    expect(document.getElementById("wardrive-panel").style.display).toBe("none");
    expect(document.getElementById("zones-panel").style.display).toBe("flex");
    expect(document.getElementById("targets-panel").style.display).toBe("flex");
    expect(document.getElementById("favorites-panel").style.display).toBe("flex");
    expect(document.getElementById("cracking-panel").style.display).toBe("flex");
    expect(document.getElementById("process-panel").style.display).toBe("flex");
    expect(document.getElementById("log-panel").style.display).toBe("block");
    expect(document.getElementById("btn-zones").disabled).toBe(false);
    expect(document.getElementById("btn-to-conquer").disabled).toBe(false);
    expect(document.getElementById("btn-heat").disabled).toBe(false);
    expect(document.getElementById("btn-intelligence").disabled).toBe(false);
    expect(document.getElementById("btn-toggle-cracking").disabled).toBe(false);
    expect(mockMap.clearWardriveLayers).toHaveBeenCalled();
    expect(mockMap.renderMarkers).toHaveBeenCalled();
    expect(mockMap.calculateZones).toHaveBeenCalled();
    expect(mockMap.calculateToConquerZones).toHaveBeenCalled();
    expect(mockMap.calculateIntelligenceZones).toHaveBeenCalled();
    expect(mockState.modes.zones).toBe(true);
    expect(mockState.modes.toConquer).toBe(true);
    expect(mockState.modes.heat).toBe(true);
    expect(mockState.modes.intelligence).toBe(true);
    expect(mockState.modes.radar).toBe(true);
  });

  test("reopens workspace with preserved rendered state", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    document.getElementById("btn-wardrive").click();
    await flushAsync();
    mockAPI.getWardriveSessions.mockClear();
    mockAPI.getWardriveHierarchy.mockClear();
    mockAPI.getWardriveInventory.mockClear();
    mockAPI.getWardriveZones.mockClear();

    document.getElementById("btn-wardrive").click();
    await flushAsync();
    mockAPI.getWardriveSessions.mockClear();
    mockAPI.getWardriveHierarchy.mockClear();
    mockAPI.getWardriveInventory.mockClear();
    mockAPI.getWardriveZones.mockClear();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(mockAPI.getWardriveInventory).not.toHaveBeenCalled();
    expect(document.getElementById("wardrive-regions-list").textContent).toContain("Rio de Janeiro");
  });

  test("regions list supports collapsing hierarchy branches", async () => {
    mockAPI.getWardriveHierarchy.mockResolvedValue({
      maps_summary: {
        loaded_files: 1,
        loaded_datasets: 1,
        regions_count: 4,
        errors: [],
        legacy_ignored: [],
        incompatible_crs: [],
      },
      regions: [
        {
          id: "br:state:rj",
          level: "state",
          level_key: "state",
          level_label: "Estado",
          depth: 1,
          parent_id: null,
          name: "RJ",
          code: "RJ",
          display_path: "Brasil > RJ",
          lineage: [
            { id: "br:country", name: "Brasil", level_key: "country", level_label: "Pais", depth: 0 },
            { id: "br:state:rj", name: "RJ", level_key: "state", level_label: "Estado", depth: 1 },
          ],
          bbox: null,
          stats: { networks_count: 7, cracked: 0, open: 2, locked: 5 },
        },
        {
          id: "city:3304557",
          level: "city",
          level_key: "city",
          level_label: "Cidade",
          depth: 2,
          parent_id: "br:state:rj",
          name: "Rio de Janeiro",
          code: "3304557",
          display_path: "Brasil > RJ > Rio de Janeiro",
          lineage: [
            { id: "br:country", name: "Brasil", level_key: "country", level_label: "Pais", depth: 0 },
            { id: "br:state:rj", name: "RJ", level_key: "state", level_label: "Estado", depth: 1 },
            { id: "city:3304557", name: "Rio de Janeiro", level_key: "city", level_label: "Cidade", depth: 2 },
          ],
          bbox: null,
          stats: { networks_count: 5, cracked: 0, open: 1, locked: 4 },
        },
        {
          id: "neighborhood:copacabana",
          level: "neighborhood",
          level_key: "neighborhood",
          level_label: "Bairro",
          depth: 3,
          parent_id: "city:3304557",
          name: "Copacabana",
          code: "copacabana",
          display_path: "Brasil > RJ > Rio de Janeiro > Copacabana",
          lineage: [
            { id: "br:country", name: "Brasil", level_key: "country", level_label: "Pais", depth: 0 },
            { id: "br:state:rj", name: "RJ", level_key: "state", level_label: "Estado", depth: 1 },
            { id: "city:3304557", name: "Rio de Janeiro", level_key: "city", level_label: "Cidade", depth: 2 },
            { id: "neighborhood:copacabana", name: "Copacabana", level_key: "neighborhood", level_label: "Bairro", depth: 3 },
          ],
          bbox: null,
          stats: { networks_count: 3, cracked: 0, open: 1, locked: 2 },
        },
        {
          id: "city:3303302",
          level: "city",
          level_key: "city",
          level_label: "Cidade",
          depth: 2,
          parent_id: "br:state:rj",
          name: "Niteroi",
          code: "3303302",
          display_path: "Brasil > RJ > Niteroi",
          lineage: [
            { id: "br:country", name: "Brasil", level_key: "country", level_label: "Pais", depth: 0 },
            { id: "br:state:rj", name: "RJ", level_key: "state", level_label: "Estado", depth: 1 },
            { id: "city:3303302", name: "Niteroi", level_key: "city", level_label: "Cidade", depth: 2 },
          ],
          bbox: null,
          stats: { networks_count: 2, cracked: 0, open: 0, locked: 2 },
        },
      ],
      unmapped_summary: { networks_count: 0, cracked: 0, open: 0, locked: 0 },
    });

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const list = document.getElementById("wardrive-regions-list");
    expect(list.textContent).toContain("RJ");
    expect(list.textContent).toContain("Rio de Janeiro");
    expect(list.textContent).toContain("Copacabana");
    expect(list.textContent).toContain("Niteroi");

    const zonesCallsBeforeCollapse = mockAPI.getWardriveZones.mock.calls.length;
    list.querySelector('[data-action="wardrive-region-toggle"][data-region-id="br:state:rj"]').click();
    await flushAsync();

    expect(mockAPI.getWardriveZones.mock.calls.length).toBe(zonesCallsBeforeCollapse);
    expect(
      list.querySelector('[data-action="wardrive-region-toggle"][data-region-id="br:state:rj"]').getAttribute("aria-expanded")
    ).toBe("false");
    expect(list.textContent).toContain("RJ");
    expect(list.textContent).not.toContain("Rio de Janeiro");
    expect(list.textContent).not.toContain("Copacabana");
    expect(list.textContent).not.toContain("Niteroi");

    list.querySelector('[data-action="wardrive-region-toggle"][data-region-id="br:state:rj"]').click();
    await flushAsync();

    expect(
      list.querySelector('[data-action="wardrive-region-toggle"][data-region-id="br:state:rj"]').getAttribute("aria-expanded")
    ).toBe("true");
    expect(list.textContent).toContain("Rio de Janeiro");
    expect(list.textContent).toContain("Copacabana");
    expect(list.textContent).toContain("Niteroi");

    list.querySelector('[data-action="wardrive-region-toggle"][data-region-id="city:3304557"]').click();
    await flushAsync();

    expect(list.textContent).toContain("Rio de Janeiro");
    expect(list.textContent).not.toContain("Copacabana");
    expect(list.textContent).toContain("Niteroi");
  });

  test("workspace explorer keeps region browsing active until zones are opened explicitly", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(document.getElementById("wardrive-region-summary").textContent).toContain("Open 1 zone");

    expect(document.getElementById("btn-wardrive-pane-regions").classList.contains("active")).toBe(true);
    expect(document.getElementById("wardrive-explorer-pane-regions").style.display).toBe("flex");
    expect(document.getElementById("wardrive-explorer-pane-zones").style.display).toBe("none");

    document.querySelector('#wardrive-region-summary [data-action="wardrive-open-zones"]').click();
    expect(document.getElementById("btn-wardrive-pane-zones").classList.contains("active")).toBe(true);
    expect(document.getElementById("wardrive-explorer-pane-zones").style.display).toBe("flex");

    document.getElementById("btn-wardrive-pane-zones").click();
    expect(document.getElementById("btn-wardrive-pane-zones").classList.contains("active")).toBe(true);
    expect(document.getElementById("wardrive-explorer-pane-zones").style.display).toBe("flex");

    document.getElementById("btn-wardrive-pane-regions").click();
    expect(document.getElementById("wardrive-explorer-pane-regions").style.display).toBe("flex");

    document.querySelector('#wardrive-regions-list [data-region-id="city:3304557"]').click();
    expect(document.getElementById("btn-wardrive-pane-regions").classList.contains("active")).toBe(true);
    expect(document.getElementById("btn-wardrive-pane-zones").classList.contains("active")).toBe(false);
    expect(document.getElementById("wardrive-zones-list").textContent).toContain("Loading zones");
    await flushAsync();

    expect(document.getElementById("wardrive-explorer-pane-regions").style.display).toBe("flex");
    expect(document.getElementById("wardrive-explorer-pane-zones").style.display).toBe("none");
    expect(document.getElementById("wardrive-zones-summary").textContent).toContain("Rio de Janeiro");
    expect(document.getElementById("wardrive-zone-count").textContent).toBe("1");
  });

  test("hard refresh button calls refresh endpoint and reloads wardrive data", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    mockAPI.getWardriveSessions.mockClear();
    mockAPI.getWardriveHierarchy.mockClear();
    mockAPI.getWardriveInventory.mockClear();
    mockAPI.getWardriveZones.mockClear();

    document.getElementById("btn-wardrive-refresh").click();
    await flushAsync();

    expect(mockAPI.refreshWardriveRuntime).toHaveBeenCalledWith({ reload_data: true, reload_maps: true });
    expect(mockAPI.getWardriveSessions).toHaveBeenCalled();
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalled();
    expect(mockAPI.getWardriveInventory).toHaveBeenCalled();
    expect(mockAPI.getWardriveZones).toHaveBeenCalled();
  });

  test("refresh listener binds once and still reloads after refresh endpoint errors", async () => {
    mockAPI.refreshWardriveRuntime.mockRejectedValueOnce(new Error("offline"));

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    mockLog.mockClear();
    mockAPI.getWardriveSessions.mockClear();
    mockAPI.getWardriveHierarchy.mockClear();
    mockAPI.getWardriveInventory.mockClear();
    mockAPI.getWardriveZones.mockClear();

    document.getElementById("btn-wardrive-refresh").click();
    await flushAsync();

    expect(mockAPI.refreshWardriveRuntime).toHaveBeenCalledTimes(1);
    expect(mockLog).toHaveBeenCalledWith("WarDrive refresh endpoint unavailable: offline", "warn");
    expect(mockAPI.getWardriveSessions).toHaveBeenCalledTimes(1);
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalledTimes(1);
    expect(mockAPI.getWardriveInventory).toHaveBeenCalledTimes(1);
    expect(mockAPI.getWardriveZones).toHaveBeenCalledTimes(1);
  });

  test("inventory tab loads map inventory on demand", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(mockAPI.getWardriveInventory).not.toHaveBeenCalled();
    document.getElementById("btn-wardrive-tab-inventory").click();
    await flushAsync();

    expect(mockAPI.getWardriveInventory).toHaveBeenCalledTimes(1);
    expect(document.getElementById("wardrive-inventory-content").textContent).toContain("ACTIVE DATASETS");
    expect(document.getElementById("wardrive-workspace-main").style.display).toBe("none");
    expect(document.getElementById("wardrive-workspace-inventory").style.display).toBe("flex");
  });

  test("filter changes refresh hierarchy with selected source/time", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    document.getElementById("wardrive-source").value = "ward";
    document.getElementById("wardrive-source").dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();
    expect(mockAPI.getWardriveHierarchy).toHaveBeenLastCalledWith({ time_window: "all", source: "ward", session_ids: [] });

    document.getElementById("wardrive-time-window").value = "24h";
    document.getElementById("wardrive-time-window").dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();
    expect(mockAPI.getWardriveSessions).toHaveBeenLastCalledWith({ time_window: "24h" });
    expect(mockAPI.getWardriveHierarchy).toHaveBeenLastCalledWith({ time_window: "24h", source: "ward", session_ids: [] });
  });

  test("refreshWardriveIfActive only executes when mode is enabled", async () => {
    const wardrive = loadModule();
    await wardrive.refreshWardriveIfActive(true);
    expect(mockAPI.getWardriveHierarchy).not.toHaveBeenCalled();

    await wardrive.activateWardriveMode();
    await flushAsync();
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalled();

    mockAPI.getWardriveHierarchy.mockClear();
    await wardrive.refreshWardriveIfActive(true);
    await flushAsync();
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalled();
  });

  test("deactivateWardriveMode is a no-op when inactive and restores suspended UI when active", async () => {
    const wardrive = loadModule();

    wardrive.deactivateWardriveMode();
    expect(mockSaveModes).not.toHaveBeenCalled();
    expect(mockMap.clearWardriveLayers).not.toHaveBeenCalled();

    await wardrive.activateWardriveMode();
    await flushAsync();

    mockState.allPositions = {
      full: { mac: "AA:BB:CC:DD:EE:01", lat: -22.9, lng: -43.2 },
    };
    wardrive.__testSetWardriveState({
      selectedSessionIds: ["session-a"],
      activeReplaySessionId: "session-a",
      sessionTracks: [{ session_id: "session-a", points: [] }],
    });
    mockSaveModes.mockClear();
    mockMap.clearWardriveLayers.mockClear();
    mockMap.renderMarkers.mockClear();

    wardrive.deactivateWardriveMode();

    expect(mockState.modes.wardrive).toBe(false);
    expect(document.getElementById("btn-wardrive").classList.contains("active")).toBe(false);
    expect(document.getElementById("wardrive-panel").style.display).toBe("none");
    expect(document.getElementById("wardrive-right-sessions-panel").style.display).toBe("none");
    expect(document.getElementById("zones-panel").style.display).toBe("flex");
    expect(document.getElementById("targets-panel").style.display).toBe("flex");
    expect(document.getElementById("favorites-panel").style.display).toBe("flex");
    expect(document.getElementById("cracking-panel").style.display).toBe("flex");
    expect(document.getElementById("process-panel").style.display).toBe("flex");
    expect(document.getElementById("log-panel").style.display).toBe("block");
    expect(document.getElementById("btn-zones").disabled).toBe(false);
    expect(document.getElementById("btn-to-conquer").disabled).toBe(false);
    expect(document.getElementById("btn-heat").disabled).toBe(false);
    expect(document.getElementById("btn-intelligence").disabled).toBe(false);
    expect(document.getElementById("btn-toggle-cracking").disabled).toBe(false);
    expect(document.getElementById("btn-process").disabled).toBe(false);
    expect(document.getElementById("btn-logs").disabled).toBe(false);
    expect(mockMap.clearWardriveLayers).toHaveBeenCalled();
    expect(wardrive.__testWardriveHelpers.getWardriveFilters().session_ids).toEqual([]);
    expect(mockMap.renderMarkers).toHaveBeenCalledWith(mockState.allPositions, false);
    expect(mockSaveModes).toHaveBeenCalledTimes(1);

    mockAPI.getWardriveHierarchy.mockClear();
    await wardrive.activateWardriveMode();
    await flushAsync();
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalledWith({
      time_window: "all",
      source: "all",
      session_ids: [],
    });
  });

  test("prewarmWardriveWorkspace caches a warm snapshot reused on activation", async () => {
    const wardrive = loadModule();

    await wardrive.prewarmWardriveWorkspace();
    await flushAsync();

    expect(mockAPI.getWardriveSessions).toHaveBeenCalledWith({ time_window: "all" });
    expect(mockAPI.getWardriveHierarchy).toHaveBeenCalledWith({
      time_window: "all",
      source: "all",
      session_ids: [],
    });

    mockAPI.getWardriveSessions.mockClear();
    mockAPI.getWardriveHierarchy.mockClear();
    mockMap.renderWardriveRegion.mockClear();
    mockMap.renderWardriveZones.mockClear();

    await wardrive.activateWardriveMode();
    await flushAsync();

    expect(mockState.modes.wardrive).toBe(true);
    expect(mockAPI.getWardriveSessions).not.toHaveBeenCalled();
    expect(mockAPI.getWardriveHierarchy).not.toHaveBeenCalled();
    expect(document.getElementById("wardrive-regions-list").textContent).toContain("Rio de Janeiro");
    expect(mockMap.renderWardriveRegion).toHaveBeenCalled();
    expect(mockMap.renderWardriveZones).toHaveBeenCalled();

    mockAPI.getWardriveSessions.mockClear();
    mockAPI.getWardriveHierarchy.mockClear();
    await wardrive.prewarmWardriveWorkspace();
    expect(mockAPI.getWardriveSessions).not.toHaveBeenCalled();
    expect(mockAPI.getWardriveHierarchy).not.toHaveBeenCalled();
  });

  test("selecting sessions forces ward source and filters map data", async () => {
    mockState.allPositions = {
      "AA:BB:CC:DD:EE:FF": {
        mac: "AA:BB:CC:DD:EE:FF",
        lat: -22.91,
        lng: -43.2,
        displayLatitude: -22.905,
        displayLongitude: -43.195,
        acc: 9,
        ts_last: 1710000000,
        ssid: "NetOne",
        encryption: "WPA2",
        sources: ["wardrive"],
        wardrive_sessions: [
          {
            session_id: "session-a",
            source_file: "session-a.csv",
            lat: -22.91,
            lng: -43.2,
            rawLatitude: -22.91,
            rawLongitude: -43.2,
            displayLatitude: -22.905,
            displayLongitude: -43.195,
            acc: 7,
            ts_last: 1710000600,
            ssid: "NetOne",
            encryption: "WPA2",
          },
        ],
      },
    };

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const sessionButton = document.querySelector(".wardrive-session-item");
    sessionButton.click();
    await settleWardriveUi();

    expect(document.getElementById("wardrive-source").value).toBe("ward");
    expect(document.getElementById("wardrive-source").disabled).toBe(true);
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("session-a");
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("1 session active");
    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Single-session playback"]')).not.toBeNull();
    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Replay timing modes"]')).not.toBeNull();
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("FOCUS TRACK");
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("MERGE SESSIONS");
    expect(document.querySelectorAll("#wardrive-route-replay .wardrive-session-overview-chip").length).toBe(0);
    expect(document.querySelector('#wardrive-route-replay [data-action="wardrive-replay-track"] .fa-car')).not.toBeNull();
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("DURATION");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("NETS");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("DIST");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("650 m");
    expect(document.getElementById("wardrive-sessions-list").textContent).not.toContain("END");
    expect(document.getElementById("wardrive-sessions-list").textContent).not.toContain("POINTS");
    expect(document.getElementById("wardrive-sessions-list").textContent).not.toContain("NETS/MIN");
    expect(document.getElementById("wardrive-sessions-list").textContent).not.toContain("NETS/H");
    expect(document.getElementById("btn-wardrive-sessions-clear").disabled).toBe(false);
    expect(mockAPI.getWardriveHierarchy).toHaveBeenLastCalledWith({
      time_window: "all",
      source: "ward",
      session_ids: ["session-a"],
    });
    expect(mockAPI.getWardriveSessionTracks).toHaveBeenLastCalledWith(["session-a"]);
    expect(mockMap.renderWardriveSessionTracks).toHaveBeenCalledWith(
      [expect.objectContaining({ session_id: "session-a" })],
      "session-a"
    );
    expect(mockMap.renderWardriveZones).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ session_id: "session-a", session_label: "session-a" }),
      ]),
      expect.objectContaining({
        sessionIds: ["session-a"],
        activeSessionId: "session-a",
      })
    );
    expect(mockMap.setWardriveReplayPlayhead).toHaveBeenCalled();
    expect(mockMap.renderMarkers).toHaveBeenCalledWith(
      expect.objectContaining({
        "AA:BB:CC:DD:EE:FF": expect.objectContaining({
          lat: -22.905,
          lng: -43.195,
          sources: ["wardrive"],
          sessionId: "session-a",
        }),
      }),
      false
    );
  });

  test("selecting a multi-neighborhood session loads zones for the city scope", async () => {
    mockAPI.getWardriveHierarchy.mockResolvedValue({
      maps_summary: {
        loaded_files: 1,
        loaded_datasets: 1,
        regions_count: 4,
        errors: [],
        legacy_ignored: [],
        incompatible_crs: [],
      },
      regions: [
        {
          id: "br:state:rj",
          level_key: "state",
          depth: 1,
          parent_id: null,
          name: "RJ",
          display_path: "Brasil > RJ",
          stats: { networks_count: 730, cracked: 0, open: 80, locked: 650 },
        },
        {
          id: "br:city:rio",
          level_key: "city",
          depth: 2,
          parent_id: "br:state:rj",
          name: "Rio de Janeiro",
          display_path: "Brasil > RJ > Rio de Janeiro",
          stats: { networks_count: 730, cracked: 0, open: 80, locked: 650 },
        },
        {
          id: "br:neighborhood:botafogo",
          level_key: "neighborhood",
          depth: 3,
          parent_id: "br:city:rio",
          name: "Botafogo",
          display_path: "Brasil > RJ > Rio de Janeiro > Botafogo",
          stats: { networks_count: 80, cracked: 0, open: 10, locked: 70 },
        },
        {
          id: "br:neighborhood:flamengo",
          level_key: "neighborhood",
          depth: 3,
          parent_id: "br:city:rio",
          name: "Flamengo",
          display_path: "Brasil > RJ > Rio de Janeiro > Flamengo",
          stats: { networks_count: 650, cracked: 0, open: 70, locked: 580 },
        },
      ],
      unmapped_summary: { networks_count: 0, cracked: 0, open: 0, locked: 0 },
    });

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    mockAPI.getWardriveZones.mockClear();
    mockMap.focusWardriveBBox.mockClear();
    mockMap.focusWardriveTrack.mockClear();
    document.querySelector(".wardrive-session-item").click();
    await settleWardriveUi();

    expect(mockAPI.getWardriveZones).toHaveBeenLastCalledWith(
      expect.objectContaining({
        region_id: "br:city:rio",
        session_ids: ["session-a"],
      }),
    );
    expect(document.getElementById("wardrive-region-summary").textContent).toContain("Rio de Janeiro");
    expect(document.getElementById("wardrive-region-summary").textContent).not.toContain("Flamengo");
    expect(mockMap.focusWardriveBBox).not.toHaveBeenCalled();
    expect(mockMap.focusWardriveTrack).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
    );
  });

  test("selecting a session loads unmapped zones when they dominate the session scope", async () => {
    mockAPI.getWardriveHierarchy.mockResolvedValue({
      maps_summary: {
        loaded_files: 1,
        loaded_datasets: 1,
        regions_count: 3,
        errors: [],
        legacy_ignored: [],
        incompatible_crs: [],
      },
      regions: [
        {
          id: "br:state:rj",
          level_key: "state",
          depth: 1,
          parent_id: null,
          name: "RJ",
          display_path: "Brasil > RJ",
          stats: { networks_count: 45, cracked: 0, open: 5, locked: 40 },
        },
        {
          id: "br:city:rio",
          level_key: "city",
          depth: 2,
          parent_id: "br:state:rj",
          name: "Rio de Janeiro",
          display_path: "Brasil > RJ > Rio de Janeiro",
          stats: { networks_count: 45, cracked: 0, open: 5, locked: 40 },
        },
        {
          id: "br:neighborhood:urca",
          level_key: "neighborhood",
          depth: 3,
          parent_id: "br:city:rio",
          name: "Urca",
          display_path: "Brasil > RJ > Rio de Janeiro > Urca",
          stats: { networks_count: 12, cracked: 0, open: 2, locked: 10 },
        },
      ],
      unmapped_summary: { networks_count: 60, cracked: 0, open: 4, locked: 56 },
    });
    mockAPI.getWardriveZones.mockResolvedValue({
      region: {
        id: "unmapped",
        level_key: "unmapped",
        depth: 999,
        name: "UNMAPPED",
        display_path: "UNMAPPED",
        bbox: { min_lat: -22.96, min_lng: -43.18, max_lat: -22.94, max_lng: -43.15 },
        outline: [],
      },
      zones: [{ id: 1, count: 60, parts: [[{ lat: -22.95, lng: -43.17 }, { lat: -22.95, lng: -43.16 }, { lat: -22.94, lng: -43.16 }]] }],
      stats: { networks_count: 60, cracked: 0, open: 4, locked: 56 },
    });

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    mockAPI.getWardriveZones.mockClear();
    document.querySelector(".wardrive-session-item").click();
    await settleWardriveUi();

    expect(mockAPI.getWardriveZones).toHaveBeenLastCalledWith(
      expect.objectContaining({
        region_id: "unmapped",
        session_ids: ["session-a"],
      }),
    );
    expect(mockMap.renderWardriveZones).toHaveBeenCalledWith(
      expect.arrayContaining([expect.objectContaining({ session_id: "session-a" })]),
      expect.objectContaining({ sessionIds: ["session-a"] }),
    );
  });

  test("session transport tag button saves icon tag without toggling session selection", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    mockAPI.getWardriveHierarchy.mockClear();
    const transportBtn = document.querySelector(".wardrive-session-transport-btn");
    expect(transportBtn).toBeTruthy();
    transportBtn.click();
    await flushAsync();

    const carOption = document.querySelector('.wardrive-session-transport-option[data-mode="car"]');
    expect(carOption).toBeTruthy();
    carOption.click();
    await flushAsync();

    expect(mockAPI.setWardriveSessionTag).toHaveBeenCalledWith("session-a", "car");
    expect(document.getElementById("btn-wardrive-sessions-clear").disabled).toBe(true);
    expect(mockAPI.getWardriveHierarchy).not.toHaveBeenCalled();
    expect(document.getElementById("wardrive-sessions-summary").textContent).not.toContain("TOP VEHICLES");
    const updatedTransportBtn = document.querySelector(".wardrive-session-transport-btn.tagged");
    expect(updatedTransportBtn).toBeTruthy();
  });

  test("route replay compare supports 2-3 sessions and blocks more than 3", async () => {
    const standardZonesPayload = {
      region: {
        id: "city:3304557",
        level: "city",
        level_key: "city",
        level_label: "Cidade",
        depth: 2,
        name: "Rio de Janeiro",
        display_path: "Brasil > RJ > Rio de Janeiro",
        bbox: { min_lat: -23, min_lng: -43.5, max_lat: -22.8, max_lng: -43.1 },
        outline: [[{ lat: -23, lng: -43.5 }, { lat: -23, lng: -43.1 }, { lat: -22.8, lng: -43.1 }]],
      },
      zones: [
        {
          id: 1,
          count: 2,
          parts: [[{ lat: -22.91, lng: -43.2 }, { lat: -22.91, lng: -43.18 }, { lat: -22.9, lng: -43.19 }]],
        },
      ],
      stats: { networks_count: 2, cracked: 0, open: 1, locked: 1 },
    };
    const focusComparisonPayload = {
      ...standardZonesPayload,
      zones: [
        {
          id: 11,
          count: 2,
          session_id: "session-a",
          session_label: "session-a",
          zone_role: "primary",
          parts: [[
            { lat: -22.91, lng: -43.2 },
            { lat: -22.91, lng: -43.18 },
            { lat: -22.9, lng: -43.19 },
          ]],
        },
        {
          id: "secondary:session-a",
          count: 3,
          session_label: "OTHER SELECTED SESSIONS",
          zone_role: "secondary",
          parts: [[
            { lat: -22.93, lng: -43.24 },
            { lat: -22.93, lng: -43.2 },
            { lat: -22.9, lng: -43.22 },
          ]],
        },
      ],
      comparison: {
        mode: "focus_active",
        session_ids: ["session-a", "session-b"],
        active_session_id: "session-a",
        layers_by_active_session: {
          "session-a": {
            primary_zones: [
              {
                id: 11,
                count: 2,
                session_id: "session-a",
                session_label: "session-a",
                zone_role: "primary",
                parts: [[
                  { lat: -22.91, lng: -43.2 },
                  { lat: -22.91, lng: -43.18 },
                  { lat: -22.9, lng: -43.19 },
                ]],
              },
            ],
            secondary_zone: {
              id: "secondary:session-a",
              count: 3,
              session_label: "OTHER SELECTED SESSIONS",
              zone_role: "secondary",
              parts: [[
                { lat: -22.93, lng: -43.24 },
                { lat: -22.93, lng: -43.2 },
                { lat: -22.9, lng: -43.22 },
              ]],
            },
          },
          "session-b": {
            primary_zones: [
              {
                id: 22,
                count: 3,
                session_id: "session-b",
                session_label: "session-b",
                zone_role: "primary",
                parts: [[
                  { lat: -22.93, lng: -43.24 },
                  { lat: -22.93, lng: -43.2 },
                  { lat: -22.9, lng: -43.22 },
                ]],
              },
            ],
            secondary_zone: {
              id: "secondary:session-b",
              count: 2,
              session_label: "OTHER SELECTED SESSIONS",
              zone_role: "secondary",
              parts: [[
                { lat: -22.91, lng: -43.2 },
                { lat: -22.91, lng: -43.18 },
                { lat: -22.9, lng: -43.19 },
              ]],
            },
          },
        },
      },
    };
    mockAPI.getWardriveZones.mockImplementation(async (payload = {}) => (
      payload?.comparison_mode === "focus_active" ? focusComparisonPayload : standardZonesPayload
    ));
    mockAPI.getWardriveSessions.mockResolvedValue({
      time_window: "all",
      sessions: [
        {
          session_id: "session-a",
          label: "session-a",
          source_file: "session-a.csv",
          started_at: 1710000000,
          ended_at: 1710000600,
          networks_count: 2,
          points_count: 4,
        },
        {
          session_id: "session-b",
          label: "session-b",
          source_file: "session-b.csv",
          started_at: 1710086400,
          ended_at: 1710087600,
          networks_count: 5,
          points_count: 5,
        },
        {
          session_id: "session-c",
          label: "session-c",
          source_file: "session-c.csv",
          started_at: 1710100000,
          ended_at: 1710100300,
          networks_count: 1,
          points_count: 1,
        },
        {
          session_id: "session-d",
          label: "session-d",
          source_file: "session-d.csv",
          started_at: 1710110000,
          ended_at: 1710110300,
          networks_count: 1,
          points_count: 1,
        },
      ],
      summary: { sessions_count: 4, networks_count: 9, points_count: 11 },
    });

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const sessions = document.querySelectorAll(".wardrive-session-item");
    sessions[0].click();
    await settleWardriveUi();
    sessions[1].click();
    await settleWardriveUi();

    expect(document.getElementById("wardrive-route-replay").textContent).toContain("2 sessions active");
    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Visual compare across 2 sessions"]')).not.toBeNull();
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("session-a");
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("session-b");
    expect(document.querySelectorAll("#wardrive-route-replay .wardrive-session-overview-chip").length).toBe(0);
    expect(document.querySelector('#wardrive-route-replay [data-session-id="session-a"] .fa-car')).not.toBeNull();
    expect(document.querySelector('#wardrive-route-replay [data-session-id="session-b"] .fa-bicycle')).not.toBeNull();
    expect(mockAPI.getWardriveSessionTracks).toHaveBeenLastCalledWith(["session-a", "session-b"]);
    expect(mockMap.focusWardriveTrack).toHaveBeenLastCalledWith(
      expect.objectContaining({
        session_id: "__selected_wardrive_tracks__",
        bbox: { min_lat: -22.93, min_lng: -43.23, max_lat: -22.9, max_lng: -43.19 },
      }),
    );
    expect(mockAPI.getWardriveZones).toHaveBeenLastCalledWith(
      expect.objectContaining({
        session_ids: ["session-a", "session-b"],
        comparison_mode: "focus_active",
        active_session_id: "session-a",
      })
    );
    expect(mockMap.renderWardriveZones).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ session_id: "session-a", zone_role: "primary" }),
        expect.objectContaining({ zone_role: "secondary" }),
      ]),
      expect.objectContaining({
        sessionIds: ["session-a", "session-b", "__comparison_secondary__"],
        activeSessionId: "session-a",
        comparisonMode: "focus_active",
      })
    );

    const zoneCallCountBeforeSwitch = mockAPI.getWardriveZones.mock.calls.length;
    document.querySelector('[data-action="wardrive-replay-track"][data-session-id="session-b"]').click();
    expect(mockMap.renderWardriveSessionTracks).toHaveBeenLastCalledWith(
      [
        expect.objectContaining({ session_id: "session-a" }),
        expect.objectContaining({ session_id: "session-b" }),
      ],
      "session-b"
    );
    expect(mockAPI.getWardriveZones.mock.calls.length).toBe(zoneCallCountBeforeSwitch);

    sessions[2].click();
    await flushAsync();
    await flushAsync();
    sessions[3].click();
    await flushAsync();

    expect(document.getElementById("wardrive-route-replay").textContent).toContain("supports up to 3 sessions");
    expect(mockAPI.getWardriveZones).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_ids: ["session-a", "session-b", "session-c", "session-d"] })
    );
    expect(mockMap.renderWardriveZones).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({ session_id: "__session_filtered__", session_label: "SELECTED SESSIONS" }),
      ]),
      expect.objectContaining({
        sessionIds: ["__session_filtered__"],
        activeSessionId: "__session_filtered__",
      })
    );
    expect(mockAPI.getWardriveSessionTracks.mock.calls).not.toContainEqual([
      ["session-a", "session-b", "session-c", "session-d"],
    ]);
  });

  test("merge button merges 2 selected sessions and swaps workspace to the merged session", async () => {
    const mergedSessionId = "merged-20260326-120000";
    const standardZonesPayload = {
      region: {
        id: "city:3304557",
        level: "city",
        level_key: "city",
        level_label: "Cidade",
        depth: 2,
        name: "Rio de Janeiro",
        display_path: "Brasil > RJ > Rio de Janeiro",
        bbox: { min_lat: -23, min_lng: -43.5, max_lat: -22.8, max_lng: -43.1 },
        outline: [[{ lat: -23, lng: -43.5 }, { lat: -23, lng: -43.1 }, { lat: -22.8, lng: -43.1 }]],
      },
      zones: [
        {
          id: 31,
          count: 4,
          session_id: mergedSessionId,
          session_label: mergedSessionId,
          parts: [[
            { lat: -22.91, lng: -43.2 },
            { lat: -22.91, lng: -43.18 },
            { lat: -22.9, lng: -43.19 },
          ]],
        },
      ],
      stats: { networks_count: 4, cracked: 0, open: 1, locked: 3 },
    };
    const focusComparisonPayload = {
      ...standardZonesPayload,
      comparison: {
        mode: "focus_active",
        session_ids: ["session-a", "session-b"],
        active_session_id: "session-a",
        layers_by_active_session: {
          "session-a": {
            primary_zones: [
              {
                id: 11,
                count: 2,
                session_id: "session-a",
                session_label: "session-a",
                zone_role: "primary",
                parts: [[
                  { lat: -22.91, lng: -43.2 },
                  { lat: -22.91, lng: -43.18 },
                  { lat: -22.9, lng: -43.19 },
                ]],
              },
            ],
            secondary_zone: {
              id: "secondary:session-a",
              count: 3,
              session_label: "OTHER SELECTED SESSIONS",
              zone_role: "secondary",
              parts: [[
                { lat: -22.93, lng: -43.24 },
                { lat: -22.93, lng: -43.2 },
                { lat: -22.9, lng: -43.22 },
              ]],
            },
          },
          "session-b": {
            primary_zones: [
              {
                id: 22,
                count: 3,
                session_id: "session-b",
                session_label: "session-b",
                zone_role: "primary",
                parts: [[
                  { lat: -22.93, lng: -43.24 },
                  { lat: -22.93, lng: -43.2 },
                  { lat: -22.9, lng: -43.22 },
                ]],
              },
            ],
            secondary_zone: {
              id: "secondary:session-b",
              count: 2,
              session_label: "OTHER SELECTED SESSIONS",
              zone_role: "secondary",
              parts: [[
                { lat: -22.91, lng: -43.2 },
                { lat: -22.91, lng: -43.18 },
                { lat: -22.9, lng: -43.19 },
              ]],
            },
          },
        },
      },
      zones: [],
    };

    mockAPI.getWardriveSessions
      .mockResolvedValueOnce({
        time_window: "all",
        sessions: [
          {
            session_id: "session-a",
            label: "session-a",
            source_file: "session-a.csv",
            started_at: 1710000000,
            ended_at: 1710000600,
            networks_count: 2,
            points_count: 4,
          },
          {
            session_id: "session-b",
            label: "session-b",
            source_file: "session-b.csv",
            started_at: 1710086400,
            ended_at: 1710087600,
            networks_count: 5,
            points_count: 5,
          },
        ],
        summary: { sessions_count: 2, networks_count: 7, points_count: 9 },
      })
      .mockResolvedValue({
        time_window: "all",
        sessions: [
          {
            session_id: mergedSessionId,
            label: mergedSessionId,
            source_file: `${mergedSessionId}.csv`,
            started_at: 1710000000,
            ended_at: 1710087600,
            networks_count: 7,
            points_count: 9,
            distance_m: 1570,
            session_type: "merged",
            merged_from_session_ids: ["session-a", "session-b"],
            merged_at: 1710087600,
          },
        ],
        summary: { sessions_count: 1, networks_count: 7, points_count: 9 },
      });
    mockAPI.getWardriveSessionTracks.mockImplementation(async (sessionIds = []) => {
      if (sessionIds.length === 2) {
        return {
          tracks: [
            {
              session_id: "session-a",
              label: "session-a",
              source_file: "session-a.csv",
              transport_mode: "car",
              bbox: { min_lat: -22.91, min_lng: -43.2, max_lat: -22.9, max_lng: -43.19 },
              center: { lat: -22.905, lng: -43.195 },
              points: [
                { lat: -22.91, lng: -43.2, ts_last: 1710000000, acc: 8 },
                { lat: -22.905, lng: -43.195, ts_last: 1710000300, acc: 9 },
              ],
              distance_m: 650,
              duration_s: 300,
              points_count: 2,
              avg_accuracy_m: 8.5,
            },
            {
              session_id: "session-b",
              label: "session-b",
              source_file: "session-b.csv",
              transport_mode: "bike",
              bbox: { min_lat: -22.93, min_lng: -43.23, max_lat: -22.91, max_lng: -43.21 },
              center: { lat: -22.92, lng: -43.22 },
              points: [
                { lat: -22.93, lng: -43.23, ts_last: 1710086400, acc: 10 },
                { lat: -22.91, lng: -43.21, ts_last: 1710087000, acc: 11 },
              ],
              distance_m: 920,
              duration_s: 600,
              points_count: 2,
              avg_accuracy_m: 10.5,
            },
          ],
          summary: { requested_sessions: 2, returned_tracks: 2 },
        };
      }
      return {
        tracks: [
          {
            session_id: mergedSessionId,
            label: mergedSessionId,
            source_file: `${mergedSessionId}.csv`,
            transport_mode: "car",
            bbox: { min_lat: -22.93, min_lng: -43.23, max_lat: -22.9, max_lng: -43.19 },
            center: { lat: -22.915, lng: -43.205 },
            points: [
              { lat: -22.91, lng: -43.2, ts_last: 1710000000, acc: 8 },
              { lat: -22.91, lng: -43.21, ts_last: 1710087000, acc: 10 },
            ],
            distance_m: 1570,
            duration_s: 900,
            points_count: 2,
            avg_accuracy_m: 9.0,
          },
        ],
        summary: { requested_sessions: 1, returned_tracks: 1 },
      };
    });
    mockAPI.getWardriveZones.mockImplementation(async (payload = {}) => (
      payload?.comparison_mode === "focus_active" ? focusComparisonPayload : standardZonesPayload
    ));

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const sessions = document.querySelectorAll(".wardrive-session-item");
    sessions[0].click();
    await settleWardriveUi();
    sessions[1].click();
    await settleWardriveUi();

    const mergeBtn = document.querySelector('[data-action="wardrive-replay-merge"]');
    expect(mergeBtn.disabled).toBe(false);
    mergeBtn.click();
    await settleWardriveUi();

    expect(window.confirm).toHaveBeenCalled();
    expect(mockAPI.mergeWardriveSessions).toHaveBeenCalledWith(["session-a", "session-b"]);
    expect(mockAPI.getWardriveHierarchy).toHaveBeenLastCalledWith({
      time_window: "all",
      source: "ward",
      session_ids: [mergedSessionId],
    });
    expect(mockAPI.getWardriveSessionTracks).toHaveBeenLastCalledWith([mergedSessionId]);
    expect(document.getElementById("wardrive-route-replay").textContent).toContain(mergedSessionId);
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("1 session active");
    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Single-session playback"]')).not.toBeNull();
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("MERGED");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain(mergedSessionId);
    expect(document.getElementById("wardrive-sessions-list").textContent).not.toContain("session-a");
    expect(document.getElementById("wardrive-sessions-list").textContent).not.toContain("session-b");
  });

  test("route replay controls drive playhead and focus", async () => {
    jest.useFakeTimers();
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    document.querySelector(".wardrive-session-item").click();
    await flushAsync();
    await flushAsync();

    document.querySelector('[data-action="wardrive-replay-focus"]').click();
    expect(mockMap.focusWardriveTrack).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: "session-a" })
    );

    const scrubber = document.querySelector('[data-action="wardrive-replay-scrub"]');
    scrubber.value = "1000";
    scrubber.dispatchEvent(new Event("input", { bubbles: true }));
    expect(mockMap.setWardriveReplayPlayhead).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
      1,
      expect.objectContaining({ segmentWeights: [300] })
    );
    expect(getReplayToggleLabel()).toContain("Replay");

    document.querySelector('[data-action="wardrive-replay-reset"]').click();
    expect(mockMap.setWardriveReplayPlayhead).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
      0,
      expect.objectContaining({ segmentWeights: [300] })
    );
    expect(getReplayToggleLabel()).toContain("Play");

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    expect(getReplayToggleLabel()).toContain("Pause");
    const playheadCallsBeforePause = mockMap.setWardriveReplayPlayhead.mock.calls.length;
    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    expect(getReplayToggleLabel()).toContain("Play");
    jest.advanceTimersByTime(200);
    expect(mockMap.setWardriveReplayPlayhead.mock.calls.length).toBe(playheadCallsBeforePause);

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    expect(getReplayToggleLabel()).toContain("Pause");
    jest.advanceTimersByTime(200);
    document.querySelector('[data-action="wardrive-replay-reset"]').click();
    expect(mockMap.setWardriveReplayPlayhead).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
      0,
      expect.objectContaining({ segmentWeights: [300] })
    );
    expect(getReplayToggleLabel()).toContain("Play");

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    expect(getReplayToggleLabel()).toContain("Pause");
    jest.advanceTimersByTime(3000);
    expect(mockMap.setWardriveReplayPlayhead).toHaveBeenCalled();
    expect(getReplayToggleLabel()).toContain("Replay");
    jest.useRealTimers();
  });

  test("route replay speed control adjusts playback timing", async () => {
    jest.useFakeTimers();
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    document.querySelector(".wardrive-session-item").click();
    await flushAsync();
    await flushAsync();

    const speedSelect = document.querySelector('[data-action="wardrive-replay-speed"]');
    expect(speedSelect.value).toBe("1");

    speedSelect.value = "0.5";
    speedSelect.dispatchEvent(new Event("change", { bubbles: true }));
    expect(document.querySelector('[data-action="wardrive-replay-speed"]').value).toBe("0.5");
    expect(speedSelect.textContent).toContain("Very Slow");

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    jest.advanceTimersByTime(800);
    expect(getReplayToggleLabel()).toContain("Pause");

    const fasterSelect = document.querySelector('[data-action="wardrive-replay-speed"]');
    fasterSelect.value = "8";
    fasterSelect.dispatchEvent(new Event("change", { bubbles: true }));
    jest.advanceTimersByTime(1200);
    expect(getReplayToggleLabel()).toContain("Replay");
    jest.useRealTimers();
  });

  test("applies wardrive config defaults for replay controls and session sort", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    window.dispatchEvent(new CustomEvent("kovil:config-applied", {
      detail: {
        config: {
          ui_wardrive_replay_speed_default: "0.1",
          ui_wardrive_replay_follow_camera_default: true,
          ui_wardrive_replay_follow_zoom_default: "19",
          ui_wardrive_replay_timing_mode_default: "compress_idle",
          ui_wardrive_sessions_sort_by: "distance",
          ui_wardrive_sessions_sort_direction: "asc",
        },
      },
    }));

    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(document.getElementById("wardrive-sessions-sort-by").value).toBe("distance");
    expect(document.getElementById("btn-wardrive-sessions-sort-dir").textContent).toContain("ASC");

    document.querySelector(".wardrive-session-item").click();
    await flushAsync();
    await flushAsync();

    expect(document.querySelector('[data-action="wardrive-replay-speed"]').value).toBe("0.1");
    expect(document.querySelector('[data-action="wardrive-replay-follow-camera"]').classList.contains("active")).toBe(true);
    expect(document.querySelector('[data-action="wardrive-replay-follow-zoom"]').value).toBe("19");
    expect(document.querySelector('[data-action="wardrive-replay-timing-mode"]').value).toBe("compress_idle");
    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Replay timing modes"]')).not.toBeNull();
  });

  test("route replay follow camera locks map controls only while playback is active", async () => {
    jest.useFakeTimers();
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    document.querySelector(".wardrive-session-item").click();
    await flushAsync();
    await flushAsync();

    const followBtn = document.querySelector('[data-action="wardrive-replay-follow-camera"]');
    followBtn.click();
    expect(followBtn.classList.contains("active")).toBe(true);
    expect(mockReplayMapInstance.dragging.disable).not.toHaveBeenCalled();

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    expect(mockReplayMapInstance.dragging.disable).toHaveBeenCalled();
    expect(mockReplayMapInstance.scrollWheelZoom.disable).toHaveBeenCalled();
    jest.advanceTimersByTime(80);
    expect(mockMap.focusWardriveReplayPlayhead).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
      expect.any(Number),
      expect.objectContaining({ zoom: 13, segmentWeights: [300] })
    );

    const focusCallsWhilePlaying = mockMap.focusWardriveReplayPlayhead.mock.calls.length;
    document.querySelector('[data-action="wardrive-replay-scrub"]').value = "500";
    document
      .querySelector('[data-action="wardrive-replay-scrub"]')
      .dispatchEvent(new Event("input", { bubbles: true }));
    expect(mockMap.focusWardriveReplayPlayhead.mock.calls.length).toBeGreaterThanOrEqual(focusCallsWhilePlaying);

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    expect(mockReplayMapInstance.dragging.enable).toHaveBeenCalled();
    expect(mockReplayMapInstance.scrollWheelZoom.enable).toHaveBeenCalled();
    const focusCallsBeforePausedScrub = mockMap.focusWardriveReplayPlayhead.mock.calls.length;

    document.querySelector('[data-action="wardrive-replay-scrub"]').value = "750";
    document
      .querySelector('[data-action="wardrive-replay-scrub"]')
      .dispatchEvent(new Event("input", { bubbles: true }));
    expect(mockMap.focusWardriveReplayPlayhead.mock.calls.length).toBe(focusCallsBeforePausedScrub);

    jest.useRealTimers();
  });

  test("route replay follow zoom and timing mode can be changed live", async () => {
    jest.useFakeTimers();
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    document.querySelector(".wardrive-session-item").click();
    await flushAsync();
    await flushAsync();

    document.querySelector('[data-action="wardrive-replay-follow-camera"]').click();
    const zoomSelect = document.querySelector('[data-action="wardrive-replay-follow-zoom"]');
    const modeSelect = document.querySelector('[data-action="wardrive-replay-timing-mode"]');
    const speedSelect = document.querySelector('[data-action="wardrive-replay-speed"]');

    zoomSelect.value = "19";
    zoomSelect.dispatchEvent(new Event("change", { bubbles: true }));
    modeSelect.value = "uniform_path";
    modeSelect.dispatchEvent(new Event("change", { bubbles: true }));
    speedSelect.value = "0.05";
    speedSelect.dispatchEvent(new Event("change", { bubbles: true }));

    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Replay timing modes"]')).not.toBeNull();
    expect(speedSelect.selectedOptions[0].textContent).toContain("Very Slow");

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    jest.advanceTimersByTime(80);

    expect(mockMap.focusWardriveReplayPlayhead).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
      expect.any(Number),
      expect.objectContaining({ zoom: 19, segmentWeights: [expect.any(Number)] })
    );
    expect(mockMap.setWardriveReplayPlayhead).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
      expect.any(Number),
      expect.objectContaining({ segmentWeights: [expect.any(Number)] })
    );

    document.querySelector('[data-action="wardrive-replay-reset"]').click();
    expect(mockReplayMapInstance.dragging.enable).toHaveBeenCalled();
    jest.useRealTimers();
  });

  test("route replay follow camera tracks only the active route in compare mode", async () => {
    jest.useFakeTimers();
    mockAPI.getWardriveSessions.mockResolvedValueOnce({
      time_window: "all",
      sessions: [
        {
          session_id: "session-a",
          label: "session-a",
          source_file: "session-a.csv",
          started_at: 1710000000,
          ended_at: 1710000600,
          networks_count: 2,
          points_count: 4,
          distance_m: 650,
          transport_mode: "car",
        },
        {
          session_id: "session-b",
          label: "session-b",
          source_file: "session-b.csv",
          started_at: 1710086400,
          ended_at: 1710087000,
          networks_count: 3,
          points_count: 4,
          distance_m: 920,
          transport_mode: "bike",
        },
      ],
      summary: { sessions_count: 2, networks_count: 5, points_count: 8, transport_modes: [], top_transport_modes: [] },
    });

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const sessionItems = document.querySelectorAll(".wardrive-session-item");
    sessionItems[0].click();
    await flushAsync();
    await flushAsync();
    sessionItems[1].click();
    await flushAsync();
    await flushAsync();

    document.querySelector('[data-action="wardrive-replay-follow-camera"]').click();
    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    jest.advanceTimersByTime(80);
    expect(mockMap.focusWardriveReplayPlayhead).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_id: "session-a" }),
      expect.any(Number),
      expect.objectContaining({ segmentWeights: [300] })
    );

    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    const secondTrackPill = Array.from(document.querySelectorAll('[data-action="wardrive-replay-track"]'))
      .find((node) => node.getAttribute("data-session-id") === "session-b");
    secondTrackPill.click();
    document.querySelector('[data-action="wardrive-replay-toggle"]').click();
    jest.advanceTimersByTime(80);

    expect(mockMap.focusWardriveReplayPlayhead).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_id: "session-b" }),
      expect.any(Number),
      expect.objectContaining({ segmentWeights: [600] })
    );
    jest.useRealTimers();
  });

  test("track switch can auto-focus and autoplay from config", async () => {
    jest.useFakeTimers();
    mockAPI.getWardriveSessions.mockResolvedValueOnce({
      time_window: "all",
      sessions: [
        {
          session_id: "session-a",
          label: "session-a",
          source_file: "session-a.csv",
          started_at: 1710000000,
          ended_at: 1710000600,
          networks_count: 2,
          points_count: 4,
          distance_m: 650,
          transport_mode: null,
        },
        {
          session_id: "session-b",
          label: "session-b",
          source_file: "session-b.csv",
          started_at: 1710086400,
          ended_at: 1710087000,
          networks_count: 3,
          points_count: 4,
          distance_m: 920,
          transport_mode: "bike",
        },
      ],
      summary: { sessions_count: 2, networks_count: 5, points_count: 8, transport_modes: [], top_transport_modes: [] },
    });
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    window.dispatchEvent(new CustomEvent("kovil:config-applied", {
      detail: {
        config: {
          ui_wardrive_replay_autoplay: true,
          ui_wardrive_replay_auto_focus: true,
        },
      },
    }));

    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const sessionItems = document.querySelectorAll(".wardrive-session-item");
    sessionItems[0].click();
    await flushAsync();
    sessionItems[1].click();
    await flushAsync();
    await flushAsync();

    const secondTrackPill = Array.from(document.querySelectorAll('[data-action="wardrive-replay-track"]'))
      .find((node) => node.getAttribute("data-session-id") === "session-b");
    secondTrackPill.click();

    expect(mockMap.focusWardriveTrack).toHaveBeenLastCalledWith(
      expect.objectContaining({ session_id: "session-b" })
    );
    expect(getReplayToggleLabel()).toContain("Pause");
    jest.useRealTimers();
  });

  test("transport popovers stay open for session-head clicks", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const transportBtn = document.querySelector(".wardrive-session-transport-btn");
    transportBtn.click();
    await flushAsync();

    const popover = document.querySelector(".wardrive-session-transport-popover");
    expect(popover.classList.contains("is-open")).toBe(true);

    document.querySelector(".wardrive-session-head").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(popover.classList.contains("is-open")).toBe(true);
  });

  test("openWardriveFromAnalytics activates inactive workspace and switches active workspace back to main tab", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    document.dispatchEvent(new CustomEvent("openWardriveFromAnalytics"));
    await flushAsync();

    expect(mockState.modes.wardrive).toBe(true);
    expect(document.getElementById("wardrive-workspace-main").style.display).toBe("flex");

    document.getElementById("btn-wardrive-tab-inventory").click();
    await flushAsync();
    expect(document.getElementById("wardrive-workspace-inventory").style.display).toBe("flex");

    const sessionsCallsBefore = mockAPI.getWardriveSessions.mock.calls.length;
    document.dispatchEvent(new CustomEvent("openWardriveFromAnalytics"));
    await flushAsync();

    expect(document.getElementById("wardrive-workspace-main").style.display).toBe("flex");
    expect(document.getElementById("wardrive-workspace-inventory").style.display).toBe("none");
    expect(mockAPI.getWardriveSessions.mock.calls.length).toBe(sessionsCallsBefore);
  });

  test("sessions panel supports sorting with asc/desc", async () => {
    mockAPI.getWardriveSessions.mockResolvedValue({
      time_window: "all",
      sessions: [
        {
          session_id: "session-a",
          label: "session-a",
          source_file: "20260316_a.csv",
          started_at: 1710000000,
          ended_at: 1710000600,
          networks_count: 8,
          points_count: 8,
          distance_m: 1400,
        },
        {
          session_id: "session-b",
          label: "session-b",
          source_file: "20260317_b.csv",
          started_at: 1710086400,
          ended_at: 1710093600,
          networks_count: 55,
          points_count: 55,
          distance_m: 500,
        },
      ],
      summary: { sessions_count: 2, networks_count: 63, points_count: 63 },
    });

    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("20260316_a");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("20260317_b");
    expect(document.getElementById("btn-wardrive-sessions-sort-dir").textContent).toContain("DESC");

    document.getElementById("wardrive-sessions-sort-by").value = "duration";
    document.getElementById("wardrive-sessions-sort-by").dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();

    const firstSortedByDuration = document.querySelector("#wardrive-sessions-list .wardrive-session-item .wardrive-session-title");
    expect(firstSortedByDuration.textContent).toContain("20260317_b");
    expect(document.getElementById("wardrive-sessions-summary").textContent).not.toContain("SORT");

    document.getElementById("btn-wardrive-sessions-sort-dir").click();
    await flushAsync();
    expect(document.getElementById("btn-wardrive-sessions-sort-dir").textContent).toContain("ASC");
    const firstSortedAsc = document.querySelector("#wardrive-sessions-list .wardrive-session-item .wardrive-session-title");
    expect(firstSortedAsc.textContent).toContain("20260316_a");

    document.getElementById("wardrive-sessions-sort-by").value = "nets";
    document.getElementById("wardrive-sessions-sort-by").dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();
    const firstSortedByNetsAsc = document.querySelector("#wardrive-sessions-list .wardrive-session-item .wardrive-session-title");
    expect(firstSortedByNetsAsc.textContent).toContain("20260316_a");

    document.getElementById("wardrive-sessions-sort-by").value = "distance";
    document.getElementById("wardrive-sessions-sort-by").dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();
    const firstSortedByDistanceAsc = document.querySelector("#wardrive-sessions-list .wardrive-session-item .wardrive-session-title");
    expect(firstSortedByDistanceAsc.textContent).toContain("20260317_b");

    document.getElementById("btn-wardrive-sessions-sort-dir").click();
    await flushAsync();
    const firstSortedByDistanceDesc = document.querySelector("#wardrive-sessions-list .wardrive-session-item .wardrive-session-title");
    expect(document.getElementById("wardrive-sessions-list").textContent).toContain("20260317_b");
    expect(firstSortedByDistanceDesc.textContent).toContain("20260316_a");
    expect(document.getElementById("wardrive-sessions-summary").textContent).not.toContain("SORT");
  });

  test("persists wardrive sessions sort preferences across module reloads", async () => {
    let wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    document.getElementById("wardrive-sessions-sort-by").value = "duration";
    document.getElementById("wardrive-sessions-sort-by").dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();

    document.getElementById("btn-wardrive-sessions-sort-dir").click();
    await flushAsync();

    expect(JSON.parse(window.localStorage.getItem("pwn_wardrive_sessions_ui"))).toEqual({
      sortBy: "duration",
      sortDirection: "asc",
    });

    document.body.innerHTML = "";
    resetState();
    mountDom();

    wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    expect(document.getElementById("wardrive-sessions-sort-by").value).toBe("duration");
    expect(document.getElementById("btn-wardrive-sessions-sort-dir").textContent).toContain("ASC");
  });

  test("merge can skip confirmation when disabled in config", async () => {
    mockAPI.getWardriveSessions.mockResolvedValueOnce({
      time_window: "all",
      sessions: [
        {
          session_id: "session-a",
          label: "session-a",
          source_file: "session-a.csv",
          started_at: 1710000000,
          ended_at: 1710000600,
          networks_count: 2,
          points_count: 4,
          distance_m: 650,
          transport_mode: null,
        },
        {
          session_id: "session-b",
          label: "session-b",
          source_file: "session-b.csv",
          started_at: 1710086400,
          ended_at: 1710087000,
          networks_count: 3,
          points_count: 4,
          distance_m: 920,
          transport_mode: "bike",
        },
      ],
      summary: { sessions_count: 2, networks_count: 5, points_count: 8, transport_modes: [], top_transport_modes: [] },
    });
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();

    window.dispatchEvent(new CustomEvent("kovil:config-applied", {
      detail: {
        config: {
          ui_wardrive_merge_confirmation: false,
        },
      },
    }));

    document.getElementById("btn-wardrive").click();
    await flushAsync();

    const sessionItems = document.querySelectorAll(".wardrive-session-item");
    sessionItems[0].click();
    await flushAsync();
    sessionItems[1].click();
    await flushAsync();
    await flushAsync();

    document.querySelector('[data-action="wardrive-replay-merge"]').click();
    await settleWardriveUi();

    expect(window.confirm).not.toHaveBeenCalled();
    expect(mockAPI.mergeWardriveSessions).toHaveBeenCalledWith(["session-a", "session-b"]);
  });

  test("clear button removes session filter, restores source selector and refreshes hierarchy", async () => {
    const wardrive = loadModule();
    wardrive.setupWardriveListeners();
    document.getElementById("btn-wardrive").click();
    await flushAsync();

    document.getElementById("wardrive-source").value = "pwn";
    document.getElementById("wardrive-source").dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();

    const sessionButton = document.querySelector(".wardrive-session-item");
    sessionButton.click();
    await flushAsync();

    document.getElementById("btn-wardrive-sessions-clear").click();
    await flushAsync();

    expect(document.getElementById("wardrive-source").disabled).toBe(false);
    expect(document.getElementById("wardrive-source").value).toBe("pwn");
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("ALL DATA");
    expect(document.getElementById("btn-wardrive-sessions-clear").disabled).toBe(true);
    expect(document.getElementById("wardrive-route-replay").textContent).toContain("Select 1-3 sessions");
    expect(document.querySelector('#wardrive-route-replay [data-ui-hint-title="Route Replay"]')).not.toBeNull();
    expect(mockAPI.getWardriveHierarchy).toHaveBeenLastCalledWith({
      time_window: "all",
      source: "pwn",
      session_ids: [],
    });
  });
});
