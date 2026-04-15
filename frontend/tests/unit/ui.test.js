const mockState = {
  allPositions: {},
  lastDataHash: "",
  isFirstLoad: true,
  openPopupMac: null,
  retryCount: 0,
  isProgrammaticInteraction: false,
  isCrackingActive: false,
  filters: { time: "ALL", search: "" },
  modes: {
    radar: false,
    intelligence: false,
    heat: false,
    zones: false,
    conquered: false,
    toConquer: false,
    targets: false,
    favs: false,
    wardrive: false,
    cracking: false,
    process: false,
    logs: false,
    noGps: false,
    multi: false,
    raw: false,
    analytics: false,
  },
  lists: { targets: [], favs: [] },
  map: { hoverCircle: null, userLocationMarker: null, watchId: null },
  ui: { hidePasswords: false, analyticsWorkspaceActive: false },
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
    artifact: "all",
  },
  multiLastClickedMac: null,
  rawFiles: [],
  rawSelectedFile: null,
  rawHashes: [],
  rawSelectedHash: null,
  rawMetadataByFile: {},
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
    networkPageSize: 15,
  },
  analyticsUi: {
    metric: "opportunity",
    source: "all",
    security: "all",
    deviceType: "all",
    dimension: "channel",
    timeWindow: "all",
    channel: "all",
    cellSize: 120,
    heatmap: null,
    channelSummary: null,
    hotspots: [],
    selectedHotspotId: null,
  },
};

const mockSaveModes = jest.fn();
const mockSaveLists = jest.fn();

const mockAPI = {
  getStatus: jest.fn(),
  getConfig: jest.fn(),
  getMapData: jest.fn(),
  getReconCacheManifest: jest.fn(),
  sync: jest.fn(),
  trustHostKey: jest.fn(),
  convertMultiPcaps: jest.fn(),
  listMultiFiles: jest.fn(),
  getMultiFileContent: jest.fn(),
  deleteMultiFile: jest.fn(),
  listRawSnifferFiles: jest.fn(),
  getRawSnifferHashes: jest.fn(),
  getRawSnifferMetadata: jest.fn(),
  extractRawSniffer: jest.fn(),
  clearDetailsFiles: jest.fn(),
  clearCache: jest.fn(),
  installDemoData: jest.fn(),
  removeDemoData: jest.fn(),
  getDemoDataStatus: jest.fn(),
  getAnalyticsHeatmap: jest.fn(),
  getAnalyticsChannelSummary: jest.fn(),
  getAnalyticsHotspots: jest.fn(),
};

const mockSocket = {
  connect: jest.fn(),
  on: jest.fn(),
};

const mockMap = {
  renderMarkers: jest.fn(),
  calculateZones: jest.fn(),
  calculateToConquerZones: jest.fn(),
  calculateDiscoveredZones: jest.fn(),
  calculateIntelligenceZones: jest.fn(),
  updateRadarCircles: jest.fn(),
  getMapInstance: jest.fn(() => ({ removeLayer: jest.fn(), setView: jest.fn() })),
  setClusterConfig: jest.fn(),
  setMarkerIcons: jest.fn(),
  clearDetailsCache: jest.fn(),
  setAnalyticsHeatmapLayer: jest.fn(),
  setAnalyticsHotspotsLayer: jest.fn(),
  setSelectedAnalyticsHotspot: jest.fn(),
  clearAnalyticsHeatmapLayer: jest.fn(),
  clearAnalyticsHotspotsLayer: jest.fn(),
  focusAnalyticsHotspot: jest.fn(),
};

const mockLog = jest.fn();
const mockBootLog = jest.fn();

const mockPlatform = {
  minimizeWindow: jest.fn(),
  maximizeWindow: jest.fn(),
  closeWindow: jest.fn(),
  setProgressBar: jest.fn(),
  togglePowerSave: jest.fn(),
};

const mockUiConfig = {
  theme: "default",
  iconPwned: "fa-skull",
  iconLocked: "fa-shield-halved",
  iconOpen: "fa-bolt",
  iconWardrive: "fa-tower-broadcast",
  wardriveColor: "teal",
  wardriveStyle: "icon",
};
const mockApplyTheme = jest.fn();
const mockApplyWardriveColor = jest.fn();
const mockApplyLayoutSettings = jest.fn();
const mockRenderDemoDataStatus = jest.fn();
const mockApplyClientConfig = jest.fn((config = {}) => {
  mockApplyLayoutSettings(config);
  mockApplyTheme(config.ui_theme || mockUiConfig.theme);
  mockApplyWardriveColor(config.ui_wardrive_color || mockUiConfig.wardriveColor);
  if (config.map_tile && typeof window.setTileLayer === "function") {
    window.setTileLayer(config.map_tile);
  }
  if (config.map_cluster_mode) {
    mockMap.setClusterConfig(config.map_cluster_mode);
    if (typeof window.setClusterConfig === "function") {
      window.setClusterConfig(config.map_cluster_mode);
    }
  }
  mockMap.setMarkerIcons(
    config.ui_icon_pwned || mockUiConfig.iconPwned,
    config.ui_icon_locked || mockUiConfig.iconLocked,
    config.ui_icon_wardrive || mockUiConfig.iconWardrive,
    config.ui_wardrive_style || mockUiConfig.wardriveStyle,
    config.ui_icon_open || mockUiConfig.iconOpen
  );
});
const mockOpenSettings = jest.fn();
const mockCloseSettings = jest.fn();
const mockSaveSettings = jest.fn();

const mockLists = {
  updateTargetsList: jest.fn(),
  updateFavsList: jest.fn(),
  updateZonesList: jest.fn(),
  updateNoGpsList: jest.fn(),
  updateMultiList: jest.fn(),
  updateMultiFilesList: jest.fn(),
  updateMultiContentsList: jest.fn(),
};

const mockActiveProcesses = {};
const mockProcesses = {
  addProcess: jest.fn(),
  updateProcess: jest.fn(),
  restoreActiveJobs: jest.fn(),
  renderProcessList: jest.fn(),
  setupProcessListeners: jest.fn(),
  handleJobCompletionSideEffects: jest.fn(),
  getActiveHashcatJob: jest.fn(() => null),
};

const mockCracking = {
  openCrackingPanel: jest.fn(),
  openMultiCrackingPanel: jest.fn(),
  setupCrackingListeners: jest.fn(),
  clearHistory: jest.fn(),
};

const mockWardrive = {
  setupWardriveListeners: jest.fn(),
  activateWardriveMode: jest.fn(),
  deactivateWardriveMode: jest.fn(),
  markWardriveDirty: jest.fn(),
  prewarmWardriveWorkspace: jest.fn(),
  refreshWardriveIfActive: jest.fn(),
};

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
  saveModes: (...args) => mockSaveModes(...args),
  saveLists: (...args) => mockSaveLists(...args),
}));

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/socket.js", () => ({
  Socket: mockSocket,
}));

jest.mock("../../src/modules/map.js", () => ({
  renderMarkers: (...args) => mockMap.renderMarkers(...args),
  calculateZones: (...args) => mockMap.calculateZones(...args),
  calculateToConquerZones: (...args) => mockMap.calculateToConquerZones(...args),
  calculateDiscoveredZones: (...args) => mockMap.calculateDiscoveredZones(...args),
  calculateIntelligenceZones: (...args) => mockMap.calculateIntelligenceZones(...args),
  updateRadarCircles: (...args) => mockMap.updateRadarCircles(...args),
  getMapInstance: (...args) => mockMap.getMapInstance(...args),
  setClusterConfig: (...args) => mockMap.setClusterConfig(...args),
  setMarkerIcons: (...args) => mockMap.setMarkerIcons(...args),
  clearDetailsCache: (...args) => mockMap.clearDetailsCache(...args),
  setAnalyticsHeatmapLayer: (...args) => mockMap.setAnalyticsHeatmapLayer(...args),
  setAnalyticsHotspotsLayer: (...args) => mockMap.setAnalyticsHotspotsLayer(...args),
  setSelectedAnalyticsHotspot: (...args) => mockMap.setSelectedAnalyticsHotspot(...args),
  clearAnalyticsHeatmapLayer: (...args) => mockMap.clearAnalyticsHeatmapLayer(...args),
  clearAnalyticsHotspotsLayer: (...args) => mockMap.clearAnalyticsHotspotsLayer(...args),
  focusAnalyticsHotspot: (...args) => mockMap.focusAnalyticsHotspot(...args),
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
  bootLog: (...args) => mockBootLog(...args),
  escapeHtml: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/platform.js", () => ({
  Platform: mockPlatform,
}));

jest.mock("../../src/modules/ui_components/ui_settings.js", () => ({
  uiConfig: mockUiConfig,
  applyClientConfig: (...args) => mockApplyClientConfig(...args),
  openSettings: (...args) => mockOpenSettings(...args),
  closeSettings: (...args) => mockCloseSettings(...args),
  renderDemoDataStatus: (...args) => mockRenderDemoDataStatus(...args),
  saveSettings: (...args) => mockSaveSettings(...args),
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => ({
  updateTargetsList: (...args) => mockLists.updateTargetsList(...args),
  updateFavsList: (...args) => mockLists.updateFavsList(...args),
  updateZonesList: (...args) => mockLists.updateZonesList(...args),
  updateNoGpsList: (...args) => mockLists.updateNoGpsList(...args),
  updateMultiList: (...args) => mockLists.updateMultiList(...args),
  updateMultiFilesList: (...args) => mockLists.updateMultiFilesList(...args),
  updateMultiContentsList: (...args) => mockLists.updateMultiContentsList(...args),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  activeProcesses: mockActiveProcesses,
  addProcess: (...args) => mockProcesses.addProcess(...args),
  updateProcess: (...args) => mockProcesses.updateProcess(...args),
  restoreActiveJobs: (...args) => mockProcesses.restoreActiveJobs(...args),
  renderProcessList: (...args) => mockProcesses.renderProcessList(...args),
  setupProcessListeners: (...args) => mockProcesses.setupProcessListeners(...args),
  handleJobCompletionSideEffects: (...args) => mockProcesses.handleJobCompletionSideEffects(...args),
  getActiveHashcatJob: (...args) => mockProcesses.getActiveHashcatJob(...args),
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: (...args) => mockCracking.openCrackingPanel(...args),
  openMultiCrackingPanel: (...args) => mockCracking.openMultiCrackingPanel(...args),
  setupCrackingListeners: (...args) => mockCracking.setupCrackingListeners(...args),
  clearHistory: (...args) => mockCracking.clearHistory(...args),
  selectedFile: null,
}));

jest.mock("../../src/modules/ui_wardrive.js", () => ({
  setupWardriveListeners: (...args) => mockWardrive.setupWardriveListeners(...args),
  activateWardriveMode: (...args) => mockWardrive.activateWardriveMode(...args),
  deactivateWardriveMode: (...args) => mockWardrive.deactivateWardriveMode(...args),
  markWardriveDirty: (...args) => mockWardrive.markWardriveDirty(...args),
  prewarmWardriveWorkspace: (...args) => mockWardrive.prewarmWardriveWorkspace(...args),
  refreshWardriveIfActive: (...args) => mockWardrive.refreshWardriveIfActive(...args),
}));

function resetState() {
  mockState.allPositions = {};
  mockState.lastDataHash = "";
  mockState.isFirstLoad = true;
  mockState.openPopupMac = null;
  mockState.retryCount = 0;
  mockState.isProgrammaticInteraction = false;
  mockState.isCrackingActive = false;
  mockState.filters = { time: "ALL", search: "" };
  mockState.modes = {
    radar: false,
    heat: false,
    zones: false,
    conquered: false,
    toConquer: false,
    targets: false,
    favs: false,
    wardrive: false,
    cracking: false,
    process: false,
    logs: false,
    noGps: false,
    multi: false,
    raw: false,
    analytics: false,
  };
  mockState.lists = { targets: [], favs: [] };
  mockState.map = { hoverCircle: null, userLocationMarker: null, watchId: null };
  mockState.ui = { hidePasswords: false, analyticsWorkspaceActive: false };
  mockState.multiSelection = [];
  mockState.multiFiles = [];
  mockState.multiSelectedFile = null;
  mockState.multiFileContents = {};
  mockState.multiItemStatus = {};
  mockState.multiFilter = "all";
  mockState.multiUi = {
    search: "",
    status: "all",
    location: "all",
    source: "all",
    artifact: "all",
  };
  mockState.multiLastClickedMac = null;
  mockState.rawFiles = [];
  mockState.rawSelectedFile = null;
  mockState.rawHashes = [];
  mockState.rawSelectedHash = null;
  mockState.rawMetadataByFile = {};
  mockState.rawSelectedNetworkByFile = {};
  mockState.rawUi = {
    fileSearch: "",
    fileStatus: "all",
    fileSort: "modified_desc",
    filePage: 1,
    filePageSize: 12,
    networkSearch: "",
    networkSort: "beacon_desc",
    networkPage: 1,
    networkPageSize: 15,
  };
  mockState.analyticsUi = {
    metric: "opportunity",
    source: "all",
    security: "all",
    deviceType: "all",
    dimension: "channel",
    timeWindow: "all",
    channel: "all",
    cellSize: 120,
    heatmap: null,
    channelSummary: null,
    hotspots: [],
    selectedHotspotId: null,
  };
}

function resetMocks() {
  resetState();
  mockSaveModes.mockClear();
  mockSaveLists.mockClear();

  [
    mockAPI,
    mockSocket,
    mockMap,
    mockPlatform,
    mockLists,
    mockProcesses,
    mockCracking,
    mockWardrive,
  ].forEach((obj) => {
    Object.values(obj).forEach((fn) => {
      if (typeof fn?.mockReset === "function") {
        fn.mockReset();
      }
    });
  });

  mockApplyTheme.mockReset();
  mockApplyWardriveColor.mockReset();
  mockApplyLayoutSettings.mockReset();
  mockRenderDemoDataStatus.mockReset();
  mockApplyClientConfig.mockClear();
  mockOpenSettings.mockReset();
  mockCloseSettings.mockReset();
  mockSaveSettings.mockReset();
  mockLog.mockReset();
  mockBootLog.mockReset();

  Object.keys(mockActiveProcesses).forEach((k) => delete mockActiveProcesses[k]);

  mockSocket.connect.mockImplementation(() => {});
  mockSocket.on.mockImplementation(() => {});
  mockMap.getMapInstance.mockReturnValue({ removeLayer: jest.fn(), setView: jest.fn() });
  mockProcesses.getActiveHashcatJob.mockReturnValue(null);

  mockAPI.getStatus.mockResolvedValue({ status: "ready", message: "ok" });
  mockAPI.getConfig.mockResolvedValue({
    map_tile: "osm",
    map_cluster_mode: "adaptive",
    ui_theme: "matrix",
    ui_icon_pwned: "fa-skull",
    ui_icon_locked: "fa-lock",
    ui_icon_open: "fa-bolt",
    ui_hide_passwords: true,
  });
  mockAPI.getMapData.mockResolvedValue({});
  mockAPI.trustHostKey.mockResolvedValue({
    status: "success",
    message: "SSH host key trusted successfully.",
  });
  mockAPI.listMultiFiles.mockResolvedValue([{ name: "batch_test.22000", size: 2048, count: 2 }]);
  mockAPI.getMultiFileContent.mockResolvedValue({ items: [{ ssid: "Net" }] });
  mockAPI.listRawSnifferFiles.mockResolvedValue([
    {
      filename: "raw_1.pcap",
      size: 1024,
      modified: 1700000000,
      cached_up_to_date: true,
      networks_count: 1,
    },
  ]);
  mockAPI.getRawSnifferHashes.mockResolvedValue([
    {
      filename: "raw_1.22000",
      size: 128,
      modified: 1700000001,
      source_raw_file: "raw_1.pcap",
      valid_hash_lines: 2,
      primary_bssid: "AA:BB:CC:DD:EE:FF",
      primary_ssid: "NetOne",
      bssid_count: 1,
      has_context: true,
    },
  ]);
  mockAPI.getRawSnifferMetadata.mockResolvedValue({
    source_file: "raw_1.pcap",
    processed_at: "2026-03-16T00:00:00Z",
    stats: { networks_count: 1, beacon_frames: 1, probe_requests: 0, eapol_frames: 1 },
    warnings: [],
    networks: [],
  });
  mockAPI.extractRawSniffer.mockResolvedValue({
    status: "noop",
    message: "No raw files to process",
    total_files: 0,
    job_id: null,
  });
  mockAPI.getAnalyticsHeatmap.mockResolvedValue({
    schema_version: 1,
    stats: { networks_count: 2, cells_count: 1, value_avg: 40 },
    cells: [{ lat: -22.9, lng: -43.2, value: 42, points_count: 2, locked_count: 1, raw_eapol_sum: 1, raw_beacon_sum: 5, raw_probe_peak_sum: 2, sample_macs: ["AA:BB:CC:DD:EE:FF"] }],
  });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValue({
    schema_version: 1,
    channels: [{ channel: 6, networks: 2, locked: 1, raw_eapol_networks: 1, opportunity_score: 80 }],
    device_summary: [{ device_type: "router_ap", networks: 2, locked: 1, raw_eapol_networks: 1, opportunity_score: 76 }],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValue({
    schema_version: 1,
    hotspots: [{ id: "H1", score: 80, center_lat: -22.9, center_lng: -43.2, radius_m: 120, networks_count: 2, locked_count: 1, top_channels: [6], top_sources: ["RAW"], sample_macs: ["AA:BB:CC:DD:EE:FF"], recommended_action: "prioritize_cracking" }],
  });
  mockAPI.getReconCacheManifest.mockResolvedValue({ scope: "test-scope" });
  mockAPI.clearDetailsFiles.mockResolvedValue({ deleted_count: 0, failed_count: 0 });
  mockAPI.clearCache.mockResolvedValue({ raw_metadata_deleted_count: 0, raw_metadata_failed_count: 0 });
  mockAPI.installDemoData.mockResolvedValue({
    profile_id: "showcase-core-v1",
    label: "Showcase Core v1",
    summary: { networks_total: 10, wardrive_sessions: 3, raw_files: 3 },
    ui_seed: {
      lists: { targets: ["AA:BB:CC:DD:EE:FF"], favs: ["11:22:33:44:55:66"] },
      modes: { targets: true, favs: true, process: true, logs: true, zones: true, conquered: true },
    },
  });
  mockAPI.removeDemoData.mockResolvedValue({
    restore_mode: "snapshot",
    ui_restore: {
      lists: { targets: [], favs: [] },
      modes: { targets: false, favs: false, process: false, logs: false, zones: false, conquered: false },
    },
  });
  window.confirm = jest.fn(() => false);
}

test("initUI normalizes wardrive to inactive on boot", async () => {
  resetMocks();
  mockState.modes.wardrive = true;
  mountUiDom();
  const { initUI } = loadUiModule();

  initUI();
  await Promise.resolve();
  await Promise.resolve();

  expect(mockState.modes.wardrive).toBe(false);
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_wardrive", JSON.stringify(false));
  expect(mockWardrive.activateWardriveMode).not.toHaveBeenCalled();
});

function createNode(tag, id, className) {
  const node = document.createElement(tag);
  if (id) node.id = id;
  if (className) node.className = className;
  document.body.appendChild(node);
  return node;
}

function mountUiDom() {
  document.body.innerHTML = "";
  createNode("div", "hud-layer");

  const titleBar = createNode("div", "title-bar");
  const title = document.createElement("span");
  title.className = "app-title";
  titleBar.appendChild(title);

  createNode("div", null, "controls-row");
  createNode("div", null, "stats-container-wrapper");

  [
    "btn-min",
    "btn-max",
    "btn-close",
    "btn-sync",
    "btn-intelligence",
    "btn-heat",
    "btn-zones",
    "btn-conquered",
    "btn-wardrive",
    "btn-to-conquer",
    "btn-discovered",
    "btn-targets",
    "btn-favs",
    "btn-map-view",
    "btn-no-gps-view",
    "btn-multi-view",
    "btn-raw-view",
    "btn-analytics-view",
    "btn-logs",
    "btn-settings",
    "btn-close-settings",
    "btn-cancel-settings",
    "btn-save-settings",
    "btn-clear-history",
    "btn-clear-details",
    "btn-clear-cache",
    "btn-install-demo-data",
    "btn-remove-demo-data",
    "btn-quick-settings",
    "btn-multi-create",
    "btn-multi-clear",
    "btn-multi-filter-all",
    "btn-multi-filter-locked",
    "btn-toggle-cracking",
    "btn-process",
  ].forEach((id) => createNode("button", id));

  [
    "zones-panel",
    "wardrive-panel",
    "targets-panel",
    "favorites-panel",
    "no-gps-panel",
    "multi-panel",
    "raw-panel",
    "analytics-panel",
    "analytics-left-hotspots-panel",
    "analytics-left-details-panel",
    "multi-all-list",
    "multi-files-list",
    "multi-contents-list",
    "raw-files-list",
    "raw-hashes-list",
    "raw-details-view",
    "loading",
  ].forEach((id) => createNode("div", id));

  createNode("input", "multi-filter-search");
  createNode("select", "multi-filter-location");
  createNode("select", "multi-filter-source");
  createNode("select", "multi-filter-artifact");
  document.getElementById("multi-filter-location").innerHTML = '<option value="all">ALL</option><option value="gps">GPS</option><option value="no-gps">NO-GPS</option>';
  document.getElementById("multi-filter-source").innerHTML = '<option value="all">ALL</option><option value="pwn">PWNAGOTCHI</option><option value="bruce">BRUCEGOTCHI</option><option value="m5">M5Evil</option><option value="ward">WARDRIVE</option><option value="raw">RAWSNIFFER</option>';
  document.getElementById("multi-filter-artifact").innerHTML = '<option value="all">ALL</option><option value="has_pcap">HAS PCAP</option><option value="has_22000">HAS 22000</option><option value="no_22000">NO 22000</option>';
  createNode("span", "multi-visible-count");
  createNode("span", "multi-eligible-count");
  createNode("span", "multi-excluded-open-count");

  createNode("button", "btn-raw-refresh");
  createNode("button", "btn-raw-reprocess-selected");
  createNode("button", "btn-raw-reprocess-pending");
  createNode("span", "raw-files-count-info");
  createNode("span", "raw-net-count-info");
  createNode("input", "raw-file-search");
  createNode("select", "raw-file-status");
  createNode("select", "raw-file-sort");
  createNode("input", "raw-network-search");
  createNode("select", "raw-network-sort");
  document.getElementById("raw-file-status").innerHTML = '<option value="all">ALL</option><option value="pending">PENDING</option><option value="cached">CACHED</option>';
  document.getElementById("raw-file-sort").innerHTML = '<option value="modified_desc">RECENT</option>';
  document.getElementById("raw-network-sort").innerHTML = '<option value="beacon_desc">BEACON</option>';

  createNode("button", "btn-analytics-refresh");
  createNode("button", "btn-analytics-add-targets");
  createNode("select", "analytics-metric-select");
  createNode("select", "analytics-source-select");
  createNode("select", "analytics-security-select");
  createNode("select", "analytics-device-type-select");
  createNode("select", "analytics-time-window-select");
  createNode("select", "analytics-channel-select");
  createNode("select", "analytics-cell-size-select");
  createNode("button", "btn-analytics-dimension-channel");
  createNode("button", "btn-analytics-dimension-device");
  createNode("div", "analytics-hotspots-list");
  createNode("div", "analytics-hotspot-details");
  createNode("tbody", "analytics-channel-body");
  createNode("tr", "analytics-channel-head");
  createNode("div", "analytics-pressure-title");
  createNode("div", "analytics-chart-channel-pressure");
  createNode("div", "analytics-chart-source-mix");
  createNode("div", "analytics-chart-security-mix");
  createNode("span", "analytics-kpi-networks");
  createNode("span", "analytics-kpi-cells");
  createNode("span", "analytics-kpi-hotspots");
  createNode("span", "analytics-kpi-value");

  document.getElementById("analytics-metric-select").innerHTML = '<option value="opportunity">OPPORTUNITY</option><option value="eapol">EAPOL</option>';
  document.getElementById("analytics-source-select").innerHTML = '<option value="all">ALL</option><option value="m5">M5Evil</option><option value="raw">RAWSNIFFER</option>';
  document.getElementById("analytics-security-select").innerHTML = '<option value="all">ALL</option><option value="locked">LOCKED</option>';
  document.getElementById("analytics-device-type-select").innerHTML = '<option value="all">ALL DEV</option><option value="router_ap">ROUTER AP</option>';
  document.getElementById("analytics-time-window-select").innerHTML = '<option value="all">ALL</option><option value="24h">24H</option>';
  document.getElementById("analytics-channel-select").innerHTML = '<option value="all">ALL CH</option>';
  document.getElementById("analytics-cell-size-select").innerHTML = '<option value="120">CELL 120m</option>';

  const rightPanels = createNode("div", null, "right-panels-container");
  const analyticsRightFiltersPanel = document.createElement("div");
  analyticsRightFiltersPanel.id = "analytics-right-filters-panel";
  rightPanels.appendChild(analyticsRightFiltersPanel);
  const analyticsRightChannelsPanel = document.createElement("div");
  analyticsRightChannelsPanel.id = "analytics-right-channels-panel";
  rightPanels.appendChild(analyticsRightChannelsPanel);
  const crackingPanel = document.createElement("div");
  crackingPanel.id = "cracking-panel";
  rightPanels.appendChild(crackingPanel);
  const bottomPanels = document.createElement("div");
  bottomPanels.className = "bottom-panels";
  rightPanels.appendChild(bottomPanels);
  const processPanel = document.createElement("div");
  processPanel.id = "process-panel";
  bottomPanels.appendChild(processPanel);
  const logPanel = document.createElement("div");
  logPanel.id = "log-panel";
  bottomPanels.appendChild(logPanel);

  createNode("input", "filter-input");
  const filterClear = createNode("button", "btn-filter-clear");
  filterClear.hidden = true;
  createNode("div", "boot-status");
  createNode("div", "boot-status-pill");
  createNode("div", "boot-progress-bar");
  createNode("div", "boot-progress-label");
  createNode("div", "boot-progress-value");
  createNode("div", "boot-subtitle");
  createNode("div", "boot-tip-copy");
  const bootBackend = createNode("div", null);
  bootBackend.dataset.bootStep = "backend";
  const bootDataset = createNode("div", null);
  bootDataset.dataset.bootStep = "dataset";
  const bootWorkspace = createNode("div", null);
  bootWorkspace.dataset.bootStep = "workspace";
  createNode("div", "boot-step-backend-meta");
  createNode("div", "boot-step-dataset-meta");
  createNode("div", "boot-step-workspace-meta");
  createNode("div", "boot-log");

  const settingsModal = createNode("div", "settings-modal");
  settingsModal.style.display = "none";
  const settingsPanel = document.createElement("div");
  settingsPanel.className = "settings-panel";
  settingsModal.appendChild(settingsPanel);
  const demoStatus = document.createElement("div");
  demoStatus.id = "demo-data-status";
  settingsPanel.appendChild(demoStatus);
  const demoSummary = document.createElement("div");
  demoSummary.id = "demo-data-summary";
  settingsPanel.appendChild(demoSummary);

  [
    "count-total",
    "count-cracked",
    "count-open",
    "count-wardrive",
    "count-locked",
  ].forEach((id) => createNode("span", id));
}

function loadUiModule() {
  jest.resetModules();
  return require("../../src/modules/ui.js");
}

async function flushAsync() {
  await Promise.resolve();
  await Promise.resolve();
}

function getSocketHandler(eventName) {
  const match = mockSocket.on.mock.calls.find(([event]) => event === eventName);
  return match ? match[1] : null;
}

describe("ui module", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    resetMocks();
    mountUiDom();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  test("initUI wires listeners, restores defaults and loads initial data", async () => {
    const ui = loadUiModule();

    ui.initUI();

    expect(mockSocket.connect).toHaveBeenCalledTimes(1);
    expect(mockProcesses.restoreActiveJobs).toHaveBeenCalledTimes(1);
    expect(mockProcesses.setupProcessListeners).toHaveBeenCalledTimes(1);
    expect(mockCracking.setupCrackingListeners).toHaveBeenCalledTimes(1);
    expect(mockAPI.getStatus).toHaveBeenCalledTimes(1);
    expect(mockAPI.getConfig).toHaveBeenCalledTimes(1);

    await flushAsync();
    jest.advanceTimersByTime(900);
    await flushAsync();

    expect(mockAPI.getMapData).toHaveBeenCalledTimes(1);
    expect(mockMap.setClusterConfig).toHaveBeenCalledWith("adaptive");
    expect(mockMap.setMarkerIcons).toHaveBeenCalledWith(
      "fa-skull",
      "fa-lock",
      "fa-tower-broadcast",
      "icon",
      "fa-bolt"
    );
    expect(mockApplyLayoutSettings).toHaveBeenCalledWith(
      expect.objectContaining({
        map_tile: "osm",
        map_cluster_mode: "adaptive",
      })
    );
    expect(mockApplyTheme).toHaveBeenCalledWith("matrix");
    expect(document.title).toContain("KOVIL MAP");
  });

  test("openBatchFromProcess falls back to first batch and opens cracking panel", async () => {
    const ui = loadUiModule();

    await ui.openBatchFromProcess("custom_name.22000");

    expect(mockState.modes.multi).toBe(true);
    expect(mockState.modes.noGps).toBe(false);
    expect(mockState.multiSelectedFile).toBe("batch_test.22000");
    expect(mockLists.updateMultiFilesList).toHaveBeenCalled();
    expect(mockLists.updateMultiContentsList).toHaveBeenCalled();
    expect(mockCracking.openMultiCrackingPanel).toHaveBeenCalledWith("batch_test.22000");
    expect(document.getElementById("multi-panel").style.display).toBe("flex");
  });

  test("openBatchFromProcess handles empty multi file list", async () => {
    mockAPI.listMultiFiles.mockResolvedValueOnce([]);

    const ui = loadUiModule();

    await ui.openBatchFromProcess(null);

    expect(mockState.multiSelectedFile).toBe(null);
    expect(mockLists.updateMultiFilesList).toHaveBeenCalled();
    expect(mockLists.updateMultiContentsList).toHaveBeenCalled();
    expect(mockCracking.openMultiCrackingPanel).not.toHaveBeenCalled();
  });

  test("raw hashes list opens cracking panel with hash context", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    document.getElementById("btn-raw-view").click();
    await flushAsync();

    expect(mockAPI.listRawSnifferFiles).toHaveBeenCalledTimes(1);
    expect(mockAPI.getRawSnifferHashes).toHaveBeenCalledTimes(1);
    expect(document.getElementById("raw-files-count-info").textContent).toBe("1/1");
    expect(document.getElementById("raw-net-count-info").textContent).toBe("0/0");
    expect(document.getElementById("btn-raw-files-prev")).toBeNull();
    expect(document.getElementById("btn-raw-files-next")).toBeNull();
    expect(document.getElementById("btn-raw-net-prev")).toBeNull();
    expect(document.getElementById("btn-raw-net-next")).toBeNull();
    expect(document.getElementById("raw-network-page-size")).toBeNull();

    const fileSearch = document.getElementById("raw-file-search");
    fileSearch.value = "missing";
    fileSearch.dispatchEvent(new Event("input", { bubbles: true }));
    expect(document.getElementById("raw-files-count-info").textContent).toBe("0/1");

    const hashItem = Array.from(document.querySelectorAll("#raw-hashes-list .list-item")).find((node) =>
      node.textContent.includes("raw_1.22000")
    );
    expect(hashItem).toBeTruthy();

    hashItem.click();
    await flushAsync();

    expect(mockCracking.openCrackingPanel).toHaveBeenCalledWith(
      "AA:BB:CC:DD:EE:FF",
      "RAW HASH raw_1.22000",
      "raw_1.22000",
      { scope: "raw_hash" }
    );
  });

  test("initUI reacts to toolbar clicks and socket callbacks", async () => {
    const ui = loadUiModule();
    mockAPI.sync.mockResolvedValue({
      status: "success",
      message: "sync ok",
      details: { handshakes: ["a"], errors: [] },
    });

    // Seed one active process for socket progress tests.
    mockActiveProcesses["job-1"] = {
      type: "HASHCAT [MASK]",
      status: "RUNNING",
      details: "capture.22000",
      percentage: 0,
      extraInfo: "",
      indeterminate: false,
    };

    ui.initUI();
    await flushAsync();

    expect(document.getElementById("btn-all")).toBeNull();
    expect(document.getElementById("btn-24h")).toBeNull();
    document.getElementById("btn-raw-view").click();
    document.getElementById("btn-intelligence").click();
    document.getElementById("btn-heat").click();
    document.getElementById("btn-zones").click();
    document.getElementById("btn-conquered").click();
    document.getElementById("btn-to-conquer").click();
    document.getElementById("btn-targets").click();
    document.getElementById("btn-favs").click();
    document.getElementById("btn-no-gps-view").click();
    document.getElementById("btn-multi-view").click();
    document.getElementById("btn-map-view").click();
    document.getElementById("btn-logs").click();
    const rightPanels = document.querySelector(".right-panels-container");
    expect(rightPanels.classList.contains("right-panels--has-logs")).toBe(true);
    expect(rightPanels.classList.contains("right-panels--only-logs")).toBe(true);
    document.getElementById("btn-logs").click();
    expect(rightPanels.classList.contains("right-panels--has-logs")).toBe(false);
    expect(rightPanels.classList.contains("right-panels--only-logs")).toBe(false);
    document.getElementById("btn-min").click();
    document.getElementById("btn-max").click();
    document.getElementById("btn-close").click();

    expect(mockMap.renderMarkers).toHaveBeenCalled();
    expect(mockMap.calculateZones).toHaveBeenCalled();
    expect(mockMap.calculateToConquerZones).toHaveBeenCalled();
    expect(mockMap.calculateIntelligenceZones).toHaveBeenCalled();
    expect(mockPlatform.minimizeWindow).toHaveBeenCalledTimes(1);
    expect(mockPlatform.maximizeWindow).toHaveBeenCalledTimes(1);
    expect(mockPlatform.closeWindow).toHaveBeenCalledTimes(1);

    document.getElementById("btn-sync").click();
    await flushAsync();
    expect(mockAPI.sync).toHaveBeenCalled();

    const progressCb = getSocketHandler("job_progress");
    const completeCb = getSocketHandler("job_complete");
    const dataCb = getSocketHandler("data_update");
    expect(progressCb).toBeTruthy();
    expect(completeCb).toBeTruthy();
    expect(dataCb).toBeTruthy();

    progressCb({
      job_id: "job-1",
      data: { percentage: 33, speed: "100kH/s", eta: "1m", stage: "RUNNING", extra: "phase" },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "job-1",
      33,
      "RUNNING",
      expect.stringContaining("100kH/s"),
      false
    );
    expect(mockPlatform.setProgressBar).toHaveBeenCalled();

    completeCb({
      id: "job-1",
      status: "success",
      type: "cracking",
      progress_data: { stage: "CRACKED" },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("job-1", 100, "COMPLETED");
    expect(mockProcesses.handleJobCompletionSideEffects).toHaveBeenCalled();

    dataCb("map_data");
    jest.advanceTimersByTime(900);
    await flushAsync();
    expect(mockAPI.getMapData).toHaveBeenCalled();
  });

  test("stats and filter listeners update UI state", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const filter = document.getElementById("filter-input");
    const clearButton = document.getElementById("btn-filter-clear");
    filter.value = "home";
    filter.dispatchEvent(new Event("input", { bubbles: true }));
    expect(clearButton.hidden).toBe(false);
    filter.dispatchEvent(new KeyboardEvent("keyup", { key: "Enter", bubbles: true }));
    expect(mockState.filters.search).toBe("home");
    expect(mockMap.renderMarkers).toHaveBeenCalled();

    document.dispatchEvent(
      new CustomEvent("statsUpdated", {
        detail: { total: 10, cracked: 2, wardrive: 1, open: 2, locked: 5, noGpsTotal: 3, noGpsCracked: 1 },
      })
    );
    expect(document.getElementById("count-total").innerText).toEqual(13);
    expect(document.getElementById("count-cracked").innerText).toEqual(3);
    expect(document.getElementById("count-open").innerText).toEqual(2);
    expect(document.getElementById("count-wardrive").innerText).toEqual(1);
    expect(document.getElementById("count-locked").innerText).toEqual(7);

    document.dispatchEvent(new CustomEvent("listsUpdated"));
    expect(mockLists.updateTargetsList).toHaveBeenCalled();
    expect(mockLists.updateFavsList).toHaveBeenCalled();

    document.dispatchEvent(new CustomEvent("zonesUpdated", { detail: [{ id: 1 }] }));
    expect(mockLists.updateZonesList).toHaveBeenCalledWith([{ id: 1 }]);
  });

  test("search clear button resets input and rerenders map without filters", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const filter = document.getElementById("filter-input");
    const clearButton = document.getElementById("btn-filter-clear");

    filter.value = "target";
    filter.dispatchEvent(new Event("input", { bubbles: true }));
    expect(mockState.filters.search).toBe("target");
    expect(clearButton.hidden).toBe(false);

    mockMap.renderMarkers.mockClear();
    mockMap.calculateZones.mockClear();
    mockMap.calculateToConquerZones.mockClear();

    clearButton.click();

    expect(filter.value).toBe("");
    expect(mockState.filters.search).toBe("");
    expect(clearButton.hidden).toBe(true);
    expect(mockMap.renderMarkers).toHaveBeenCalledWith(mockState.allPositions, true);
    expect(mockMap.calculateZones).toHaveBeenCalledWith(mockState.allPositions);
    expect(mockMap.calculateToConquerZones).toHaveBeenCalledWith(mockState.allPositions);
  });

  test("settings modal supports overlay click and ESC close", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const modal = document.getElementById("settings-modal");
    const panel = modal.querySelector(".settings-panel");
    modal.style.display = "flex";

    modal.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockCloseSettings).toHaveBeenCalledTimes(1);

    panel.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockCloseSettings).toHaveBeenCalledTimes(1);

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(mockCloseSettings).toHaveBeenCalledTimes(2);
  });

  test("test helpers expand mock networks and parse mac from filenames", () => {
    const ui = loadUiModule();

    const merged = ui.__test.addMockNetworks({
      "AA:AA:AA:AA:AA:AA": {
        mac: "AA:AA:AA:AA:AA:AA",
        ssid: "existing",
        lat: 0,
        lng: 0,
      },
    });

    // Adds many deterministic mocked entries while preserving existing keys.
    expect(Object.keys(merged).length).toBeGreaterThan(50);
    expect(merged["AA:AA:AA:AA:AA:AA"]).toBeDefined();
    expect(merged["AA:ED:00:00:00:01"]).toBeDefined();
    expect(merged["AA:NS:00:00:00:01"]).toBeDefined();

    expect(ui.__test.parseMacFromFilename("capture_aabbccddeeff.pcap")).toBe("AA:BB:CC:DD:EE:FF");
    expect(ui.__test.parseMacFromFilename("no-mac-here.txt")).toBeNull();
  });

  test("checkBackendStatus handles busy and error branches", async () => {
    const ui = loadUiModule();
    mockAPI.getStatus
      .mockResolvedValueOnce({ status: "busy", message: "warming up" })
      .mockRejectedValueOnce(new Error("offline"));

    await ui.__test.checkBackendStatus();
    expect(document.getElementById("boot-status").innerText).toBe("WARMING UP");
    expect(document.getElementById("boot-status-pill").innerText).toBe("BACKEND BUSY");
    expect(document.getElementById("boot-progress-value").innerText).toBe("28%");
    expect(document.querySelector('[data-boot-step="backend"]').classList.contains("is-active")).toBe(true);
    expect(mockBootLog).toHaveBeenCalledWith("Backend busy: warming up");

    await ui.__test.checkBackendStatus();
    expect(document.getElementById("boot-status").innerText).toBe("CONNECTING...");
    expect(document.getElementById("boot-status-pill").dataset.tone).toBe("error");
    expect(document.getElementById("boot-progress-label").innerText).toContain("backend connection");
    expect(mockBootLog).toHaveBeenCalledWith("Waiting for backend connection...");
  });

  test("loadData covers unchanged-hash and retry-on-error branches", async () => {
    const ui = loadUiModule();
    const data = { A: { mac: "AA", ssid: "One", lat: 1, lng: 2 } };

    mockAPI.getMapData.mockResolvedValueOnce(data);
    mockState.lastDataHash = JSON.stringify(data);
    await ui.__test.loadData();
    expect(mockMap.renderMarkers).not.toHaveBeenCalled();
    expect(mockMap.clearDetailsCache).not.toHaveBeenCalled();

    mockAPI.getMapData.mockRejectedValueOnce(new Error("boom"));
    await ui.__test.loadData();
    expect(mockState.retryCount).toBe(1);
    expect(document.getElementById("boot-status").innerText).toBe("RETRY SCHEDULED");
    expect(document.querySelector('[data-boot-step="dataset"]').classList.contains("is-error")).toBe(true);
    expect(mockBootLog).toHaveBeenCalledWith("Data load failed. Retrying in 2s...");
  });

  test("loadData clears popup details cache when dataset hash changes", async () => {
    const ui = loadUiModule();
    const data = { A: { mac: "AA", ssid: "One", lat: 1, lng: 2 } };
    mockState.lastDataHash = "";
    mockAPI.getMapData.mockResolvedValueOnce(data);

    await ui.__test.loadData();

    expect(mockMap.clearDetailsCache).toHaveBeenCalledTimes(1);
    expect(mockMap.renderMarkers).toHaveBeenCalledWith(data, false);
    expect(mockWardrive.prewarmWardriveWorkspace).toHaveBeenCalledTimes(1);
    expect(document.getElementById("boot-status").innerText).toBe("ONLINE");
    expect(document.getElementById("loading").style.display).toBe("none");
  });

  test("loadData primes the recon cache manifest after dataset refresh", async () => {
    const ui = loadUiModule();
    const data = { A: { mac: "AA", ssid: "One", lat: 1, lng: 2 } };
    mockState.lastDataHash = "";
    mockAPI.getMapData.mockResolvedValueOnce(data);

    await ui.__test.loadData();
    await Promise.resolve();

    expect(mockAPI.getReconCacheManifest).toHaveBeenCalledTimes(1);
  });

  test("loadData triggers to-conquer, multi updates and first-load log", async () => {
    const ui = loadUiModule();
    const data = { A: { mac: "AA", ssid: "One", lat: 1, lng: 2 } };

    mockState.lastDataHash = "";
    mockState.modes.toConquer = true;
    mockState.modes.multi = true;
    mockState.isFirstLoad = true;
    mockAPI.getMapData.mockResolvedValueOnce(data);

    await ui.__test.loadData();

    expect(mockMap.calculateToConquerZones).toHaveBeenCalledWith(data);
    expect(mockLists.updateMultiList).toHaveBeenCalled();
    expect(mockLog).toHaveBeenCalledWith("System Online. Loaded 1 networks.", "success");
    expect(mockState.isFirstLoad).toBe(false);
  });

  test("data_update defers load during cracking and retries when idle", async () => {
    const ui = loadUiModule();
    const data = { A: { mac: "AA", ssid: "One", lat: 1, lng: 2 } };

    mockState.lastDataHash = "";
    mockAPI.getStatus.mockResolvedValueOnce({ status: "ready", message: "ok" });
    mockAPI.getMapData.mockResolvedValue(data);

    ui.initUI();
    await flushAsync();
    jest.advanceTimersByTime(800);
    await flushAsync();
    expect(mockAPI.getMapData).toHaveBeenCalledTimes(1);

    const dataCb = getSocketHandler("data_update");
    expect(dataCb).toBeTruthy();

    mockState.isCrackingActive = true;
    dataCb("map_data");
    jest.advanceTimersByTime(800);
    await flushAsync();
    expect(mockAPI.getMapData).toHaveBeenCalledTimes(1);

    mockState.isCrackingActive = false;
    jest.advanceTimersByTime(1500);
    jest.advanceTimersByTime(800);
    await flushAsync();
    expect(mockAPI.getMapData).toHaveBeenCalledTimes(2);
  });

  test("syncData handles force flag, host-key trust flow, non-success and catch", async () => {
    const ui = loadUiModule();
    const btn = document.getElementById("btn-sync");

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: true });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: { handshakes: [], errors: ["warn-1"], wardrive: { files_count: 2, networks_count: 5 } },
    });
    await ui.__test.syncData();
    expect(btn.classList.contains("active")).toBe(true);
    expect(mockLog).toHaveBeenCalledWith("Pwnagotchi FORCE SYNC enabled: downloading all matching files.", "warn");
    expect(mockLog).toHaveBeenCalledWith("Wardrive: 2 files | 5 networks", "success");
    expect(mockLog).toHaveBeenCalledWith("warn-1", "error");

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({ status: "error", message: "denied", details: { handshakes: [], errors: [] } });
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith("Sync Error: denied", "error");

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync
      .mockResolvedValueOnce({
        status: "error",
        code: "ssh_host_key_not_trusted",
        message: "trust required",
        details: {
          host: "10.0.0.2",
          port: 22,
          host_key: {
            host: "10.0.0.2",
            port: 22,
            key_type: "ssh-ed25519",
            fingerprint_sha256: "SHA256:abc123",
          },
        },
      })
      .mockResolvedValueOnce({
        status: "success",
        message: "sync ok",
        details: { handshakes: [], errors: [] },
      });
    window.confirm.mockReturnValueOnce(true);
    await ui.__test.syncData();
    expect(window.confirm).toHaveBeenCalled();
    expect(mockAPI.trustHostKey).toHaveBeenCalledWith("10.0.0.2", 22, false, null);
    expect(mockLog).toHaveBeenCalledWith("SSH host key trusted successfully.", "success");

    mockAPI.getConfig.mockRejectedValueOnce(new Error("cfg down"));
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith("Sync Failed: cfg down", "error");
  });

  test("syncData emits explicit Bruce fingerprint feedback when hidden reprocess is planned", async () => {
    const ui = loadUiModule();

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: [],
        bruce: {
          handshakes_seen: 3,
          handshakes_to_process: 2,
          handshakes_hidden_refresh: 1,
          handshakes_missing_details: 1,
          handshakes_invalid_details: 0,
          fingerprint_job_id: "fp-job-1",
        },
      },
    });
    await ui.__test.syncData();
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "fp-job-1",
      "FINGERPRINT",
      "Bruce (2 files)",
      "STARTING"
    );
    expect(mockLog).toHaveBeenCalledWith(
      "Processing 2 Bruce fingerprints in background (hidden 1 | missing 1 | invalid 0).",
      "info"
    );

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: [],
        bruce: {
          handshakes_seen: 4,
          handshakes_to_process: 2,
          handshakes_hidden_refresh: 2,
          handshakes_missing_details: 0,
          handshakes_invalid_details: 0,
        },
      },
    });
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith(
      "Bruce fingerprint planned 2 files (hidden 2 | missing 0 | invalid 0), but no background job id was returned.",
      "warn"
    );

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: [],
        bruce: {
          handshakes_seen: 4,
          handshakes_to_process: 0,
          handshakes_hidden_refresh: 0,
          handshakes_missing_details: 0,
          handshakes_invalid_details: 0,
        },
      },
    });
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith(
      "Bruce handshakes up to date: no hidden/missing/invalid files to reprocess.",
      "info"
    );

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "error",
      message: "timed out",
      details: {
        handshakes: [],
        errors: [],
        bruce: {
          handshakes_seen: 10,
          handshakes_to_process: 3,
          handshakes_hidden_refresh: 3,
          handshakes_missing_details: 0,
          handshakes_invalid_details: 0,
          fingerprint_job_id: "fp-job-err",
        },
      },
    });
    await ui.__test.syncData();
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "fp-job-err",
      "FINGERPRINT",
      "Bruce (3 files)",
      "STARTING"
    );
    expect(mockLog).toHaveBeenCalledWith(
      "Sync failed (timed out), but processing 3 Bruce fingerprints locally (hidden 3 | missing 0 | invalid 0).",
      "warn"
    );
  });

  test("syncData emits explicit M5Evil fingerprint feedback when local planning is returned", async () => {
    const ui = loadUiModule();

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: [],
        m5evil: {
          handshakes_seen: 4,
          handshakes_to_process: 2,
          handshakes_hidden_refresh: 1,
          handshakes_missing_details: 1,
          handshakes_invalid_details: 0,
          fingerprint_job_id: "fp-m5-1",
        },
      },
    });

    await ui.__test.syncData();
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "fp-m5-1",
      "FINGERPRINT",
      "M5Evil (2 files)",
      "STARTING"
    );
    expect(mockLog).toHaveBeenCalledWith(
      "Processing 2 M5Evil fingerprints in background (hidden 1 | missing 1 | invalid 0).",
      "info"
    );
  });

  test("syncData creates M5Evil handshake and Wardrive processes for Cardputer sync", async () => {
    const ui = loadUiModule();

    mockAPI.getConfig.mockResolvedValueOnce({
      force_sync: false,
      m5_sync_enabled: true,
    });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: [],
        m5evil_remote_sync: {
          status: "success",
          downloaded_handshakes: 2,
          downloaded_wardrive_csvs: 1,
          handshake_files_to_download: 2,
          wardrive_files_to_download: 1,
          message: "M5Evil remote web sync completed",
        },
      },
    });

    await ui.__test.syncData();

    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      "SYNC",
      "M5Evil handshakes",
      "STARTING"
    );
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      "SYNC",
      "M5Evil Wardrive CSVs",
      "STARTING"
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      0,
      "QUEUED",
      "Queued behind M5Evil handshakes",
      false
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      0,
      "QUEUED",
      "Queued behind M5Evil RAW sniffer",
      false
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      0,
      "QUEUED",
      "Queued behind M5Evil Master Sniffer",
      false
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      100,
      "COMPLETED",
      "2/2",
      false
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      100,
      "COMPLETED",
      "1/1",
      false
    );
  });

  test("syncData queues later Bruce stages behind the active handshake stage", async () => {
    const ui = loadUiModule();

    mockAPI.getConfig.mockResolvedValueOnce({
      force_sync: false,
      bruce_sync_enabled: true,
    });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: [],
        bruce_remote_sync: {
          status: "success",
          downloaded_handshakes: 1,
          downloaded_rawsniffer_pcaps: 2,
          downloaded_wardrive_csvs: 1,
          handshake_files_to_download: 1,
          rawsniffer_files_to_download: 2,
          wardrive_files_to_download: 1,
          message: "Bruce remote web sync completed",
        },
      },
    });

    await ui.__test.syncData();

    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::bruce::"),
      "SYNC",
      "Bruce handshakes",
      "STARTING"
    );
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::bruce::"),
      "SYNC",
      "Bruce raw sniffer",
      "STARTING"
    );
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::bruce::"),
      "SYNC",
      "Bruce Wardrive CSVs",
      "STARTING"
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::bruce::"),
      0,
      "QUEUED",
      "Queued behind Bruce handshakes",
      false
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::bruce::"),
      0,
      "QUEUED",
      "Queued behind Bruce RAW sniffer",
      false
    );
  });

  test("syncData creates and finalizes Pwnagotchi sync process", async () => {
    const ui = loadUiModule();

    mockAPI.getConfig.mockResolvedValueOnce({
      force_sync: false,
      pwn_sync_enabled: true,
    });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: [],
        pwnagotchi_remote_sync: {
          status: "success",
          downloaded_handshakes: 3,
          handshake_files_to_download: 3,
          message: "Pwnagotchi sync completed",
        },
      },
    });

    await ui.__test.syncData();

    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::pwnagotchi::"),
      "SYNC",
      "Pwnagotchi handshakes",
      "STARTING"
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::pwnagotchi::"),
      100,
      "COMPLETED",
      "3/3",
      false
    );
  });

  test("syncData marks M5Evil sync as partial when some files fail", async () => {
    const ui = loadUiModule();

    mockAPI.getConfig.mockResolvedValueOnce({
      force_sync: false,
      m5_sync_enabled: true,
    });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        handshakes: [],
        errors: ["Failed to download wardriving-03.csv: timed out"],
        m5evil_remote_sync: {
          status: "partial",
          downloaded_handshakes: 2,
          downloaded_wardrive_csvs: 3,
          handshake_files_to_download: 2,
          wardrive_files_to_download: 4,
          wardrive_files_failed: 1,
          message: "M5Evil Admin WebUI sync completed with errors",
        },
      },
    });

    await ui.__test.syncData();

    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      expect.stringContaining("sync::m5evil::"),
      100,
      "PARTIAL",
      "3/4 | 1 failed",
      false
    );
  });

  test("syncData covers host key cancel, trust errors, metrics and rawsniffer job", async () => {
    const ui = loadUiModule();

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "error",
      code: "ssh_host_key_mismatch",
      message: "trust required",
      details: {
        host: "10.0.0.2",
        port: 22,
        host_key: {
          host: "10.0.0.2",
          port: 22,
          key_type: "ssh-ed25519",
          fingerprint_sha256: "SHA256:new",
        },
        expected_host_key: { fingerprint_sha256: "SHA256:prev" },
      },
    });
    window.confirm.mockReturnValueOnce(false);
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith("Sync canceled: host key was not trusted.", "info");
    expect(mockAPI.trustHostKey).not.toHaveBeenCalled();

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "error",
      code: "ssh_host_key_not_trusted",
      message: "trust required",
      details: {
        host: "10.0.0.3",
        port: 22,
        host_key: { host: "10.0.0.3", port: 22, key_type: "ssh-ed25519", fingerprint_md5: "MD5:abc" },
      },
    });
    mockAPI.trustHostKey.mockResolvedValueOnce({ status: "error", message: "nope" });
    window.confirm.mockReturnValueOnce(true);
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith("Host key trust failed: nope", "error");

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync
      .mockResolvedValueOnce({
        status: "error",
        code: "ssh_host_key_not_trusted",
        message: "trust required",
        details: { host: "10.0.0.4", port: 22, host_key: { host: "10.0.0.4", port: 22 } },
      })
      .mockResolvedValueOnce({ status: "error", message: "retry failed", details: {} });
    mockAPI.trustHostKey.mockResolvedValueOnce({ status: "success", message: "ok" });
    window.confirm.mockReturnValueOnce(true);
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith("Sync Error: retry failed", "error");

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "error",
      message: "timeout",
      details: {
        sync_stages: { remote_sync: { status: "failed", message: "timeout" } },
        metrics: { remote_sync_ms: 123, fingerprint_plan_ms: 1, fingerprint_queue_ms: 2, rawsniffer_queue_ms: 3 },
        rawsniffer: { job_id: "raw-1", files_to_process: 2 },
        handshakes: [],
        errors: [],
      },
    });
    await ui.__test.syncData();
    expect(mockProcesses.addProcess).toHaveBeenCalledWith("raw-1", "RAW SNIFFER", "RAW unified (2 files)", "STARTING");
    expect(mockLog).toHaveBeenCalledWith(expect.stringContaining("Sync stage remote: failed"), "warn");
    expect(mockLog).toHaveBeenCalledWith(expect.stringContaining("Sync timings: remote 123ms"), "info");

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "error",
      code: "ssh_host_key_not_trusted",
      message: "trust required",
      details: { host: "10.0.0.6", port: 22, host_key: { host: "10.0.0.6", port: 22 } },
    });
    mockAPI.trustHostKey.mockRejectedValueOnce(new Error("trust down"));
    window.confirm.mockReturnValueOnce(true);
    await ui.__test.syncData();
    expect(mockLog).toHaveBeenCalledWith("Host key trust failed: trust down", "error");

    mockAPI.getConfig.mockResolvedValueOnce({ force_sync: false });
    mockAPI.sync.mockResolvedValueOnce({
      status: "success",
      message: "ok",
      details: {
        rawsniffer: { job_id: "raw-ok", files_to_process: 3 },
        handshakes: [],
        errors: [],
      },
    });
    await ui.__test.syncData();
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "raw-ok",
      "RAW SNIFFER",
      "RAW unified (3 files)",
      "STARTING"
    );
    expect(mockLog).toHaveBeenCalledWith(
      "Processing 3 RAW PCAP files in background...",
      "info"
    );
  });

  test("multi helpers cover success and failures", async () => {
    const ui = loadUiModule();

    mockState.allPositions = {
      "AA:AA:AA:AA:AA:AA": { mac: "AA:AA:AA:AA:AA:AA", handshake_files: ["a.pcap"], ssid: "SSID-A" },
      "BB:BB:BB:BB:BB:BB": { mac: "BB:BB:BB:BB:BB:BB", handshake_files: [], ssid: "SSID-B" },
    };

    await ui.__test.handleMultiCreate();
    expect(mockLog).toHaveBeenCalledWith("Select at least one network to create a multi file.", "warn");

    mockState.multiSelection = ["BB:BB:BB:BB:BB:BB"];
    await ui.__test.handleMultiCreate();
    expect(mockLog).toHaveBeenCalledWith("No PCAP files found for selected networks.", "error");

    mockState.multiSelection = ["AA:AA:AA:AA:AA:AA"];
    mockAPI.convertMultiPcaps.mockResolvedValueOnce({ status: "started", job_id: "m1", output_file: "batch_x.22000" });
    await ui.__test.handleMultiCreate();
    expect(mockProcesses.addProcess).toHaveBeenCalledWith("m1", "MULTI CONVERSION", "batch_x.22000", "STARTING");
    expect(mockState.multiSelection).toEqual([]);

    mockState.multiSelection = ["AA:AA:AA:AA:AA:AA"];
    mockAPI.convertMultiPcaps.mockResolvedValueOnce({ status: "error", message: "bad" });
    await ui.__test.handleMultiCreate();
    expect(mockLog).toHaveBeenCalledWith("Multi conversion failed to start: bad", "error");

    mockState.multiSelection = ["AA:AA:AA:AA:AA:AA"];
    mockAPI.convertMultiPcaps.mockRejectedValueOnce(new Error("network"));
    await ui.__test.handleMultiCreate();
    expect(mockLog).toHaveBeenCalledWith("Multi conversion error: network", "error");

    await ui.__test.refreshMultiFiles();
    expect(mockLists.updateMultiFilesList).toHaveBeenCalled();

    mockAPI.listMultiFiles.mockRejectedValueOnce(new Error("x"));
    await ui.__test.refreshMultiFiles();

    mockAPI.getMultiFileContent.mockResolvedValueOnce({ items: [{ ssid: "S" }] });
    await ui.__test.loadMultiContents("batch.22000");
    expect(mockState.multiFileContents["batch.22000"]).toEqual([{ ssid: "S" }]);

    mockAPI.getMultiFileContent.mockRejectedValueOnce(new Error("y"));
    await ui.__test.loadMultiContents("batch_fail.22000");
    expect(mockState.multiFileContents["batch_fail.22000"]).toEqual([]);

    ui.__test.handleMultiClear();
    expect(mockState.multiSelection).toEqual([]);
    expect(mockLists.updateMultiList).toHaveBeenCalled();
  });

  test("initUI restores active panel modes on startup", async () => {
    mockState.modes = {
      radar: false,
      heat: false,
      zones: true,
      conquered: true,
      toConquer: true,
      targets: true,
      favs: true,
      cracking: true,
      process: true,
      logs: true,
      noGps: true,
      multi: true,
    };

    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    expect(document.getElementById("btn-zones").classList.contains("active")).toBe(true);
    expect(document.getElementById("zones-panel").style.display).toBe("flex");
    expect(document.getElementById("btn-conquered").classList.contains("active")).toBe(true);
    expect(document.getElementById("btn-targets").classList.contains("active")).toBe(true);
    expect(document.getElementById("targets-panel").style.display).toBe("flex");
    expect(document.getElementById("btn-favs").classList.contains("active")).toBe(true);
    expect(document.getElementById("favorites-panel").style.display).toBe("flex");
    expect(document.getElementById("btn-toggle-cracking").classList.contains("active")).toBe(true);
    expect(document.getElementById("cracking-panel").style.display).toBe("flex");
    expect(document.getElementById("btn-process").classList.contains("active")).toBe(true);
    expect(document.getElementById("process-panel").style.display).toBe("flex");
    expect(document.getElementById("btn-logs").classList.contains("active")).toBe(true);
    expect(document.getElementById("log-panel").style.display).toBe("block");
    const rightPanels = document.querySelector(".right-panels-container");
    expect(rightPanels.classList.contains("right-panels--has-cracking")).toBe(true);
    expect(rightPanels.classList.contains("right-panels--has-process")).toBe(true);
    expect(rightPanels.classList.contains("right-panels--has-logs")).toBe(true);
    expect(rightPanels.classList.contains("right-panels--only-cracking")).toBe(false);
    expect(rightPanels.classList.contains("right-panels--only-process")).toBe(false);
    expect(rightPanels.classList.contains("right-panels--only-logs")).toBe(false);
    expect(document.getElementById("btn-no-gps-view").classList.contains("active")).toBe(true);
    expect(document.getElementById("btn-multi-view").classList.contains("active")).toBe(true);
    expect(mockProcesses.renderProcessList).toHaveBeenCalled();
  });

  test("multi list listeners cover change/click and shift-range branches", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const multiList = document.getElementById("multi-all-list");
    multiList.innerHTML = `
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:01" type="checkbox"></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:02" type="checkbox"></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:03" type="checkbox"></div>
    `;

    const checks = multiList.querySelectorAll(".multi-select-chk");
    checks[0].checked = true;
    checks[0].dispatchEvent(new Event("change", { bubbles: true }));
    expect(mockState.multiSelection).toContain("AA:AA:AA:AA:AA:01");

    // non-shift path toggles one row
    checks[1].closest(".list-item").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockState.multiSelection).toContain("AA:AA:AA:AA:AA:02");

    // shift path selects range
    mockState.multiLastClickedMac = "AA:AA:AA:AA:AA:01";
    checks[2].closest(".list-item").dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true }));
    expect(mockState.multiSelection).toContain("AA:AA:AA:AA:AA:03");
    expect(mockLists.updateMultiList).toHaveBeenCalled();
  });

  test("multi files listener covers delete success/failure/error and item open", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const filesList = document.getElementById("multi-files-list");
    filesList.innerHTML = `
      <div class="list-item" data-name="batch_1.22000">
        <button class="multi-delete" data-name="batch_1.22000"></button>
      </div>
      <div class="list-item" data-name="batch_2.22000"></div>
    `;

    mockState.multiSelectedFile = "batch_1.22000";

    mockAPI.deleteMultiFile.mockResolvedValueOnce({ deleted: true });
    filesList.querySelector(".multi-delete").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    await flushAsync();
    expect(mockLog).toHaveBeenCalledWith("Multi file deleted: batch_1.22000", "success");

    mockAPI.deleteMultiFile.mockResolvedValueOnce({ deleted: false, message: "denied" });
    filesList.querySelector(".multi-delete").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    await flushAsync();
    expect(mockLog).toHaveBeenCalledWith("Failed to delete multi file: denied", "error");

    mockAPI.deleteMultiFile.mockRejectedValueOnce(new Error("boom"));
    filesList.querySelector(".multi-delete").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    await flushAsync();
    expect(mockLog).toHaveBeenCalledWith("Delete error: boom", "error");

    const secondItem = filesList.querySelector('[data-name="batch_2.22000"]');
    secondItem.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    await flushAsync();
    expect(mockCracking.openMultiCrackingPanel).toHaveBeenCalledWith("batch_2.22000");
  });

  test("socket job_complete covers aircrack, success-exhausted and conversion_multi branches", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const jobComplete = getSocketHandler("job_complete");
    expect(jobComplete).toBeTruthy();

    mockActiveProcesses["a1"] = { type: "AIRCRACK-NG", status: "RUNNING", details: "a.pcap" };
    jobComplete({ id: "a1", status: "success", type: "aircrack", progress_data: { stage: "EXHAUSTED" } });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("a1", 100, "EXHAUSTED", "Password not found");

    mockActiveProcesses["a2"] = { type: "AIRCRACK-NG", status: "RUNNING", details: "a.pcap" };
    jobComplete({ id: "a2", status: "success", type: "aircrack", progress_data: { stage: "CRACKED" } });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("a2", 100, "CRACKED");

    mockActiveProcesses["h1"] = { type: "HASHCAT", status: "RUNNING", details: "h.22000" };
    jobComplete({ id: "h1", status: "success", type: "cracking", progress_data: { stage: "EXHAUSTED" } });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("h1", 100, "EXHAUSTED", "Password not found");

    mockActiveProcesses["m1"] = { type: "MULTI CONVERSION", status: "RUNNING", details: "batch.22000" };
    jobComplete({ id: "m1", status: "failed", type: "conversion_multi", progress_data: { stage: "ERROR" } });
    expect(mockAPI.listMultiFiles).toHaveBeenCalled();

    const rawCalls = mockAPI.listRawSnifferFiles.mock.calls.length;
    jobComplete({ id: "raw1", status: "success", type: "rawsniffer_multi", progress_data: {} });
    expect(mockAPI.listRawSnifferFiles.mock.calls.length).toBeGreaterThan(rawCalls);

    mockActiveProcesses["fp-job::file1"] = { type: "FINGERPRINT", status: "RUNNING", details: "file1" };
    mockActiveProcesses["fp-job::file2"] = { type: "FINGERPRINT", status: "RUNNING", details: "file2" };
    jobComplete({
      id: "fp-job",
      status: "success",
      type: "fingerprint_multi",
      progress_data: {
        items: [
          { file: "file1", status: "success", details_count: 2 },
          { file: "file2", status: "skipped", reason: "ignored" },
        ],
      },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("fp-job::file1", 100, "SUCCESS", "2 details", false);
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("fp-job::file2", 100, "SKIPPED", "ignored", false);
  });

  test("initUI applies tile layer and top-bars resize sync debounce", async () => {
    const setTileLayer = jest.fn();
    window.setTileLayer = setTileLayer;

    const left = document.querySelector(".controls-row");
    const right = document.querySelector(".stats-container-wrapper");
    Object.defineProperty(left, "offsetHeight", { configurable: true, get: () => 24 });
    Object.defineProperty(right, "offsetHeight", { configurable: true, get: () => 42 });

    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    expect(setTileLayer).toHaveBeenCalledWith("osm");
    expect(left.style.height).toBe("42px");
    expect(right.style.height).toBe("42px");

    window.dispatchEvent(new Event("resize"));
    window.dispatchEvent(new Event("resize"));
    jest.advanceTimersByTime(149);
    jest.advanceTimersByTime(1);
    expect(left.style.height).toBe("42px");
    expect(right.style.height).toBe("42px");
  });

  test("initUI logs config load failures", async () => {
    const ui = loadUiModule();
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    mockAPI.getConfig.mockRejectedValueOnce(new Error("cfg-err"));

    ui.initUI();
    await flushAsync();

    expect(errorSpy).toHaveBeenCalledWith("Failed to load config", expect.any(Error));
    errorSpy.mockRestore();
  });

  test("initUI honors raw mode on load", async () => {
    mockState.modes.raw = true;
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    expect(document.getElementById("btn-raw-view").classList.contains("active")).toBe(true);
    expect(document.getElementById("raw-panel").style.display).toBe("flex");
    expect(mockAPI.listRawSnifferFiles).toHaveBeenCalled();
  });

  test("initUI honors analytics mode on load", async () => {
    mockState.modes.analytics = true;
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    expect(document.getElementById("btn-analytics-view").classList.contains("active")).toBe(true);
    expect(document.getElementById("analytics-panel").style.display).toBe("flex");
  });

  test("analytics time window select remains unchanged by ui module init", async () => {
    mockState.modes.analytics = true;
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const timeWindowSelect = document.getElementById("analytics-time-window-select");
    timeWindowSelect.value = "all";
    timeWindowSelect.dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();
    expect(mockState.filters.time).toBe("ALL");
    expect(mockState.analyticsUi.timeWindow).toBe("all");

    timeWindowSelect.value = "24h";
    timeWindowSelect.dispatchEvent(new Event("change", { bubbles: true }));
    await flushAsync();
    expect(mockState.filters.time).toBe("ALL");
    expect(mockState.analyticsUi.timeWindow).toBe("all");
  });

  test("exitAnalyticsView event clears analytics mode and layers", async () => {
    mockState.modes.analytics = true;
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    document.dispatchEvent(new Event("exitAnalyticsView"));
    expect(mockState.modes.analytics).toBe(false);
    expect(mockMap.clearAnalyticsHeatmapLayer).toHaveBeenCalled();
    expect(mockMap.clearAnalyticsHotspotsLayer).toHaveBeenCalled();
  });

  test("clear details/cache actions refresh data and handle failures", async () => {
    mockState.modes.raw = true;
    mockState.modes.analytics = true;
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    window.confirm.mockReturnValueOnce(true);
    mockAPI.clearDetailsFiles.mockResolvedValueOnce({ deleted_count: 3, failed_count: 1 });
    document.getElementById("btn-clear-details").click();
    await flushAsync();
    expect(mockAPI.clearDetailsFiles).toHaveBeenCalled();
    expect(mockMap.clearDetailsCache).toHaveBeenCalled();
    expect(mockAPI.listRawSnifferFiles).toHaveBeenCalled();
    expect(mockLog).toHaveBeenCalledWith(
      "Details cleanup complete: deleted 3 | failed 1.",
      "warn"
    );

    window.confirm.mockReturnValueOnce(true);
    mockAPI.clearDetailsFiles.mockRejectedValueOnce(new Error("details-down"));
    document.getElementById("btn-clear-details").click();
    await flushAsync();
    expect(mockLog).toHaveBeenCalledWith("Failed to clear details: details-down", "error");

    window.confirm.mockReturnValueOnce(true);
    mockAPI.clearCache.mockResolvedValueOnce({ raw_metadata_deleted_count: 2, raw_metadata_failed_count: 1 });
    document.getElementById("btn-clear-cache").click();
    await flushAsync();
    expect(mockAPI.clearCache).toHaveBeenCalled();
    expect(mockLog).toHaveBeenCalledWith(
      "Cache cleanup complete: raw metadata deleted 2 | failed 1.",
      "warn"
    );

    window.confirm.mockReturnValueOnce(true);
    mockAPI.clearCache.mockRejectedValueOnce(new Error("cache-down"));
    document.getElementById("btn-clear-cache").click();
    await flushAsync();
    expect(mockLog).toHaveBeenCalledWith("Failed to clear cache: cache-down", "error");
  });

  test("socket branches cover idle reload, job_update active and aircrack canceled", async () => {
    mockAPI.getStatus.mockResolvedValueOnce({ status: "busy", message: "warming" });
    mockAPI.getMapData.mockResolvedValue({ A: { mac: "AA", ssid: "One", lat: 1, lng: 2 } });
    const ui = loadUiModule();

    ui.initUI();
    await flushAsync();

    await ui.__test.loadData();
    expect(mockAPI.getMapData).toHaveBeenCalledTimes(1);

    mockState.isCrackingActive = true;
    const dataCb = getSocketHandler("data_update");
    dataCb("map_data");
    jest.advanceTimersByTime(800);
    expect(mockAPI.getMapData).toHaveBeenCalledTimes(1);

    mockState.isCrackingActive = false;
    jest.advanceTimersByTime(1500);
    jest.advanceTimersByTime(800);
    await flushAsync();
    expect(mockAPI.getMapData).toHaveBeenCalledTimes(2);

    mockActiveProcesses["j-up"] = { type: "HASHCAT", status: "RUNNING", details: "cap.22000" };
    const updateCb = getSocketHandler("job_update");
    updateCb({ id: "j-up", status: "queued", progress_data: { percentage: 7 } });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("j-up", 7, "QUEUED");

    updateCb({
      id: "raw-multi",
      status: "running",
      type: "rawsniffer_multi",
      progress_data: { percentage: 20, total_steps: 3, stage: "PROCESSING", extra: "step" },
    });
    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "raw-multi",
      "RAW SNIFFER",
      "Process 3 files",
      "RUNNING"
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "raw-multi",
      20,
      "PROCESSING",
      "step",
      false
    );

    mockActiveProcesses["j-air"] = { type: "AIRCRACK-NG", status: "RUNNING", details: "cap.pcap" };
    const completeCb = getSocketHandler("job_complete");
    completeCb({ id: "j-air", status: "canceled", type: "aircrack", progress_data: { stage: "ERROR" } });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("j-air", 100, "CANCELED");
    expect(mockLog).toHaveBeenCalledWith("Job aircrack canceled.", "warn");
  });

  test("multi selection fallback and multi filter buttons cover remaining branches", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const multiList = document.getElementById("multi-all-list");
    multiList.innerHTML = `
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:01" type="checkbox" checked></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:02" type="checkbox"></div>
    `;

    mockState.multiSelection = ["AA:AA:AA:AA:AA:01"];
    const firstChk = multiList.querySelector('.multi-select-chk[data-mac="AA:AA:AA:AA:AA:01"]');
    firstChk.checked = false;
    firstChk.dispatchEvent(new Event("change", { bubbles: true }));
    expect(mockState.multiSelection).toEqual([]);

    mockState.multiLastClickedMac = "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ";
    const secondRow = multiList.querySelector('.multi-select-chk[data-mac="AA:AA:AA:AA:AA:02"]').closest(".list-item");
    secondRow.dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true }));
    expect(mockState.multiSelection).toContain("AA:AA:AA:AA:AA:02");

    document.getElementById("btn-multi-filter-all").click();
    expect(mockState.multiFilter).toBe("all");
    expect(document.getElementById("btn-multi-filter-all").classList.contains("active")).toBe(true);

    document.getElementById("btn-multi-filter-locked").click();
    expect(mockState.multiFilter).toBe("locked");
    expect(document.getElementById("btn-multi-filter-locked").classList.contains("active")).toBe(true);

    const multiSearch = document.getElementById("multi-filter-search");
    multiSearch.value = "ward";
    multiSearch.dispatchEvent(new Event("input", { bubbles: true }));
    expect(mockState.multiUi.search).toBe("ward");

    const multiLocation = document.getElementById("multi-filter-location");
    multiLocation.value = "no-gps";
    multiLocation.dispatchEvent(new Event("change", { bubbles: true }));
    expect(mockState.multiUi.location).toBe("no-gps");

    const multiSource = document.getElementById("multi-filter-source");
    multiSource.value = "raw";
    multiSource.dispatchEvent(new Event("change", { bubbles: true }));
    expect(mockState.multiUi.source).toBe("raw");

    const multiArtifact = document.getElementById("multi-filter-artifact");
    multiArtifact.value = "has_22000";
    multiArtifact.dispatchEvent(new Event("change", { bubbles: true }));
    expect(mockState.multiUi.artifact).toBe("has_22000");
  });

  test("socket no-op branches and non-reset title branch are handled", async () => {
    const ui = loadUiModule();
    mockProcesses.getActiveHashcatJob.mockReturnValue({ id: "still-running" });
    ui.initUI();
    await flushAsync();

    const dataCb = getSocketHandler("data_update");
    const progressCb = getSocketHandler("job_progress");
    const updateCb = getSocketHandler("job_update");
    const completeCb = getSocketHandler("job_complete");

    dataCb("other_payload");
    progressCb({ job_id: "unknown", data: { stage: "QUEUED" } });
    updateCb({ id: "unknown", status: "queued", progress_data: { percentage: 0 } });
    completeCb({ id: "unknown", status: "success", type: "aircrack", progress_data: { stage: "CRACKED" } });

    expect(mockProcesses.updateProcess).not.toHaveBeenCalledWith("unknown", expect.anything(), expect.anything());
    expect(document.title).toContain("KOVIL MAP");
  });

  test("socket job_progress updates title and progress bar for hashcat jobs", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    mockActiveProcesses["job-hash"] = { type: "HASHCAT", status: "RUNNING", details: "hash.22000" };
    const progressCb = getSocketHandler("job_progress");

    progressCb({
      job_id: "job-hash",
      data: { percentage: 25, stage: "RUNNING", extra: "1.2MH/s", eta: "1m" },
    });

    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "job-hash",
      25,
      "RUNNING",
      expect.stringContaining("ETA"),
      false
    );
    expect(mockPlatform.setProgressBar).toHaveBeenCalledWith(0.25, "normal");
    expect(document.title).toContain("CONQUERING 25%");
    expect(document.querySelector("#title-bar .app-title").textContent).toContain("CONQUERING 25%");

    progressCb({
      job_id: "job-hash",
      data: { percentage: 0, stage: "RUNNING", extra: "", eta: "" },
    });
    expect(mockPlatform.setProgressBar).toHaveBeenCalledWith(0, "indeterminate");
  });

  test("socket job_progress formats sparse extra info without empty pipe segments", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    mockActiveProcesses["job-sync"] = { type: "SYNC", status: "RUNNING", details: "M5Evil handshakes" };
    const progressCb = getSocketHandler("job_progress");

    progressCb({
      job_id: "job-sync",
      data: { percentage: 60, stage: "RUNNING", extra: "HS_A.pcap [1.0 KB / 2.0 KB]" },
    });

    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "job-sync",
      60,
      "RUNNING",
      "HS_A.pcap [1.0 KB / 2.0 KB]",
      false
    );
  });

  test("socket job_update and fingerprint finalize errors are caught", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    const updateCb = getSocketHandler("job_update");
    mockProcesses.addProcess.mockImplementationOnce(() => {
      throw new Error("add-fail");
    });
    updateCb({ id: "bad-job", status: "running", type: "custom", progress_data: { percentage: 5 } });
    expect(errSpy).toHaveBeenCalledWith("Failed to add job from job_update:", expect.any(Error));

    mockActiveProcesses["fp-parent::file1.pcap"] = { type: "FINGERPRINT", status: "RUNNING" };
    mockProcesses.updateProcess.mockImplementationOnce(() => {
      throw new Error("finalize-fail");
    });
    const completeCb = getSocketHandler("job_complete");
    completeCb({
      id: "fp-parent",
      status: "success",
      type: "fingerprint_multi",
      progress_data: { items: [{ file: "file1.pcap", status: "success", details_count: 2 }] },
    });
    expect(errSpy).toHaveBeenCalledWith("Failed to finalize fingerprint child entries:", expect.any(Error));
    errSpy.mockRestore();
  });

  test("socket job_update handles fingerprint and generic job branches", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const updateCb = getSocketHandler("job_update");
    updateCb({
      id: "fp-job",
      status: "running",
      type: "fingerprint_multi",
      meta: { files_to_process: ["a.pcap", "b.pcap"] },
      progress_data: { percentage: 12, total_steps: 2, stage: "PROCESSING", extra: "step" },
    });

    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "fp-job",
      "BRUCE PCAP IMPORT",
      "Import 2 files",
      "RUNNING"
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "fp-job",
      12,
      "PROCESSING",
      "step",
      false
    );

    updateCb({
      id: "generic-job",
      status: "queued",
      type: null,
      meta: { output_file: "out.22000" },
    });

    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "generic-job",
      "GENERIC",
      "out.22000",
      "QUEUED"
    );
  });

  test("socket job_update formats raw_prepare_all jobs with and without a BSSID", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const updateCb = getSocketHandler("job_update");

    updateCb({
      id: "prep-1",
      status: "running",
      type: "raw_prepare_all",
      meta: {
        bssid: "aa:bb:cc:dd:ee:ff",
        files_to_process: ["a.pcap", "b.pcap"],
      },
      progress_data: {},
    });

    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "prep-1",
      "RAW SNIFFER PREPARE ALL",
      "aa:bb:cc:dd:ee:ff (2 files)",
      "RUNNING",
      "aa:bb:cc:dd:ee:ff"
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "prep-1",
      0,
      "RUNNING",
      "aa:bb:cc:dd:ee:ff (2 files)",
      false
    );

    mockProcesses.addProcess.mockClear();
    mockProcesses.updateProcess.mockClear();

    updateCb({
      id: "prep-2",
      status: "queued",
      type: "raw_prepare_all",
      meta: {},
      progress_data: {
        total_steps: 3,
        extra: "fallback details",
      },
    });

    expect(mockProcesses.addProcess).toHaveBeenCalledWith(
      "prep-2",
      "RAW SNIFFER PREPARE ALL",
      "Process 3 files",
      "QUEUED"
    );
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "prep-2",
      0,
      "QUEUED",
      "fallback details",
      false
    );
  });

  test("socket job_complete covers aircrack and success exhausted branches", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const completeCb = getSocketHandler("job_complete");
    mockActiveProcesses["air-exh"] = { type: "AIRCRACK-NG", status: "RUNNING", details: "cap.pcap" };
    completeCb({
      id: "air-exh",
      status: "success",
      type: "aircrack",
      progress_data: { stage: "EXHAUSTED" },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("air-exh", 100, "EXHAUSTED", "Password not found");
    expect(mockLog).toHaveBeenCalledWith("Job aircrack finished: Password not found.", "warn");

    mockActiveProcesses["air-cracked"] = { type: "AIRCRACK-NG", status: "RUNNING", details: "cap2.pcap" };
    completeCb({
      id: "air-cracked",
      status: "success",
      type: "aircrack",
      progress_data: { stage: "CRACKED" },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("air-cracked", 100, "CRACKED");
    expect(mockLog).toHaveBeenCalledWith("Job aircrack finished: Password found.", "success");
    expect(mockProcesses.handleJobCompletionSideEffects).toHaveBeenCalled();

    mockActiveProcesses["hash-exh"] = { type: "HASHCAT", status: "RUNNING", details: "hash.22000" };
    completeCb({
      id: "hash-exh",
      status: "success",
      type: "cracking",
      progress_data: { stage: "EXHAUSTED" },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("hash-exh", 100, "EXHAUSTED", "Password not found");
    expect(mockLog).toHaveBeenCalledWith("Job cracking finished: Password not found.", "warn");
  });

  test("socket job_complete refreshes lists and updates fingerprint children", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const completeCb = getSocketHandler("job_complete");
    mockAPI.listMultiFiles.mockResolvedValueOnce([]);
    mockAPI.listRawSnifferFiles.mockResolvedValueOnce([]);
    mockAPI.getRawSnifferHashes.mockResolvedValueOnce([]);

    mockActiveProcesses["fp-parent::file1.pcap"] = { type: "FINGERPRINT", status: "RUNNING" };
    completeCb({
      id: "fp-parent",
      status: "success",
      type: "fingerprint_multi",
      progress_data: { items: [{ file: "file1.pcap", status: "success", details_count: 2 }] },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "fp-parent::file1.pcap",
      100,
      "SUCCESS",
      "2 details",
      false
    );

    completeCb({ id: "conv-job", status: "failed", type: "conversion_multi", progress_data: {} });
    completeCb({ id: "raw-job", status: "failed", type: "rawsniffer_multi", progress_data: {} });
    await flushAsync();

    expect(mockAPI.listMultiFiles).toHaveBeenCalled();
    expect(mockAPI.listRawSnifferFiles).toHaveBeenCalled();
  });

  test("socket job_complete dispatches rawPrepareAllComplete details for partial, up-to-date and fallback statuses", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const completeCb = getSocketHandler("job_complete");
    const events = [];
    document.addEventListener("rawPrepareAllComplete", (event) => events.push(event.detail));

    completeCb({
      id: "prep-partial",
      status: "success",
      type: "raw_prepare_all",
      progress_data: {
        stage: "PARTIAL",
        processed: 4,
        succeeded: 3,
        failed: 1,
      },
      meta: {
        bssid: "aa:bb:cc:dd:ee:ff",
      },
    });

    completeCb({
      id: "prep-current",
      status: "success",
      type: "raw_prepare_all",
      progress_data: {
        stage: "UP TO DATE",
      },
      meta: {
        bssid: "11:22:33:44:55:66",
        raw_prepare_summary: {
          processed: 2,
          succeeded: 2,
          failed: 0,
          canonical_hash: "canon-1",
        },
      },
    });

    completeCb({
      id: "prep-failed",
      status: "failed",
      type: "raw_prepare_all",
      progress_data: {
        processed: 1,
        succeeded: 0,
        failed: 1,
      },
      meta: {
        bssid: "22:33:44:55:66:77",
      },
    });

    expect(events).toEqual([
      {
        mac: "AA:BB:CC:DD:EE:FF",
        status: "success_partial",
        canonical_hash: null,
        summary: "3/4 source files processed (1 failed)",
      },
      {
        mac: "11:22:33:44:55:66",
        status: "up_to_date",
        canonical_hash: "canon-1",
        summary: "2/2 source files processed",
      },
      {
        mac: "22:33:44:55:66:77",
        status: "failed",
        canonical_hash: null,
        summary: "0/1 source files processed (1 failed)",
      },
    ]);
  });

  test("multi list/file early-return branches and filter keyup non-enter path", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    const multiList = document.getElementById("multi-all-list");
    multiList.innerHTML = `
      <div class="list-item"><span class="no-checkbox">x</span></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="" type="checkbox"></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:01" type="checkbox" disabled></div>
    `;
    multiList.querySelector(".no-checkbox").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    multiList.querySelector('[data-mac=""]').closest(".list-item").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    multiList.querySelector('[data-mac="AA:AA:AA:AA:AA:01"]').closest(".list-item").dispatchEvent(new MouseEvent("click", { bubbles: true }));

    const filesList = document.getElementById("multi-files-list");
    filesList.innerHTML = `
      <div class="list-item"><button class="multi-delete"></button></div>
      <div class="list-item"></div>
    `;
    filesList.querySelector(".multi-delete").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    filesList.querySelectorAll(".list-item")[1].dispatchEvent(new MouseEvent("click", { bubbles: true }));
    await flushAsync();

    mockState.modes.noGps = true;
    mockState.modes.multi = true;
    const filter = document.getElementById("filter-input");
    filter.value = "abc";
    filter.dispatchEvent(new Event("input", { bubbles: true }));
    filter.dispatchEvent(new KeyboardEvent("keyup", { key: "a", bubbles: true }));
    expect(mockLists.updateNoGpsList).toHaveBeenCalled();
    expect(mockLists.updateMultiList).toHaveBeenCalled();
  });

  test("analytics view opens recon workspace", async () => {
    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    document.getElementById("btn-analytics-view").click();
    await flushAsync();

    expect(mockState.modes.analytics).toBe(true);
    expect(document.getElementById("analytics-panel").style.display).toBe("flex");
    expect(document.getElementById("no-gps-panel").style.display).toBe("none");
    expect(document.getElementById("multi-panel").style.display).toBe("none");
    expect(document.getElementById("raw-panel").style.display).toBe("none");
    expect(document.getElementById("btn-map-view").classList.contains("active")).toBe(false);
    expect(document.getElementById("btn-analytics-view").classList.contains("active")).toBe(true);
  });

  test("analytics view preserves side panels and map view exits recon workspace", async () => {
    mockState.modes.zones = true;
    mockState.modes.targets = true;
    mockState.modes.favs = true;
    mockState.modes.cracking = true;
    mockState.modes.process = true;
    mockState.modes.logs = true;

    const ui = loadUiModule();
    ui.initUI();
    await flushAsync();

    document.getElementById("btn-analytics-view").click();
    await flushAsync();

    expect(document.getElementById("analytics-panel").style.display).toBe("flex");
    expect(document.getElementById("zones-panel").style.display).toBe("flex");
    expect(document.getElementById("targets-panel").style.display).toBe("flex");
    expect(document.getElementById("favorites-panel").style.display).toBe("flex");
    expect(document.getElementById("cracking-panel").style.display).toBe("flex");
    expect(document.getElementById("process-panel").style.display).toBe("flex");
    expect(document.getElementById("log-panel").style.display).toBe("block");
    expect(document.getElementById("btn-toggle-cracking").disabled).toBe(false);
    expect(document.getElementById("btn-process").disabled).toBe(false);
    expect(document.getElementById("btn-logs").disabled).toBe(false);
    expect(document.getElementById("btn-zones").disabled).toBe(false);
    expect(document.getElementById("btn-targets").disabled).toBe(false);
    expect(document.getElementById("btn-favs").disabled).toBe(false);

    document.getElementById("btn-map-view").click();
    await flushAsync();

    expect(mockState.modes.analytics).toBe(false);
    expect(document.getElementById("analytics-panel").style.display).toBe("none");
    expect(document.getElementById("zones-panel").style.display).toBe("flex");
    expect(document.getElementById("targets-panel").style.display).toBe("flex");
    expect(document.getElementById("favorites-panel").style.display).toBe("flex");
    expect(document.getElementById("cracking-panel").style.display).toBe("flex");
    expect(document.getElementById("process-panel").style.display).toBe("flex");
    expect(document.getElementById("log-panel").style.display).toBe("block");
    expect(document.getElementById("btn-toggle-cracking").disabled).toBe(false);
    expect(document.getElementById("btn-process").disabled).toBe(false);
    expect(document.getElementById("btn-logs").disabled).toBe(false);
    expect(document.getElementById("btn-zones").disabled).toBe(false);
    expect(document.getElementById("btn-targets").disabled).toBe(false);
    expect(document.getElementById("btn-favs").disabled).toBe(false);
    expect(mockMap.clearAnalyticsHotspotsLayer).toHaveBeenCalled();
  });

  test("init and socket cover sparse config branches and progress without speed/eta/extra", async () => {
    mockState.modes.process = true;
    mockActiveProcesses["seed"] = { type: "HASHCAT", status: "RUNNING", details: "x.22000" };
    mockAPI.getConfig.mockResolvedValueOnce({});
    mockAPI.getStatus.mockResolvedValueOnce({ status: "ready", message: "ok" });

    const ui = loadUiModule();
    delete window.setTileLayer;
    ui.initUI();
    await flushAsync();

    expect(mockProcesses.renderProcessList).not.toHaveBeenCalled();
    expect(mockApplyTheme).toHaveBeenCalled();
    expect(mockMap.setMarkerIcons).toHaveBeenCalled();

    const progressCb = getSocketHandler("job_progress");
    mockActiveProcesses["job-lite"] = { type: "HASHCAT", status: "RUNNING", details: "hash.22000" };
    progressCb({
      job_id: "job-lite",
      data: { percentage: 100, stage: "RUNNING" },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith(
      "job-lite",
      100,
      "RUNNING",
      "",
      true
    );

    const completeCb = getSocketHandler("job_complete");
    completeCb({
      id: "job-lite",
      status: "failed",
      type: "cracking",
      progress_data: { stage: "ERROR" },
    });
    expect(mockProcesses.updateProcess).toHaveBeenCalledWith("job-lite", 100, "FAILED");
    expect(mockLog).toHaveBeenCalledWith("Job cracking failed.", "error");
  });
});
