const mockAPI = {
  getAnalyticsHeatmap: jest.fn(),
  getAnalyticsChannelSummary: jest.fn(),
  getAnalyticsHotspots: jest.fn(),
};

const mockLog = jest.fn();
const mockSetAnalyticsHeatmapLayer = jest.fn();
const mockClearAnalyticsHeatmapLayer = jest.fn();
const mockSetAnalyticsHotspotsLayer = jest.fn();
const mockClearAnalyticsHotspotsLayer = jest.fn();
const mockSetSelectedAnalyticsHotspot = jest.fn();
const mockFocusAnalyticsHotspot = jest.fn();
const mockSaveLists = jest.fn();

const mockState = {
  ui: {},
  modes: {
    zones: false,
    targets: false,
    favs: false,
    cracking: false,
    process: false,
    logs: false,
    analytics: true,
  },
  filters: { time: "ALL" },
  lists: { targets: [] },
  analyticsUi: null,
};

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
  escapeHtml: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/map.js", () => ({
  setAnalyticsHeatmapLayer: (...args) => mockSetAnalyticsHeatmapLayer(...args),
  clearAnalyticsHeatmapLayer: (...args) => mockClearAnalyticsHeatmapLayer(...args),
  setAnalyticsHotspotsLayer: (...args) => mockSetAnalyticsHotspotsLayer(...args),
  clearAnalyticsHotspotsLayer: (...args) => mockClearAnalyticsHotspotsLayer(...args),
  setSelectedAnalyticsHotspot: (...args) => mockSetSelectedAnalyticsHotspot(...args),
  focusAnalyticsHotspot: (...args) => mockFocusAnalyticsHotspot(...args),
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
  saveLists: (...args) => mockSaveLists(...args),
}));

const {
  setAnalyticsWorkspaceActive,
  getAnalyticsUiState,
  persistAnalyticsUi,
  refreshAnalyticsPanel,
  setupAnalyticsListeners,
} = require("../../src/modules/ui_analytics.js");

function mountAnalyticsDom() {
  document.body.innerHTML = `
    <div id="hud-layer"></div>
    <div id="analytics-panel"></div>
    <div id="analytics-left-hotspots-panel"></div>
    <div id="analytics-left-details-panel"></div>
    <div id="analytics-right-filters-panel"></div>
    <div id="analytics-right-channels-panel"></div>
    <div id="zones-panel"></div>
    <div id="targets-panel"></div>
    <div id="favorites-panel"></div>
    <div id="cracking-panel"></div>
    <div id="process-panel"></div>
    <div id="log-panel"></div>
    <div class="right-panels-container"></div>
    <div class="controls-row"></div>
    <div class="stats-container-wrapper"></div>
    <button id="btn-toggle-cracking"></button>
    <button id="btn-process"></button>
    <button id="btn-logs"></button>
    <button id="btn-zones"></button>
    <button id="btn-targets"></button>
    <button id="btn-favs"></button>
    <button id="btn-24h"></button>
    <button id="btn-all"></button>
    <select id="analytics-metric-select"></select>
    <select id="analytics-source-select"></select>
    <select id="analytics-security-select"></select>
    <select id="analytics-device-type-select"></select>
    <select id="analytics-time-window-select"></select>
    <select id="analytics-channel-select"></select>
    <button id="btn-analytics-refresh"></button>
    <button id="btn-analytics-open-wardrive"></button>
    <button id="btn-analytics-add-targets"></button>
    <button id="btn-analytics-dimension-channel"></button>
    <button id="btn-analytics-dimension-device"></button>
    <div id="analytics-kpi-networks"></div>
    <div id="analytics-kpi-cells"></div>
    <div id="analytics-kpi-hotspots"></div>
    <div id="analytics-kpi-value"></div>
    <table>
      <thead id="analytics-channel-head"></thead>
      <tbody id="analytics-channel-body"></tbody>
    </table>
    <div id="analytics-chart-channel-pressure"></div>
    <div id="analytics-chart-source-mix"></div>
    <div id="analytics-chart-security-mix"></div>
    <div id="analytics-pressure-title"></div>
    <div id="analytics-hotspots-list"></div>
    <div id="analytics-hotspot-details"></div>
    <div id="analytics-wardrive-context"></div>
  `;

  document.getElementById("analytics-time-window-select").innerHTML =
    '<option value="all">ALL</option><option value="24h">24H</option>';
  document.getElementById("analytics-channel-select").innerHTML =
    '<option value="all">ALL</option><option value="6">CH 6</option>';

  const left = document.querySelector(".controls-row");
  const right = document.querySelector(".stats-container-wrapper");
  Object.defineProperty(left, "offsetHeight", { configurable: true, get: () => 120 });
  Object.defineProperty(right, "offsetHeight", { configurable: true, get: () => 80 });
}

function resetState() {
  mockState.ui = {};
  mockState.modes = {
    zones: false,
    targets: false,
    favs: false,
    cracking: false,
    process: false,
    logs: false,
    analytics: true,
  };
  mockState.filters = { time: "ALL" };
  mockState.lists = { targets: [] };
  mockState.analyticsUi = null;
}

function resetMocks() {
  [
    mockAPI.getAnalyticsHeatmap,
    mockAPI.getAnalyticsChannelSummary,
    mockAPI.getAnalyticsHotspots,
    mockLog,
    mockSetAnalyticsHeatmapLayer,
    mockClearAnalyticsHeatmapLayer,
    mockSetAnalyticsHotspotsLayer,
    mockClearAnalyticsHotspotsLayer,
    mockSetSelectedAnalyticsHotspot,
    mockFocusAnalyticsHotspot,
    mockSaveLists,
  ].forEach((fn) => fn.mockReset());

  mockAPI.getAnalyticsHeatmap.mockResolvedValue({
    cells: [{ lat: 0, lng: 0, value: 1 }],
    stats: { networks_count: 3, cells_count: 2, value_avg: 1.5 },
  });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValue({
    channels: [
      { channel: 6, networks: 2, locked: 1, raw_eapol_networks: 1, opportunity_score: 42, open: 1, cracked: 0 },
    ],
    device_summary: [
      { device_type: "router_ap", networks: 2, locked: 1, raw_eapol_networks: 1, opportunity_score: 42 },
    ],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValue({
    hotspots: [
      {
        id: "h1",
        score: 10,
        networks_count: 2,
        locked_count: 1,
        center_lat: 1,
        center_lng: 2,
        radius_m: 50,
        top_channels: ["6"],
        top_sources: ["RAW"],
        sample_macs: ["AA:BB:CC:DD:EE:FF"],
        recommended_action: "scan",
        decision_factors: ["1 locked network concentrates here."],
      },
    ],
  });
}

beforeEach(() => {
  mountAnalyticsDom();
  resetState();
  resetMocks();
  localStorage.clear();
});

test("setAnalyticsWorkspaceActive toggles panels and buttons", () => {
  mockState.modes = { ...mockState.modes, cracking: true, logs: true };

  setAnalyticsWorkspaceActive(true);

  expect(document.getElementById("hud-layer").classList.contains("analytics-workspace-active")).toBe(true);
  expect(document.getElementById("zones-panel").style.display).toBe("none");
  expect(document.getElementById("btn-logs").disabled).toBe(true);

  setAnalyticsWorkspaceActive(false);

  expect(document.getElementById("hud-layer").classList.contains("analytics-workspace-active")).toBe(false);
  expect(document.getElementById("cracking-panel").style.display).toBe("flex");
  expect(document.getElementById("btn-logs").disabled).toBe(false);
  expect(document.querySelector(".controls-row").style.height).toBe("120px");
});

test("setAnalyticsWorkspaceActive tolerates missing elements", () => {
  document.getElementById("hud-layer").remove();
  document.getElementById("analytics-left-hotspots-panel").remove();
  document.getElementById("analytics-left-details-panel").remove();
  document.getElementById("analytics-right-filters-panel").remove();
  document.getElementById("analytics-right-channels-panel").remove();
  document.getElementById("zones-panel").remove();
  document.getElementById("targets-panel").remove();
  document.getElementById("favorites-panel").remove();
  document.getElementById("cracking-panel").remove();
  document.getElementById("process-panel").remove();
  document.getElementById("log-panel").remove();
  document.getElementById("btn-logs").remove();
  document.querySelector(".right-panels-container").remove();
  document.querySelector(".controls-row").remove();
  document.querySelector(".stats-container-wrapper").remove();

  mockState.ui = null;
  setAnalyticsWorkspaceActive(true);
  expect(mockState.ui.analyticsWorkspaceActive).toBe(true);
  setAnalyticsWorkspaceActive(false);
  expect(mockState.ui.analyticsWorkspaceActive).toBe(false);
});

test("setAnalyticsWorkspaceActive skips height sync when bars have zero height", () => {
  const left = document.querySelector(".controls-row");
  const right = document.querySelector(".stats-container-wrapper");
  Object.defineProperty(left, "offsetHeight", { configurable: true, get: () => 0 });
  Object.defineProperty(right, "offsetHeight", { configurable: true, get: () => 0 });

  setAnalyticsWorkspaceActive(true);

  expect(left.style.height).toBe("auto");
  expect(right.style.height).toBe("auto");
});

test("setAnalyticsWorkspaceActive updates right panel layout classes", () => {
  mockState.modes = { ...mockState.modes, cracking: false, process: true, logs: false };

  setAnalyticsWorkspaceActive(true);

  const container = document.querySelector(".right-panels-container");
  expect(container.classList.contains("right-panels--has-process")).toBe(true);
  expect(container.classList.contains("right-panels--only-process")).toBe(true);
});

test("setAnalyticsWorkspaceActive restores side panels when disabled", () => {
  mockState.modes = { ...mockState.modes, zones: true, targets: true, favs: true, logs: true };

  setAnalyticsWorkspaceActive(false);

  expect(document.getElementById("zones-panel").style.display).toBe("flex");
  expect(document.getElementById("targets-panel").style.display).toBe("flex");
  expect(document.getElementById("favorites-panel").style.display).toBe("flex");
  expect(document.getElementById("log-panel").style.display).toBe("block");
});

test("getAnalyticsUiState normalizes defaults", () => {
  mockState.analyticsUi = { dimension: "invalid" };
  const uiState = getAnalyticsUiState();
  expect(uiState.dimension).toBe("channel");
});

test("getAnalyticsUiState keeps valid dimension", () => {
  mockState.analyticsUi = { dimension: "device" };
  const uiState = getAnalyticsUiState();
  expect(uiState.dimension).toBe("device");
});

test("persistAnalyticsUi stores values", () => {
  mockState.analyticsUi = {
    metric: "opportunity",
    source: "raw",
    security: "all",
    deviceType: "router_ap",
    dimension: "channel",
    timeWindow: "all",
    channel: "all",
  };

  persistAnalyticsUi();

  expect(localStorage.getItem("pwn_analytics_metric")).toBe("opportunity");
  expect(localStorage.getItem("pwn_analytics_source")).toBe("raw");
});

test("refreshAnalyticsPanel skips when analytics disabled and not forced", async () => {
  mockState.modes.analytics = false;
  await refreshAnalyticsPanel(false);
  expect(mockAPI.getAnalyticsHeatmap).not.toHaveBeenCalled();
});

test("refreshAnalyticsPanel renders analytics and handles errors", async () => {
  await refreshAnalyticsPanel(true);

  expect(mockSetAnalyticsHeatmapLayer).toHaveBeenCalledWith([{ lat: 0, lng: 0, value: 1 }], "opportunity");
  expect(mockSetAnalyticsHotspotsLayer).toHaveBeenCalledWith(
    [expect.objectContaining({ id: "h1" })],
    null
  );
  expect(document.getElementById("analytics-hotspots-list").innerHTML).toContain("H1");
  expect(document.getElementById("analytics-hotspot-details").textContent).toContain(
    "Select a hotspot to inspect tactical context."
  );
  expect(document.getElementById("analytics-chart-source-mix").textContent).toContain("RAWSNIFFER");
  expect(document.getElementById("analytics-wardrive-context").textContent).toContain("WarDrive Context");

  mockAPI.getAnalyticsHeatmap.mockRejectedValueOnce(new Error("boom"));
  await refreshAnalyticsPanel(true);
  expect(mockClearAnalyticsHeatmapLayer).toHaveBeenCalled();
  expect(mockClearAnalyticsHotspotsLayer).toHaveBeenCalled();
  expect(mockLog).toHaveBeenCalledWith("Analytics refresh failed: boom", "error");
});

test("refreshAnalyticsPanel handles empty datasets", async () => {
  mockState.analyticsUi = {
    ...getAnalyticsUiState(),
    channel: "6",
    dimension: "device",
    selectedHotspotId: "missing",
  };
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({ cells: [], stats: {} });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({ channels: [], device_summary: [] });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({ hotspots: [] });

  await refreshAnalyticsPanel(true);

  expect(getAnalyticsUiState().channel).toBe("all");
  expect(document.getElementById("analytics-channel-body").innerHTML).toContain("No device summary available.");
  expect(document.getElementById("analytics-chart-channel-pressure").innerHTML).toContain("No device pressure data");
  expect(document.getElementById("analytics-chart-source-mix").innerHTML).toContain("No source mix data");
  expect(document.getElementById("analytics-chart-security-mix").innerHTML).toContain("No security mix data");
  expect(document.getElementById("analytics-hotspots-list").innerHTML).toContain("No hotspots yet.");
  expect(document.getElementById("analytics-hotspot-details").textContent).toContain(
    "Select a hotspot to inspect tactical context."
  );

  mockState.analyticsUi.dimension = "channel";
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({ channels: [], device_summary: [] });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({ hotspots: [] });
  await refreshAnalyticsPanel(true);
  expect(document.getElementById("analytics-channel-body").innerHTML).toContain("No channel summary available.");
});

test("refreshAnalyticsPanel renders pressure rows and source mix when data is present", async () => {
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({
    cells: [{ lat: 1, lng: 2, value: 5 }],
    stats: { networks_count: 5, cells_count: 1, value_avg: 2.5 },
  });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [{ channel: 6, networks: 2, locked: 1, raw_eapol_networks: 1, opportunity_score: 50 }],
    device_summary: [],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({
    hotspots: [
      {
        id: "h2",
        score: 12,
        networks_count: 3,
        locked_count: 1,
        center_lat: 1,
        center_lng: 2,
        radius_m: 50,
        top_channels: ["6"],
        top_sources: ["RAW", "PWN"],
        sample_macs: ["AA:BB:CC:DD:EE:FF"],
      },
    ],
  });

  await refreshAnalyticsPanel(true);

  expect(document.getElementById("analytics-chart-channel-pressure").innerHTML).toContain("analytics-chart-row");
  expect(document.getElementById("analytics-chart-source-mix").textContent).toContain("RAWSNIFFER");
  expect(document.querySelectorAll("#analytics-hotspots-list .list-item").length).toBe(1);
});

test("refreshAnalyticsPanel renders device summary labels and security mix totals", async () => {
  mockState.analyticsUi = { ...getAnalyticsUiState(), dimension: "device" };
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({
    cells: [{ lat: 1, lng: 2, value: 5 }],
    stats: { networks_count: 7, cells_count: 2, value_avg: 3.3 },
  });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [
      { channel: 1, networks: 4, locked: 2, open: 1, cracked: 1, raw_eapol_networks: 0, opportunity_score: 10 },
    ],
    device_summary: [
      { device_type: "router_ap", networks: 3, locked: 2, raw_eapol_networks: 1, opportunity_score: 50 },
      { device_type: "router", networks: 2, locked: 1, raw_eapol_networks: 0, opportunity_score: 20 },
      { device_type: "custom_device", networks: 1, locked: 0, raw_eapol_networks: 0, opportunity_score: 5 },
    ],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({
    hotspots: [
      {
        id: "2",
        score: 5,
        networks_count: 1,
        locked_count: 1,
        center_lat: 1,
        center_lng: 2,
        radius_m: 50,
        top_sources: ["RAW"],
        sample_macs: [],
      },
    ],
  });

  await refreshAnalyticsPanel(true);

  expect(document.getElementById("analytics-channel-head").innerHTML).toContain("TYPE");
  expect(document.getElementById("analytics-channel-body").textContent).toContain("Router AP");
  expect(document.getElementById("analytics-channel-body").textContent).toContain("custom device");
  expect(document.getElementById("analytics-chart-security-mix").textContent).toContain("LOCKED 2");
  expect(document.getElementById("analytics-chart-security-mix").textContent).toContain("OPEN 1");
  expect(document.getElementById("analytics-chart-security-mix").textContent).toContain("CRACKED 1");
  expect(document.getElementById("analytics-kpi-networks").textContent).toBe("7");
  expect(document.getElementById("analytics-kpi-cells").textContent).toBe("2");
  expect(document.getElementById("analytics-kpi-hotspots").textContent).toBe("1");
  expect(document.getElementById("analytics-kpi-value").textContent).toBe("3.3");
  expect(document.getElementById("analytics-hotspots-list").textContent).toContain("H2");
});

test("refreshAnalyticsPanel renders hotspot details for channels, sources and sample macs", async () => {
  mockState.analyticsUi = { ...getAnalyticsUiState(), selectedHotspotId: "H9" };
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({ cells: [], stats: {} });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [{ channel: 1, networks: 1, locked: 0, raw_eapol_networks: 0, opportunity_score: 0 }],
    device_summary: [],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({
    hotspots: [
      {
        id: "H9",
        score: 7,
        networks_count: 2,
        locked_count: 1,
        center_lat: 1,
        center_lng: 2,
        radius_m: 50,
        top_channels: ["1", "6"],
        top_sources: ["PWN", "RAW"],
        candidate_macs: [
          "AA:BB:CC:DD:EE:03",
          "AA:BB:CC:DD:EE:01",
          "AA:BB:CC:DD:EE:04",
          "AA:BB:CC:DD:EE:05",
          "AA:BB:CC:DD:EE:06",
          "AA:BB:CC:DD:EE:07",
          "AA:BB:CC:DD:EE:08",
          "AA:BB:CC:DD:EE:09",
          "AA:BB:CC:DD:EE:10",
        ],
        sample_macs: ["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"],
        recommended_action: "scan",
        decision_factors: ["Dominant channels: 1, 6."],
      },
    ],
  });

  await refreshAnalyticsPanel(true);

  const details = document.getElementById("analytics-hotspot-details").innerHTML;
  expect(details).toContain("Overview");
  expect(details).toContain("Why This Hotspot Matters");
  expect(details).toContain("Priority Targets");
  expect(details).toContain("1, 6");
  expect(details).toContain("PWNAGOTCHI");
  expect(details).toContain("RAWSNIFFER");
  expect(details).toContain("AA:BB:CC:DD:EE:03");
  expect(details).toContain("+1 more candidates hidden from preview.");
});

test("refreshAnalyticsPanel sends channel query and handles null heatmap payloads", async () => {
  mockState.analyticsUi = {
    ...getAnalyticsUiState(),
    channel: "6",
    channelSummary: { channels: [{ channel: 6 }] },
  };
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce(null);
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [{ channel: 6, networks: 1, locked: 0, raw_eapol_networks: 0, opportunity_score: 5 }],
    device_summary: [],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({ hotspots: null });

  await refreshAnalyticsPanel(true);

  expect(mockAPI.getAnalyticsHeatmap).toHaveBeenCalledWith(
    expect.objectContaining({ channel: "6" })
  );
  expect(mockSetAnalyticsHeatmapLayer).toHaveBeenCalledWith([], "opportunity");
});

test("refreshAnalyticsPanel renders empty pressure chart when scores are zero", async () => {
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({ cells: [], stats: {} });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [{ channel: 6, networks: 1, locked: 0, raw_eapol_networks: 0, opportunity_score: 0 }],
    device_summary: [],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({ hotspots: [] });

  await refreshAnalyticsPanel(true);

  expect(document.getElementById("analytics-chart-channel-pressure").textContent).toContain(
    "No channel pressure data."
  );
});
test("refreshAnalyticsPanel filters invalid channels from selector options", async () => {
  mockState.analyticsUi = { ...getAnalyticsUiState(), channel: "6" };
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({ cells: [], stats: {} });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [{ channel: "bad", networks: 1, locked: 0, raw_eapol_networks: 0, opportunity_score: 0 }],
    device_summary: [],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({ hotspots: [] });

  await refreshAnalyticsPanel(true);

  const channelSelect = document.getElementById("analytics-channel-select");
  expect(channelSelect.innerHTML).toContain("ALL CH");
  expect(channelSelect.innerHTML).not.toContain("CH NaN");
  expect(getAnalyticsUiState().channel).toBe("all");
});

test("refreshAnalyticsPanel keeps channel when selection is available", async () => {
  mockState.analyticsUi = {
    ...getAnalyticsUiState(),
    channel: "6",
    channelSummary: { channels: [{ channel: 6 }] },
  };
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({ cells: [], stats: {} });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [{ channel: 6, networks: 1, locked: 0, raw_eapol_networks: 0, opportunity_score: 1 }],
    device_summary: [],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({
    hotspots: [{ id: "h1", score: 1, networks_count: 0, locked_count: 0 }],
  });

  await refreshAnalyticsPanel(true);

  expect(getAnalyticsUiState().channel).toBe("6");
});

test("refreshAnalyticsPanel resets channel when previous selection is unavailable", async () => {
  mockState.analyticsUi = { ...getAnalyticsUiState(), channel: "99" };
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({ cells: [], stats: {} });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({
    channels: [{ channel: 6, networks: 1, locked: 1, raw_eapol_networks: 0, opportunity_score: 10 }],
    device_summary: [],
  });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({ hotspots: [] });

  await refreshAnalyticsPanel(true);

  expect(getAnalyticsUiState().channel).toBe("all");
});

test("refreshAnalyticsPanel renders hotspot code fallback when id is missing", async () => {
  mockAPI.getAnalyticsHeatmap.mockResolvedValueOnce({ cells: [], stats: {} });
  mockAPI.getAnalyticsChannelSummary.mockResolvedValueOnce({ channels: [], device_summary: [] });
  mockAPI.getAnalyticsHotspots.mockResolvedValueOnce({
    hotspots: [
      { id: "", score: 1, networks_count: 0, locked_count: 0 },
    ],
  });

  await refreshAnalyticsPanel(true);

  expect(document.getElementById("analytics-hotspots-list").innerHTML).toContain(">-<");
});

test("setupAnalyticsListeners binds filters, dimension, hotspots, targets", async () => {
  setupAnalyticsListeners();

  const timeWindowSelect = document.getElementById("analytics-time-window-select");
  timeWindowSelect.value = "24h";
  timeWindowSelect.dispatchEvent(new Event("change", { bubbles: true }));
  expect(mockState.filters.time).toBe("24H");
  expect(document.getElementById("btn-24h").classList.contains("active")).toBe(true);
  await Promise.resolve();
  expect(mockAPI.getAnalyticsHeatmap).toHaveBeenCalled();

  timeWindowSelect.value = "all";
  timeWindowSelect.dispatchEvent(new Event("change", { bubbles: true }));
  expect(mockState.filters.time).toBe("ALL");
  expect(document.getElementById("btn-all").classList.contains("active")).toBe(true);

  document.getElementById("btn-analytics-dimension-device").click();
  expect(getAnalyticsUiState().dimension).toBe("device");
  document.getElementById("btn-analytics-dimension-channel").click();
  expect(getAnalyticsUiState().dimension).toBe("channel");

  document.getElementById("btn-analytics-refresh").click();
  await Promise.resolve();
  expect(mockAPI.getAnalyticsHeatmap).toHaveBeenCalled();

  const wardriveEvent = jest.fn();
  document.addEventListener("openWardriveFromAnalytics", wardriveEvent);
  document.getElementById("btn-analytics-open-wardrive").click();
  expect(wardriveEvent).toHaveBeenCalled();

  mockState.analyticsUi = {
    ...getAnalyticsUiState(),
    hotspots: [
      {
        id: "h1",
        score: 10,
        networks_count: 2,
        locked_count: 1,
        candidate_macs: ["AA:BB:CC:DD:EE:FF"],
      },
    ],
    selectedHotspotId: "h1",
  };
  document.getElementById("analytics-hotspots-list").innerHTML = `
    <div class="list-item" data-hotspot-id="h1"></div>
  `;
  document.querySelector("#analytics-hotspots-list .list-item").click();
  expect(mockSetSelectedAnalyticsHotspot).toHaveBeenCalledWith("h1");
  expect(mockFocusAnalyticsHotspot).toHaveBeenCalled();

  mockState.lists.targets = [];
  document.getElementById("btn-analytics-add-targets").click();
  expect(mockSaveLists).toHaveBeenCalled();
  expect(mockLog).toHaveBeenCalledWith("Added 1 hotspot targets.", "success");

  document.getElementById("btn-analytics-add-targets").click();
  expect(mockLog).toHaveBeenCalledWith(
    "All hotspot sample targets are already in target list.",
    "info"
  );

  mockState.analyticsUi = { ...getAnalyticsUiState(), hotspots: [], selectedHotspotId: null };
  document.getElementById("btn-analytics-add-targets").click();
  expect(mockLog).toHaveBeenCalledWith("Select a hotspot first.", "warn");

  mockState.analyticsUi = {
    ...getAnalyticsUiState(),
    hotspots: [{ id: "h2", sample_macs: [] }],
    selectedHotspotId: "h2",
  };
  document.getElementById("btn-analytics-add-targets").click();
  expect(mockLog).toHaveBeenCalledWith("Selected hotspot has no sample MAC targets.", "warn");
});

test("setupAnalyticsListeners ignores hotspot clicks without valid item/id", () => {
  setupAnalyticsListeners();

  const list = document.getElementById("analytics-hotspots-list");
  list.dispatchEvent(new MouseEvent("click", { bubbles: true }));

  list.innerHTML = '<div class="list-item"></div>';
  list.querySelector(".list-item").dispatchEvent(new MouseEvent("click", { bubbles: true }));

  expect(mockSetSelectedAnalyticsHotspot).not.toHaveBeenCalled();
  expect(mockFocusAnalyticsHotspot).not.toHaveBeenCalled();
});

test("setupAnalyticsListeners sets selected hotspot without focus when cache is empty", () => {
  setupAnalyticsListeners();
  mockState.analyticsUi = { ...getAnalyticsUiState(), hotspots: [], selectedHotspotId: null };

  const list = document.getElementById("analytics-hotspots-list");
  list.innerHTML = '<div class="list-item" data-hotspot-id="h99"></div>';
  list.querySelector(".list-item").dispatchEvent(new MouseEvent("click", { bubbles: true }));

  expect(mockSetSelectedAnalyticsHotspot).toHaveBeenCalledWith("h99");
  expect(mockFocusAnalyticsHotspot).not.toHaveBeenCalled();
});

test("setupAnalyticsListeners handles missing controls safely", () => {
  document.getElementById("analytics-metric-select").remove();
  document.getElementById("analytics-source-select").remove();
  document.getElementById("analytics-security-select").remove();
  document.getElementById("analytics-device-type-select").remove();
  document.getElementById("analytics-time-window-select").remove();
  document.getElementById("analytics-channel-select").remove();
  document.getElementById("btn-analytics-refresh").remove();
  document.getElementById("btn-analytics-open-wardrive").remove();
  document.getElementById("btn-analytics-add-targets").remove();
  document.getElementById("btn-analytics-dimension-channel").remove();
  document.getElementById("btn-analytics-dimension-device").remove();
  document.getElementById("analytics-hotspots-list").remove();

  expect(() => setupAnalyticsListeners()).not.toThrow();
});
