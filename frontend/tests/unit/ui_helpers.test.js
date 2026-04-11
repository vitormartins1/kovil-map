const mockState = {
  allPositions: { AA: { ssid: "Cafe" } },
  filters: { search: "" },
  modes: {
    noGps: false,
    multi: false,
    cracking: false,
    process: false,
    logs: false,
  },
};

const mockMap = {
  renderMarkers: jest.fn(),
  calculateZones: jest.fn(),
  calculateToConquerZones: jest.fn(),
  calculateDiscoveredZones: jest.fn(),
  calculateIntelligenceZones: jest.fn(),
  updateRadarCircles: jest.fn(),
  clearDetailsCache: jest.fn(),
  clearAnalyticsHeatmapLayer: jest.fn(),
  clearAnalyticsHotspotsLayer: jest.fn(),
};

const mockLists = {
  updateTargetsList: jest.fn(),
  updateFavsList: jest.fn(),
  updateZonesList: jest.fn(),
  updateIntelligenceZonesList: jest.fn(),
  updateNoGpsList: jest.fn(),
  updateMultiList: jest.fn(),
  updateMultiFilesList: jest.fn(),
  updateMultiContentsList: jest.fn(),
};

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
  saveModes: jest.fn(),
}));

jest.mock("../../src/modules/api.js", () => ({
  API: {},
}));

jest.mock("../../src/modules/socket.js", () => ({
  Socket: {
    connect: jest.fn(),
    on: jest.fn(),
  },
}));

jest.mock("../../src/modules/map.js", () => mockMap);

jest.mock("../../src/modules/utils.js", () => ({
  log: jest.fn(),
  bootLog: jest.fn(),
}));

jest.mock("../../src/modules/platform.js", () => ({
  Platform: {
    setProgressBar: jest.fn(),
  },
}));

jest.mock("../../src/modules/ui_components/ui_settings.js", () => ({
  uiConfig: {},
  applyClientConfig: jest.fn(),
  openSettings: jest.fn(),
  closeSettings: jest.fn(),
  saveSettings: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => mockLists);

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  activeProcesses: {},
  addProcess: jest.fn(),
  updateProcess: jest.fn(),
  restoreActiveJobs: jest.fn(),
  renderProcessList: jest.fn(),
  setupProcessListeners: jest.fn(),
  handleJobCompletionSideEffects: jest.fn(),
  getActiveHashcatJob: jest.fn(() => null),
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openMultiCrackingPanel: jest.fn(),
  setupCrackingListeners: jest.fn(),
  clearHistory: jest.fn(),
}));

jest.mock("../../src/modules/ui_raw.js", () => ({
  setupRawListeners: jest.fn(),
  refreshRawFiles: jest.fn(),
}));

jest.mock("../../src/modules/ui_analytics.js", () => ({
  setupAnalyticsListeners: jest.fn(),
  refreshAnalyticsPanel: jest.fn(),
  setAnalyticsWorkspaceActive: jest.fn(),
}));

jest.mock("../../src/modules/ui_multi.js", () => ({
  setupMultiListeners: jest.fn(),
  handleMultiCreate: jest.fn(),
  handleMultiClear: jest.fn(),
  refreshMultiFiles: jest.fn(),
  loadMultiContents: jest.fn(),
}));

jest.mock("../../src/modules/ui_wardrive.js", () => ({
  deactivateWardriveMode: jest.fn(),
  markWardriveDirty: jest.fn(),
  prewarmWardriveWorkspace: jest.fn(),
  refreshWardriveIfActive: jest.fn(),
  setupWardriveListeners: jest.fn(),
}));

const { __testUiHelpers } = require("../../src/modules/ui.js");

describe("ui helper coverage", () => {
  beforeEach(() => {
    mockState.filters.search = "";
    mockState.modes = {
      noGps: false,
      multi: false,
      cracking: false,
      process: false,
      logs: false,
    };
    Object.values(mockMap).forEach((fn) => fn.mockClear?.());
    Object.values(mockLists).forEach((fn) => fn.mockClear?.());
    document.title = "Initial";
    document.body.innerHTML = "";
  });

  test("search helpers toggle clear button and refresh dependent lists", () => {
    document.body.innerHTML = `<button id="btn-filter-clear" hidden aria-hidden="true"></button>`;
    mockState.modes.noGps = true;
    mockState.modes.multi = true;

    __testUiHelpers.applyMainSearchFilter(" Cafe ", { render: true });

    expect(mockState.filters.search).toBe(" cafe ");
    expect(document.getElementById("btn-filter-clear").hidden).toBe(false);
    expect(document.getElementById("btn-filter-clear").getAttribute("aria-hidden")).toBe(
      "false",
    );
    expect(mockMap.renderMarkers).toHaveBeenCalledWith(mockState.allPositions, true);
    expect(mockMap.calculateZones).toHaveBeenCalledWith(mockState.allPositions);
    expect(mockMap.calculateToConquerZones).toHaveBeenCalledWith(mockState.allPositions);
    expect(mockLists.updateNoGpsList).toHaveBeenCalled();
    expect(mockLists.updateMultiList).toHaveBeenCalled();

    __testUiHelpers.applyMainSearchFilter("", { render: false });
    expect(document.getElementById("btn-filter-clear").hidden).toBe(true);
    expect(document.getElementById("btn-filter-clear").getAttribute("aria-hidden")).toBe(
      "true",
    );
  });

  test("right panel layout helpers toggle mutually exclusive classes", () => {
    document.body.innerHTML = `<div class="right-panels-container"></div>`;
    const panel = document.querySelector(".right-panels-container");

    mockState.modes.cracking = true;
    __testUiHelpers.syncRightPanelsLayout();
    expect(panel.classList.contains("right-panels--has-cracking")).toBe(true);
    expect(panel.classList.contains("right-panels--only-cracking")).toBe(true);

    mockState.modes.process = true;
    mockState.modes.logs = true;
    __testUiHelpers.syncRightPanelsLayout();
    expect(panel.classList.contains("right-panels--has-process")).toBe(true);
    expect(panel.classList.contains("right-panels--has-logs")).toBe(true);
    expect(panel.classList.contains("right-panels--only-cracking")).toBe(false);
  });

  test("title helpers render cracking title and restore default title", () => {
    document.body.innerHTML = `<div id="title-bar"><span class="app-title"></span></div>`;

    expect(__testUiHelpers.buildCrackingTitle(42.4, "")).toBe(
      "KOVIL MAP // CONQUERING 42%",
    );
    expect(__testUiHelpers.buildCrackingTitle(Number.NaN, "eta 1m")).toBe(
      "KOVIL MAP // CONQUERING 0% eta 1m",
    );

    __testUiHelpers.setAppTitle("Custom");
    expect(document.title).toBe("Custom");
    expect(document.querySelector("#title-bar .app-title").textContent).toContain("Custom");

    __testUiHelpers.resetAppTitle();
    expect(document.title).toBe("KOVIL MAP");
    expect(document.querySelector("#title-bar .app-title").textContent).toContain(
      "KOVIL MAP",
    );
  });
});
