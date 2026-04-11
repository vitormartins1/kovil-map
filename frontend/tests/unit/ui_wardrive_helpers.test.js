jest.mock("../../src/modules/state.js", () => ({
  STATE: {
    modes: {},
    filters: { time: "ALL" },
  },
  saveModes: jest.fn(),
}));

jest.mock("../../src/modules/api.js", () => ({
  API: {},
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: jest.fn(),
  escapeHtml: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/map.js", () => ({
  calculateDiscoveredZones: jest.fn(),
  calculateIntelligenceZones: jest.fn(),
  calculateToConquerZones: jest.fn(),
  calculateZones: jest.fn(),
  clearAnalyticsHeatmapLayer: jest.fn(),
  clearAnalyticsHotspotsLayer: jest.fn(),
  clearWardriveLayers: jest.fn(),
  focusWardriveTrack: jest.fn(),
  focusWardriveReplayPlayhead: jest.fn(),
  focusWardriveBBox: jest.fn(),
  focusWardriveZone: jest.fn(),
  getMapInstance: jest.fn(() => null),
  getWardriveSessionPalette: jest.fn(() => ({})),
  renderMarkers: jest.fn(),
  renderWardriveRegion: jest.fn(),
  renderWardriveSessionTracks: jest.fn(),
  renderWardriveZones: jest.fn(),
  setWardriveReplayPlayhead: jest.fn(),
  updateRadarCircles: jest.fn(),
}));

jest.mock("../../src/modules/ui_recon.js", () => ({
  setReconWorkspaceActive: jest.fn(),
}));

const {
  __testWardriveHelpers,
  __testSetWardriveState,
  __testResetWardriveState,
} = require("../../src/modules/ui_wardrive.js");

describe("ui_wardrive helper coverage", () => {
  beforeEach(() => {
    localStorage.clear();
    __testResetWardriveState();
  });

  test("level helpers normalize depth and locale sort by name", () => {
    expect(__testWardriveHelpers.getLevelWeight({ depth: 7 })).toBe(7);
    expect(__testWardriveHelpers.getLevelWeight({ level_key: "city" })).toBe(2);
    expect(__testWardriveHelpers.getLevelWeight({ level: "mystery" })).toBe(99);

    expect(
      __testWardriveHelpers.byLevelName(
        { level_key: "city", name: "B" },
        { level_key: "city", name: "A" },
      ),
    ).toBeGreaterThan(0);
  });

  test("session sort helpers fall back to safe defaults", () => {
    expect(__testWardriveHelpers.normalizeWardriveSessionSortBy("DISTANCE")).toBe(
      "distance",
    );
    expect(__testWardriveHelpers.normalizeWardriveSessionSortBy("weird")).toBe("none");
    expect(__testWardriveHelpers.normalizeWardriveSessionSortDirection("asc")).toBe(
      "asc",
    );
    expect(__testWardriveHelpers.normalizeWardriveSessionSortDirection("sideways")).toBe(
      "desc",
    );
  });

  test("loadWardriveSessionsUiFilters handles missing, invalid and valid storage", () => {
    expect(__testWardriveHelpers.loadWardriveSessionsUiFilters()).toEqual({
      sortBy: "none",
      sortDirection: "desc",
    });

    localStorage.setItem(
      "pwn_wardrive_sessions_ui",
      JSON.stringify({ sortBy: "distance", sortDirection: "asc" }),
    );
    expect(__testWardriveHelpers.loadWardriveSessionsUiFilters()).toEqual({
      sortBy: "distance",
      sortDirection: "asc",
    });

    localStorage.setItem("pwn_wardrive_sessions_ui", "{");
    expect(__testWardriveHelpers.loadWardriveSessionsUiFilters()).toEqual({
      sortBy: "none",
      sortDirection: "desc",
    });
  });

  test("region and formatting helpers cover explicit, lineage and fallback paths", () => {
    expect(__testWardriveHelpers.getRegionLevelLabel({ level_label: "Zona" })).toBe(
      "Zona",
    );
    expect(__testWardriveHelpers.getRegionLevelLabel({ level_key: "city" })).toBe(
      "City",
    );
    expect(__testWardriveHelpers.getRegionLevelLabel({ level_key: "other" })).toBe(
      "Region",
    );

    expect(
      __testWardriveHelpers.getRegionDisplayPath({ display_path: "A > B" }),
    ).toBe("A > B");
    expect(
      __testWardriveHelpers.getRegionDisplayPath({
        lineage: [{ name: "A" }, { name: "B" }],
      }),
    ).toBe("A > B");
    expect(__testWardriveHelpers.getRegionDisplayPath({ name: "Solo" })).toBe("Solo");

    expect(__testWardriveHelpers.formatDuration(0, 0)).toBe("--");
    expect(__testWardriveHelpers.formatDuration(0, 3661)).toBe("1h 1m");
    expect(__testWardriveHelpers.formatDuration(0, 90)).toBe("1m 30s");
    expect(__testWardriveHelpers.formatDuration(0, 12)).toBe("12s");
    expect(__testWardriveHelpers.getSessionDurationSeconds(10, 5)).toBe(0);
    expect(__testWardriveHelpers.formatDistanceMeters(-1)).toBe("--");
    expect(__testWardriveHelpers.formatDistanceMeters(1250)).toBe("1.25 km");
    expect(__testWardriveHelpers.formatDistanceMeters(125)).toBe("125 m");
    expect(__testWardriveHelpers.formatWardriveSessionDisplayName(" route.csv ")).toBe(
      "route",
    );
    expect(
      __testWardriveHelpers.formatWardriveSessionDisplayName("m5evil__wardriving-03.csv"),
    ).toBe("wardriving-03");
    expect(__testWardriveHelpers.formatWardriveSessionDisplayName("")).toBe(
      "wardrive",
    );
    expect(__testWardriveHelpers.formatAccuracyMeters(0)).toBe("--");
    expect(__testWardriveHelpers.formatAccuracyMeters(4.44)).toBe("4.4 m");
  });

  test("transport and replay helpers normalize and summarize", () => {
    expect(__testWardriveHelpers.normalizeTransportMode("CAR")).toBe("car");
    expect(__testWardriveHelpers.normalizeTransportMode("unknown")).toBeNull();
    expect(__testWardriveHelpers.getTransportMeta("plane")).toEqual({
      mode: "plane",
      icon: "fa-plane",
      label: "Plane",
    });
    expect(__testWardriveHelpers.getTransportMeta("")).toEqual({
      mode: null,
      icon: "fa-route",
      label: "Set transport mode",
    });

    expect(
      __testWardriveHelpers.summarizeTransportModes([
        { transport_mode: "car", networks_count: 10, points_count: 100 },
        { transport_mode: "car", networks_count: 3, points_count: 20 },
        { transport_mode: "walk", networks_count: 9, points_count: 90 },
        { transport_mode: "invalid", networks_count: 1, points_count: 1 },
      ]),
    ).toEqual([
      { transport_mode: "car", sessions_count: 2, networks_count: 13, points_count: 120 },
      { transport_mode: "walk", sessions_count: 1, networks_count: 9, points_count: 90 },
    ]);

    expect(__testWardriveHelpers.normalizeWardriveReplaySpeed("2")).toBe(2);
    expect(__testWardriveHelpers.normalizeWardriveReplaySpeed("8")).toBe(8);
    expect(__testWardriveHelpers.normalizeWardriveReplaySpeed("7")).toBe(1);
    expect(__testWardriveHelpers.normalizeWardriveReplaySpeed("bad")).toBe(1);
    expect(__testWardriveHelpers.normalizeWardriveReplayTimingMode("COMPRESS_IDLE")).toBe("compress_idle");
    expect(__testWardriveHelpers.normalizeWardriveReplayTimingMode("warp")).toBe("real_time");
    expect(__testWardriveHelpers.normalizeWardriveReplayFollowZoom("19")).toBe("19");
    expect(__testWardriveHelpers.normalizeWardriveReplayFollowZoom("21")).toBe("current");
    expect(__testWardriveHelpers.formatWardriveReplaySpeed("2.5")).toBe("2.5x · Very Fast");
    expect(__testWardriveHelpers.formatWardriveReplaySpeed("8")).toBe("8x · Ultra");
  });

  test("replay timing helpers support real time, compressed idle and uniform path", () => {
    const track = {
      points: [
        { lat: -22.9, lng: -43.2, ts_last: 0 },
        { lat: -22.90001, lng: -43.20001, ts_last: 7200 },
        { lat: -22.90002, lng: -43.20002, ts_last: 7210 },
        { lat: -22.89, lng: -43.19, ts_last: 7510 },
      ],
    };

    expect(__testWardriveHelpers.getWardriveReplaySegmentWeights(track, "real_time")).toEqual([
      7200,
      10,
      300,
    ]);
    expect(__testWardriveHelpers.getWardriveReplaySegmentWeights(track, "compress_idle")).toEqual([
      1.5,
      1.5,
      300,
    ]);

    const uniformWeights = __testWardriveHelpers.getWardriveReplaySegmentWeights(track, "uniform_path");
    expect(uniformWeights).toHaveLength(3);
    expect(uniformWeights[0]).toBeGreaterThanOrEqual(5);
    expect(uniformWeights[1]).toBeGreaterThanOrEqual(5);
    expect(uniformWeights[2]).toBeGreaterThan(uniformWeights[1]);

    expect(__testWardriveHelpers.getWardriveReplayTimingModeMeta("compress_idle")).toMatchObject({
      value: "compress_idle",
      label: "Compress Idle",
    });
  });

  test("camera zoom helper resolves fixed zooms and current fallback", () => {
    __testSetWardriveState({ replayFollowZoom: "19" });
    expect(__testWardriveHelpers.resolveWardriveReplayCameraZoom()).toBe(19);

    __testSetWardriveState({ replayFollowZoom: "current" });
    expect(__testWardriveHelpers.resolveWardriveReplayCameraZoom()).toBeNull();
  });

  test("selected session helpers derive overlays and active replay track", () => {
    __testSetWardriveState({
      selectedSessionIds: ["s1", "s2", "s3"],
      sessions: [
        { session_id: "s1", label: "One" },
        { session_id: "s4", label: "Four" },
      ],
      sessionTracks: [
        { session_id: "s2", label: "Track 2" },
        { session_id: "s3", label: "Track 3" },
      ],
      activeReplaySessionId: "s3",
    });

    expect(__testWardriveHelpers.getWardriveSelectedSessions()).toEqual([
      { session_id: "s1", label: "One" },
    ]);
    expect(__testWardriveHelpers.getWardriveReplayTracks()).toEqual([
      { session_id: "s2", label: "Track 2" },
      { session_id: "s3", label: "Track 3" },
    ]);
    expect(__testWardriveHelpers.getActiveWardriveReplayTrack()).toEqual({
      session_id: "s3",
      label: "Track 3",
    });
    expect(__testWardriveHelpers.getWardriveZoneOverlaySessionIds()).toEqual([
      "s1",
      "s2",
      "s3",
    ]);
    expect(__testWardriveHelpers.getWardriveFocusComparisonSessionIds()).toEqual([
      "s1",
      "s2",
      "s3",
    ]);

    __testSetWardriveState({ selectedSessionIds: ["a", "b", "c", "d"] });
    expect(__testWardriveHelpers.getWardriveZoneOverlaySessionIds()).toEqual([]);
    expect(__testWardriveHelpers.getWardriveFocusComparisonSessionIds()).toEqual([]);
  });

  test("scope and numeric helpers handle single, multiple and missing selections", () => {
    __testSetWardriveState({ selectedSessionIds: [] });
    expect(__testWardriveHelpers.getWardriveStandardZoneScope()).toBeNull();

    __testSetWardriveState({ selectedSessionIds: ["s1"] });
    expect(
      __testWardriveHelpers.getWardriveStandardZoneScope(
        new Map([["s1", { source_file: "route-1.csv" }]]),
      ),
    ).toEqual({
      sessionId: "s1",
      sessionLabel: "route-1.csv",
      sessionIds: ["s1"],
      activeSessionId: "s1",
    });

    __testSetWardriveState({ selectedSessionIds: ["s1", "s2"] });
    expect(__testWardriveHelpers.getWardriveStandardZoneScope()).toEqual({
      sessionId: "__session_filtered__",
      sessionLabel: "SELECTED SESSIONS",
      sessionIds: ["__session_filtered__"],
      activeSessionId: "__session_filtered__",
    });

    expect(__testWardriveHelpers.getFiniteWardriveNumber("bad", undefined, 9, 10)).toBe(9);
    expect(__testWardriveHelpers.getFiniteWardriveNumber("bad", null)).toBe(0);
    expect(__testWardriveHelpers.getFiniteWardriveNumber("bad", undefined)).toBeNull();
  });

  test("comparison helpers normalize payloads and presets", () => {
    __testSetWardriveState({ activeReplaySessionId: "s2" });

    expect(__testWardriveHelpers.getWardriveComparisonActiveSessionId()).toBeNull();
    expect(
      __testWardriveHelpers.getWardriveComparisonActiveSessionId({
        sessionIds: ["s1", "s2"],
        activeSessionId: "s1",
      }),
    ).toBe("s2");
    __testSetWardriveState({ activeReplaySessionId: "missing" });
    expect(
      __testWardriveHelpers.getWardriveComparisonActiveSessionId({
        sessionIds: ["s1", "s2"],
        activeSessionId: "s2",
      }),
    ).toBe("s2");
    expect(
      __testWardriveHelpers.getWardriveComparisonActiveSessionId({
        sessionIds: ["s1", "s2"],
      }),
    ).toBe("s1");

    expect(__testWardriveHelpers.normalizeWardriveComparisonPayload()).toBeNull();
    expect(
      __testWardriveHelpers.normalizeWardriveComparisonPayload({ mode: "other" }),
    ).toBeNull();

    const normalized = __testWardriveHelpers.normalizeWardriveComparisonPayload(
      {
        mode: "focus_active",
        session_ids: ["s1", "s2", "", "s1"],
        active_session_id: "s2",
        layers_by_active_session: {
          s1: {
            primary_zones: [{ name: "Alpha", ap_count: 2 }],
            secondary_zone: { name: "Beta", ap_count: 5 },
          },
          s2: {
            primary_zones: [{ name: "Gamma", ap_count: 1 }],
          },
        },
      },
      new Map([
        ["s1", { label: "Session One" }],
        ["s2", { source_file: "route-two.csv" }],
      ]),
    );

    expect(normalized.mode).toBe("focus_active");
    expect(normalized.sessionIds).toEqual(["s1", "s2"]);
    expect(normalized.activeSessionId).toBe("s2");
    expect(normalized.layersByActiveSession.s1.primary_zones[0]).toMatchObject({
      session_id: "s1",
      session_label: "Session One",
      zone_role: "primary",
    });
    expect(normalized.layersByActiveSession.s1.secondary_zone).toMatchObject({
      session_id: "__comparison_secondary__",
      session_label: "OTHER SELECTED SESSIONS",
      zone_role: "secondary",
    });

    expect(__testWardriveHelpers.buildWardriveComparisonPreset(null)).toEqual([]);
    expect(
      __testWardriveHelpers.buildWardriveComparisonPreset(normalized, "s1"),
    ).toHaveLength(2);
    expect(
      __testWardriveHelpers.buildWardriveComparisonPreset(normalized, "unknown"),
    ).toEqual([{ ...normalized.layersByActiveSession.s2.primary_zones[0] }]);
  });

  test("mergeHierarchyWithUnmapped appends unmapped summary only when needed", () => {
    expect(
      __testWardriveHelpers.mergeHierarchyWithUnmapped({
        regions: [{ id: "city", level_key: "city", name: "Rio" }],
        unmapped_summary: { networks_count: 0 },
      }),
    ).toEqual([{ id: "city", level_key: "city", name: "Rio" }]);

    const merged = __testWardriveHelpers.mergeHierarchyWithUnmapped({
      regions: [{ id: "state", level_key: "state", name: "RJ" }],
      unmapped_summary: { networks_count: 3 },
    });
    expect(merged.some((item) => item.id === "unmapped")).toBe(true);
  });

  test("zone render, filters and workspace warmth helpers cover default branches", () => {
    const { STATE } = require("../../src/modules/state.js");

    __testSetWardriveState({
      lastZoneComparison: {
        mode: "focus_active",
        sessionIds: ["s1", "s2"],
        activeSessionId: "s1",
      },
      activeReplaySessionId: "s2",
    });
    expect(__testWardriveHelpers.getWardriveZoneRenderContext()).toMatchObject({
      comparisonMode: "focus_active",
      activeSessionId: "s2",
    });

    __testSetWardriveState({ lastZoneComparison: null, selectedSessionIds: ["s3"] });
    expect(__testWardriveHelpers.getWardriveZoneRenderContext()).toEqual({
      sessionIds: ["s3"],
      activeSessionId: "s3",
      comparisonMode: "standard",
      comparison: null,
    });

    __testSetWardriveState({ selectedSessionIds: [] });
    expect(__testWardriveHelpers.getWardriveZoneRenderContext()).toEqual({
      sessionIds: [],
      activeSessionId: null,
      comparisonMode: "standard",
      comparison: null,
    });

    expect(
      __testWardriveHelpers.decorateWardriveZones(
        [{ id: 7, name: "Zone A" }],
        { sessionId: "s7", sessionLabel: "Session 7" },
      ),
    ).toEqual([
      expect.objectContaining({
        id: 7,
        session_id: "s7",
        session_label: "Session 7",
        zone_uid: "s7:7:0",
      }),
    ]);

    document.body.innerHTML = `
      <select id="wardrive-time-window">
        <option value=""></option>
        <option value="all">all</option>
        <option value="24h">24h</option>
      </select>
      <select id="wardrive-source">
        <option value=""></option>
        <option value="all">all</option>
        <option value="ward">ward</option>
        <option value="sync">sync</option>
      </select>
    `;

    STATE.filters.time = "24H";
    __testSetWardriveState({ selectedSessionIds: ["s1"], sourceBeforeSessionOverride: null });
    __testWardriveHelpers.ensureWardriveFilterDefaults();
    expect(document.getElementById("wardrive-time-window").value).toBe("24h");
    expect(document.getElementById("wardrive-source").value).toBe("ward");
    expect(document.getElementById("wardrive-source").disabled).toBe(true);

    __testSetWardriveState({ selectedSessionIds: [] });
    __testWardriveHelpers.syncWardriveSourceLock();
    expect(document.getElementById("wardrive-source").disabled).toBe(false);
    expect(document.getElementById("wardrive-source").value).toBe("all");

    expect(__testWardriveHelpers.getWardriveFilters()).toEqual({
      time_window: "24h",
      source: "all",
      session_ids: [],
    });

    __testSetWardriveState({ selectedSessionIds: ["s1"] });
    expect(__testWardriveHelpers.getWardriveFilters()).toEqual({
      time_window: "24h",
      source: "ward",
      session_ids: ["s1"],
    });

    __testSetWardriveState({
      hierarchy: [{ id: "city" }],
      workspaceWarm: true,
      workspaceDirty: false,
    });
    expect(__testWardriveHelpers.hasWarmWorkspaceSnapshot()).toBe(true);
    __testSetWardriveState({ workspaceDirty: true });
    expect(__testWardriveHelpers.hasWarmWorkspaceSnapshot()).toBe(false);
  });

  test("map mode and workspace visibility helpers update DOM affordances", () => {
    const { STATE } = require("../../src/modules/state.js");
    const { setReconWorkspaceActive } = require("../../src/modules/ui_recon.js");
    const {
      clearAnalyticsHeatmapLayer,
      clearAnalyticsHotspotsLayer,
    } = require("../../src/modules/map.js");

    document.body.innerHTML = `
      <button id="btn-map-view"></button>
      <button id="btn-no-gps-view"></button>
      <button id="btn-multi-view"></button>
      <button id="btn-raw-view"></button>
      <button id="btn-analytics-view"></button>
      <button id="btn-zones"></button>
      <button id="btn-conquered"></button>
      <button id="btn-targets"></button>
      <button id="btn-favs"></button>
      <button id="btn-toggle-cracking"></button>
      <button id="btn-process"></button>
      <button id="btn-logs"></button>
      <button id="btn-to-conquer"></button>
      <button id="btn-heat"></button>
      <button id="btn-intelligence"></button>
      <div id="hud-layer"></div>
      <div id="wardrive-panel"></div>
      <div id="wardrive-right-sessions-panel"></div>
      <div id="zones-panel" style="display:flex"></div>
      <div id="targets-panel" style="display:flex"></div>
      <div id="favorites-panel" style="display:flex"></div>
      <div id="cracking-panel" style="display:flex"></div>
      <div id="process-panel" style="display:flex"></div>
      <div id="log-panel" style="display:block"></div>
      <div id="no-gps-panel" style="display:flex"></div>
      <div id="multi-panel" style="display:flex"></div>
      <div id="raw-panel" style="display:flex"></div>
      <div id="analytics-panel" style="display:flex"></div>
      <div id="wardrive-workspace-main"></div>
      <div id="wardrive-workspace-inventory"></div>
      <button id="btn-wardrive-tab-workspace"></button>
      <button id="btn-wardrive-tab-inventory"></button>
      <div class="controls-row"></div>
      <div class="stats-container-wrapper"></div>
    `;

    STATE.modes = { noGps: true, multi: true, raw: true, analytics: true };
    __testWardriveHelpers.setMapViewOnly();
    expect(STATE.modes.noGps).toBe(false);
    expect(STATE.modes.multi).toBe(false);
    expect(document.getElementById("btn-map-view").classList.contains("active")).toBe(true);
    expect(document.getElementById("analytics-panel").style.display).toBe("none");
    expect(setReconWorkspaceActive).toHaveBeenCalledWith(false);
    expect(clearAnalyticsHeatmapLayer).toHaveBeenCalled();
    expect(clearAnalyticsHotspotsLayer).toHaveBeenCalled();

    __testWardriveHelpers.suspendButtons(["btn-zones", "btn-targets"], true);
    expect(document.getElementById("btn-zones").disabled).toBe(true);
    expect(document.getElementById("btn-zones").classList.contains("suspended")).toBe(true);
    __testWardriveHelpers.suspendLeftPanels(false);
    expect(document.getElementById("btn-zones").disabled).toBe(false);
    __testWardriveHelpers.suspendRightPanels(true);
    expect(document.getElementById("btn-toggle-cracking").disabled).toBe(true);
    __testWardriveHelpers.suspendMapModeButtons(true);
    expect(document.getElementById("btn-heat").disabled).toBe(true);
    __testWardriveHelpers.syncMapModeButton("btn-intelligence", true);
    expect(document.getElementById("btn-intelligence").classList.contains("active")).toBe(true);

    __testSetWardriveState({ workspaceTab: "inventory" });
    __testWardriveHelpers.applyWardriveWorkspaceTabUi();
    expect(document.getElementById("wardrive-workspace-main").style.display).toBe("none");
    expect(document.getElementById("btn-wardrive-tab-inventory").classList.contains("active")).toBe(true);

    __testWardriveHelpers.applyWardriveWorkspaceVisibility(true);
    expect(document.getElementById("hud-layer").classList.contains("wardrive-workspace-active")).toBe(true);
    expect(document.getElementById("zones-panel").style.display).toBe("none");

    __testWardriveHelpers.applyWardriveWorkspaceVisibility(false);
    expect(document.getElementById("wardrive-panel").style.display).toBe("none");
    expect(document.getElementById("wardrive-right-sessions-panel").style.display).toBe("none");
  });
});
