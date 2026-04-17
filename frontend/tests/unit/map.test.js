const mockState = {
  allPositions: {},
  openPopupMac: null,
  isProgrammaticInteraction: false,
  ignorePopupClose: false,
  isFirstLoad: false,
  isCrackingActive: false,
  filters: { time: "ALL", search: "" },
  modes: {
    radar: false,
    heat: false,
    zones: false,
    toConquer: false,
  },
  lists: { targets: [], favs: [] },
  map: { hoverCircle: null },
  ui: { hidePasswords: false },
  crackingByMac: {},
};

const mockSaveLists = jest.fn();
const mockCopyToClipboard = jest.fn();
const mockLog = jest.fn();
const mockOpenCrackingPanel = jest.fn();
const mockAPI = {
  getZones: jest.fn(),
  getToConquerZones: jest.fn(),
  getVendor: jest.fn(),
  getVendorAlt: jest.fn(),
  getFingerprintDetails: jest.fn(),
};

jest.mock("../../src/modules/config.js", () => ({
  CONFIG: {
    MAP: {
      DEFAULT_LAT: -22.9,
      DEFAULT_LNG: -43.2,
      DEFAULT_ZOOM: 13,
    },
  },
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
  saveLists: (...args) => mockSaveLists(...args),
}));

jest.mock("../../src/modules/utils.js", () => ({
  escapeHtml: (value) => String(value ?? ""),
  copyToClipboard: (...args) => mockCopyToClipboard(...args),
  log: (...args) => mockLog(...args),
  safeText: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: (...args) => mockOpenCrackingPanel(...args),
}));

function resetState() {
  mockState.allPositions = {};
  mockState.openPopupMac = null;
  mockState.isProgrammaticInteraction = false;
  mockState.ignorePopupClose = false;
  mockState.isFirstLoad = false;
  mockState.isCrackingActive = false;
  mockState.filters = { time: "ALL", search: "" };
  mockState.modes = { radar: false, heat: false, zones: false, toConquer: false };
  mockState.lists = { targets: [], favs: [] };
  mockState.map = { hoverCircle: null };
  mockState.ui = { hidePasswords: false };
  mockState.crackingByMac = {};
}

function createLeafletMock() {
  const clusterLayers = [];
  const panes = {};
  const mapObj = {
    __events: {},
    setView: jest.fn().mockReturnThis(),
    addLayer: jest.fn(),
    removeLayer: jest.fn(),
    eachLayer: jest.fn(),
    hasLayer: jest.fn(() => true),
    getCenter: jest.fn(() => ({ lat: -22.9, lng: -43.2 })),
    getZoom: jest.fn(() => 13),
    getBounds: jest.fn(() => ({
      pad: jest.fn(() => ({
        contains: jest.fn(() => true),
      })),
    })),
    fitBounds: jest.fn(),
    panInside: jest.fn(),
    createPane: jest.fn((name) => {
      const pane = { style: {} };
      panes[name] = pane;
      return pane;
    }),
    getPane: jest.fn((name) => panes[name] || null),
    on: jest.fn((name, handler) => {
      mapObj.__events[name] = handler;
      return mapObj;
    }),
  };

  const tileLayerInstance = {
    addTo: jest.fn().mockReturnThis(),
    bringToBack: jest.fn(),
  };

  const markerCluster = {
    addLayer: jest.fn((layer) => {
      clusterLayers.push(layer);
    }),
    clearLayers: jest.fn(() => {
      clusterLayers.length = 0;
    }),
    eachLayer: jest.fn((cb) => {
      clusterLayers.forEach((layer) => cb(layer));
    }),
    getVisibleParent: jest.fn((layer) => layer),
    zoomToShowLayer: jest.fn((layer, cb) => {
      if (cb) cb();
    }),
    __layers: clusterLayers,
  };

  const makeLayerGroup = () => ({
    addTo: jest.fn().mockReturnThis(),
    clearLayers: jest.fn(),
    addLayer: jest.fn(),
    bringToFront: jest.fn(),
  });

  const polygonLayer = {
    bindTooltip: jest.fn().mockReturnThis(),
    setStyle: jest.fn().mockReturnThis(),
    addTo: jest.fn().mockReturnThis(),
  };

  const polylineLayer = {
    bindTooltip: jest.fn().mockReturnThis(),
    addTo: jest.fn().mockReturnThis(),
  };

  const circleMarkerLayer = {
    addTo: jest.fn().mockReturnThis(),
  };

  return {
    mapObj,
    markerCluster,
    panes,
    L: {
      map: jest.fn(() => mapObj),
      tileLayer: jest.fn(() => tileLayerInstance),
      markerClusterGroup: jest.fn(() => markerCluster),
      layerGroup: jest.fn(() => makeLayerGroup()),
      divIcon: jest.fn(() => ({ icon: true })),
      point: jest.fn((x, y) => ({ x, y })),
      marker: jest.fn((latlng, options = {}) => {
        const events = {};
        const marker = {
          options,
          latlng,
          _popupOpen: false,
          _popupContent: "",
          on: jest.fn((name, handler) => {
            if (events[name]) {
              const prev = events[name];
              events[name] = (...args) => {
                prev(...args);
                handler(...args);
              };
            } else {
              events[name] = handler;
            }
          }),
          bindPopup: jest.fn((content) => {
            marker._popupContent = content;
          }),
          openPopup: jest.fn(() => {
            marker._popupOpen = true;
            if (marker._popupContent) {
              document.body.innerHTML = marker._popupContent;
            }
            if (events.popupopen) events.popupopen();
          }),
          closePopup: jest.fn(() => {
            marker._popupOpen = false;
            if (events.popupclose) events.popupclose();
          }),
          getPopup: jest.fn(() => ({
            isOpen: () => marker._popupOpen,
          })),
          setZIndexOffset: jest.fn(),
          setIcon: jest.fn(),
          getLatLng: jest.fn(() => latlng),
          __events: events,
        };
        return marker;
      }),
      latLngBounds: jest.fn(() => ({
        extend: jest.fn(),
      })),
      heatLayer: jest.fn(() => ({
        addTo: jest.fn().mockReturnValue({
          bringToBack: jest.fn(),
        }),
      })),
      circle: jest.fn((latlng, options = {}) => ({
        latlng,
        options,
        bindTooltip: jest.fn().mockReturnThis(),
        setStyle: jest.fn().mockReturnThis(),
        addTo: jest.fn().mockReturnThis(),
      })),
      polygon: jest.fn(() => polygonLayer),
      polyline: jest.fn(() => polylineLayer),
      circleMarker: jest.fn(() => circleMarkerLayer),
    },
  };
}

function loadMapModule() {
  jest.resetModules();
  return require("../../src/modules/map.js");
}

describe("map module", () => {
  beforeEach(() => {
    resetState();
    document.documentElement.style.removeProperty("--theme-color");
    mockSaveLists.mockClear();
    mockCopyToClipboard.mockClear();
    mockLog.mockClear();
    mockOpenCrackingPanel.mockClear();
    mockAPI.getZones.mockReset();
    mockAPI.getToConquerZones.mockReset();
    mockAPI.getVendor.mockReset();
    mockAPI.getVendorAlt.mockReset();
    mockAPI.getFingerprintDetails.mockReset();
  });

  test("initMap bootstraps map instance and exposes helpers", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    expect(leaflet.L.map).toHaveBeenCalledWith("map", {
      zoomControl: false,
      attributionControl: false,
    });
    expect(leaflet.L.markerClusterGroup).toHaveBeenCalled();
    expect(mapModule.getMapInstance()).toBe(leaflet.mapObj);
    expect(window.setTileLayer).toBe(mapModule.setTileLayer);
    expect(window.setClusterConfig).toBe(mapModule.setClusterConfig);
  });

  test("setTileLayer supports provider-specific options and fallback", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.setTileLayer("esri_sat");
    const esriCall = leaflet.L.tileLayer.mock.calls[leaflet.L.tileLayer.mock.calls.length - 1];
    expect(esriCall[0]).toContain("arcgisonline.com");
    expect(esriCall[1].subdomains).toBeUndefined();

    mapModule.setTileLayer("osm");
    const osmCall = leaflet.L.tileLayer.mock.calls[leaflet.L.tileLayer.mock.calls.length - 1];
    expect(osmCall[1].subdomains).toBe("abc");

    mapModule.setTileLayer("unknown-provider");
    const fallbackCall = leaflet.L.tileLayer.mock.calls[leaflet.L.tileLayer.mock.calls.length - 1];
    expect(fallbackCall[0]).toContain("cartocdn.com/dark_all");
  });

  test("wardrive overlays render and focus helpers fit bounds", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    document.documentElement.style.setProperty("--theme-color", "#ffcc00");

    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.renderWardriveRegion({
      outline: [[
        { lat: -22.95, lng: -43.25 },
        { lat: -22.95, lng: -43.15 },
        { lat: -22.88, lng: -43.15 },
      ]],
    });
    mapModule.renderWardriveZones([
      {
        parts: [[
          { lat: -22.91, lng: -43.2 },
          { lat: -22.91, lng: -43.18 },
          { lat: -22.9, lng: -43.19 },
        ]],
      },
    ]);
    expect(leaflet.L.polygon).toHaveBeenCalled();
    const regionCall = leaflet.L.polygon.mock.calls[0];
    expect(regionCall[1]).toEqual(expect.objectContaining({
      color: "#ffcc00",
      fillColor: "#ffcc00",
      fillOpacity: 0,
      opacity: 0.95,
    }));
    const zoneCall = leaflet.L.polygon.mock.calls[1];
    expect(zoneCall[1]).toEqual(expect.objectContaining({
      color: "#00ffd0",
      fillColor: "#00ffd0",
      fillOpacity: 0.12,
    }));

    const palette = mapModule.getWardriveSessionPalette(
      ["session-a", "session-b", "__comparison_secondary__"],
      "session-b",
      { comparisonMode: "focus_active" }
    );
    mapModule.renderWardriveZones(
      [
        {
          session_id: "session-b",
          parts: [[
            { lat: -22.92, lng: -43.21 },
            { lat: -22.92, lng: -43.19 },
            { lat: -22.905, lng: -43.2 },
          ]],
        },
      ],
      {
        sessionIds: ["session-a", "session-b", "__comparison_secondary__"],
        activeSessionId: "session-b",
        comparisonMode: "focus_active",
      }
    );
    const styledZoneCall = leaflet.L.polygon.mock.calls[leaflet.L.polygon.mock.calls.length - 1];
    expect(styledZoneCall[1]).toEqual(expect.objectContaining({
      color: palette["session-b"].innerColor,
      fillColor: palette["session-b"].innerColor,
      fillOpacity: palette["session-b"].zoneFillOpacity,
      weight: palette["session-b"].zoneWeight,
    }));
    expect(palette["session-b"].innerColor).toBe("#ffcc00");
    expect(palette["session-a"].innerColor).toBe("#ffd27e");

    mapModule.renderWardriveZones(
      [
        {
          session_id: "__comparison_secondary__",
          parts: [[
            [
              { lat: -22.94, lng: -43.24 },
              { lat: -22.94, lng: -43.18 },
              { lat: -22.88, lng: -43.18 },
            ],
            [
              { lat: -22.92, lng: -43.22 },
              { lat: -22.92, lng: -43.2 },
              { lat: -22.9, lng: -43.21 },
            ],
          ]],
        },
      ],
      {
        sessionIds: ["session-a", "session-b", "__comparison_secondary__"],
        activeSessionId: "session-b",
        comparisonMode: "focus_active",
      }
    );
    const secondaryZoneCall = leaflet.L.polygon.mock.calls[leaflet.L.polygon.mock.calls.length - 1];
    expect(secondaryZoneCall[0]).toEqual(expect.any(Array));
    expect(secondaryZoneCall[1]).toEqual(expect.objectContaining({
      color: palette["__comparison_secondary__"].innerColor,
      dashArray: palette["__comparison_secondary__"].zoneDashArray,
      fillOpacity: palette["__comparison_secondary__"].zoneFillOpacity,
    }));

    mapModule.focusWardriveBBox({
      min_lat: -23,
      min_lng: -43.5,
      max_lat: -22.8,
      max_lng: -43.1,
    });
    expect(leaflet.mapObj.fitBounds).toHaveBeenCalled();

    mapModule.focusWardriveZone({
      parts: [[
        [
          { lat: -22.91, lng: -43.2 },
          { lat: -22.91, lng: -43.18 },
          { lat: -22.9, lng: -43.19 },
        ],
        [
          { lat: -22.907, lng: -43.197 },
          { lat: -22.907, lng: -43.193 },
          { lat: -22.904, lng: -43.195 },
        ],
      ]],
    });
    expect(leaflet.mapObj.fitBounds).toHaveBeenCalledTimes(2);
  });

  test("wardrive palette honors configurable route, primary zone and secondary accents", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    document.documentElement.style.setProperty("--theme-color", "#11ccff");

    const mapModule = loadMapModule();
    mapModule.initMap();

    window.dispatchEvent(new CustomEvent("kovil:config-applied", {
      detail: {
        config: {
          ui_wardrive_route_accent_color: "orange",
          ui_wardrive_primary_zone_accent_color: "purple",
          ui_wardrive_secondary_accent_color: "white",
        },
      },
    }));

    const palette = mapModule.getWardriveSessionPalette(
      ["session-a", "session-b", "__comparison_secondary__"],
      "session-b",
      { comparisonMode: "focus_active" }
    );

    expect(palette["session-b"].trackColor).toBe("#ff8c00");
    expect(palette["session-b"].zoneColor).toBe("#bc13fe");
    expect(palette["session-a"].trackColor).toBe("#f5fbff");
    expect(palette["__comparison_secondary__"].zoneColor).toBe("#f5fbff");

    mapModule.renderWardriveSessionTracks([
      {
        session_id: "session-b",
        label: "session-b",
        points: [
          { lat: -22.93, lng: -43.23 },
          { lat: -22.91, lng: -43.21 },
        ],
      },
    ], "session-b");
    expect(leaflet.L.polyline.mock.calls[1][1]).toEqual(expect.objectContaining({
      color: "#ff8c00",
    }));

    mapModule.renderWardriveZones([
      {
        session_id: "session-b",
        parts: [[
          { lat: -22.92, lng: -43.21 },
          { lat: -22.92, lng: -43.19 },
          { lat: -22.905, lng: -43.2 },
        ]],
      },
    ], {
      sessionIds: ["session-a", "session-b", "__comparison_secondary__"],
      activeSessionId: "session-b",
      comparisonMode: "focus_active",
    });
    const zoneCall = leaflet.L.polygon.mock.calls[leaflet.L.polygon.mock.calls.length - 1];
    expect(zoneCall[1]).toEqual(expect.objectContaining({
      color: "#bc13fe",
      fillColor: "#bc13fe",
    }));
  });

  test("analytics heat layer renders and hotspot focus applies bounds", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.setAnalyticsHeatmapLayer(
      [{ lat: -22.9, lng: -43.2, value: 80, points_count: 2 }],
      "opportunity"
    );
    expect(leaflet.L.heatLayer).toHaveBeenCalled();

    mapModule.focusAnalyticsHotspot({
      mesh: [
        { lat: -22.91, lng: -43.21 },
        { lat: -22.89, lng: -43.2 },
        { lat: -22.9, lng: -43.18 },
      ],
    });
    expect(leaflet.mapObj.fitBounds).toHaveBeenCalled();
  });

  test("analytics heat layer redraws on zoomend", () => {
    jest.useFakeTimers();
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.analytics = true;
    mapModule.setAnalyticsHeatmapLayer(
      [{ lat: -22.9, lng: -43.2, value: 30, points_count: 1 }],
      "opportunity"
    );
    const initialCalls = leaflet.L.heatLayer.mock.calls.length;

    expect(typeof leaflet.mapObj.__events.zoomend).toBe("function");
    leaflet.mapObj.__events.zoomend();
    jest.advanceTimersByTime(50);

    expect(leaflet.L.heatLayer.mock.calls.length).toBeGreaterThan(initialCalls);
    jest.useRealTimers();
  });

  test("analytics heat redraw skips when analytics disabled or cache empty", () => {
    jest.useFakeTimers();
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.analytics = false;
    leaflet.mapObj.__events.zoomend();
    expect(jest.getTimerCount()).toBe(0);

    mockState.modes.analytics = true;
    leaflet.mapObj.__events.zoomend();
    expect(jest.getTimerCount()).toBe(0);

    mapModule.setAnalyticsHeatmapLayer([{ lat: -22.9, lng: -43.2, value: 30 }], "probe");
    leaflet.mapObj.__events.zoomend();
    expect(jest.getTimerCount()).toBe(1);

    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  test("analytics heat layer falls back to full dataset when viewport is too tight", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.analytics = true;
    leaflet.mapObj.getBounds = jest.fn(() => ({
      pad: jest.fn(() => ({
        contains: jest.fn((coord) => coord[0] > 50),
      })),
    }));

    mapModule.setAnalyticsHeatmapLayer(
      [
        { lat: 10, lng: 10, value: 1 },
        { lat: 60, lng: 60, value: 2 },
      ],
      "density"
    );

    const points = leaflet.L.heatLayer.mock.calls[0][0];
    expect(points.length).toBe(2);
  });

  test("clearAnalyticsHeatmapLayer removes layer and clears pending redraw", () => {
    jest.useFakeTimers();
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.analytics = true;
    mapModule.setAnalyticsHeatmapLayer([{ lat: -22.9, lng: -43.2, value: 80 }], "opportunity");
    const heatLayer = leaflet.L.heatLayer.mock.results[0].value;
    const addedLayer = heatLayer.addTo.mock.results[0].value;

    leaflet.mapObj.__events.zoomend();
    expect(jest.getTimerCount()).toBe(1);

    mapModule.clearAnalyticsHeatmapLayer();
    expect(jest.getTimerCount()).toBe(0);
    expect(leaflet.mapObj.removeLayer).toHaveBeenCalledWith(addedLayer);

    jest.useRealTimers();
  });

  test("analytics hotspot layer renders selected mesh and clears", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();
    mockState.modes.analytics = true;

    mapModule.setAnalyticsHotspotsLayer(
      [
        {
          id: "H1",
          center_lat: -22.9,
          center_lng: -43.2,
          radius_m: 120,
          score: 81,
          locked_count: 4,
          mesh: [
            { lat: -22.901, lng: -43.201 },
            { lat: -22.899, lng: -43.2 },
            { lat: -22.901, lng: -43.199 },
          ],
        },
        {
          id: "H2",
          center_lat: -22.91,
          center_lng: -43.21,
          radius_m: 90,
          score: 55,
          locked_count: 2,
          mesh: [
            { lat: -22.911, lng: -43.211 },
            { lat: -22.909, lng: -43.21 },
            { lat: -22.911, lng: -43.209 },
          ],
        },
        { id: "BAD", center_lat: undefined, center_lng: -43.2, radius_m: 100, score: 10, locked_count: 0 },
      ],
      "H1"
    );

    expect(leaflet.L.polygon).toHaveBeenCalledTimes(1);
    expect(leaflet.L.polygon.mock.calls[0][1].color).toBe("#00f3ff");

    const callsBeforeReselect = leaflet.L.polygon.mock.calls.length;
    mapModule.setSelectedAnalyticsHotspot("H2");
    expect(leaflet.L.polygon.mock.calls.length).toBeGreaterThan(callsBeforeReselect);
    const lastCallArgs = leaflet.L.polygon.mock.calls[leaflet.L.polygon.mock.calls.length - 1][1];
    expect(lastCallArgs.color).toBe("#00f3ff");

    mapModule.clearAnalyticsHotspotsLayer();
    const hotspotLayer = leaflet.L.layerGroup.mock.results[leaflet.L.layerGroup.mock.results.length - 1].value;
    expect(hotspotLayer.clearLayers).toHaveBeenCalled();
  });

  test("analytics hotspot layer skips circle fallback when mesh is unavailable", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();
    mockState.modes.analytics = true;

    mapModule.setAnalyticsHotspotsLayer(
      [{ id: "H3", center_lat: -22.9, center_lng: -43.2, radius_m: 120, score: 10, locked_count: 1 }],
      "H3"
    );

    expect(leaflet.L.circle).not.toHaveBeenCalled();
  });

  test("wardrive replay tracks render, focus and update playhead", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    expect(leaflet.mapObj.createPane).toHaveBeenCalledWith("wardriveReplayPlayheadPane");
    expect(leaflet.panes.wardriveReplayPlayheadPane.style.zIndex).toBe("690");

    const track = {
      session_id: "session-a",
      label: "Session A",
      transport_mode: "car",
      bbox: { min_lat: -22.91, min_lng: -43.2, max_lat: -22.9, max_lng: -43.19 },
      points: [
        { lat: -22.91, lng: -43.2, ts_last: 1, acc: 8 },
        { lat: -22.9, lng: -43.19, ts_last: 2, acc: 9 },
      ],
    };

    mapModule.renderWardriveSessionTracks([track], "session-a");
    expect(leaflet.L.polyline).toHaveBeenCalled();

    mapModule.setWardriveReplayPlayhead(track, 1);
    expect(leaflet.L.divIcon).toHaveBeenCalled();
    expect(leaflet.L.marker).toHaveBeenCalled();
    expect(leaflet.L.marker).toHaveBeenLastCalledWith(
      expect.any(Array),
      expect.objectContaining({
        pane: "wardriveReplayPlayheadPane",
        zIndexOffset: 20000,
      })
    );
    const replayMarker = leaflet.L.marker.mock.results[leaflet.L.marker.mock.results.length - 1].value;
    expect(replayMarker.setZIndexOffset).toHaveBeenCalledWith(20000);

    mapModule.focusWardriveTrack(track);
    expect(leaflet.mapObj.fitBounds).toHaveBeenCalled();
  });

  test("wardrive replay playhead interpolates smoothly between points", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    const track = {
      session_id: "session-a",
      label: "Session A",
      transport_mode: "car",
      points: [
        { lat: -22.91, lng: -43.2, ts_last: 0, acc: 8 },
        { lat: -22.905, lng: -43.195, ts_last: 10, acc: 9 },
        { lat: -22.9, lng: -43.19, ts_last: 30, acc: 10 },
      ],
    };

    mapModule.setWardriveReplayPlayhead(track, 0.5);

    const [lat, lng] = leaflet.L.marker.mock.calls[0][0];
    expect(lat).toBeCloseTo(-22.90375, 5);
    expect(lng).toBeCloseTo(-43.19375, 5);
  });

  test("wardrive replay camera helper centers active playhead with fixed or current zoom", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    const track = {
      session_id: "session-a",
      points: [
        { lat: 0, lng: 0, ts_last: 0 },
        { lat: 10, lng: 10, ts_last: 10 },
        { lat: 20, lng: 0, ts_last: 30 },
      ],
    };

    mapModule.focusWardriveReplayPlayhead(track, 0.5, { segmentWeights: [1, 3], zoom: 15 });
    let [coords, zoom, options] = leaflet.mapObj.setView.mock.calls[leaflet.mapObj.setView.mock.calls.length - 1];
    expect(coords[0]).toBeCloseTo(13.333333, 5);
    expect(coords[1]).toBeCloseTo(6.666667, 5);
    expect(zoom).toBe(15);
    expect(options).toEqual({ animate: false });

    mapModule.focusWardriveReplayPlayhead(track, 0.5);
    [coords, zoom, options] = leaflet.mapObj.setView.mock.calls[leaflet.mapObj.setView.mock.calls.length - 1];
    expect(coords[0]).toBeCloseTo(12.5, 5);
    expect(coords[1]).toBeCloseTo(7.5, 5);
    expect(zoom).toBe(13);
    expect(options).toEqual({ animate: false });
  });

  test("getAreaContextForMac returns hotspot metadata when available", () => {
    const mapModule = loadMapModule();
    const mac = "AA:BB:CC:DD:EE:77";

    mockState.modes.analytics = false;
    mockState.allPositions = { [mac]: { mac, lat: 1, lng: 2 } };
    expect(mapModule.getAreaContextForMac(mac)).toBeNull();

    mockState.modes.analytics = true;
    mockState.analyticsUi = {
      hotspots: [
        {
          id: "BAD",
          center_lat: null,
          center_lng: 2,
          radius_m: 0,
          score: 1,
        },
        {
          id: "H9",
          center_lat: 1,
          center_lng: 2,
          radius_m: 1000,
          score: 88,
          locked_count: 3,
          top_channels: ["6"],
        },
      ],
      selectedHotspotId: "H9",
    };

    expect(mapModule.getAreaContextForMac(mac)).toEqual({
      hotspot_id: "H9",
      score: 88,
      dominant_channel: "6",
      nearby_locked: 3,
    });
  });

  test("getAreaContextForMac returns null for missing/invalid positions and hotspots", () => {
    const mapModule = loadMapModule();
    const mac = "AA:BB:CC:DD:EE:88";

    mockState.modes.analytics = true;
    mockState.allPositions = {};
    expect(mapModule.getAreaContextForMac(mac)).toBeNull();

    mockState.allPositions = { [mac]: { mac, lat: "NaN", lng: 2 } };
    mockState.analyticsUi = { hotspots: [] };
    expect(mapModule.getAreaContextForMac(mac)).toBeNull();

    mockState.allPositions = { [mac]: { mac, lat: 1, lng: 2 } };
    mockState.analyticsUi = {
      hotspots: [{ id: "H0", center_lat: 1, center_lng: 2, radius_m: 0, score: 5 }],
      selectedHotspotId: "H0",
    };
    expect(mapModule.getAreaContextForMac(mac)).toBeNull();

    mockState.analyticsUi = {
      hotspots: [{ id: "H1", center_lat: 1, center_lng: 2, radius_m: 1000, score: 10, locked_count: 2 }],
      selectedHotspotId: "H1",
    };
    expect(mapModule.getAreaContextForMac(mac)).toEqual({
      hotspot_id: "H1",
      score: 10,
      dominant_channel: null,
      nearby_locked: 2,
    });
  });

  test("toggleTarget and toggleFav update state and emit event", () => {
    const mapModule = loadMapModule();
    mockState.isProgrammaticInteraction = true;

    const mac = "AA:BB:CC:DD:EE:FF";
    const events = [];
    document.addEventListener("listsUpdated", () => events.push("updated"));

    mapModule.toggleTarget(mac);
    expect(mockState.lists.targets).toEqual([mac]);

    mapModule.toggleTarget(mac);
    expect(mockState.lists.targets).toEqual([]);

    mapModule.toggleFav(mac);
    expect(mockState.lists.favs).toEqual([mac]);

    mapModule.toggleFav(mac);
    expect(mockState.lists.favs).toEqual([]);

    expect(mockSaveLists).toHaveBeenCalledTimes(4);
    expect(events.length).toBe(4);
  });

  test("calculateZones sends cracked points and draws polygons", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.conquered = true;
    mockAPI.getZones.mockResolvedValue({
      zones: [
        {
          parts: [[{ lat: 1, lng: 2 }, { lat: 1, lng: 3 }, { lat: 2, lng: 3 }]],
        },
      ],
    });

    const data = {
      one: {
        mac: "AA:00:00:00:00:01",
        pass: "secret",
        lat: 1,
        lng: 2,
        acc: 15,
        ts_last: Date.now() / 1000,
      },
    };

    await mapModule.calculateZones(data);

    expect(mockAPI.getZones).toHaveBeenCalledWith({
      points: [{ lat: 1, lng: 2, acc: 15 }],
      eps_m: 200,
      min_samples: 3,
    });
    expect(leaflet.L.polygon).toHaveBeenCalledTimes(1);
    expect(mockLog).toHaveBeenCalledWith(expect.stringContaining("Zones:"), "info");
  });

  test("calculateZones emits empty zones when there are no cracked points", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.conquered = true;

    const zonesEvents = [];
    document.addEventListener("zonesUpdated", (e) => zonesEvents.push(e.detail));

    await mapModule.calculateZones({
      one: {
        mac: "AA:00:00:00:00:02",
        pass: "",
        lat: 1,
        lng: 2,
        ts_last: Date.now() / 1000,
      },
    });

    expect(mockAPI.getZones).not.toHaveBeenCalled();
    expect(zonesEvents[zonesEvents.length - 1]).toEqual([]);
  });

  test("calculateToConquerZones sends conquered and locked candidates", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.toConquer = true;
    mockAPI.getToConquerZones.mockResolvedValue({
      zones: [
        {
          parts: [[{ lat: 1, lng: 2 }, { lat: 1, lng: 4 }, { lat: 2, lng: 4 }]],
        },
      ],
    });

    await mapModule.calculateToConquerZones({
      conquered: {
        mac: "AA:00:00:00:00:03",
        pass: "secret",
        ssid: "Known",
        encryption: "WPA2",
        lat: 1,
        lng: 2,
        acc: 7,
        ts_last: Date.now() / 1000,
      },
      locked: {
        mac: "AA:00:00:00:00:04",
        pass: "",
        ssid: "Locked",
        encryption: "WPA2",
        network_state: "locked",
        lat: 1.5,
        lng: 2.5,
        acc: 8,
        ts_last: Date.now() / 1000,
      },
      open: {
        mac: "AA:00:00:00:00:05",
        pass: "",
        ssid: "Open",
        encryption: "OPEN",
        lat: 1.7,
        lng: 2.7,
        ts_last: Date.now() / 1000,
      },
    });

    expect(mockAPI.getToConquerZones).toHaveBeenCalledWith(
      expect.objectContaining({
        conquered_points: [{ lat: 1, lng: 2, acc: 7 }],
        to_conquer_points: [{ lat: 1.5, lng: 2.5, acc: 8 }],
      })
    );
    expect(leaflet.L.polygon).toHaveBeenCalledTimes(1);
  });

  test("renderMarkers creates marker layers, opens popup and updates status", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockAPI.getVendor.mockResolvedValue({ vendor: "Vendor A" });
    mockAPI.getVendorAlt.mockResolvedValue({ vendor: "Vendor B" });
    mockAPI.getFingerprintDetails.mockResolvedValue({
      security: { wpa_version: "WPA2", akm: ["PSK"], pairwise_ciphers: ["CCMP"], pmf: "capable" },
      wps: { present: false },
      classification: { type: "router", confidence: 0.9 },
      raw_sniffer: {
        present: true,
        files_count: 2,
        aggregate: {
          beacon_count_total: 200,
          eapol_count_total: 4,
          probe_client_count_peak: 12,
          channels: [1, 6],
          frequencies_mhz: [2412, 2437],
        },
      },
      meta: {},
    });

    const statsEvents = [];
    document.addEventListener("statsUpdated", (e) => statsEvents.push(e.detail));

    const data = {
      locked: {
        mac: "AA:BB:CC:DD:EE:01",
        ssid: "LockedNet",
        encryption: "WPA2",
        lat: 1,
        lng: 2,
        acc: 12,
        ts_last: Date.now() / 1000,
        handshake_files: ["locked.pcap", "locked.22000", "locked.details"],
        raw_beacon_count: 120,
        raw_eapol_count: 3,
      },
      cracked: {
        mac: "AA:BB:CC:DD:EE:02",
        ssid: "CrackedNet",
        pass: "secret",
        encryption: "WPA2",
        lat: 1.1,
        lng: 2.1,
        acc: 15,
        ts_last: Date.now() / 1000,
      },
      open: {
        mac: "AA:BB:CC:DD:EE:03",
        ssid: "OpenNet",
        encryption: "OPEN",
        lat: 1.2,
        lng: 2.2,
        acc: 9,
        ts_last: Date.now() / 1000,
      },
      hidden: {
        mac: "AA:BB:CC:DD:EE:04",
        ssid: "",
        encryption: "WPA2",
        lat: 1.3,
        lng: 2.3,
        acc: 8,
        ts_last: Date.now() / 1000,
      },
      nogps: {
        mac: "AA:BB:CC:DD:EE:05",
        ssid: "NoGPS",
        encryption: "WPA2",
        type: "no-gps",
        pass: "",
      },
      wardrive: {
        mac: "AA:BB:CC:DD:EE:06",
        ssid: "WardriveNet",
        encryption: "WPA2",
        lat: 1.4,
        lng: 2.4,
        acc: 11,
        ts_last: Date.now() / 1000,
        sources: ["wardrive"],
      },
    };

    mapModule.renderMarkers(data);

    expect(leaflet.markerCluster.__layers.length).toBe(5);
    expect(statsEvents[statsEvents.length - 1]).toEqual(
      expect.objectContaining({
        total: 5,
        cracked: 1,
        open: 1,
        hidden: 1,
        noGpsTotal: 1,
        wardrive: 1,
      })
    );

    const popupMarker = leaflet.markerCluster.__layers[0];
    popupMarker.openPopup();
    await Promise.resolve();
    await Promise.resolve();

    expect(mockAPI.getFingerprintDetails).toHaveBeenCalledWith({ filename: "locked.details" });
    const popupText = document.body.textContent || "";
    expect(document.querySelector(".popup-card-header")).not.toBeNull();
    expect(document.querySelector('[data-popup-section="overview"]')).not.toBeNull();
    expect(document.querySelector('[data-popup-section="signal"]')).not.toBeNull();
    expect(document.querySelector('[data-popup-section="security"]')).not.toBeNull();
    expect(document.querySelector('[data-popup-section="raw"]')).not.toBeNull();
    expect(document.querySelector(".popup-chip-security")).not.toBeNull();
    expect(document.querySelector(".source-badge")).not.toBeNull();
    expect(popupText).toContain("PCAP");
    expect(popupText).toContain("HANDSHAKE");
    expect(popupText).toContain("HASH // CRACK");
    expect(popupText).toContain("RAW FILES");
    expect(popupText).toContain("RAW STATS");
    expect(popupText).not.toContain("RAW CH/FREQ");
    expect(popupText).not.toContain("beacons 120 | eapol 3");

    mapModule.updateMarkersStatus();
    expect(popupMarker.setIcon).toHaveBeenCalled();

    mapModule.updateMarkerStatusByMac("AA:BB:CC:DD:EE:01");
    expect(popupMarker.setIcon).toHaveBeenCalled();

    mockState.modes.radar = true;
    mapModule.updateRadarCircles();
    expect(leaflet.L.circle).toHaveBeenCalled();
  });

  test("renderMarkers shows raw fallback row when details request fails", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockAPI.getVendor.mockResolvedValue({ vendor: "Vendor A" });
    mockAPI.getVendorAlt.mockResolvedValue({ vendor: "Vendor B" });
    mockAPI.getFingerprintDetails.mockRejectedValue(new Error("details down"));

    const data = {
      locked: {
        mac: "AA:BB:CC:DD:EE:91",
        ssid: "LockedNet",
        encryption: "WPA2",
        lat: 1,
        lng: 2,
        acc: 12,
        ts_last: Date.now() / 1000,
        handshake_files: ["locked.details"],
        raw_beacon_count: 9,
        raw_eapol_count: 1,
      },
    };

    mapModule.renderMarkers(data);
    const popupMarker = leaflet.markerCluster.__layers[0];
    popupMarker.openPopup();
    await Promise.resolve();
    await Promise.resolve();

    const popupText = document.body.textContent || "";
    expect(document.querySelector('[data-popup-section="raw"]')).not.toBeNull();
    expect(popupText).toContain("RAW");
    expect(popupText).toContain("beacons 9 | eapol 1");
    expect(popupText).not.toContain("RAW FILES");
    expect(document.querySelectorAll(".popup-raw-summary-fallback").length).toBe(1);
  });

  test("renderMarkers supports #brucegotchi tag and source badge", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.filters.search = "#brucegotchi";

    const data = {
      bruce: {
        mac: "AA:BB:CC:DD:EE:10",
        ssid: "BruceNet",
        encryption: "WPA2",
        lat: 1.1,
        lng: 2.1,
        acc: 9,
        ts_last: Date.now() / 1000,
        sources: ["brucegotchi"],
      },
      pwn: {
        mac: "AA:BB:CC:DD:EE:11",
        ssid: "PwnNet",
        encryption: "WPA2",
        lat: 1.2,
        lng: 2.2,
        acc: 9,
        ts_last: Date.now() / 1000,
        sources: ["pwnagotchi"],
      },
    };

    mapModule.renderMarkers(data);
    expect(leaflet.markerCluster.__layers.length).toBe(1);

    const popupMarker = leaflet.markerCluster.__layers[0];
    popupMarker.openPopup();
    await Promise.resolve();

    const badge = document.querySelector(".source-brucegotchi");
    expect(badge).not.toBeNull();
    expect(badge.textContent).toContain("BRUCEGOTCHI");
  });

  test("renderMarkers supports #rawsniffer tag and source badge", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.filters.search = "#rawsniffer";

    const data = {
      raw: {
        mac: "AA:BB:CC:DD:EE:12",
        ssid: "RawNet",
        encryption: "WPA2",
        lat: 1.3,
        lng: 2.3,
        acc: 9,
        ts_last: Date.now() / 1000,
        sources: ["bruce_raw"],
      },
      bruce: {
        mac: "AA:BB:CC:DD:EE:13",
        ssid: "BruceNet",
        encryption: "WPA2",
        lat: 1.4,
        lng: 2.4,
        acc: 9,
        ts_last: Date.now() / 1000,
        sources: ["brucegotchi"],
      },
    };

    mapModule.renderMarkers(data);
    expect(leaflet.markerCluster.__layers.length).toBe(1);

    const popupMarker = leaflet.markerCluster.__layers[0];
    popupMarker.openPopup();
    await Promise.resolve();

    const badge = document.querySelector(".source-rawsniffer");
    expect(badge).not.toBeNull();
    expect(badge.textContent).toContain("RAWSNIFFER");
  });

  test("renderMarkers supports #m5evil tag and source badge", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.filters.search = "#m5evil";

    const data = {
      m5: {
        mac: "AA:BB:CC:DD:EE:21",
        ssid: "M5Net",
        encryption: "WPA2",
        lat: 1.5,
        lng: 2.5,
        acc: 9,
        ts_last: Date.now() / 1000,
        sources: ["m5evil"],
      },
      bruce: {
        mac: "AA:BB:CC:DD:EE:22",
        ssid: "BruceNet",
        encryption: "WPA2",
        lat: 1.6,
        lng: 2.6,
        acc: 9,
        ts_last: Date.now() / 1000,
        sources: ["brucegotchi"],
      },
    };

    mapModule.renderMarkers(data);
    expect(leaflet.markerCluster.__layers.length).toBe(1);

    const popupMarker = leaflet.markerCluster.__layers[0];
    popupMarker.openPopup();
    await Promise.resolve();

    const badge = document.querySelector(".source-m5evil");
    expect(badge).not.toBeNull();
    expect(badge.textContent).toContain("M5Evil");
  });

  test("focusAndOpenPopup opens visible marker and clears programmatic flag", () => {
    jest.useFakeTimers();

    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    const marker = {
      options: { posData: { mac: "AA:BB:CC:DD:EE:FF" } },
      getLatLng: jest.fn(() => [1, 2]),
      openPopup: jest.fn(),
    };

    leaflet.markerCluster.eachLayer.mockImplementation((cb) => cb(marker));
    leaflet.markerCluster.getVisibleParent.mockReturnValue(marker);

    mapModule.focusAndOpenPopup("AA:BB:CC:DD:EE:FF");

    expect(leaflet.mapObj.panInside).toHaveBeenCalledWith([1, 2], expect.any(Object));
    expect(marker.openPopup).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(500);
    expect(mockState.isProgrammaticInteraction).toBe(false);

    jest.useRealTimers();
  });

  test("focusAndOpenPopup handles clustered marker via zoomToShowLayer", () => {
    jest.useFakeTimers();

    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    const marker = {
      options: { posData: { mac: "00:11:22:33:44:55" } },
      getLatLng: jest.fn(() => [3, 4]),
      openPopup: jest.fn(),
    };

    leaflet.markerCluster.eachLayer.mockImplementation((cb) => cb(marker));
    leaflet.markerCluster.getVisibleParent.mockReturnValue({ id: "cluster-parent" });

    mapModule.focusAndOpenPopup("00:11:22:33:44:55");

    expect(leaflet.markerCluster.zoomToShowLayer).toHaveBeenCalledWith(marker, expect.any(Function));
    expect(leaflet.mapObj.panInside).toHaveBeenCalledWith([3, 4], expect.any(Object));
    expect(marker.openPopup).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(1000);
    expect(mockState.isProgrammaticInteraction).toBe(false);

    jest.useRealTimers();
  });

  test("setTileLayer and setClusterConfig are safe no-ops before map init", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();

    expect(() => mapModule.setTileLayer("osm")).not.toThrow();
    expect(() => mapModule.setClusterConfig("adaptive")).not.toThrow();
  });

  test("cluster config transitions and marker icon refresh paths are applied", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.allPositions = {
      one: {
        mac: "AA:AA:AA:AA:AA:01",
        ssid: "Node",
        encryption: "WPA2",
        lat: 1,
        lng: 1,
        ts_last: Date.now() / 1000,
      },
    };

    leaflet.mapObj.removeLayer.mockClear();
    mapModule.setClusterConfig("invalid");
    mapModule.setClusterConfig("performance");
    expect(leaflet.mapObj.removeLayer).not.toHaveBeenCalled();

    mapModule.setClusterConfig("tight");
    expect(leaflet.mapObj.removeLayer).toHaveBeenCalled();
    expect(leaflet.L.markerClusterGroup).toHaveBeenCalledTimes(2);
    expect(leaflet.mapObj.setView).toHaveBeenCalled();

    leaflet.markerCluster.clearLayers.mockClear();
    mapModule.setMarkerIcons("fa-cat", "fa-lock");
    expect(leaflet.markerCluster.clearLayers).toHaveBeenCalled();
  });

  test("cluster icon renderer prioritizes target, then cracked, and supports current cluster modes", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    const opts = leaflet.L.markerClusterGroup.mock.calls[0][0];
    expect(opts.disableClusteringAtZoom).toBeUndefined();
    const iconCreate = opts.iconCreateFunction;

    mockState.lists.targets = ["AA:AA:AA:AA:AA:AA"];
    iconCreate({
      getChildCount: () => 2,
      getAllChildMarkers: () => [{ options: { posData: { mac: "AA:AA:AA:AA:AA:AA" } } }],
    });
    let last = leaflet.L.divIcon.mock.calls[leaflet.L.divIcon.mock.calls.length - 1][0];
    expect(last.className).toContain("cluster-target");

    mockState.lists.targets = [];
    iconCreate({
      getChildCount: () => 3,
      getAllChildMarkers: () => [{ options: { posData: { mac: "BB:BB:BB:BB:BB:BB", pass: "secret" } } }],
    });
    last = leaflet.L.divIcon.mock.calls[leaflet.L.divIcon.mock.calls.length - 1][0];
    expect(last.className).toContain("cluster-cracked");

    iconCreate({
      getChildCount: () => 1,
      getAllChildMarkers: () => [{ options: {} }],
    });
    last = leaflet.L.divIcon.mock.calls[leaflet.L.divIcon.mock.calls.length - 1][0];
    expect(last.className).toContain("cyber-cluster");

    mapModule.setClusterConfig("tight");
    const tightOpts = leaflet.L.markerClusterGroup.mock.calls[leaflet.L.markerClusterGroup.mock.calls.length - 1][0];
    expect(tightOpts.maxClusterRadius).toBe(35);
    expect(tightOpts.disableClusteringAtZoom).toBeUndefined();
  });

  test("renderMarkers covers heat/radar hover and popup close cleanup branches", () => {
    jest.useFakeTimers();
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.heat = true;
    mockState.modes.radar = false;
    const mac = "AA:BB:CC:DD:EE:50";
    const data = {
      one: {
        mac,
        ssid: "HoverNet",
        encryption: "WPA2",
        lat: 2,
        lng: 3,
        acc: 10,
        ts_last: Date.now() / 1000,
      },
    };

    mapModule.renderMarkers(data, true);
    expect(leaflet.L.heatLayer).toHaveBeenCalled();

    const marker = leaflet.markerCluster.__layers[0];
    marker.__events.mouseover();
    expect(leaflet.L.circle).toHaveBeenCalled();
    marker.__events.mouseout();
    expect(leaflet.mapObj.removeLayer).toHaveBeenCalled();

    mockState.openPopupMac = mac;
    mockState.ignorePopupClose = true;
    marker.__events.popupclose();
    expect(mockState.openPopupMac).toBe(mac);

    mockState.ignorePopupClose = false;
    marker.__events.popupclose();
    jest.advanceTimersByTime(100);
    expect(mockState.openPopupMac).toBe(null);
    jest.useRealTimers();
  });

  test("renderMarkers respects filters and skips heat when cracking is active", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.heat = true;
    mockState.isCrackingActive = true;
    mockState.filters.time = "24H";
    mockState.filters.search = "needle";

    mapModule.renderMarkers({
      stale: {
        mac: "AA:AA:AA:AA:AA:70",
        ssid: "no-match",
        encryption: "WPA2",
        lat: 1,
        lng: 1,
        ts_last: (Date.now() / 1000) - 90000,
      },
    });

    expect(leaflet.markerCluster.__layers.length).toBe(0);
    expect(leaflet.L.heatLayer).not.toHaveBeenCalled();
  });

  test("renderMarkers matches search by MAC without separators", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.filters.search = "aabbccddee99";

    mapModule.renderMarkers({
      visible: {
        mac: "AA:BB:CC:DD:EE:99",
        ssid: "Mac Search Net",
        encryption: "WPA2",
        lat: 1,
        lng: 1,
        ts_last: Date.now() / 1000,
      },
    });

    expect(leaflet.markerCluster.__layers.length).toBe(1);
  });

  test("renderMarkers preserves open popup from map layers when no state is set", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.openPopupMac = null;
    leaflet.mapObj.eachLayer.mockImplementation((cb) =>
      cb({
        getPopup: () => ({ isOpen: () => true }),
        options: { posData: { mac: "AA:BB:CC:DD:EE:75" } },
      })
    );

    mapModule.renderMarkers({});
    expect(mockState.openPopupMac).toBe("AA:BB:CC:DD:EE:75");
  });

  test("renderMarkers covers cracking icons, wardrive badge and icon prefix", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.setMarkerIcons("skull", "lock", "fa-tower-broadcast", "badge");
    mockState.crackingByMac = {
      "AA:BB:CC:DD:EE:70": { status: "QUEUED", type: "HASHCAT 22000" },
      "AA:BB:CC:DD:EE:71": { status: "RUNNING", type: "AIRCRACK" },
    };

    mapModule.renderMarkers({
      queued: {
        mac: "AA:BB:CC:DD:EE:70",
        ssid: "QueuedNet",
        encryption: "WPA2",
        network_state: "locked",
        lat: 1,
        lng: 1,
        ts_last: Date.now() / 1000,
      },
      running: {
        mac: "AA:BB:CC:DD:EE:71",
        ssid: "RunningNet",
        encryption: "WPA2",
        network_state: "locked",
        lat: 1.1,
        lng: 1.1,
        ts_last: Date.now() / 1000,
      },
      wardrive: {
        mac: "AA:BB:CC:DD:EE:72",
        ssid: "WardriveNet",
        encryption: "WPA2",
        lat: 1.2,
        lng: 1.2,
        ts_last: Date.now() / 1000,
        sources: ["wardrive"],
      },
      locked: {
        mac: "AA:BB:CC:DD:EE:73",
        ssid: "LockedNet",
        encryption: "WPA2",
        network_state: "locked",
        lat: 1.3,
        lng: 1.3,
        ts_last: Date.now() / 1000,
      },
    });

    const iconHtml = leaflet.L.divIcon.mock.calls.map((call) => call[0].html).join(" ");
    expect(iconHtml).toContain("m-cracking-queued");
    expect(iconHtml).toContain("fa-cat");
    expect(iconHtml).toContain("fa-wind");
    expect(iconHtml).toContain("wardrive-badge");
    expect(iconHtml).toContain("fa-solid lock");
  });

  test("renderMarkers applies wardrive pulse style when configured", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.setMarkerIcons("fa-skull", "fa-shield-halved", "fa-tower-broadcast", "pulse");
    mapModule.renderMarkers({
      wardrive: {
        mac: "AA:BB:CC:DD:EE:74",
        ssid: "PulseNet",
        encryption: "WPA2",
        lat: 1.4,
        lng: 1.4,
        ts_last: Date.now() / 1000,
        sources: ["wardrive"],
      },
    });

    const iconHtml = leaflet.L.divIcon.mock.calls.map((call) => call[0].html).join(" ");
    expect(iconHtml).toContain("m-wardrive-pulse");
  });

  test("renderMarkers injects extra rows and reopens popup for open mac", () => {
    jest.useFakeTimers();
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    leaflet.markerCluster.getVisibleParent.mockReturnValue({ id: "cluster-parent" });

    mockState.modes.analytics = true;
    mockState.analyticsUi = {
      hotspots: [
        { id: "H1", center_lat: 1, center_lng: 2, radius_m: 2000, score: 55, top_channels: ["6"] },
      ],
      selectedHotspotId: "H1",
    };

    const mac = "AA:BB:CC:DD:EE:90";
    mockState.openPopupMac = mac;
    const ts = Date.now() / 1000;
    mapModule.renderMarkers(
      {
        one: {
          mac,
          ssid: "FocusNet",
          encryption: "WPA2",
          lat: 1,
          lng: 2,
          acc: 6,
          ts_last: ts,
          ts_first: ts - 5000,
          channel: 6,
          frequency: 2437,
          rssi: -40,
          altitude: 12.3,
          raw_beacon_count: 5,
          raw_eapol_count: 1,
          handshake_files: ["focus.pcap"],
        },
      },
      true
    );

    const marker = leaflet.markerCluster.__layers[0];
    jest.advanceTimersByTime(100);
    expect(marker.openPopup).toHaveBeenCalled();
    expect(leaflet.markerCluster.zoomToShowLayer).toHaveBeenCalled();

    const popupText = document.body.textContent || "";
    expect(document.querySelector('[data-popup-section="access"]')).not.toBeNull();
    expect(popupText).toContain("CH");
    expect(popupText).toContain("FREQ");
    expect(popupText).toContain("PCAP");
    expect(popupText).not.toContain("HANDSHAKE");
    expect(popupText).toContain("HASH // CRACK");
    expect(popupText).toContain("RAW");
    expect(popupText).toContain("AREA");
    expect(popupText).toContain("RSSI");
    expect(popupText).toContain("ALT");
    expect(popupText).toContain("FIRST SEEN");
    expect(popupText).toContain("HASH // CRACK");
    jest.useRealTimers();
  });

  test("renderMarkers shows raw CSV accuracy when source accuracy differs from operational accuracy", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    const ts = Date.now() / 1000;
    mapModule.renderMarkers({
      wardrive: {
        mac: "AA:BB:CC:DD:EE:06",
        ssid: "WardriveNet",
        encryption: "WPA2",
        lat: 1.4,
        lng: 2.4,
        acc: 8.0,
        sourceAccuracyMeters: 80,
        ts_last: ts,
        sources: ["wardrive"],
      },
    });

    const marker = leaflet.markerCluster.__layers[0];
    marker.openPopup();

    const popupText = document.body.textContent || "";
    expect(popupText).toContain("ACC");
    expect(popupText).toContain("8.0m");
    expect(popupText).toContain("RAW ACC");
    expect(popupText).toContain("80.0m");
  });

  test("renderMarkers shows hidden popup crack CTA only when 22000 exists", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.renderMarkers({
      hiddenPcapOnly: {
        mac: "AA:BB:CC:DD:EE:A1",
        ssid: "",
        encryption: "WPA2",
        lat: 5,
        lng: 6,
        acc: 10,
        ts_last: Date.now() / 1000,
        handshake_files: ["hidden_only.pcap"],
      },
      hiddenReady: {
        mac: "AA:BB:CC:DD:EE:A2",
        ssid: "",
        encryption: "WPA2",
        lat: 5.1,
        lng: 6.1,
        acc: 10,
        ts_last: Date.now() / 1000,
        handshake_files: ["hidden_ready.pcap", "hidden_ready.22000"],
      },
    });

    const pcapOnlyMarker = leaflet.markerCluster.__layers[0];
    pcapOnlyMarker.openPopup();
    let popupText = document.body.textContent || "";
    expect(document.querySelector('[data-popup-section="access"]')).not.toBeNull();
    expect(popupText).toContain("PCAP");
    expect(popupText).not.toContain("HANDSHAKE");
    expect(popupText).toContain("HASH // CRACK");

    const readyMarker = leaflet.markerCluster.__layers[1];
    readyMarker.openPopup();
    await Promise.resolve();
    popupText = document.body.textContent || "";
    expect(document.querySelector('[data-popup-section="access"]')).not.toBeNull();
    expect(document.querySelector(".popup-crack-cta")).not.toBeNull();
    expect(popupText).toContain("PCAP");
    expect(popupText).toContain("HANDSHAKE");
    expect(popupText).toContain("HASH // CRACK");
    jest.useRealTimers();
  });

  test("renderMarkers hides access section for wardrive-only networks", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;

    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.renderMarkers({
      wardriveOnly: {
        mac: "AA:BB:CC:DD:EE:A3",
        ssid: "GPSOnlyNet",
        encryption: "WPA2",
        lat: 6,
        lng: 7,
        acc: 10,
        ts_last: Date.now() / 1000,
        sources: ["wardrive"],
      },
    });

    const marker = leaflet.markerCluster.__layers[0];
    marker.openPopup();
    const popupText = document.body.textContent || "";
    expect(popupText).toContain("GPS ONLY");
    expect(document.querySelector('[data-popup-section="access"]')).toBeNull();
    expect(popupText).not.toContain("HASH // CRACK");
  });

  test("renderMarkers opens popup when marker is already visible", () => {
    jest.useFakeTimers();
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    const mac = "AA:BB:CC:DD:EE:95";
    mockState.openPopupMac = mac;
    mapModule.renderMarkers(
      {
        one: {
          mac,
          ssid: "VisibleNet",
          encryption: "WPA2",
          lat: 3,
          lng: 4,
          ts_last: Date.now() / 1000,
        },
      },
      true
    );

    const marker = leaflet.markerCluster.__layers[0];
    leaflet.markerCluster.getVisibleParent.mockReturnValue(marker);
    jest.advanceTimersByTime(100);
    expect(marker.openPopup).toHaveBeenCalled();
    expect(leaflet.markerCluster.zoomToShowLayer).not.toHaveBeenCalled();
    jest.useRealTimers();
  });

  test("renderMarkers opens marker directly during programmatic interaction", () => {
    jest.useFakeTimers();
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    const mac = "AA:BB:CC:DD:EE:99";
    mockState.openPopupMac = mac;
    mapModule.renderMarkers(
      {
        one: {
          mac,
          ssid: "ProgrammaticNet",
          encryption: "WPA2",
          lat: 2,
          lng: 3,
          ts_last: Date.now() / 1000,
        },
      },
      true
    );

    const marker = leaflet.markerCluster.__layers[0];
    mockState.isProgrammaticInteraction = true;
    jest.advanceTimersByTime(100);
    expect(marker.openPopup).toHaveBeenCalled();
    jest.useRealTimers();
  });

  test("popup open caches details, fetches vendor and popup close clears rows", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mapModule.clearDetailsCache();
    mockAPI.getVendor.mockResolvedValue({ vendor: "Vendor A" });
    mockAPI.getVendorAlt.mockResolvedValue({ vendor: "Vendor B" });
    mockAPI.getFingerprintDetails.mockResolvedValue({ security: { wpa_version: "WPA2" }, meta: {} });

    const mac = "AA:BB:CC:DD:EE:91";
    mapModule.renderMarkers({
      locked: {
        mac,
        ssid: "LockedNet",
        encryption: "WPA2",
        lat: 1,
        lng: 2,
        acc: 10,
        ts_last: Date.now() / 1000,
        handshake_files: ["locked.details"],
      },
    });

    const marker = leaflet.markerCluster.__layers[0];
    marker.openPopup();
    await Promise.resolve();
    await Promise.resolve();

    const macKey = mac.replace(/:/g, "");
    const vendorSpan = document.getElementById(`vendor-${macKey}`);
    const vendorAltSpan = document.getElementById(`vendor-alt-${macKey}`);
    if (vendorSpan) vendorSpan.innerText = "Loading...";
    if (vendorAltSpan) vendorAltSpan.innerText = "Loading...";
    marker.__events.popupopen();
    await Promise.resolve();

    expect(mockAPI.getVendor).toHaveBeenCalledWith(mac);
    expect(mockAPI.getVendorAlt).toHaveBeenCalledWith(mac);
    expect(document.querySelectorAll(".detail-row").length).toBeGreaterThan(0);

    marker.__events.popupopen();
    await Promise.resolve();
    expect(mockAPI.getFingerprintDetails).toHaveBeenCalledTimes(1);

    marker.__events.popupclose();
    expect(document.querySelectorAll(".detail-row").length).toBe(0);
  });

  test("popup open sets vendor placeholders to error on fetch failure", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockAPI.getVendor.mockRejectedValueOnce(new Error("vendor down"));
    mockAPI.getVendorAlt.mockRejectedValueOnce(new Error("vendor down"));

    const mac = "AA:BB:CC:DD:EE:93";
    mapModule.renderMarkers({
      locked: {
        mac,
        ssid: "VendorNet",
        encryption: "WPA2",
        lat: 1,
        lng: 2,
        acc: 10,
        ts_last: Date.now() / 1000,
        handshake_files: [],
      },
    });

    const marker = leaflet.markerCluster.__layers[0];
    const macKey = mac.replace(/:/g, "");
    marker.openPopup();
    const vendorEl = document.getElementById(`vendor-${macKey}`);
    const vendorAltEl = document.getElementById(`vendor-alt-${macKey}`);
    Object.defineProperty(vendorEl, "innerText", {
      configurable: true,
      get() {
        return this.textContent || "";
      },
      set(value) {
        this.textContent = value;
      },
    });
    Object.defineProperty(vendorAltEl, "innerText", {
      configurable: true,
      get() {
        return this.textContent || "";
      },
      set(value) {
        this.textContent = value;
      },
    });
    vendorEl.innerText = "Loading...";
    vendorAltEl.innerText = "Loading...";
    marker.__events.popupopen();
    await Promise.resolve();
    await Promise.resolve();

    expect(vendorEl).not.toBeNull();
    expect(vendorAltEl).not.toBeNull();
    expect(vendorEl.textContent).toBe("Err");
    expect(vendorAltEl.textContent).toBe("Err");
  });

  test("refreshPopupDetails clears previous rows and reinjects details", () => {
    const mapModule = loadMapModule();
    const mac = "AA:BB:CC:DD:EE:92";
    const macKey = mac.replace(/:/g, "");

    document.body.innerHTML = `
      <div class="data-card">
        <div id="data-rows-${macKey}">
          <div class="detail-row">old</div>
          <div class="data-row" id="sec-row-${macKey}"><span class="d-label">SEC</span><span class="d-val"></span></div>
        </div>
      </div>
    `;

    window.refreshPopupDetails(mac, {
      security: { wpa_version: "WPA3" },
      wps: { present: false },
      classification: { type: "router", confidence: 0.9 },
      meta: {},
    });

    const rows = document.querySelectorAll(`#data-rows-${macKey} .detail-row`);
    expect(rows.length).toBeGreaterThan(0);
  });

  test("popup action handlers cover copy, target/fav toggles, crack trigger and pass visibility", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mockState.isProgrammaticInteraction = true;

    const mac = "AA:BB:CC:DD:EE:60";
    const macKey = mac.replace(/:/g, "");
    document.body.innerHTML = `
      <div class="data-card">
        <div id="data-rows-${macKey}">
          <div class="data-row">
            <span id="pass-val-${macKey}" data-pass="supersecret">supersecret</span>
            <i id="pass-eye-${macKey}" class="fa-solid fa-eye" data-action="toggle-pass-visibility" data-mac="${mac}"></i>
          </div>
        </div>
        <div id="copy-btn" data-action="copy" data-copy="copied"></div>
        <div id="target-btn" data-action="toggle-target" data-mac="${mac}"></div>
        <div id="fav-btn" data-action="toggle-fav" data-mac="${mac}"></div>
        <div id="crack-btn" data-action="trigger-crack" data-mac="${mac}" data-ssid="My%20Network"></div>
      </div>
    `;

    mapModule.__testBindPopupActionHandlers({ mac });
    document.getElementById("copy-btn").click();
    expect(mockCopyToClipboard).toHaveBeenCalledWith("copied");

    document.getElementById("target-btn").click();
    document.getElementById("fav-btn").click();
    expect(mockState.lists.targets).toContain(mac);
    expect(mockState.lists.favs).toContain(mac);

    document.getElementById("crack-btn").click();
    expect(mockOpenCrackingPanel).toHaveBeenCalledWith(mac, "My Network");

    document.getElementById("pass-eye-" + macKey).click();
    expect(document.getElementById("pass-val-" + macKey).textContent).not.toBe("supersecret");
  });

  test("details injection handles fallbacks, already-applied guard and missing containers", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    const mac = "AA:BB:CC:DD:EE:61";
    const macKey = mac.replace(/:/g, "");

    document.body.innerHTML = `
      <div class="data-card">
        <div id="data-rows-${macKey}">
          <div class="data-row" id="sec-row-${macKey}"><span class="d-label">SEC</span><span class="d-val"></span></div>
          <div class="data-row" id="pass-row-${macKey}">
            <div class="vault-btn"></div>
          </div>
        </div>
      </div>
    `;

    mapModule.__testInjectDetailsIntoPopup(mac, {
      security: { group_cipher: "CCMP", akm: [], pairwise_ciphers: [] },
      wps: { present: false },
      classification: { type: "unknown", confidence: 0.2 },
      raw_sniffer: {
        present: true,
        files_count: 1,
        aggregate: {
          beacon_count_total: 33,
          eapol_count_total: 2,
          probe_client_count_peak: 7,
          channels: [6],
          frequencies_mhz: [2437],
        },
      },
      meta: {},
    });
    const rows = document.querySelectorAll(`#data-rows-${macKey} .detail-row`);
    expect(rows.length).toBeGreaterThan(0);
    expect(document.getElementById(`data-rows-${macKey}`).lastElementChild.id).toBe(`pass-row-${macKey}`);
    expect(document.getElementById(`data-rows-${macKey}`).textContent).toContain("RAW FILES");
    expect(document.getElementById(`data-rows-${macKey}`).textContent).toContain("RAW STATS");
    expect(document.getElementById(`data-rows-${macKey}`).textContent).not.toContain("RAW CH/FREQ");

    // second injection should be ignored by guard
    mapModule.__testInjectDetailsIntoPopup(mac, {
      security: { wpa_version: "WPA3" },
      wps: { present: true },
      classification: { type: "router", confidence: 0.99 },
      meta: {},
    });
    const rowsAfter = document.querySelectorAll(`#data-rows-${macKey} .detail-row`);
    expect(rowsAfter.length).toBe(rows.length);

    document.body.innerHTML = `<div class="data-card"></div>`;
    expect(() => mapModule.__testInjectDetailsIntoPopup(mac, null)).not.toThrow();
    expect(() => mapModule.__testInjectDetailsIntoPopup(mac, { security: {} })).not.toThrow();
  });

  test("details injection renders radio, rates, phy, caps, qbss and device classification rows", () => {
    const mapModule = loadMapModule();
    const mac = "AA:BB:CC:DD:EE:88";
    const macKey = mac.replace(/:/g, "");

    document.body.innerHTML = `
      <div class="data-card">
        <div id="data-rows-${macKey}">
          <div class="data-row" id="sec-row-${macKey}"><span class="d-label">SEC</span><span class="d-val"></span></div>
        </div>
      </div>
    `;

    mapModule.__testInjectDetailsIntoPopup(mac, {
      security: {
        wpa_version: "WPA2",
        akm: ["PSK"],
        pairwise_ciphers: ["CCMP"],
        pmf: "capable",
        group_cipher: "TKIP",
      },
      wps: { present: true, manufacturer: "Acme", model_name: "X1", device_name: "Router" },
      classification: { type: "router_ap", confidence: 0.92, tier: "gold" },
      radio: {
        channel: 6,
        band: 2.4,
        frequency_mhz: 2437,
        signal_dbm_avg: -40,
        signal_dbm_min: -70,
        signal_dbm_max: -20,
        datarate_mbps_avg: 12.5,
        datarate_mbps_max: 54,
      },
      rates: { all: [1, 2, 5.5], max_rate_mbps: 54 },
      phy: { ht_present: true, ht_width_code: "40", vht_present: false, vht_width_code: "80" },
      capabilities: { flags: [], privacy: true, short_preamble: true, qos: true },
      qbss: { station_count: 3, channel_utilization: 20, available_capacity: 50 },
      raw_sniffer: { present: false },
      meta: {},
    });

    const text = document.getElementById(`data-rows-${macKey}`).textContent || "";
    expect(text).toContain("CHANNEL / BAND");
    expect(text).toContain("SIGNAL");
    expect(text).toContain("RATES");
    expect(text).toContain("PHY");
    expect(text).toContain("CAPS");
    expect(text).toContain("QBSS");
    expect(text).toContain("DEVICE");
  });

  test("details injection renders phy width codes when ht/vht flags are false", () => {
    const mapModule = loadMapModule();
    const mac = "AA:BB:CC:DD:EE:89";
    const macKey = mac.replace(/:/g, "");

    document.body.innerHTML = `
      <div class="data-card">
        <div id="data-rows-${macKey}">
          <div class="data-row" id="sec-row-${macKey}"><span class="d-label">SEC</span><span class="d-val"></span></div>
        </div>
      </div>
    `;

    mapModule.__testInjectDetailsIntoPopup(mac, {
      security: { wpa_version: "WPA2", akm: ["PSK"], pairwise_ciphers: ["CCMP"], group_cipher: "CCMP" },
      wps: { present: false },
      classification: { type: "unknown", confidence: 0.2 },
      phy: { ht_present: false, ht_width_code: "20", vht_present: true, vht_width_code: "80" },
      meta: {},
    });

    const text = document.getElementById(`data-rows-${macKey}`).textContent || "";
    expect(text).toContain("HT w=20");
    expect(text).toContain("VHT w=80");
  });

  test("calculate zones/to-conquer early returns and error paths are handled", async () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    mockState.modes.conquered = false;
    await mapModule.calculateZones({});
    expect(mockAPI.getZones).not.toHaveBeenCalled();

    mockState.modes.conquered = true;
    mockAPI.getZones.mockRejectedValueOnce(new Error("zones down"));
    await mapModule.calculateZones({
      one: {
        mac: "AA:BB:CC:DD:EE:62",
        pass: "secret",
        lat: 1,
        lng: 1,
        acc: 5,
        ts_last: Date.now() / 1000,
      },
    });
    expect(mockLog).toHaveBeenCalledWith("Zones unavailable: zones down", "warn");

    mockState.modes.toConquer = true;
    await mapModule.calculateToConquerZones({
      onlyConquered: {
        mac: "AA:BB:CC:DD:EE:63",
        pass: "secret",
        ssid: "done",
        encryption: "WPA2",
        lat: 1,
        lng: 1,
        ts_last: Date.now() / 1000,
      },
    });
    expect(mockAPI.getToConquerZones).not.toHaveBeenCalled();

    mockAPI.getToConquerZones.mockRejectedValueOnce(new Error("to-conquer down"));
    await mapModule.calculateToConquerZones({
      locked: {
        mac: "AA:BB:CC:DD:EE:64",
        pass: "",
        ssid: "need",
        encryption: "WPA2",
        network_state: "locked",
        lat: 1.2,
        lng: 1.2,
        ts_last: Date.now() / 1000,
      },
    });
    expect(mockLog).toHaveBeenCalledWith("To-conquer zones unavailable: to-conquer down", "warn");
  });

  test("focusAndOpenPopup with missing marker and radar early-return branches", () => {
    const leaflet = createLeafletMock();
    global.L = leaflet.L;
    const mapModule = loadMapModule();
    mapModule.initMap();

    leaflet.markerCluster.eachLayer.mockImplementation(() => {});
    mapModule.focusAndOpenPopup("FF:FF:FF:FF:FF:FF");
    expect(leaflet.mapObj.panInside).not.toHaveBeenCalled();

    mockState.modes.radar = false;
    mapModule.updateRadarCircles();
    expect(leaflet.L.circle).not.toHaveBeenCalled();

    mockState.modes.radar = true;
    mockState.isCrackingActive = true;
    mapModule.updateRadarCircles();
    expect(leaflet.L.circle).not.toHaveBeenCalled();
  });
});
