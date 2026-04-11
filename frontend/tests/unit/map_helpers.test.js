jest.mock("../../src/modules/state.js", () => ({
  STATE: {
    analyticsUi: {},
    allPositions: {},
    modes: {
      analytics: false,
    },
  },
  saveLists: jest.fn(),
}));

jest.mock("../../src/modules/utils.js", () => ({
  escapeHtml: (value) => String(value ?? ""),
  copyToClipboard: jest.fn(),
  log: jest.fn(),
  safeText: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/api.js", () => ({
  API: {},
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: jest.fn(),
}));

jest.mock("../../src/modules/layout.js", () => ({
  getHudAutoPanPadding: jest.fn(() => ({
    topLeft: [0, 0],
    bottomRight: [0, 0],
  })),
}));

jest.mock("../../src/modules/map_raw.js", () => ({
  getRawSummaryFromPosition: jest.fn(() => null),
  insertRawSummaryFallbackRow: jest.fn(),
}));

jest.mock("../../src/modules/source_tags.js", () => ({
  getSourceBadges: jest.fn(() => []),
  getSourceFlags: jest.fn((sources = []) => {
    const set = new Set(Array.isArray(sources) ? sources : []);
    return {
      hasWardrive: set.has("wardrive"),
      hasPwnagotchi: set.has("pwnagotchi"),
      hasBrucegotchi: set.has("brucegotchi"),
      hasM5evil: set.has("m5evil"),
      hasRawsniffer: set.has("rawsniffer"),
    };
  }),
}));

const { getAreaContextForMac, __testMapHelpers, __testSetMapState } = require("../../src/modules/map.js");

describe("map helper coverage", () => {
  beforeEach(() => {
    __testSetMapState({
      analyticsUi: {},
      allPositions: {},
      modes: { analytics: false },
    });
  });

  test("polygon helpers handle invalid shapes and inside matches", () => {
    expect(__testMapHelpers.pointInPolygon(0, 0, null)).toBe(false);
    expect(
      __testMapHelpers.pointInPolygon(0.5, 0.5, [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 },
        { lat: 1, lng: 1 },
        { lat: 1, lng: 0 },
      ]),
    ).toBe(true);
    expect(
      __testMapHelpers.pointInPolygon(2, 2, [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 },
        { lat: 1, lng: 1 },
        { lat: 1, lng: 0 },
      ]),
    ).toBe(false);
  });

  test("matching hotspot helper covers analytics guards, mesh and radius fallbacks", () => {
    expect(__testMapHelpers.getMatchingHotspotForPosition({ lat: 1, lng: 1 })).toBeNull();

    __testSetMapState({
      modes: { analytics: true },
      analyticsUi: { hotspots: [], selectedHotspotId: "h1" },
    });
    expect(__testMapHelpers.getMatchingHotspotForPosition({ lat: 1, lng: 1 })).toBeNull();

    __testSetMapState({
      analyticsUi: {
        hotspots: [
          {
            id: "h1",
            score: 1,
            mesh: [
              { lat: 0, lng: 0 },
              { lat: 0, lng: 2 },
              { lat: 2, lng: 2 },
              { lat: 2, lng: 0 },
            ],
          },
          {
            id: "h1",
            score: 9,
            center_lat: 1,
            center_lng: 1,
            radius_m: 500,
          },
        ],
        selectedHotspotId: "h1",
      },
    });
    expect(
      __testMapHelpers.getMatchingHotspotForPosition({ lat: 1, lng: 1 }).score,
    ).toBe(9);

    __testSetMapState({
      analyticsUi: {
        hotspots: [
          {
            id: "h2",
            score: 4,
            center_lat: 0,
            center_lng: 0,
            radius_m: 10,
          },
        ],
        selectedHotspotId: "h2",
      },
    });
    expect(
      __testMapHelpers.getMatchingHotspotForPosition({ lat: 2, lng: 2 }),
    ).toBeNull();
  });

  test("area context derives hotspot payload and handles absent matches", () => {
    expect(getAreaContextForMac("AA:BB")).toBeNull();

    __testSetMapState({
      modes: { analytics: true },
      allPositions: {
        "AA:BB:CC:DD:EE:FF": { mac: "AA:BB:CC:DD:EE:FF", lat: 1, lng: 1 },
      },
      analyticsUi: {
        selectedHotspotId: "hot-1",
        hotspots: [
          {
            id: "hot-1",
            score: 7,
            top_channels: [6, 11],
            locked_count: 3,
            mesh: [
              { lat: 0, lng: 0 },
              { lat: 0, lng: 2 },
              { lat: 2, lng: 2 },
              { lat: 2, lng: 0 },
            ],
          },
        ],
      },
    });

    expect(getAreaContextForMac("aa:bb:cc:dd:ee:ff")).toEqual({
      hotspot_id: "hot-1",
      score: 7,
      dominant_channel: 6,
      nearby_locked: 3,
    });
  });

  test("device, search and bounds helpers normalize values", () => {
    expect(__testMapHelpers.getDeviceTypeLabel("router")).toBe("Router AP");
    expect(__testMapHelpers.getDeviceTypeLabel("custom_device")).toBe("custom device");
    expect(
      __testMapHelpers.isWardriveOnlySource({
        hasWardrive: true,
        hasPwnagotchi: false,
        hasBrucegotchi: false,
        hasM5evil: false,
        hasRawsniffer: false,
      }),
    ).toBe(true);
    expect(
      __testMapHelpers.isWardriveOnlySource({
        hasWardrive: true,
        hasPwnagotchi: true,
        hasBrucegotchi: false,
        hasM5evil: false,
        hasRawsniffer: false,
      }),
    ).toBe(false);
    expect(__testMapHelpers.getNormalizedMacSearchValue("AA:BB-CC:DD-EE:FF")).toBe(
      "aabbccddeeff",
    );
    expect(
      __testMapHelpers.buildSearchableText(
        { ssid: "Cafe", mac: "AA:BB:CC:DD:EE:FF" },
        "Vendor",
        "#wardrive",
      ),
    ).toContain("aabbccddeeff");
    expect(__testMapHelpers.maskPassword("abc")).toBe("****");
    expect(__testMapHelpers.maskPassword("abcdefgh")).toBe("********");
    expect(__testMapHelpers.escapeAttribute(`a"&'<b>`)).toBe("a&quot;&amp;&#39;&lt;b&gt;");
    expect(__testMapHelpers.boundsFromBBox(null)).toBeNull();
    expect(
      __testMapHelpers.boundsFromBBox({
        min_lat: 1,
        min_lng: 2,
        max_lat: 3,
        max_lng: 4,
      }),
    ).toEqual([
      [1, 2],
      [3, 4],
    ]);
  });

  test("wardrive polygon, style and replay helpers cover fallback branches", () => {
    expect(__testMapHelpers.normalizePolygonRings(null)).toEqual([]);
    expect(
      __testMapHelpers.normalizePolygonRings([
        [
          { lat: 0, lng: 0 },
          { lat: 0, lng: 1 },
          { lat: 1, lng: 1 },
        ],
        [{ lat: 1, lng: 1 }],
      ]),
    ).toEqual([
      [
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 },
        { lat: 1, lng: 1 },
      ],
    ]);
    expect(
      __testMapHelpers.normalizePolygonRings([
        { lat: 0, lng: 0 },
        { lat: 0, lng: 1 },
        { lat: 1, lng: 1 },
      ]),
    ).toHaveLength(1);

    expect(
      __testMapHelpers.buildWardriveSessionStyle("#00f", "#0f0", true, "focus_active"),
    ).toMatchObject({
      trackColor: "#00f",
      zoneColor: "#0f0",
      outerWeight: 8,
      zoneFillOpacity: 0.18,
    });
    expect(
      __testMapHelpers.buildWardriveSessionStyle("#00f", "#0f0", false, "standard"),
    ).toMatchObject({
      trackColor: "#00f",
      zoneColor: "#0f0",
      outerWeight: 5,
      zoneFillOpacity: 0.08,
    });

    expect(__testMapHelpers.getWardriveReplayPosition([], 0.3)).toBeNull();
    expect(
      __testMapHelpers.getWardriveReplayPosition([{ lat: "1", lng: "2", ts_last: 10 }], 0.3),
    ).toEqual({ lat: 1, lng: 2, ts_last: 10 });

    expect(
      __testMapHelpers.getWardriveReplayPosition(
        [
          { lat: 0, lng: 0, ts_last: 5 },
          { lat: 10, lng: 10, ts_last: 5 },
        ],
        1,
      ),
    ).toEqual({ lat: 10, lng: 10, ts_last: 5 });

    const interpolated = __testMapHelpers.getWardriveReplayPosition(
      [
        { lat: 0, lng: 0, ts_last: 0 },
        { lat: 10, lng: 10, ts_last: 10 },
        { lat: 20, lng: 0, ts_last: 30 },
      ],
      0.5,
    );
    expect(interpolated).toMatchObject({ lat: 12.5, lng: 7.5, ts_last: 15 });

    const weighted = __testMapHelpers.getWardriveReplayPosition(
      [
        { lat: 0, lng: 0, ts_last: 0 },
        { lat: 10, lng: 10, ts_last: 10 },
        { lat: 20, lng: 0, ts_last: 30 },
      ],
      0.5,
      [1, 3],
    );
    expect(weighted.lat).toBeCloseTo(13.333, 2);
    expect(weighted.lng).toBeCloseTo(6.666, 2);
  });
});
