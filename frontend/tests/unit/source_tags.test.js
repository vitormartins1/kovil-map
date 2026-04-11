const {
  normalizeSources,
  getSourceFlags,
  getSourceBadges,
  getSourceTokens,
  matchesSourceFilter,
  mapAnalyticsSourceLabel,
} = require("../../src/modules/source_tags.js");

test("normalizeSources defaults and expands raw source variants", () => {
  expect(normalizeSources()).toEqual(["pwnagotchi"]);
  expect(normalizeSources([])).toEqual(["pwnagotchi"]);
  expect(normalizeSources(["BrUcE_RaW"])).toEqual(["brucegotchi", "rawsniffer"]);
  expect(normalizeSources(["m5evil_raw_sniffing"])).toEqual(["m5evil", "rawsniffer"]);
  expect(normalizeSources(["m5evil_master_raw_sniffing"])).toEqual(["m5evil", "rawsniffer"]);
  expect(normalizeSources(["pwnagotchi", "bruce_raw", "wardrive", "pwnagotchi"]).sort()).toEqual(
    ["pwnagotchi", "brucegotchi", "rawsniffer", "wardrive"].sort()
  );
});

test("normalizeSources falls back when only empty values are provided", () => {
  expect(normalizeSources(["", "  ", null, undefined])).toEqual(["pwnagotchi"]);
});

test("getSourceFlags reports all known sources", () => {
  const flags = getSourceFlags(["pwnagotchi", "wardrive", "brucegotchi", "m5evil_master_raw_sniffing", "bruce_raw"]);
  expect(flags.hasPwnagotchi).toBe(true);
  expect(flags.hasWardrive).toBe(true);
  expect(flags.hasBrucegotchi).toBe(true);
  expect(flags.hasM5evil).toBe(true);
  expect(flags.hasRawsniffer).toBe(true);
});

test("getSourceBadges returns labeled classes", () => {
  const badges = getSourceBadges(["bruce_raw", "wardrive"]);
  expect(badges).toEqual([
    { label: "WARDRIVE", className: "source-badge source-wardrive" },
    { label: "BRUCEGOTCHI", className: "source-badge source-brucegotchi" },
    { label: "RAWSNIFFER", className: "source-badge source-rawsniffer" },
  ]);
});

test("getSourceTokens produces normalized source names", () => {
  const tokens = getSourceTokens(["pwnagotchi", "brucegotchi", "m5evil"]);
  expect(tokens).toEqual(["PWNAGOTCHI", "BRUCEGOTCHI", "M5Evil"]);
});

test("matchesSourceFilter works with normalized sources", () => {
  const sources = ["bruce_raw", "wardrive", "m5evil_master_raw_sniffing"];
  expect(matchesSourceFilter(sources, "raw")).toBe(true);
  expect(matchesSourceFilter(sources, "ward")).toBe(true);
  expect(matchesSourceFilter(sources, "m5")).toBe(true);
  expect(matchesSourceFilter(sources, "bruce")).toBe(true);
  expect(matchesSourceFilter(sources, "pwn")).toBe(false);
  expect(matchesSourceFilter(sources, "all")).toBe(true);
  expect(matchesSourceFilter(sources, "unknown")).toBe(true);
});

test("mapAnalyticsSourceLabel maps legacy keys", () => {
  expect(mapAnalyticsSourceLabel("RAW")).toBe("RAWSNIFFER");
  expect(mapAnalyticsSourceLabel("BRUCE_RAW_SNIFFING")).toBe("BRUCE RAW");
  expect(mapAnalyticsSourceLabel("M5EVIL_RAW_SNIFFING")).toBe("M5EVIL RAW");
  expect(mapAnalyticsSourceLabel("M5EVIL_MASTER_RAW_SNIFFING")).toBe("M5EVIL MASTER RAW");
  expect(mapAnalyticsSourceLabel("PWN")).toBe("PWNAGOTCHI");
  expect(mapAnalyticsSourceLabel("WARD")).toBe("WARDRIVE");
  expect(mapAnalyticsSourceLabel("BRUCE")).toBe("BRUCEGOTCHI");
  expect(mapAnalyticsSourceLabel("M5")).toBe("M5Evil");
  expect(mapAnalyticsSourceLabel("UNKNOWN")).toBe("UNKNOWN");
});

test("mapAnalyticsSourceLabel trims and uppercases inputs", () => {
  expect(mapAnalyticsSourceLabel(" raw ")).toBe("RAWSNIFFER");
  expect(mapAnalyticsSourceLabel(null)).toBe("");
});
