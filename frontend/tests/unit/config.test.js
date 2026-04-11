const { CONFIG } = require("../../src/modules/config.js");

test("CONFIG exposes expected API endpoints", () => {
  expect(CONFIG.URLS.MAP_DATA).toBe("http://127.0.0.1:8000/api/map/data");
  expect(CONFIG.URLS.SYNC).toBe("http://127.0.0.1:8000/api/sync");
  expect(CONFIG.URLS.SYNC_TRUST_HOST_KEY).toBe("http://127.0.0.1:8000/api/sync/trust-host-key");
  expect(CONFIG.URLS.VENDOR).toBe("http://127.0.0.1:8000/api/vendors");
  expect(CONFIG.URLS.STATUS).toBe("http://127.0.0.1:8000/api/health");
});

test("CONFIG exposes map defaults", () => {
  expect(CONFIG.MAP.DEFAULT_LAT).toBeCloseTo(-23.5505);
  expect(CONFIG.MAP.DEFAULT_LNG).toBeCloseTo(-46.6333);
  expect(CONFIG.MAP.DEFAULT_ZOOM).toBe(13);
});
