const fs = require("fs");
const path = require("path");

describe("index.html security posture", () => {
  test("uses only local script assets and self-only script CSP", () => {
    const html = fs.readFileSync(
      path.join(__dirname, "../../src/index.html"),
      "utf-8",
    );

    expect(html).toContain("script-src 'self'");
    expect(html).not.toContain("https://unpkg.com");
    expect(html).not.toContain("https://cdnjs.cloudflare.com");
    expect(html).toContain('vendor/leaflet/leaflet.js');
    expect(html).toContain('vendor/nouislider/nouislider.min.js');
    expect(html).toContain('vendor/fontawesome/css/all.min.css');
  });
});
