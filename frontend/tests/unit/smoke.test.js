const fs = require("fs");
const path = require("path");

const frontendRoot = path.resolve(__dirname, "..", "..");

function read(relPath) {
  return fs.readFileSync(path.join(frontendRoot, relPath), "utf8");
}

test("package.json has expected Electron entrypoints", () => {
  const pkg = JSON.parse(read("package.json"));
  expect(pkg.main).toBe("main.js");
  expect(pkg.scripts?.start).toBeTruthy();
  expect(pkg.scripts?.dist).toBeTruthy();
  expect(pkg.build?.appId).toBeTruthy();
});

test("critical frontend files exist", () => {
  const required = [
    "main.js",
    "src/index.html",
    "src/renderer.js",
    "src/modules/api.js",
    "src/modules/socket.js",
    "src/css/styles.css",
  ];

  for (const relPath of required) {
    expect(fs.existsSync(path.join(frontendRoot, relPath))).toBe(true);
  }
});

test("index.html defines a CSP and local backend connect-src", () => {
  const html = read("src/index.html");
  expect(html).toMatch(/Content-Security-Policy/i);
  expect(html).toMatch(/http:\/\/127\.0\.0\.1:8000/);
  expect(html).toMatch(/ws:\/\/127\.0\.0\.1:8000/);
});

test("API and socket modules target local backend", () => {
  const api = read("src/modules/api.js");
  const socket = read("src/modules/socket.js");

  expect(api).toMatch(/127\.0\.0\.1:8000/);
  expect(socket).toMatch(/127\.0\.0\.1:8000/);
});

test("index.html includes association hint-first and association hint-rule mode controls", () => {
  const html = read("src/index.html");
  expect(html).toMatch(/value="association_hint_first"/);
  expect(html).toMatch(/value="association_hint_rule"/);
  expect(html).toMatch(/id="crack-association-hints-input"/);
});

test("index.html includes M5Evil reachability help for same-network WebUI and remote exposure", () => {
  const html = read("src/index.html");
  expect(html).toMatch(/M5EVIL ADMIN WEBUI/);
  expect(html).toMatch(/SAME-NETWORK WEBUI/);
  expect(html).toMatch(/REMOTE EXPOSURE/);
  expect(html).toMatch(/same Wi-Fi\/network as the desktop/);
  expect(html).toMatch(/Start Captive Portal/);
  expect(html).toMatch(/IP shown by the Cardputer/);
  expect(html).toMatch(/wifi_ssid/);
  expect(html).toMatch(/wifi_password/);
  expect(html).toMatch(/tcp_host/);
  expect(html).toMatch(/tcp_port/);
  expect(html).toMatch(/webpassword/);
  expect(html).not.toMatch(/HANDSHAKE SD PATH/);
  expect(html).not.toMatch(/WARDRIVE SD PATH/);
});

test("index.html includes Pwnagotchi SSH sync card, test button, and USB guidance", () => {
  const html = read("src/index.html");
  expect(html).toMatch(/PWNAGOTCHI SSH SYNC/);
  expect(html).toMatch(/btn-conf-pwn-test/);
  expect(html).toMatch(/USB SSH SETUP/);
  expect(html).toMatch(/SAME-HOST SSH OVER USB/);
  expect(html).toMatch(/USB\/RNDIS network interface/);
  expect(html).toMatch(/TEST CONNECTION/);
});
