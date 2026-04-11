const {
  escapeHtml,
  safeText,
  copyToClipboard,
  log,
  bootLog,
  convexHull,
  expandPointsByAccuracy,
} = require("../../src/modules/utils.js");

test("escapeHtml escapes reserved chars", () => {
  expect(escapeHtml("<a&\"' >")).toBe("&lt;a&amp;&quot;&#039; &gt;");
  expect(escapeHtml("")).toBe("");
  expect(escapeHtml(null)).toBeNull();
});

test("safeText normalizes nullish and converts values to string", () => {
  expect(safeText(null)).toBe("");
  expect(safeText(undefined)).toBe("");
  expect(safeText(123)).toBe("123");
});

test("log returns safely when panel does not exist", () => {
  expect(() => log("test")).not.toThrow();
});

test("log prepends entries and applies severity class", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';

  log("warn-msg", "warn");
  log("error-msg", "error");
  log("ok-msg", "success");

  const entries = [...document.querySelectorAll("#log-panel .log-entry")];
  expect(entries.length).toBe(3);
  expect(entries[0].innerHTML).toContain("ok-msg");
  expect(entries[0].innerHTML).toContain("log-highlight");
  expect(entries[1].innerHTML).toContain("error-msg");
  expect(entries[1].innerHTML).toContain("log-danger");
  expect(entries[2].innerHTML).toContain("warn-msg");
  expect(entries[2].innerHTML).toContain("log-warn");
});

test("bootLog appends boot entry", () => {
  document.body.innerHTML = '<div id="boot-log"></div>';
  bootLog("ready");
  expect(document.getElementById("boot-log").innerHTML).toContain("[BOOT] ready");
});

test("log and bootLog do not inject HTML from untrusted payload", async () => {
  document.body.innerHTML = '<div id="log-panel"></div><div id="boot-log"></div>';
  const payload = '<img src=x onerror="window.__xss__=1">';

  log(payload, "warn");
  bootLog(payload);
  await copyToClipboard(payload);
  await Promise.resolve();

  expect(document.querySelectorAll("#log-panel img").length).toBe(0);
  expect(document.querySelectorAll("#boot-log img").length).toBe(0);
  expect(document.getElementById("log-panel").textContent).toContain(payload);
  expect(document.getElementById("boot-log").textContent).toContain(payload);
});

test("copyToClipboard writes text and logs feedback", async () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  await copyToClipboard("abc123");
  await Promise.resolve();
  expect(navigator.clipboard.writeText).toHaveBeenCalledWith("abc123");
  expect(document.getElementById("log-panel").innerHTML).toContain("Copied to clipboard: abc123");
});

test("convexHull returns hull points counter-clockwise and handles short inputs", () => {
  const pts = [
    { lat: 0, lng: 0 },
    { lat: 1, lng: 0 },
    { lat: 1, lng: 1 },
    { lat: 0, lng: 1 },
    { lat: 0.5, lng: 0.5 },
  ];
  const hull = convexHull(pts);
  expect(hull).toHaveLength(4);
  expect(convexHull([])).toEqual([]);
  expect(convexHull([{ lat: 1, lng: 1 }])).toEqual([{ lat: 1, lng: 1 }]);
});

test("expandPointsByAccuracy expands points based on accuracy radius", () => {
  const input = [
    { lat: 10, lng: 20, acc: 0 },
    { lat: 11, lng: 21, acc: 10 },
    { lat: null, lng: 0, acc: 50 },
  ];
  const expanded = expandPointsByAccuracy(input, 4);

  // First point contributes 1, second contributes 1 + 4, invalid lat is skipped
  expect(expanded.length).toBe(6);
  expect(expanded[0]).toEqual({ lat: 10, lng: 20 });
  expect(expanded[1]).toEqual({ lat: 11, lng: 21 });
  expect(expandPointsByAccuracy([], 8)).toEqual([]);
});
