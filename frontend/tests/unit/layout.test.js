const { getHudAutoPanPadding } = require("../../src/modules/layout.js");

test("getHudAutoPanPadding falls back when getComputedStyle is unavailable", () => {
  const original = window.getComputedStyle;
  window.getComputedStyle = undefined;

  const padding = getHudAutoPanPadding();
  expect(padding).toEqual({
    topLeft: [320, 60],
    bottomRight: [540, 30],
  });

  window.getComputedStyle = original;
});

test("getHudAutoPanPadding reads css variables when available", () => {
  const original = window.getComputedStyle;
  window.getComputedStyle = () => ({
    getPropertyValue: (name) => {
      if (name === "--left-sidebar-w") return "200px";
      if (name === "--right-panels-w") return "360px";
      if (name === "--hud-inset") return "10px";
      if (name === "--hud-pan-top") return "40px";
      if (name === "--hud-pan-bottom") return "12px";
      return "";
    },
  });

  const padding = getHudAutoPanPadding();
  expect(padding).toEqual({
    topLeft: [220, 40],
    bottomRight: [380, 12],
  });

  window.getComputedStyle = original;
});
