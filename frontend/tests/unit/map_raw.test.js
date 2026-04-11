const { getRawSummaryFromPosition, insertRawSummaryFallbackRow } = require("../../src/modules/map_raw.js");

beforeEach(() => {
  document.body.innerHTML = "";
});

test("getRawSummaryFromPosition returns summary when counts exist", () => {
  expect(getRawSummaryFromPosition({ raw_beacon_count: 0, raw_eapol_count: 0 })).toBeNull();
  const summary = getRawSummaryFromPosition({ raw_beacon_count: 2, raw_eapol_count: 1 });
  expect(summary).toEqual({
    rawBeaconCount: 2,
    rawEapolCount: 1,
    summaryText: "beacons 2 | eapol 1",
  });
});

test("insertRawSummaryFallbackRow inserts row before pass row", () => {
  document.body.innerHTML = `
    <div id="data-rows-AABBCC">
      <div id="pass-row-AABBCC"></div>
    </div>
  `;

  insertRawSummaryFallbackRow({
    mac: "AA:BB:CC",
    raw_beacon_count: 3,
    raw_eapol_count: 0,
  });

  const rows = document.querySelectorAll("#data-rows-AABBCC .raw-summary-row");
  expect(rows).toHaveLength(1);
  const container = document.getElementById("data-rows-AABBCC");
  expect(container.firstElementChild.classList.contains("raw-summary-row")).toBe(true);

  insertRawSummaryFallbackRow({
    mac: "AA:BB:CC",
    raw_beacon_count: 3,
    raw_eapol_count: 0,
  });
  expect(document.querySelectorAll("#data-rows-AABBCC .raw-summary-row")).toHaveLength(1);
});

test("insertRawSummaryFallbackRow no-ops without container or counts", () => {
  insertRawSummaryFallbackRow({
    mac: "AA:BB:CC",
    raw_beacon_count: 0,
    raw_eapol_count: 0,
  });

  document.body.innerHTML = "";
  insertRawSummaryFallbackRow({
    mac: "DD:EE:FF",
    raw_beacon_count: 4,
    raw_eapol_count: 1,
  });

  expect(document.querySelectorAll(".raw-summary-row")).toHaveLength(0);
});
