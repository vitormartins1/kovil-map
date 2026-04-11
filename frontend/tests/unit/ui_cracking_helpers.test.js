jest.mock("../../src/modules/api.js", () => ({
  API: {},
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: jest.fn(),
  escapeHtml: (value) => String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;"),
}));

jest.mock("../../src/modules/attack_modes.js", () => ({
  getModePanelLabel: jest.fn(),
  getModeRunLabel: jest.fn(),
  isSlowCandidatesCompatible: jest.fn(),
  modeRequiresAssociationHints: jest.fn(),
  modeRequiresMaskProfile: jest.fn(),
  modeRequiresSecondWordlist: jest.fn(),
  modeRequiresWordlist: jest.fn(),
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: { modes: {}, allPositions: {} },
  saveModes: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => ({
  updateNoGpsList: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  activeProcesses: {},
  addProcess: jest.fn(),
  updateProcess: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_history.js", () => ({
  renderHistoryPanel: jest.fn(),
}));

const { __testUiCrackingHelpers } = require("../../src/modules/ui_components/ui_cracking.js");

describe("ui_cracking helper coverage", () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <div id="crack-raw-context-summary"></div>
      <button id="crack-raw-prepare-all-btn"></button>
    `;
  });

  test("basic string and filename helpers normalize values", () => {
    expect(__testUiCrackingHelpers.escapeMaybe(null)).toBe("—");
    expect(__testUiCrackingHelpers.escapeMaybe("SSID")).toBe("SSID");
    expect(__testUiCrackingHelpers.isAssociationMode("association")).toBe(true);
    expect(__testUiCrackingHelpers.isAssociationMode("straight")).toBe(false);
    expect(__testUiCrackingHelpers.isRawHashFilename("raw_demo.22000")).toBe(true);
    expect(__testUiCrackingHelpers.isRawHashFilename("capture.22000")).toBe(false);
    expect(__testUiCrackingHelpers.getFileStem("capture.pcap")).toBe("capture");
    expect(__testUiCrackingHelpers.getFileStem("capture")).toBe("capture");
    expect(__testUiCrackingHelpers.isValidMac("AA:BB:CC:DD:EE:FF")).toBe(true);
    expect(__testUiCrackingHelpers.isValidMac("aabbccddeeff")).toBe(false);
  });

  test("raw hash scoping helper handles direct, fallback and synthetic results", () => {
    const files = [
      { name: "raw_a.22000" },
      { name: "raw_a.try" },
      { name: "other.22000" },
    ];

    expect(__testUiCrackingHelpers.filterFilesForRawHashScope(files, "")).toBe(files);
    expect(
      __testUiCrackingHelpers.filterFilesForRawHashScope(files, "raw_a.22000"),
    ).toEqual([{ name: "raw_a.22000" }, { name: "raw_a.try" }]);
    expect(
      __testUiCrackingHelpers.filterFilesForRawHashScope(files, "other.22000"),
    ).toEqual([{ name: "other.22000" }]);
    expect(
      __testUiCrackingHelpers.filterFilesForRawHashScope(files, "missing.22000"),
    ).toEqual([
      expect.objectContaining({
        name: "missing.22000",
        type: "22000",
        size: 0,
      }),
    ]);
  });

  test("raw context helpers sanitize payloads and render summaries", () => {
    const normalized = __testUiCrackingHelpers.normalizeRawContextPayload({
      present: false,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        null,
        {
          source_file: "capture.pcap",
          ssid: "Cafe",
          channel: "6",
          frequency_mhz: "2437",
          beacon_count: "4",
          eapol_count: "2",
          warnings: ["note"],
        },
      ],
      hash_files: [
        {
          filename: "raw_hash.22000",
          valid_hash_lines: "3",
          source_raw_file: "capture.pcap",
          modified: "100",
          size: "2048",
        },
      ],
      aggregate: { eapol_count_total: 2 },
    });

    expect(normalized.present).toBe(true);
    expect(normalized.files_count).toBe(1);
    expect(normalized.hash_files_count).toBe(1);
    expect(normalized.files[0]).toMatchObject({
      source_file: "capture.pcap",
      channel: 6,
      frequency_mhz: 2437,
      beacon_count: 4,
      eapol_count: 2,
    });

    expect(__testUiCrackingHelpers.formatRawProcessedAt(null)).toBe("Processed: unknown");
    expect(__testUiCrackingHelpers.formatRawProcessedAt("not-a-date")).toBe(
      "Processed: not-a-date",
    );
    expect(__testUiCrackingHelpers.formatRawProcessedAt("2026-01-01T00:00:00Z")).toContain(
      "Processed:",
    );

    __testUiCrackingHelpers.renderRawContextSummary(normalized);
    expect(document.getElementById("crack-raw-context-summary").textContent).toContain(
      "1 RAW hash(es) linked",
    );

    __testUiCrackingHelpers.renderRawContextSummary({
      files_count: 2,
      hash_files_count: 0,
      hash_files: [],
      aggregate: {},
    });
    expect(document.getElementById("crack-raw-context-summary").textContent).toContain(
      "No RAW hashes linked yet",
    );

    __testUiCrackingHelpers.renderRawContextSummary(
      { files_count: 0, hash_files_count: 0, hash_files: [], aggregate: {} },
      "Custom summary",
    );
    expect(document.getElementById("crack-raw-context-summary").textContent).toBe(
      "Custom summary",
    );
  });

  test("result and button helpers resolve canonical hashes and running state", () => {
    expect(
      __testUiCrackingHelpers.resolveCanonicalHashFromResult({
        canonical_hash: "canon.22000",
      }),
    ).toBe("canon.22000");
    expect(
      __testUiCrackingHelpers.resolveCanonicalHashFromResult({
        artifacts: { hash_file: "artifact.22000" },
      }),
    ).toBe("artifact.22000");
    expect(__testUiCrackingHelpers.resolveCanonicalHashFromResult(null)).toBeNull();

    __testUiCrackingHelpers.setRawPrepareAllButtonState({ running: true });
    expect(document.getElementById("crack-raw-prepare-all-btn").disabled).toBe(true);
    expect(document.getElementById("crack-raw-prepare-all-btn").innerHTML).toContain(
      "RUNNING",
    );

    __testUiCrackingHelpers.setRawPrepareAllButtonState({ running: false });
    expect(document.getElementById("crack-raw-prepare-all-btn").disabled).toBe(false);
    expect(document.getElementById("crack-raw-prepare-all-btn").innerHTML).toBe(
      "BUILD CANONICAL FROM ALL",
    );
  });
});
