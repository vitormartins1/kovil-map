const mockAPI = {
  getConfig: jest.fn(),
  getCustomWordlists: jest.fn(),
  getHashcatRules: jest.fn(),
  getHashcatMasks: jest.fn(),
  getHashcatDevices: jest.fn(),
  getHandshakeSet: jest.fn(),
  getHandshakeFiles: jest.fn(),
  getHandshakeRawContext: jest.fn(),
  buildCombinedCapture: jest.fn(),
  prepareHandshakeRaw: jest.fn(),
  prepareHandshakeRawAll: jest.fn(),
  getBatchFiles: jest.fn(),
  getMultiFileContent: jest.fn(),
  startCracking: jest.fn(),
  startAircrack: jest.fn(),
  convertPcap: jest.fn(),
  extractFingerprint: jest.fn(),
  getFingerprintDetails: jest.fn(),
  getAttackRecommendation: jest.fn(),
  previewAssociationCandidates: jest.fn(),
  getFileContent: jest.fn(),
  clearHistory: jest.fn(),
};

const mockState = {
  modes: { cracking: false, analytics: false },
  allPositions: {},
  openPopupMac: null,
};

const mockSaveModes = jest.fn();
const mockLog = jest.fn();
const mockUpdateNoGpsList = jest.fn();
const mockAddProcess = jest.fn();
const mockUpdateProcess = jest.fn();
const mockActiveProcesses = {};
const mockRenderHistoryPanel = jest.fn();

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
  saveModes: (...args) => mockSaveModes(...args),
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
  escapeHtml: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => ({
  updateNoGpsList: (...args) => mockUpdateNoGpsList(...args),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  activeProcesses: mockActiveProcesses,
  addProcess: (...args) => mockAddProcess(...args),
  updateProcess: (...args) => mockUpdateProcess(...args),
}));

jest.mock("../../src/modules/ui_components/ui_history.js", () => ({
  renderHistoryPanel: (...args) => mockRenderHistoryPanel(...args),
}));

function resetState() {
  mockState.modes = { cracking: false, analytics: false };
  mockState.allPositions = {};
  mockState.openPopupMac = null;

  Object.keys(mockActiveProcesses).forEach((key) => delete mockActiveProcesses[key]);

  mockSaveModes.mockClear();
  mockLog.mockClear();
  mockUpdateNoGpsList.mockClear();
  mockAddProcess.mockClear();
  mockUpdateProcess.mockClear();
  mockRenderHistoryPanel.mockClear();

  Object.keys(mockAPI).forEach((key) => {
    if (typeof mockAPI[key]?.mockReset === "function") {
      mockAPI[key].mockReset();
    }
  });

  mockAPI.getConfig.mockResolvedValue({
    hashcat_optimized: false,
    hashcat_slow: true,
    hashcat_device_default: "1",
  });
  mockAPI.getCustomWordlists.mockResolvedValue([{ name: "wl.txt", path: "/wl.txt" }]);
  mockAPI.getHashcatRules.mockResolvedValue([{ name: "best64.rule", path: "/best64.rule" }]);
  mockAPI.getHashcatMasks.mockResolvedValue([{ name: "wifi.hcmask", path: "/wifi.hcmask" }]);
  mockAPI.getHashcatDevices.mockResolvedValue([
    { id: "1", name: "Mock GPU", type: "OpenCL", backend: "OpenCL" },
  ]);
  mockAPI.getHandshakeSet.mockRejectedValue(new Error("not available"));
  mockAPI.getHandshakeFiles.mockResolvedValue([
    { name: "capture.pcap", type: "pcap", size: 1024, modified: 1700000000 },
    { name: "capture.22000", type: "22000", size: 1024, modified: 1700000001 },
    { name: "capture.cracked", type: "cracked", size: 100, modified: 1700000002 },
    { name: "capture.details", type: "details", size: 100, modified: 1700000003 },
    { name: "capture.try", type: "try", size: 100, modified: 1700000004 },
  ]);
  mockAPI.getHandshakeRawContext.mockResolvedValue({ present: false, files: [] });
  mockAPI.buildCombinedCapture.mockResolvedValue({
    status: "success",
    build_id: "build-123456",
    output_file: "combined.22000",
  });
  mockAPI.prepareHandshakeRaw.mockResolvedValue({
    status: "success",
    canonical_hash: "focused.22000",
    artifacts: { pcap_file: null, hash_file: "focused.22000" },
  });
  mockAPI.prepareHandshakeRawAll.mockResolvedValue({
    status: "started",
    job_id: "job-raw-all",
    total_files: 1,
  });
  mockAPI.getBatchFiles.mockResolvedValue([
    { name: "batch_alpha.22000", type: "batch", size: 2048, modified: 1700001000 },
    { name: "batch_alpha.try", type: "try", size: 128, modified: 1700001001 },
  ]);
  mockAPI.getMultiFileContent.mockResolvedValue({ items: [] });
  mockAPI.startCracking.mockResolvedValue({ status: "started", job_id: "job-123" });
  mockAPI.startAircrack.mockResolvedValue({ status: "started", job_id: "job-air" });
  mockAPI.convertPcap.mockResolvedValue({ status: "started", job_id: "job-conv" });
  mockAPI.extractFingerprint.mockResolvedValue({ saved_path: "/tmp/capture.details", details: {} });
  mockAPI.getFingerprintDetails.mockResolvedValue({
    ssid: "My SSID",
    bssid: "AA:BB:CC:DD:EE:FF",
    security: { wpa_version: "WPA2", akm: ["PSK"], pairwise_ciphers: ["CCMP"], group_cipher: "CCMP", pmf: "capable" },
    wps: { present: false },
    classification: { type: "router", confidence: 0.9, evidence: ["ssid_pattern"] },
    meta: { source: "test", timestamp: "2026-02-08T00:00:00Z" },
  });
  mockAPI.getAttackRecommendation.mockResolvedValue({
    target: { filename: "capture.22000", mac: "AA:BB:CC:DD:EE:FF" },
    action: "run",
    recommended_mode: "rules",
    candidate_modes: ["rules", "straight"],
    reasons: ["Mock recommendation"],
    attack_score: {
      score: 72,
      priority: "high",
      score_reasons: [{ delta: 10, reason: "valid hash lines" }],
    },
    quality_gate: { passed: true, can_override: true, checks: [] },
  });
  mockAPI.previewAssociationCandidates.mockResolvedValue({
    status: "success",
    mode: "association_hint_first",
    candidate_count: 42,
    capped: false,
    cap: 60000,
    sample_candidates: ["candidate1", "candidate2"],
    sources: {
      seed_counts: { ssid: 1, hint: 2, fallback_hint: 0, ssid_fallback: 1 },
      ssid_count: 1,
      hint_count: 2,
      transformations: ["original", "common_suffixes"],
    },
    warnings: [],
  });
  mockAPI.getFileContent.mockResolvedValue("hash:password");
  mockAPI.clearHistory.mockResolvedValue({ deleted_count: 2 });
}

function mountCrackingDom() {
  document.body.innerHTML = `
    <button id="btn-toggle-cracking"></button>
    <div id="cracking-panel"><button class="close-panel"></button></div>

    <div id="crack-ssid"></div>
    <div id="crack-mac"></div>
    <div id="crack-handshake-set-summary"></div>
    <div id="crack-file-list"></div>
    <div id="crack-raw-context-section" style="display:none">
      <div id="crack-raw-context-summary"></div>
      <button id="crack-raw-prepare-all-btn" data-action="raw-auto-prepare-all">AUTO PREPARE ALL</button>
      <div id="crack-raw-context-list"></div>
    </div>
    <div id="crack-actions" style="display:none"></div>

    <div id="selected-file-info"></div>
    <button id="btn-convert-hash"></button>
    <button id="btn-pcap-generate-hash"></button>
    <button id="btn-quick-attack"></button>
    <button id="btn-extract-details"></button>

    <div id="file-type-badge"></div>
    <div id="crack-progress-text"></div>
    <div id="crack-mini-bar"></div>
    <div class="crack-status-container"></div>

    <div id="crack-config-preview"></div>
    <div id="crack-aircrack-options"></div>
    <div id="crack-pcap-conversions"></div>
    <div id="crack-file-feedback"></div>

    <button id="aircrack-legacy-toggle" data-expanded="false"><span class="legacy-toggle-arrow"></span></button>

    <select id="wordlist-select"></select>
    <select id="crack-wordlist-select"></select>
    <select id="crack-wordlist-2-select"></select>
    <select id="crack-rule-select"></select>
    <select id="crack-rule-2-select"></select>
    <select id="crack-mask-profile-select"></select>
    <select id="crack-device-select"></select>

    <div id="crack-device-row"></div>

    <input id="flag-optimized" type="checkbox" />
    <input id="flag-slow" type="checkbox" />
    <input id="flag-increment" type="checkbox" />

    <select id="custom-mode-select">
      <option value="straight">straight</option>
      <option value="association">association</option>
      <option value="association_hint_first">association_hint_first</option>
      <option value="combinator">combinator</option>
      <option value="combinator_passphrase">combinator_passphrase</option>
      <option value="mask_profile">mask_profile</option>
      <option value="mask">mask</option>
      <option value="hybrid">hybrid</option>
      <option value="hybrid_reverse">hybrid_reverse</option>
      <option value="hybrid_mask_profile">hybrid_mask_profile</option>
      <option value="hybrid_reverse_mask_profile">hybrid_reverse_mask_profile</option>
    </select>
    <span id="custom-mode-label"></span>

    <input id="custom-workload-slider" value="3" />
    <span id="custom-workload-val">3</span>

    <div id="crack-wordlist-row"></div>
    <div id="crack-wordlist-2-row"></div>
    <div id="crack-rule-row"></div>
    <div id="crack-rule-2-row"></div>
    <span id="crack-rule-label"></span>

    <div id="crack-mask-row"><div><button id="mask-help-btn"></button></div></div>
    <div id="crack-mask-profile-row"></div>
    <div id="crack-association-hint-row"></div>
    <div id="crack-association-hints-row"></div>
    <div id="crack-association-preview-row"></div>
    <div id="flag-increment-container"></div>
    <div id="crack-increment-row"></div>
    <button id="btn-association-preview"></button>

    <input id="crack-mask-input" value="?a?a?a?a?a?a?a?a" />
    <textarea id="crack-association-hints-input"></textarea>
    <input id="crack-association-hint-input" />

    <div id="increment-slider"></div>
    <span id="inc-val-min"></span>
    <span id="inc-val-max"></span>
  `;

  const sliderState = {
    values: [1, 8],
    get: jest.fn(() => sliderState.values),
    set: jest.fn((next) => {
      sliderState.values = [Number(next[0]), Number(next[1])];
    }),
    on: jest.fn(),
  };

  global.noUiSlider = {
    create: jest.fn(() => sliderState),
  };
  window.noUiSlider = global.noUiSlider;
}

async function flushAsync() {
  await Promise.resolve();
  await Promise.resolve();
}

async function openReady22000Panel(uiCracking) {
  await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.22000");
}

function setMode(mode) {
  const select = document.getElementById("custom-mode-select");
  select.value = mode;
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

function clickFileByName(name) {
  const item = Array.from(document.querySelectorAll("#crack-file-list .file-item")).find((el) =>
    el.textContent.includes(name)
  );
  expect(item).toBeTruthy();
  item.click();
}

function loadUiCrackingModule() {
  jest.resetModules();
  return require("../../src/modules/ui_components/ui_cracking.js");
}

describe("ui_cracking actions", () => {
  beforeEach(() => {
    resetState();
    mountCrackingDom();
    delete document.documentElement.dataset.crackingAccordionMode;
    window.alert = jest.fn();
    window.confirm = jest.fn().mockReturnValue(true);
  });

  test("startCracking sends hint-first payload and enforces slow=false", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    setMode("association_hint_first");
    document.getElementById("crack-association-hints-input").value = "companywifi\nbackup";
    document.getElementById("flag-slow").checked = true;

    document.getElementById("btn-convert-hash").click();
    await flushAsync();

    expect(mockAPI.startCracking).toHaveBeenCalledTimes(1);
    const args = mockAPI.startCracking.mock.calls[0];
    expect(args[0]).toBe("capture.22000");
    expect(args[1]).toBe("association_hint_first");
    expect(args[7]).toBe(false); // isSlow
    expect(args[15]).toBe(null); // association_hint (legacy)
    expect(args[16]).toBe("companywifi\nbackup"); // association_hints
    expect(args[17]).toBe(false); // skipQualityGate default
    expect(mockAddProcess).toHaveBeenCalledWith(
      "job-123",
      expect.stringContaining("ASSOC MULTI-HINT"),
      "capture.22000",
      "STARTING",
      "AA:BB:CC:DD:EE:FF"
    );
  });

  test("startCracking blocks hint-first mode without hints", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    setMode("association_hint_first");
    document.getElementById("crack-association-hints-input").value = "\n   \n";

    document.getElementById("btn-convert-hash").click();
    await flushAsync();

    expect(mockAPI.startCracking).not.toHaveBeenCalled();
    expect(document.getElementById("crack-progress-text").innerText).toBe("HINT REQUIRED");
    expect(document.getElementById("btn-convert-hash").disabled).toBe(false);
  });

  test("association preview calls API and renders candidates card", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    setMode("association_hint_first");
    document.getElementById("crack-association-hints-input").value = "companywifi\nbackup";

    document.getElementById("btn-association-preview").click();
    await flushAsync();

    expect(mockAPI.previewAssociationCandidates).toHaveBeenCalledWith(
      "capture.22000",
      "association_hint_first",
      null,
      "companywifi\nbackup",
      null,
      null,
      "AA:BB:CC:DD:EE:FF"
    );
    expect(document.getElementById("crack-file-feedback").textContent).toContain("ASSOCIATION PREVIEW");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("Top Candidates");

    mockAPI.previewAssociationCandidates.mockRejectedValueOnce(new Error("preview fail"));
    document.getElementById("btn-association-preview").click();
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain("Failed to preview candidates");
  });

  test("openCrackingPanel renders handshake set groups and auto-selects preferred capture", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi", "m5evil"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 3, pcap: 3, hash_22000: 1, details: 1, cracked: 0, history: 0 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.pcap", type: "pcap", size: 1024, modified: 1700000000, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "HS_AABBCCDDEEFF.pcap", type: "pcap", size: 640, modified: 1700000002, capture_id: "cap-bruce", source: "brucegotchi", device_label: "Brucegotchi", source_path_role: "bruce_handshakes" },
      { name: "hidden_aabbccddeeff__wdrs__.22000", type: "22000", size: 80, modified: 1700000003, capture_id: null, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
    ]);

    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    expect(document.getElementById("crack-handshake-set-summary").textContent).toContain("HANDSHAKE SET");
    expect(document.getElementById("crack-handshake-set-summary").textContent).not.toContain("Preferred:");
    expect(document.getElementById("selected-file-info").textContent).toContain("Cafe_aabbccddeeff.22000");
    expect(document.getElementById("crack-file-list").textContent).toContain("LEGACY / SHARED ARTIFACTS");
    expect(document.getElementById("crack-file-list").textContent).toContain("HS_AABBCCDDEEFF.pcap");

    const legacyHeader = Array.from(
      document.querySelectorAll("#crack-file-list .capture-group-header")
    ).find((el) => el.textContent.includes("LEGACY / SHARED ARTIFACTS"));
    expect(legacyHeader).toBeTruthy();

    const legacyBody = legacyHeader.nextElementSibling;
    expect(legacyBody.hidden).toBe(true);

    legacyHeader.click();
    expect(legacyBody.hidden).toBe(false);

    legacyHeader.click();
    expect(legacyBody.hidden).toBe(true);
  });

  test("capture rows inside device accordions do not repeat the device badge", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi", "m5evil"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 3, pcap: 3, hash_22000: 1, details: 0, cracked: 0, history: 0 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
        {
          capture_id: "cap-m5",
          source: "m5evil",
          device_label: "M5Evil",
          source_filename: "HS_AABBCCDDEEFF_M5.pcap",
          source_path_role: "m5evil_handshakes",
          resolved_ssid: "",
          quality: { score: 15, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "HS_AABBCCDDEEFF.pcap", type: "pcap", size: 640, modified: 1700000002, capture_id: "cap-bruce", source: "brucegotchi", device_label: "Brucegotchi", source_path_role: "bruce_handshakes" },
      { name: "HS_AABBCCDDEEFF_M5.pcap", type: "pcap", size: 610, modified: 1700000003, capture_id: "cap-m5", source: "m5evil", device_label: "M5Evil", source_path_role: "m5evil_handshakes" },
    ]);

    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const pwnRow = document.querySelector('.file-item[data-capture-id="cap-pwn"]');
    const bruceRow = document.querySelector('.file-item[data-capture-id="cap-bruce"]');
    const m5Row = document.querySelector('.file-item[data-capture-id="cap-m5"]');

    expect(pwnRow.textContent).not.toContain("Pwnagotchi");
    expect(bruceRow.textContent).not.toContain("Brucegotchi");
    expect(m5Row.textContent).not.toContain("M5Evil");
  });

  test("default selected file marks its owning device accordion active and renders derived divider", async () => {
    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "HS_AABBCCDDEEFF.pcap", type: "pcap", size: 640, modified: 1700000002, capture_id: "cap-bruce", source: "brucegotchi", device_label: "Brucegotchi", source_path_role: "bruce_handshakes" },
      { name: "legacy_shared.22000", type: "22000", size: 90, modified: 1700000003, legacy_shared: true, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    expect(document.querySelector(".capture-section-divider-label")?.textContent).toContain("DERIVED / SHARED ARTIFACTS");
    const selectedRow = document.querySelector("#crack-file-list .file-item.selected");
    expect(selectedRow).toBeTruthy();
    const activeGroup = selectedRow.closest(".capture-group");
    expect(activeGroup?.classList.contains("capture-group-active")).toBe(true);
    const activeHeader = activeGroup?.querySelector(":scope > .capture-group-header");
    expect(activeHeader?.classList.contains("capture-group-header-active")).toBe(true);

    const bruceHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("Brucegotchi"));
    expect(bruceHeader?.classList.contains("capture-group-header-active")).toBe(false);
  });

  test("RAW selection activates both RAW root and nested device accordions", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [{ raw_item_id: "raw::pcap::city", source: "brucegotchi", device_label: "Bruce", source_file: "raw_city_center.pcap", filename: "raw_city_center.pcap", eapol_count: 2, beacon_count: 9 }],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel(
      "AA:BB:CC:DD:EE:FF",
      "My SSID",
      "raw_city_center.pcap"
    );
    await flushAsync();

    const rawRootHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("RAW Sniffer"));
    const rawDeviceHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("Bruce"));
    const rawRoot = rawRootHeader?.closest(".capture-group-raw-root");
    const rawBody = rawRoot?.querySelector(":scope > .crack-raw-context-body");
    const rawChild = rawBody?.querySelector(":scope > .capture-group-raw-child");
    expect(rawRootHeader?.classList.contains("capture-group-header-active")).toBe(true);
    expect(rawDeviceHeader?.classList.contains("capture-group-header-active")).toBe(true);
    expect(rawBody?.classList.contains("crack-raw-context-body-tree")).toBe(true);
    expect(rawChild?.querySelector(":scope > .capture-group-header")?.textContent).toContain("Bruce");
  });

  test("combined and legacy selections activate their own accordions", async () => {
    mockAPI.getHandshakeSet.mockResolvedValue({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0, combined: 1 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
      combined_candidates: [
        {
          name: "combined.22000",
          type: "22000",
          size: 120,
          modified: 1700000011,
          combined_build_id: "build-1",
          included_capture_count: 2,
          deduped_hash_count: 5,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValue([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "legacy_shared.22000", type: "22000", size: 90, modified: 1700000003, legacy_shared: true, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe", "combined.22000");
    await flushAsync();
    const combinedHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("COMBINED CANDIDATES"));
    expect(combinedHeader?.classList.contains("capture-group-header-active")).toBe(true);

    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe", "legacy_shared.22000");
    await flushAsync();
    const legacyHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("LEGACY / SHARED ARTIFACTS"));
    expect(legacyHeader?.classList.contains("capture-group-header-active")).toBe(true);
  });

  test("opening derived accordions auto-selects their first file", async () => {
    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0, combined: 1 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
      combined_candidates: [
        {
          name: "combined_latest.22000",
          type: "22000",
          size: 120,
          modified: 1700000011,
          combined_build_id: "build-1",
          included_capture_count: 2,
          deduped_hash_count: 5,
        },
        {
          name: "combined_older.22000",
          type: "22000",
          size: 110,
          modified: 1700000009,
          combined_build_id: "build-0",
          included_capture_count: 2,
          deduped_hash_count: 4,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "legacy_a.22000", type: "22000", size: 90, modified: 1700000003, legacy_shared: true, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
      { name: "legacy_b.details", type: "details", size: 32, modified: 1700000002, legacy_shared: true, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const combinedHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("COMBINED CANDIDATES"));
    combinedHeader.click();
    await flushAsync();
    expect(document.getElementById("selected-file-info").textContent).toContain("combined_latest.22000");

    const legacyHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("LEGACY / SHARED ARTIFACTS"));
    legacyHeader.click();
    await flushAsync();
    expect(document.getElementById("selected-file-info").textContent).toContain("legacy_a.22000");
  });

  test("opening RAW nested accordions auto-selects their first file while RAW root does not", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        { raw_item_id: "raw::pcap::bruce-1", source: "brucegotchi", device_label: "Bruce", source_file: "raw_city_center.pcap", filename: "raw_city_center.pcap", eapol_count: 2, beacon_count: 9 },
        { raw_item_id: "raw::pcap::m5-1", source: "m5evil", device_label: "M5Evil", source_file: "raw_m5_drive.pcap", filename: "raw_m5_drive.pcap", eapol_count: 1, beacon_count: 3 },
      ],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const rawRoot = document.querySelector("#crack-file-list .capture-group-raw-root");
    const rawChildren = Array.from(rawRoot.querySelectorAll(":scope > .crack-raw-context-body > .capture-group-raw-child"));
    expect(rawChildren).toHaveLength(2);
    expect(rawChildren[0].textContent).toContain("Bruce");
    expect(rawChildren[1].textContent).toContain("M5Evil");

    const initialSelected = document.getElementById("selected-file-info").textContent;
    const rawRootHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("RAW Sniffer"));
    rawRootHeader.click();
    await flushAsync();
    expect(document.getElementById("selected-file-info").textContent).toBe(initialSelected);

    const bruceRawHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("Bruce"));
    bruceRawHeader.click();
    await flushAsync();
    expect(document.getElementById("selected-file-info").textContent).toContain("raw_city_center.pcap");
  });

  test("RAW canonical WDRS accordion renders as a RAW child branch", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "hidden_aabbccddeeff__wdrs__.22000", type: "22000", size: 90, modified: 1700000003, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
    ]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [{ raw_item_id: "raw::pcap::bruce-1", source: "brucegotchi", device_label: "Bruce", source_file: "raw_city_center.pcap", filename: "raw_city_center.pcap", eapol_count: 2, beacon_count: 9 }],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const rawRoot = document.querySelector("#crack-file-list .capture-group-raw-root");
    const rawChildren = Array.from(rawRoot.querySelectorAll(":scope > .crack-raw-context-body > .capture-group-raw-child"));
    expect(rawChildren.map((node) => node.querySelector(":scope > .capture-group-header")?.textContent)).toEqual(
      expect.arrayContaining([
        expect.stringContaining("Bruce"),
        expect.stringContaining("Canonical (WDRS)"),
      ])
    );
  });

  test("single accordion mode closes sibling top-level groups when opening another branch", async () => {
    document.documentElement.dataset.crackingAccordionMode = "single";
    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0, combined: 1 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
      combined_candidates: [
        {
          name: "combined.22000",
          type: "22000",
          size: 120,
          modified: 1700000011,
          combined_build_id: "build-1",
          included_capture_count: 2,
          deduped_hash_count: 5,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "HS_AABBCCDDEEFF.pcap", type: "pcap", size: 640, modified: 1700000002, capture_id: "cap-bruce", source: "brucegotchi", device_label: "Brucegotchi", source_path_role: "bruce_handshakes" },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const pwnHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("Pwnagotchi"));
    const combinedHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("COMBINED CANDIDATES"));
    const pwnBody = pwnHeader.nextElementSibling;
    const combinedBody = combinedHeader.nextElementSibling;

    expect(pwnBody.hidden).toBe(false);
    combinedHeader.click();
    expect(combinedBody.hidden).toBe(false);
    expect(pwnBody.hidden).toBe(true);
  });

  test("multi accordion mode keeps sibling groups open", async () => {
    document.documentElement.dataset.crackingAccordionMode = "multi";
    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0, combined: 1 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
      combined_candidates: [
        {
          name: "combined.22000",
          type: "22000",
          size: 120,
          modified: 1700000011,
          combined_build_id: "build-1",
          included_capture_count: 2,
          deduped_hash_count: 5,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "HS_AABBCCDDEEFF.pcap", type: "pcap", size: 640, modified: 1700000002, capture_id: "cap-bruce", source: "brucegotchi", device_label: "Brucegotchi", source_path_role: "bruce_handshakes" },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const pwnHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("Pwnagotchi"));
    const combinedHeader = Array.from(document.querySelectorAll("#crack-file-list .capture-group-header"))
      .find((el) => el.textContent.includes("COMBINED CANDIDATES"));
    const pwnBody = pwnHeader.nextElementSibling;
    const combinedBody = combinedHeader.nextElementSibling;

    expect(pwnBody.hidden).toBe(false);
    combinedHeader.click();
    expect(combinedBody.hidden).toBe(false);
    expect(pwnBody.hidden).toBe(false);
  });

  test("combined candidates accordion builds and reselects the new combined artifact", async () => {
    mockAPI.getHandshakeSet
      .mockResolvedValueOnce({
        handshake_set_id: "aabbccddeeff",
        mac: "AA:BB:CC:DD:EE:FF",
        resolved_ssid: "Cafe",
        sources: ["pwnagotchi", "brucegotchi"],
        preferred_capture_id: "cap-pwn",
        artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0, combined: 0 },
        captures: [
          {
            capture_id: "cap-pwn",
            source: "pwnagotchi",
            device_label: "Pwnagotchi",
            source_filename: "Cafe_aabbccddeeff.pcap",
            source_path_role: "handshakes",
            resolved_ssid: "Cafe",
            quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
            is_preferred: true,
          },
          {
            capture_id: "cap-bruce",
            source: "brucegotchi",
            device_label: "Brucegotchi",
            source_filename: "HS_AABBCCDDEEFF.pcap",
            source_path_role: "bruce_handshakes",
            resolved_ssid: "",
            quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
            is_preferred: false,
          },
        ],
        combined_candidates: [],
      })
      .mockResolvedValueOnce({
        handshake_set_id: "aabbccddeeff",
        mac: "AA:BB:CC:DD:EE:FF",
        resolved_ssid: "Cafe",
        sources: ["pwnagotchi", "brucegotchi"],
        preferred_capture_id: "cap-pwn",
        artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0, combined: 1 },
        captures: [
          {
            capture_id: "cap-pwn",
            source: "pwnagotchi",
            device_label: "Pwnagotchi",
            source_filename: "Cafe_aabbccddeeff.pcap",
            source_path_role: "handshakes",
            resolved_ssid: "Cafe",
            quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
            is_preferred: true,
          },
          {
            capture_id: "cap-bruce",
            source: "brucegotchi",
            device_label: "Brucegotchi",
            source_filename: "HS_AABBCCDDEEFF.pcap",
            source_path_role: "bruce_handshakes",
            resolved_ssid: "",
            quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
            is_preferred: false,
          },
        ],
        combined_candidates: [
          {
            name: "combined.22000",
            type: "22000",
            size: 240,
            modified: 1700000300,
            combined_build_id: "build-123456",
            artifact_scope: "combined",
            included_capture_ids: ["cap-pwn", "cap-bruce"],
            included_captures: [
              {
                capture_id: "cap-pwn",
                source: "pwnagotchi",
                device_label: "Pwnagotchi",
                source_filename: "Cafe_aabbccddeeff.pcap",
                source_kind: "existing_hash",
                valid_hash_lines: 12,
              },
              {
                capture_id: "cap-bruce",
                source: "brucegotchi",
                device_label: "Brucegotchi",
                source_filename: "HS_AABBCCDDEEFF.pcap",
                source_kind: "converted_from_pcap",
                valid_hash_lines: 17,
              },
            ],
            deduped_hash_count: 2,
          },
        ],
      });
    mockAPI.getHandshakeFiles
      .mockResolvedValueOnce([
        { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      ])
      .mockResolvedValueOnce([
        { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const buildButton = Array.from(document.querySelectorAll("#crack-file-list button"))
      .find((el) => el.textContent.includes("BUILD COMBINED CANDIDATE"));
    expect(buildButton).toBeTruthy();

    buildButton.click();
    await flushAsync();
    await flushAsync();
    for (let idx = 0; idx < 8; idx += 1) {
      if (document.getElementById("crack-file-list").textContent.includes("COMBINED CANDIDATES")) {
        break;
      }
      await flushAsync();
    }

    expect(mockAPI.buildCombinedCapture).toHaveBeenCalledWith("AA:BB:CC:DD:EE:FF", [
      "cap-pwn",
      "cap-bruce",
    ]);
    expect(mockAddProcess).toHaveBeenCalledWith(
      expect.stringMatching(/^combined-build-/),
      "BUILD COMBINED CANDIDATE",
      "Cafe (2 captures)",
      "STARTING",
      "AA:BB:CC:DD:EE:FF"
    );
    expect(mockUpdateProcess).toHaveBeenCalledWith(
      expect.stringMatching(/^combined-build-/),
      5,
      "RUNNING",
      "2 capture(s) selected",
      true
    );
    expect(mockUpdateProcess).toHaveBeenCalledWith(
      expect.stringMatching(/^combined-build-/),
      100,
      "COMPLETED",
      "combined.22000",
      false
    );
    expect(document.getElementById("crack-file-list").textContent).toContain("COMBINED CANDIDATES");
    expect(document.getElementById("crack-file-list").textContent).toContain("combined.22000");
  });

  test("combined candidate selection shows origin metadata below attack memory", async () => {
    mockAPI.getHandshakeSet.mockResolvedValue({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 2, pcap: 2, hash_22000: 1, details: 0, cracked: 0, history: 0, combined: 1 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 12 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 17 },
          is_preferred: false,
        },
      ],
      combined_candidates: [
        {
          name: "combined.22000",
          type: "22000",
          size: 240,
          modified: 1700000300,
          combined_build_id: "build-123456",
          artifact_scope: "combined",
          included_capture_ids: ["cap-pwn", "cap-bruce"],
          included_captures: [
            {
              capture_id: "cap-pwn",
              source: "pwnagotchi",
              device_label: "Pwnagotchi",
              source_filename: "Cafe_aabbccddeeff.pcap",
              source_kind: "existing_hash",
              valid_hash_lines: 12,
            },
            {
              capture_id: "cap-bruce",
              source: "brucegotchi",
              device_label: "Brucegotchi",
              source_filename: "HS_AABBCCDDEEFF.pcap",
              source_kind: "converted_from_pcap",
              valid_hash_lines: 17,
            },
          ],
          included_capture_count: 2,
          deduped_hash_count: 29,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValue([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe", "combined.22000", { combinedBuildId: "build-123456" });
    await flushAsync();
    await flushAsync();

    const feedback = document.getElementById("crack-file-feedback").textContent;
    expect(feedback).toContain("COMBINED ORIGIN");
    expect(feedback).toContain("2 capture(s) included");
    expect(feedback).toContain("29 deduped hash line(s)");
    expect(feedback).toContain("Pwnagotchi");
    expect(feedback).toContain("Brucegotchi");
    expect(feedback).toContain("Cafe_aabbccddeeff.pcap");
    expect(feedback).toContain("HS_AABBCCDDEEFF.pcap");
  });

  test("startCracking treats recommendation as context-only and does not render force override", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    mockAPI.getAttackRecommendation.mockResolvedValue({
      target: { filename: "capture.22000", mac: "AA:BB:CC:DD:EE:FF" },
      action: "run",
      recommended_mode: "rules",
      candidate_modes: ["rules"],
      reasons: ["override needed"],
      attack_score: { score: 51, priority: "medium", score_reasons: [] },
      attempt_feedback: {
        scope: "hashcat",
        totals: { attempts: 2, distinct_modes: 1, exhausted: 1, fatal: 1, cracked: 0 },
        by_mode: [{ mode: "rules", attempts: 2, exhausted: 1, fatal: 1, cracked: 0, last_used: "2026-03-17T10:00:00" }],
        recent: [
          {
            started_at: "2026-03-17T10:00:00",
            mode: "rules",
            outcome: "fatal",
            params: { workload: "4", wordlist: "top.txt" },
          },
          {
            started_at: "2026-03-16T10:00:00",
            mode: "rules",
            outcome: "exhausted",
            params: { workload: "3", wordlist: "top.txt" },
          },
        ],
        tip: "Repeated exhausted runs; change mode or candidate source before retrying.",
      },
      handshake_readiness: {
        status: "weak_ready",
        score: 55,
        reason: "RAW EAPOL available",
        signals: { valid_hash_lines: 0, raw_eapol_total: 4, raw_beacon_total: 12, raw_files_count: 1 },
        enrichment: { existing_hash_files: [], pending_hash_files: ["raw_1.22000"] },
      },
      quality_gate: {
        passed: false,
        can_override: true,
        checks: [{ passed: false, severity: "warning", message: "already cracked?" }],
      },
    });

    await openReady22000Panel(uiCracking);
    expect(document.getElementById("crack-file-feedback").textContent).not.toContain("FORCE CRACK ANYWAY");
    expect(document.getElementById("btn-insights-force-crack")).toBeNull();
    expect(document.getElementById("crack-file-feedback").textContent).toContain("Context");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("Handshake Readiness");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("ATTACK MEMORY");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("rules");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("FATAL");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("weak_ready");
    expect(document.querySelector("#crack-file-feedback .insights-context-badge")).not.toBeNull();

    mockAPI.startCracking.mockResolvedValueOnce({ status: "started", job_id: "job-force" });

    document.getElementById("btn-convert-hash").click();
    await flushAsync();
    const firstCall = mockAPI.startCracking.mock.calls[0];
    expect(firstCall[17]).toBe(false);
    expect(mockAddProcess).toHaveBeenCalledWith(
      "job-force",
      expect.stringContaining("HASHCAT"),
      "capture.22000",
      "STARTING",
      "AA:BB:CC:DD:EE:FF"
    );
  });

  test("22000 recommendation query includes filename and mac when mac is valid", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    expect(mockAPI.getAttackRecommendation).toHaveBeenCalledWith({
      filename: "capture.22000",
      mac: "AA:BB:CC:DD:EE:FF",
      captureId: null,
      combinedBuildId: null,
    });
  });

  test("raw hash scope keeps only same-prefix files in cracking list", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "HS_840112985626.try", type: "try", size: 900, modified: 1700000000 },
      { name: "HS_840112985626.22000", type: "22000", size: 200, modified: 1700000000 },
      { name: "raw_18.22000", type: "22000", size: 200, modified: 1700000001 },
      { name: "raw_18.try", type: "try", size: 20, modified: 1700000002 },
      { name: "raw_17.22000", type: "22000", size: 150, modified: 1700000003 },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel(
      "84:01:12:98:56:26",
      "RAW HASH raw_18.22000",
      "raw_18.22000",
      { scope: "raw_hash" }
    );

    const names = Array.from(document.querySelectorAll("#crack-file-list .file-item .file-name-text"))
      .map((el) => el.textContent.trim());
    expect(names).toContain("raw_18.22000");
    expect(names).toContain("raw_18.try");
    expect(names).not.toContain("HS_840112985626.22000");
    expect(names).not.toContain("HS_840112985626.try");
    expect(names).not.toContain("raw_17.22000");
  });

  test("raw hash scope renders flat batch-like list without device groups", async () => {
    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["m5evil"],
      preferred_capture_id: "cap-1",
      artifact_summary: { captures: 1, pcap: 1, hash_22000: 1, details: 1, cracked: 0, history: 1, combined: 0 },
      captures: [
        {
          capture_id: "cap-1",
          source: "m5evil",
          device_label: "M5Evil",
          source_filename: "raw_1.pcap",
          ssid: "Cafe",
          resolved_ssid: "Cafe",
          quality: { score: 80, tier: "high", reasons: ["ok"], valid_hash_lines: 2, details_richness: 3 },
          is_preferred: true,
          legacy_shared_artifacts: false,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "raw_1.22000", type: "22000", size: 200, modified: 1700000001 },
      { name: "raw_1.details", type: "details", size: 50, modified: 1700000002 },
      { name: "raw_1.try", type: "try", size: 20, modified: 1700000003 },
      { name: "raw_2.22000", type: "22000", size: 200, modified: 1700000004 },
    ]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        {
          raw_item_id: "raw::pcap::abc123",
          artifact_type: "pcap",
          source: "m5evil",
          device_label: "M5Evil",
          filename: "raw_1.pcap",
          source_file: "raw_1.pcap",
          eapol_count: 1,
          beacon_count: 8,
        },
      ],
      hash_files: [
        {
          raw_item_id: "raw::22000::def456",
          artifact_type: "22000",
          source: "m5evil",
          device_label: "M5Evil",
          filename: "raw_1.22000",
          source_raw_file: "raw_1.pcap",
          valid_hash_lines: 2,
          matched_lines: 3,
        },
      ],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel(
      "AA:BB:CC:DD:EE:FF",
      "RAW HASH raw_1.22000",
      "raw_1.22000",
      { scope: "raw_hash" }
    );

    const names = Array.from(document.querySelectorAll("#crack-file-list .file-item .file-name-text"))
      .map((el) => el.textContent.trim());
    expect(names).toEqual(["raw_1.22000", "raw_1.details", "raw_1.try"]);
    expect(document.querySelectorAll("#crack-file-list .capture-group").length).toBe(0);
    expect(document.getElementById("selected-file-info").textContent).toContain("RAW HASH");
    expect(document.getElementById("selected-file-info").textContent).not.toContain("M5Evil");
    const summaryText = document.getElementById("crack-handshake-set-summary").textContent;
    expect(summaryText).toContain("HANDSHAKE SET");
    expect(summaryText).toContain("raw_1.22000");
    expect(summaryText).toContain("valid 2");
    expect(summaryText).toContain("matched 3");
    expect(summaryText).toContain("EAPOL missing");
    expect(summaryText).toContain("invalid 1");
    expect(summaryText).toContain("RAW HASH");
  });

  test("shows RAW extraction guidance when captured files are empty but RAW context exists", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        {
          source_file: "raw_city_center.pcap",
          eapol_count: 4,
          beacon_count: 30,
          channel: 6,
          frequency_mhz: 2437,
          processed_at: "2026-03-23T18:00:00Z",
        },
      ],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    expect(mockAPI.getHandshakeRawContext).toHaveBeenCalledWith("AA:BB:CC:DD:EE:FF");
    expect(document.getElementById("crack-file-list").textContent).toContain(
      "no valid WPA handshake (EAPOL) is linked yet"
    );
    expect(document.querySelector('#crack-file-list [data-action="raw-auto-prepare"]')).toBeFalsy();
    expect(document.querySelector('#crack-file-list [data-action="raw-auto-prepare-all"]')).toBeTruthy();
    expect(document.getElementById("crack-file-list").textContent).toContain(
      "No RAW hashes linked yet"
    );
  });

  test("RAW PCAP selection exposes build action in main controls and refreshes files", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "focused.22000", type: "22000", size: 420, modified: 1700000200 },
    ]);
    mockAPI.getHandshakeRawContext.mockResolvedValue({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [{
        raw_item_id: "raw::pcap::city",
        source_file: "raw_city_center.pcap",
        filename: "raw_city_center.pcap",
        eapol_count: 2,
        beacon_count: 9,
      }],
      hash_files: [{ filename: "raw_12.22000", valid_hash_lines: 5, source_raw_file: "raw_city_center.pcap" }],
    });
    mockAPI.prepareHandshakeRaw.mockResolvedValueOnce({
      status: "success",
      message: "Canonical hash updated",
      canonical_hash: "focused.22000",
      artifacts: { pcap_file: null, hash_file: "focused.22000" },
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    const rawRow = document.querySelector('.file-item[data-raw-item-id="raw::pcap::city"]');
    expect(rawRow).toBeTruthy();
    rawRow.click();
    await flushAsync();

    const button = document.getElementById("btn-convert-hash");
    expect(button.innerHTML).toContain("BUILD CANONICAL");
    button.click();
    await flushAsync();
    await flushAsync();

    expect(mockAPI.prepareHandshakeRaw).toHaveBeenCalledWith("AA:BB:CC:DD:EE:FF", {
      source_file: "raw_city_center.pcap",
      raw_item_id: "raw::pcap::city",
      force: false,
    });
    expect(mockAddProcess).toHaveBeenCalledWith(
      expect.stringMatching(/^raw-prepare-item-/),
      "RAW SNIFFER BUILD CANONICAL",
      "AA:BB:CC:DD:EE:FF · raw_city_center.pcap",
      "STARTING",
      "AA:BB:CC:DD:EE:FF"
    );
    expect(mockUpdateProcess).toHaveBeenCalledWith(
      expect.stringMatching(/^raw-prepare-item-/),
      100,
      "COMPLETED",
      "focused.22000",
      false
    );

    for (let idx = 0; idx < 8; idx += 1) {
      if (document.getElementById("crack-file-list").textContent.includes("focused.22000")) {
        break;
      }
      await flushAsync();
    }
    expect(document.getElementById("crack-file-list").textContent).toContain("focused.22000");
  });

  test("RAW PCAP uses normal PCAP actions and RAW 22000 uses cracking actions", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "raw_1.details", type: "details", size: 44, modified: 1700000002 },
      { name: "raw_1.try", type: "try", size: 12, modified: 1700000003 },
      { name: "raw_1.cracked", type: "cracked", size: 6, modified: 1700000004 },
    ]);
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        {
          raw_item_id: "raw::pcap::abc123",
          artifact_type: "pcap",
          source: "m5evil",
          device_label: "M5Evil",
          filename: "raw_1.pcap",
          source_file: "raw_1.pcap",
          eapol_count: 1,
          beacon_count: 8,
        },
      ],
      hash_files: [
        {
          raw_item_id: "raw::22000::def456",
          artifact_type: "22000",
          source: "m5evil",
          device_label: "M5Evil",
          filename: "raw_1.22000",
          source_raw_file: "raw_1.pcap",
          valid_hash_lines: 2,
        },
      ],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    const rawPcapRow = document.querySelector('.file-item[data-raw-item-id="raw::pcap::abc123"]');
    rawPcapRow.click();
    await flushAsync();
    expect(document.getElementById("btn-convert-hash").innerHTML).toContain("BUILD CANONICAL");
    expect(document.getElementById("btn-pcap-generate-hash").disabled).toBe(false);
    expect(document.getElementById("btn-quick-attack").disabled).toBe(false);
    mockAPI.convertPcap.mockResolvedValueOnce({ status: "started", job_id: "job-convert" });
    document.getElementById("btn-pcap-generate-hash").click();
    await flushAsync();
    expect(mockAPI.convertPcap).toHaveBeenCalledWith("raw_1.pcap", null, "raw::pcap::abc123");

    const rawHashRow = document.querySelector('.file-item[data-raw-item-id="raw::22000::def456"]');
    rawHashRow.click();
    await flushAsync();
    expect(document.getElementById("btn-convert-hash").innerHTML).toContain("START CRACKING");
    expect(document.getElementById("selected-file-info").textContent).toContain("RAW HASH");
    expect(document.getElementById("selected-file-info").textContent).not.toContain("M5Evil");
    const fileListText = document.getElementById("crack-file-list").textContent;
    expect(fileListText).toContain("raw_1.details");
    expect(fileListText).toContain("raw_1.try");
    expect(fileListText).toContain("raw_1.cracked");

    const rawTryRow = Array.from(document.querySelectorAll('#crack-file-list .file-item'))
      .find((el) => (el.textContent || '').includes('raw_1.try'));
    expect(rawTryRow).toBeTruthy();
    rawTryRow.click();
    await flushAsync();
    expect(mockRenderHistoryPanel).toHaveBeenCalledWith(
      "raw_1.try",
      document.getElementById("crack-file-feedback"),
      expect.objectContaining({ captureId: null, combinedBuildId: null })
    );

    mockAPI.startCracking.mockResolvedValueOnce({ status: "started", job_id: "job-hash" });
    rawHashRow.click();
    await flushAsync();
    document.getElementById("btn-convert-hash").click();
    await flushAsync();
    expect(mockAPI.startCracking).toHaveBeenCalled();
  });

  test("canonical WDRS files render inside RAW section instead of legacy", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "hidden_aabbccddeeff__wdrs__.22000", type: "22000", size: 80, modified: 1700000003, capture_id: null, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
    ]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [{ raw_item_id: "raw::pcap::city", source_file: "raw_city_center.pcap", filename: "raw_city_center.pcap", eapol_count: 2, beacon_count: 9 }],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel(
      "AA:BB:CC:DD:EE:FF",
      "My SSID",
      "hidden_aabbccddeeff__wdrs__.22000"
    );

    const groupNames = Array.from(document.querySelectorAll("#crack-file-list .capture-group-name"))
      .map((el) => el.textContent.trim());
    expect(groupNames).toContain("Canonical (WDRS)");
    const legacySection = Array.from(document.querySelectorAll("#crack-file-list .capture-group"))
      .find((el) => el.textContent.includes("LEGACY / SHARED ARTIFACTS"));
    expect(legacySection?.textContent || "").not.toContain("hidden_aabbccddeeff__wdrs__.22000");
  });

  test("semantic badge classes stay distinct for details, raw, combined, legacy/shared and WDRS", async () => {
    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 1, pcap: 1, hash_22000: 1, details: 1, cracked: 0, history: 0, combined: 1 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
      ],
      combined_candidates: [
        {
          name: "combined.22000",
          type: "22000",
          size: 120,
          modified: 1700000011,
          combined_build_id: "build-1",
          included_capture_count: 1,
          deduped_hash_count: 5,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "Cafe_aabbccddeeff.details", type: "details", size: 80, modified: 1700000002, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
      { name: "legacy_shared.22000", type: "22000", size: 90, modified: 1700000003, legacy_shared: true, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
      { name: "hidden_aabbccddeeff__wdrs__.22000", type: "22000", size: 95, modified: 1700000004, source: "legacy", device_label: "Legacy", source_path_role: "handshakes" },
    ]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [{ raw_item_id: "raw::pcap::city", source: "brucegotchi", device_label: "Bruce", source_file: "raw_city_center.pcap", filename: "raw_city_center.pcap", eapol_count: 2, beacon_count: 9 }],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel(
      "AA:BB:CC:DD:EE:FF",
      "Cafe",
      "hidden_aabbccddeeff__wdrs__.22000"
    );

    expect(document.querySelector("#crack-file-list .file-type-tag.badge-details")).toBeTruthy();
    expect(document.querySelector("#selected-file-info .badge-role-state-wdrs")).toBeTruthy();
    expect(document.querySelector("#crack-file-list .badge-role-state-raw")).toBeTruthy();
    expect(document.querySelector("#crack-file-list .badge-role-state-combined")).toBeTruthy();
    expect(document.querySelector("#crack-file-list .badge-role-state-shared")).toBeTruthy();
  });

  test("handshake set summary shows RAW Sniffer and Combined badges plus dynamic counts when present", async () => {
    mockAPI.getHandshakeSet.mockResolvedValueOnce({
      handshake_set_id: "aabbccddeeff",
      mac: "AA:BB:CC:DD:EE:FF",
      resolved_ssid: "Cafe",
      sources: ["pwnagotchi", "brucegotchi"],
      preferred_capture_id: "cap-pwn",
      artifact_summary: { captures: 2, pcap: 2, hash_22000: 3, details: 1, cracked: 0, history: 0, combined: 1 },
      captures: [
        {
          capture_id: "cap-pwn",
          source: "pwnagotchi",
          device_label: "Pwnagotchi",
          source_filename: "Cafe_aabbccddeeff.pcap",
          source_path_role: "handshakes",
          resolved_ssid: "Cafe",
          quality: { score: 81, tier: "high", reasons: ["Valid .22000 available"], valid_hash_lines: 1 },
          is_preferred: true,
        },
        {
          capture_id: "cap-bruce",
          source: "brucegotchi",
          device_label: "Brucegotchi",
          source_filename: "HS_AABBCCDDEEFF.pcap",
          source_path_role: "bruce_handshakes",
          resolved_ssid: "",
          quality: { score: 18, tier: "low", reasons: ["Only raw capture available"], valid_hash_lines: 0 },
          is_preferred: false,
        },
      ],
      combined_candidates: [
        {
          name: "combined.22000",
          type: "22000",
          size: 120,
          modified: 1700000011,
          combined_build_id: "build-1",
          included_capture_count: 2,
          deduped_hash_count: 5,
        },
      ],
    });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "Cafe_aabbccddeeff.22000", type: "22000", size: 120, modified: 1700000001, capture_id: "cap-pwn", source: "pwnagotchi", device_label: "Pwnagotchi", source_path_role: "handshakes" },
    ]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [{ raw_item_id: "raw::pcap::city", source: "brucegotchi", device_label: "Bruce", source_file: "raw_city_center.pcap", filename: "raw_city_center.pcap", eapol_count: 2, beacon_count: 9 }],
      hash_files: [{ raw_item_id: "raw::22000::city", source: "brucegotchi", device_label: "Bruce", filename: "raw_city_center.22000", valid_hash_lines: 4, source_raw_file: "raw_city_center.pcap" }],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Cafe");
    await flushAsync();

    const summary = document.getElementById("crack-handshake-set-summary").textContent;
    expect(summary).toContain("2 capture(s)");
    expect(summary).toContain("3 hash file(s)");
    expect(summary).toContain("1 details");
    expect(summary).toContain("0 cracked");
    expect(summary).toContain("2 RAW item(s)");
    expect(summary).toContain("1 combined build(s)");
    expect(document.querySelector("#crack-handshake-set-summary .badge-role-state-raw")).toBeTruthy();
    expect(document.querySelector("#crack-handshake-set-summary .badge-role-state-combined")).toBeTruthy();
  });

  test("AUTO PREPARE ALL starts async process and adds process entry", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [{ source_file: "raw_city_center.pcap", eapol_count: 2, beacon_count: 9 }],
      hash_files: [{ filename: "raw_12.22000", valid_hash_lines: 5, source_raw_file: "raw_city_center.pcap" }],
    });
    mockAPI.prepareHandshakeRawAll.mockResolvedValueOnce({
      status: "started",
      job_id: "job-raw-all",
      total_files: 1,
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    const button = document.querySelector('#crack-file-list [data-action="raw-auto-prepare-all"]');
    expect(button).toBeTruthy();
    button.click();
    await flushAsync();

    expect(mockAPI.prepareHandshakeRawAll).toHaveBeenCalledWith("AA:BB:CC:DD:EE:FF", {
      force: false,
    });
    expect(mockAddProcess).toHaveBeenCalledWith(
      "job-raw-all",
      "RAW SNIFFER PREPARE ALL",
      "AA:BB:CC:DD:EE:FF (1 source files)",
      "STARTING",
      "AA:BB:CC:DD:EE:FF"
    );
  });

  test("RAW PCAP details extraction uses raw_item_id", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValue({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        {
          raw_item_id: "raw::pcap::abc123",
          artifact_type: "pcap",
          source: "m5evil",
          device_label: "M5Evil",
          filename: "raw_1.pcap",
          source_file: "raw_1.pcap",
          eapol_count: 1,
          beacon_count: 8,
        },
      ],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    const rawRow = document.querySelector('.file-item[data-raw-item-id="raw::pcap::abc123"]');
    expect(rawRow).toBeTruthy();
    rawRow.click();
    await flushAsync();

    document.getElementById("btn-extract-details").click();
    await flushAsync();

    expect(mockAPI.extractFingerprint).toHaveBeenCalledWith(
      "raw_1.pcap",
      false,
      null,
      "raw::pcap::abc123",
      "AA:BB:CC:DD:EE:FF"
    );
  });

  test("RAW PCAP shows open analysis action when RAW analysis is available", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        {
          raw_item_id: "raw::pcap::abc123",
          artifact_type: "pcap",
          source: "brucegotchi",
          device_label: "Bruce",
          filename: "raw_1.pcap",
          source_file: "raw_1.pcap",
          eapol_count: 2,
          beacon_count: 8,
          analysis_present: true,
          analysis_summary: {
            duration_s: 12.5,
            networks_count: 2,
            clients_count: 1,
            handshake_candidate_count: 1,
            noisy_capture: false,
          },
        },
      ],
      hash_files: [],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    const rawRow = document.querySelector('.file-item[data-raw-item-id="raw::pcap::abc123"]');
    rawRow.click();
    await flushAsync();

    const button = document.querySelector('[data-open-raw-analysis="true"]');
    expect(button).toBeTruthy();
    expect(document.getElementById("crack-file-feedback").textContent).toContain("RAW Analysis available");
  });

  test("RAW PCAP with details uses details-style feedback and avoids repeated device badge in row", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    mockAPI.getHandshakeRawContext.mockResolvedValueOnce({
      present: true,
      bssid: "AA:BB:CC:DD:EE:FF",
      files: [
        {
          raw_item_id: "raw::pcap::abc123",
          artifact_type: "pcap",
          source: "m5evil",
          device_label: "M5Evil",
          filename: "raw_1.pcap",
          source_file: "raw_1.pcap",
          bssid: "AA:BB:CC:DD:EE:FF",
          eapol_count: 1,
          beacon_count: 8,
          details_present: true,
          details_filename: "raw_1.details",
          details_size: 512,
          details_modified: 1700000000,
        },
      ],
      hash_files: [],
    });
    mockAPI.getFingerprintDetails.mockResolvedValueOnce({
      ssid: "My SSID",
      bssid: "AA:BB:CC:DD:EE:FF",
      security: { wpa_version: "WPA2", akm: ["PSK"], pairwise_ciphers: ["CCMP"], group_cipher: "CCMP", pmf: "capable" },
      wps: { present: false },
      classification: { type: "router", confidence: 0.9, evidence: ["ssid_pattern"] },
      meta: { source: "raw", timestamp: "2026-02-08T00:00:00Z" },
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    const rawRow = document.querySelector('.file-item[data-raw-item-id="raw::pcap::abc123"]');
    expect(rawRow).toBeTruthy();
    expect(rawRow.textContent).not.toContain("M5Evil");
    expect(rawRow.textContent).not.toContain("raw_1.details");
    expect(document.getElementById("crack-file-list").textContent).toContain("raw_1.details");

    const detailsRow = Array.from(document.querySelectorAll("#crack-file-list .file-item"))
      .find((el) => el.textContent.includes("raw_1.details"));
    expect(detailsRow).toBeTruthy();
    expect(detailsRow.classList.contains("raw-context-details-row")).toBe(true);
    expect(detailsRow.querySelector(".fa-magnifying-glass-chart")).toBeTruthy();
    expect(detailsRow.textContent).toContain("0.5 KB");
    expect(detailsRow.textContent).toContain("AA:BB:CC:DD:EE:FF");

    rawRow.click();
    await flushAsync();

    expect(document.getElementById("crack-file-feedback").classList.contains("crack-feedback-details")).toBe(true);
    expect(document.getElementById("crack-file-feedback").textContent).toContain("DETAILS");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("raw_1.pcap");
  });

  test("startCracking blocks mask_profile mode when no profile is selected", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    setMode("mask_profile");
    document.getElementById("crack-mask-profile-select").value = "";

    document.getElementById("btn-convert-hash").click();
    await flushAsync();

    expect(mockAPI.startCracking).not.toHaveBeenCalled();
    expect(document.getElementById("crack-progress-text").innerText).toBe("MASK PROFILE REQUIRED");
    expect(document.getElementById("btn-convert-hash").disabled).toBe(false);
  });

  test("updateCrackingPanelStatus updates buttons and retry state for failures", () => {
    const uiCracking = loadUiCrackingModule();

    uiCracking.updateCrackingPanelStatus({
      status: "RUNNING",
      percentage: 42,
      type: "HASHCAT [MASK]",
      extraInfo: "GPU 100kH/s",
      indeterminate: false,
    });

    expect(document.getElementById("btn-convert-hash").disabled).toBe(true);
    expect(document.getElementById("crack-progress-text").innerText).toContain("RUNNING (42%)");

    uiCracking.updateCrackingPanelStatus({
      status: "FAILED",
      percentage: 100,
      type: "HASHCAT [MASK]",
      extraInfo: "",
      indeterminate: false,
    });

    expect(document.getElementById("btn-convert-hash").disabled).toBe(false);
    expect(document.getElementById("btn-convert-hash").innerText).toBe("RETRY");
    expect(document.getElementById("crack-progress-text").innerText).toContain("FAILED");
  });

  test("handleJobCompletionSideEffects appends generated hash file to no-gps network", () => {
    const uiCracking = loadUiCrackingModule();

    mockActiveProcesses["job-1"] = {
      type: "GENERATE HASH (22000)",
      details: "captured_aabbccddeeff.pcap",
    };

    mockState.allPositions = {
      "AA:BB:CC:DD:EE:FF": {
        mac: "AA:BB:CC:DD:EE:FF",
        handshake_files: [],
      },
    };

    uiCracking.handleJobCompletionSideEffects({ id: "job-1" });

    expect(mockState.allPositions["AA:BB:CC:DD:EE:FF"].handshake_files).toContain(
      "captured_aabbccddeeff.22000"
    );
    expect(mockUpdateNoGpsList).toHaveBeenCalledTimes(1);
  });

  test("pcap selection supports conversion and aircrack actions", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.pcap");

    document.getElementById("btn-pcap-generate-hash").click();
    await flushAsync();
    expect(mockAPI.convertPcap).toHaveBeenCalledWith("capture.pcap", null, null);
    expect(mockAddProcess).toHaveBeenCalledWith(
      "job-conv",
      "GENERATE HASH (22000)",
      "capture.pcap",
      "STARTING",
      "AA:BB:CC:DD:EE:FF"
    );

    document.getElementById("btn-quick-attack").click();
    await flushAsync();
    expect(mockAPI.startAircrack).toHaveBeenCalledWith("capture.pcap", "AA:BB:CC:DD:EE:FF", "/wl.txt", null, null);
    expect(mockAddProcess).toHaveBeenCalledWith(
      "job-air",
      "AIRCRACK-NG",
      "capture.pcap",
      "STARTING",
      "AA:BB:CC:DD:EE:FF"
    );
  });

  test("file selection renders cracked/details/history views", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.22000");

    clickFileByName("capture.cracked");
    await flushAsync();
    expect(mockAPI.getFileContent).toHaveBeenCalledWith("capture.cracked", {
      captureId: null,
      combinedBuildId: null,
      mac: null,
    });
    expect(document.getElementById("crack-file-feedback").textContent).toContain("CRACKED DATA FOUND");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("hash:password");

    clickFileByName("capture.details");
    await flushAsync();
    expect(mockAPI.getFingerprintDetails).toHaveBeenCalledWith({
      filename: "capture.details",
      captureId: null,
    });
    expect(mockAPI.getAttackRecommendation.mock.calls).toEqual(
      expect.arrayContaining([
        [
          {
            mac: "AA:BB:CC:DD:EE:FF",
          },
        ],
      ])
    );
    expect(document.getElementById("crack-file-feedback").textContent).toContain("My SSID");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("ATTACK INSIGHTS");
    expect(document.getElementById("crack-file-feedback").classList.contains("crack-feedback-details")).toBe(true);
    expect(document.querySelector("#crack-file-feedback .details-view-scroll")).not.toBeNull();

    clickFileByName("capture.try");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").classList.contains("crack-feedback-details")).toBe(false);
    expect(mockRenderHistoryPanel).toHaveBeenCalledWith(
      "capture.try",
      document.getElementById("crack-file-feedback"),
      {
        captureId: null,
        combinedBuildId: null,
        mac: null,
      }
    );
  });

  test("openMultiCrackingPanel loads batch files and allows clearHistory", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    await uiCracking.openMultiCrackingPanel("batch_alpha.22000");
    expect(mockAPI.getBatchFiles).toHaveBeenCalledWith("batch_alpha.22000");
    expect(mockAPI.getMultiFileContent).toHaveBeenCalledWith("batch_alpha.22000");
    expect(document.getElementById("crack-ssid").innerText).toBe("BATCH");
    expect(document.getElementById("crack-mac").innerText).toBe("batch_alpha.22000");

    await uiCracking.clearHistory();
    expect(mockAPI.clearHistory).toHaveBeenCalledTimes(1);
    expect(mockLog).toHaveBeenCalledWith("History cleared. Deleted 2 files.", "success");
  });

  test("batch recommendation uses manifest MAC context when available", async () => {
    mockAPI.getMultiFileContent.mockResolvedValueOnce({
      items: [
        { ssid: "HS", mac: "001122334455", status: "OK" },
        { ssid: "OfficeWiFi", mac: "AABBCCDDEEFF", status: "OK" },
      ],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    await uiCracking.openMultiCrackingPanel("batch_alpha.22000");

    expect(mockAPI.getAttackRecommendation).toHaveBeenCalledWith({
      filename: "batch_alpha.22000",
      mac: "AA:BB:CC:DD:EE:FF",
    });
  });

  test("batch recommendation falls back to filename-only without valid manifest MAC", async () => {
    mockAPI.getMultiFileContent.mockResolvedValueOnce({
      items: [{ ssid: "HS", mac: "", status: "FAILED" }],
    });

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    await uiCracking.openMultiCrackingPanel("batch_alpha.22000");

    expect(mockAPI.getAttackRecommendation).toHaveBeenCalledWith({
      filename: "batch_alpha.22000",
    });
  });

  test("resource/default loaders handle fallback and error branches", async () => {
    const uiCracking = loadUiCrackingModule();
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    mockAPI.getCustomWordlists.mockResolvedValueOnce([]);
    mockAPI.getHashcatRules.mockResolvedValueOnce([]);
    mockAPI.getHashcatMasks.mockResolvedValueOnce([]);
    mockAPI.getHashcatDevices.mockResolvedValueOnce([]);
    await uiCracking.__test.loadCrackingResources();

    expect(document.getElementById("crack-rule-select").options.length).toBeGreaterThan(0);
    expect(document.getElementById("crack-rule-select").options[0].value).toBe("default");
    expect(document.getElementById("crack-mask-profile-select").disabled).toBe(true);
    expect(document.getElementById("crack-wordlist-select").disabled).toBe(true);

    mockAPI.getConfig.mockRejectedValueOnce(new Error("cfg fail"));
    await uiCracking.__test.loadCrackingDefaults();
    expect(errorSpy).toHaveBeenCalledWith("Failed to load config for preview", expect.any(Error));
    errorSpy.mockRestore();
  });

  test("updateWordlistVisibility covers digits/mask/hybrid branches", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    document.getElementById("flag-increment").checked = true;

    uiCracking.__test.updateWordlistVisibility("digits");
    expect(document.getElementById("crack-mask-row").style.display).toBe("flex");
    expect(document.getElementById("crack-mask-input").readOnly).toBe(true);
    expect(document.getElementById("auto-mask-chk").disabled).toBe(true);

    document.getElementById("flag-increment").checked = true;
    uiCracking.__test.updateWordlistVisibility("mask");
    expect(document.getElementById("flag-increment-container").style.display).toBe("flex");
    expect(document.getElementById("crack-increment-row").style.display).toBe("flex");
    expect(document.getElementById("auto-mask-chk").disabled).toBe(false);

    uiCracking.__test.updateWordlistVisibility("hybrid");
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("flex");
    expect(document.getElementById("crack-mask-row").style.display).toBe("flex");

    uiCracking.__test.updateWordlistVisibility("hybrid_reverse");
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("flex");
    expect(document.getElementById("crack-mask-row").style.display).toBe("flex");

    uiCracking.__test.updateWordlistVisibility("hybrid_mask_profile");
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("flex");
    expect(document.getElementById("crack-mask-profile-row").style.display).toBe("flex");
    expect(document.getElementById("crack-mask-row").style.display).toBe("none");

    uiCracking.__test.updateWordlistVisibility("hybrid_reverse_mask_profile");
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("flex");
    expect(document.getElementById("crack-mask-profile-row").style.display).toBe("flex");
    expect(document.getElementById("crack-mask-row").style.display).toBe("none");

    uiCracking.__test.updateWordlistVisibility("combinator_passphrase");
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("flex");
    expect(document.getElementById("crack-wordlist-2-row").style.display).toBe("flex");
  });

  test("startConversion covers already-cracking, failed-start and API-error branches", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.pcap", type: "pcap" });
    document.getElementById("crack-ssid").innerText = "SSID";
    document.getElementById("crack-mac").innerText = "AA:BB:CC:DD:EE:FF";

    mockActiveProcesses["job-run"] = { details: "capture.22000", status: "RUNNING" };
    await uiCracking.__test.startConversion();
    expect(mockLog).toHaveBeenCalledWith(
      "Cannot convert: capture.22000 is currently being cracked. Stop the cracking job first.",
      "error"
    );

    delete mockActiveProcesses["job-run"];
    mockAPI.convertPcap.mockResolvedValueOnce({ status: "error", message: "denied" });
    await uiCracking.__test.startConversion();
    expect(document.getElementById("crack-progress-text").innerText).toBe("FAILED TO START");

    mockAPI.convertPcap.mockRejectedValueOnce(new Error("boom"));
    await uiCracking.__test.startConversion();
    expect(document.getElementById("crack-progress-text").innerText).toBe("API ERROR");
  });

  test("startCracking covers wordlist required, failed-start, API-error and increment mask branches", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.22000", type: "22000" });

    document.getElementById("custom-mode-select").value = "rules";
    document.getElementById("crack-wordlist-select").value = "";
    await uiCracking.__test.startCracking();
    expect(document.getElementById("crack-progress-text").innerText).toBe("WORDLIST REQUIRED");

    document.getElementById("custom-mode-select").value = "mask";
    document.getElementById("flag-increment").checked = true;
    document.getElementById("crack-mask-input").value = "";
    const slider = { get: jest.fn(() => [1, 4]) };
    uiCracking.__test.setIncrementSlider(slider);
    document.body.insertAdjacentHTML("beforeend", '<input id="auto-mask-chk" type="checkbox" checked />');

    mockAPI.startCracking.mockResolvedValueOnce({ status: "started", job_id: "job-inc" });
    await uiCracking.__test.startCracking();
    const args = mockAPI.startCracking.mock.calls[mockAPI.startCracking.mock.calls.length - 1];
    expect(args[5]).toBe("?a?a?a?a");

    mockAPI.startCracking.mockResolvedValueOnce({ status: "error", message: "nope" });
    await uiCracking.__test.startCracking();
    expect(document.getElementById("crack-progress-text").innerText).toBe("FAILED TO START");

    mockAPI.startCracking.mockRejectedValueOnce(new Error("api down"));
    await uiCracking.__test.startCracking();
    expect(document.getElementById("crack-progress-text").innerText).toBe("API ERROR");
  });

  test("startAircrack covers wordlist required, failed-start and API-error branches", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.pcap", type: "pcap" });
    document.getElementById("crack-mac").innerText = "AA:BB:CC:DD:EE:FF";

    document.getElementById("wordlist-select").value = "";
    await uiCracking.__test.startAircrack();
    expect(document.getElementById("crack-progress-text").innerText).toBe("WORDLIST REQUIRED");

    document.getElementById("wordlist-select").innerHTML = '<option value="/wl.txt">wl</option>';
    document.getElementById("wordlist-select").value = "/wl.txt";
    mockAPI.startAircrack.mockResolvedValueOnce({ status: "error", message: "bad" });
    await uiCracking.__test.startAircrack();
    expect(document.getElementById("crack-progress-text").innerText).toBe("FAILED TO START");

    mockAPI.startAircrack.mockRejectedValueOnce(new Error("down"));
    await uiCracking.__test.startAircrack();
    expect(document.getElementById("crack-progress-text").innerText).toBe("API ERROR");

    uiCracking.__test.setSelectedFile({ name: "raw_1.pcap", type: "raw_pcap", raw_item_id: "raw::pcap::abc123" });
    mockAPI.startAircrack.mockResolvedValueOnce({ status: "started", job_id: "job-raw-air" });
    await uiCracking.__test.startAircrack();
    expect(mockAPI.startAircrack).toHaveBeenLastCalledWith(
      "raw_1.pcap",
      "AA:BB:CC:DD:EE:FF",
      "/wl.txt",
      null,
      "raw::pcap::abc123"
    );
  });

  test("startFingerprint and clearHistory cover remaining branch paths", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.details", type: "details" });
    uiCracking.__test.setCurrentFiles([{ name: "capture.pcap", type: "pcap" }]);
    mockState.openPopupMac = "AA:BB:CC:DD:EE:FF";
    mockState.allPositions["AA:BB:CC:DD:EE:FF"] = { handshake_files: [] };
    document.getElementById("crack-mac").innerText = "AA:BB:CC:DD:EE:FF";
    document.getElementById("crack-ssid").innerText = "My SSID";
    window.refreshPopupDetails = jest.fn();

    mockAPI.extractFingerprint.mockResolvedValueOnce({ saved_path: "/tmp/capture.details" });
    await uiCracking.__test.startFingerprint("btn-extract-details");
    expect(mockAPI.getFingerprintDetails).toHaveBeenCalled();
    expect(window.refreshPopupDetails).toHaveBeenCalled();

    mockAPI.extractFingerprint.mockRejectedValueOnce(new Error("extract fail"));
    await uiCracking.__test.startFingerprint("btn-extract-details");
    expect(mockLog).toHaveBeenCalledWith("Failed to extract details: extract fail", "error");

    window.confirm = jest.fn().mockReturnValue(false);
    await uiCracking.clearHistory();
    expect(mockAPI.clearHistory).not.toHaveBeenCalled();

    window.confirm = jest.fn().mockReturnValue(true);
    mockAPI.clearHistory.mockResolvedValueOnce({});
    await uiCracking.clearHistory();
    expect(mockLog).toHaveBeenCalledWith("Failed to clear history.", "error");

    mockAPI.clearHistory.mockRejectedValueOnce(new Error("clear fail"));
    await uiCracking.clearHistory();
    expect(mockLog).toHaveBeenCalledWith("Error clearing history: clear fail", "error");
  });

  test("listener toggles and mode variants cover remaining visibility branches", async () => {
    const uiCracking = loadUiCrackingModule();
    const dispatchSpy = jest.spyOn(document, "dispatchEvent");
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);
    const countLayoutEvents = () =>
      dispatchSpy.mock.calls.filter(([evt]) => evt && evt.type === "rightPanelsModeChanged").length;
    const baselineEvents = countLayoutEvents();

    document.getElementById("btn-toggle-cracking").click();
    expect(mockState.modes.cracking).toBe(false);
    expect(document.getElementById("cracking-panel").style.display).toBe("none");
    expect(countLayoutEvents()).toBe(baselineEvents + 1);
    document.getElementById("btn-toggle-cracking").click();
    expect(mockState.modes.cracking).toBe(true);
    expect(document.getElementById("cracking-panel").style.display).toBe("flex");
    expect(countLayoutEvents()).toBe(baselineEvents + 2);

    document.querySelector("#cracking-panel .close-panel").click();
    expect(mockState.modes.cracking).toBe(false);
    expect(document.getElementById("cracking-panel").style.display).toBe("none");
    expect(countLayoutEvents()).toBe(baselineEvents + 3);

    document.getElementById("aircrack-legacy-toggle").click();
    expect(document.getElementById("aircrack-legacy-toggle").getAttribute("data-expanded")).toBe("true");
    expect(document.getElementById("crack-aircrack-options").style.display).toBe("flex");

    uiCracking.__test.updateWordlistVisibility("passphrase");
    expect(document.getElementById("crack-rule-2-row").style.display).toBe("flex");
    expect(document.getElementById("crack-rule-label").innerText).toBe("RULE #1:");

    uiCracking.__test.updateWordlistVisibility("association");
    expect(document.getElementById("crack-association-hint-row").style.display).toBe("flex");

    uiCracking.__test.updateWordlistVisibility("combinator");
    expect(document.getElementById("crack-wordlist-2-row").style.display).toBe("flex");

    uiCracking.__test.updateWordlistVisibility("unknown_mode");
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("flex");
    dispatchSpy.mockRestore();
  });

  test("mode change handlers and action dispatch cover crack/aircrack guards", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    // workload slider listener
    document.getElementById("custom-workload-slider").value = "4";
    document.getElementById("custom-workload-slider").dispatchEvent(new Event("input", { bubbles: true }));
    expect(document.getElementById("custom-workload-val").innerText).toBe("4");

    // increment checkbox listener
    document.getElementById("flag-increment").checked = true;
    document.getElementById("flag-increment").dispatchEvent(new Event("change", { bubbles: true }));
    expect(document.getElementById("crack-increment-row").style.display).toBe("flex");
    document.getElementById("flag-increment").checked = false;
    document.getElementById("flag-increment").dispatchEvent(new Event("change", { bubbles: true }));
    expect(document.getElementById("crack-increment-row").style.display).toBe("none");

    // history details toggle listener
    document.body.insertAdjacentHTML("beforeend", '<div class="history-details"></div>');
    const detailsNode = document.querySelector(".history-details");
    detailsNode.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(detailsNode.classList.contains("expanded")).toBe(true);

    // no selected file guard for crack/aircrack actions
    uiCracking.__test.setSelectedFile(null);
    document.getElementById("btn-convert-hash").click();
    document.getElementById("btn-pcap-generate-hash").click();
    document.getElementById("btn-quick-attack").click();

    // unsupported type falls through in crack action guard
    uiCracking.__test.setSelectedFile({ name: "capture.try", type: "try" });
    document.getElementById("btn-convert-hash").click();
    await flushAsync();
  });

  test("manual increment mask branch and clearHistory(selected try) branch", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.22000", type: "22000" });
    document.getElementById("custom-mode-select").value = "mask";
    document.getElementById("crack-wordlist-select").innerHTML = '<option value="/wl.txt">wl</option>';
    document.getElementById("crack-wordlist-select").value = "/wl.txt";
    document.getElementById("flag-increment").checked = true;
    document.getElementById("crack-mask-input").value = "?a?a"; // len 2
    document.body.insertAdjacentHTML("beforeend", '<input id="auto-mask-chk" type="checkbox" />');
    document.getElementById("auto-mask-chk").checked = false;
    uiCracking.__test.setIncrementSlider({ get: jest.fn(() => [1, 8]) });

    mockAPI.startCracking.mockResolvedValueOnce({ status: "started", job_id: "job-manual" });
    await uiCracking.__test.startCracking();
    const args = mockAPI.startCracking.mock.calls[mockAPI.startCracking.mock.calls.length - 1];
    expect(args[12]).toBe(1); // incrementMin
    expect(args[13]).toBe(2); // incrementMax capped by mask len

    uiCracking.__test.setSelectedFile({ name: "capture.try", type: "try" });
    document.getElementById("crack-mac").innerText = "AA:BB:CC:DD:EE:FF";
    document.getElementById("crack-ssid").innerText = "My SSID";
    window.confirm = jest.fn().mockReturnValue(true);
    mockAPI.clearHistory.mockResolvedValueOnce({ deleted_count: 1 });
    await uiCracking.clearHistory();
    expect(mockLog).toHaveBeenCalledWith("History cleared. Deleted 1 files.", "success");
  });

  test("auto-mask listeners cover manual sync, input min clamp and slider update callback", async () => {
    const uiCracking = loadUiCrackingModule();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.22000");

    const slider = global.noUiSlider.create.mock.results[0].value;
    const sliderOpts = global.noUiSlider.create.mock.calls[0][1];
    const autoChk = document.getElementById("auto-mask-chk");
    const maskInput = document.getElementById("crack-mask-input");

    expect(sliderOpts.format.to(2.9)).toBe(3);
    expect(sliderOpts.format.from("7")).toBe(7);

    slider.get.mockReturnValue([5, 8]);
    maskInput.value = "?a?a?a";
    autoChk.checked = false;
    autoChk.dispatchEvent(new Event("change", { bubbles: true }));
    expect(maskInput.readOnly).toBe(false);
    expect(slider.set).toHaveBeenCalledWith([5, 3]);

    slider.get.mockReturnValue([5, 8]);
    maskInput.value = "?a";
    maskInput.dispatchEvent(new Event("input", { bubbles: true }));
    expect(slider.set).toHaveBeenCalledWith([1, 1]);

    slider.get.mockReturnValue([1, 4]);
    autoChk.checked = true;
    autoChk.dispatchEvent(new Event("change", { bubbles: true }));
    expect(maskInput.readOnly).toBe(true);
    expect(maskInput.value).toBe("?a?a?a?a");

    const updateCb = slider.on.mock.calls.find(([evt]) => evt === "update")[1];
    updateCb([2, 6], 1);
    expect(document.getElementById("inc-val-min").innerText).toBe(2);
    expect(document.getElementById("inc-val-max").innerText).toBe(6);
    expect(maskInput.value).toBe("?a?a?a?a?a?a");
  });

  test("openCrackingPanel handles empty files, gps badge and list error", async () => {
    const uiCracking = loadUiCrackingModule();

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");
    expect(document.getElementById("crack-file-list").innerHTML).toContain("No files found locally");

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "capture.gps.json", type: "json", size: 33, modified: 1700000000 },
    ]);
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");
    expect(document.getElementById("crack-file-list").textContent).toContain("GPS");

    mockAPI.getHandshakeFiles.mockRejectedValueOnce(new Error("list failed"));
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");
    expect(document.getElementById("crack-file-list").innerHTML).toContain("Error loading files");
    expect(mockLog).toHaveBeenCalledWith("Error loading files for AA:BB:CC:DD:EE:FF: list failed", "error");
  });

  test("openCrackingPanel dispatches exitAnalyticsView when analytics mode is active", async () => {
    const uiCracking = loadUiCrackingModule();
    const exitListener = jest.fn();
    document.addEventListener("exitAnalyticsView", exitListener);

    mockState.modes.analytics = true;
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.22000");

    expect(exitListener).toHaveBeenCalledTimes(1);
  });

  test("openCrackingPanel raw hash scope injects placeholder file when missing", async () => {
    const uiCracking = loadUiCrackingModule();
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "other.22000", type: "22000", size: 10, modified: 1700000000 },
    ]);
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "raw_missing.22000", {
      scope: "raw_hash",
    });

    expect(document.getElementById("crack-file-list").textContent).toContain("raw_missing.22000");
    expect(uiCracking.__test.getSelectedFile().name).toBe("raw_missing.22000");
  });

  test("openCrackingPanel sorts captured files alphabetically", async () => {
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "zeta.22000", type: "22000", size: 120, modified: 1700000005 },
      { name: "file10.22000", type: "22000", size: 120, modified: 1700000004 },
      { name: "Alpha.22000", type: "22000", size: 120, modified: 1700000002 },
      { name: "file2.22000", type: "22000", size: 120, modified: 1700000003 },
    ]);

    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    const names = Array.from(document.querySelectorAll("#crack-file-list .file-item .file-name-text"))
      .map((el) => el.textContent.trim());

    expect(names).toEqual(["Alpha.22000", "file2.22000", "file10.22000", "zeta.22000"]);
  });

  test("openMultiCrackingPanel uses batch context for source labels", async () => {
    const uiCracking = loadUiCrackingModule();
    mockAPI.getMultiFileContent.mockResolvedValueOnce({
      items: [{ mac: "aa:bb:cc:dd:ee:ff", ssid: "Cafe", status: "OK", reason: "HANDSHAKE OK" }],
    });
    mockAPI.getBatchFiles.mockResolvedValueOnce([
      { name: "batch_ctx.22000", type: "batch", size: 100, modified: 1700001000 },
    ]);

    await uiCracking.openMultiCrackingPanel("batch_ctx.22000");
    await flushAsync();

    expect(mockAPI.getAttackRecommendation).toHaveBeenCalledWith(
      expect.objectContaining({ filename: "batch_ctx.22000", mac: "AA:BB:CC:DD:EE:FF" })
    );
    expect(document.getElementById("crack-file-feedback").textContent).toContain(
      "Cafe · batch_ctx.22000"
    );

    mockAPI.getMultiFileContent.mockResolvedValueOnce({
      items: [{ mac_address: "11:22:33:44:55:66", ssid: "HIDDEN", status: "OK" }],
    });
    mockAPI.getBatchFiles.mockResolvedValueOnce([
      { name: "batch_hidden.22000", type: "batch", size: 100, modified: 1700001000 },
    ]);

    await uiCracking.openMultiCrackingPanel("batch_hidden.22000");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain(
      "batch_hidden.22000 · partial context"
    );
  });

  test("batch .22000 selection renders handshake summary with batch stats", async () => {
    const uiCracking = loadUiCrackingModule();
    mockAPI.getMultiFileContent.mockResolvedValueOnce({
      items: [
        { mac: "aa:bb:cc:dd:ee:ff", ssid: "Cafe", status: "OK", reason: "HANDSHAKE OK", cracked: true },
        { mac: "11:22:33:44:55:66", ssid: "HS", status: "FAILED", reason: "EAPOL MISSING/INVALID" },
        { mac: "22:33:44:55:66:77", ssid: "Lab", status: "FAILED", reason: "INVALID DETAILS" },
      ],
    });
    mockAPI.getBatchFiles.mockResolvedValueOnce([
      { name: "batch_stats.22000", type: "batch", size: 200, modified: 1700000001 },
      { name: "batch_stats.try", type: "try", size: 20, modified: 1700000002 },
    ]);

    await uiCracking.openMultiCrackingPanel("batch_stats.22000");
    await flushAsync();

    const summaryText = document.getElementById("crack-handshake-set-summary").textContent;
    expect(summaryText).toContain("HANDSHAKE SET");
    expect(summaryText).toContain("3 item(s)");
    expect(summaryText).toContain("1 handshake OK");
    expect(summaryText).toContain("1 EAPOL missing");
    expect(summaryText).toContain("2 invalid");
    expect(summaryText).toContain("1 cracked");
    expect(summaryText).not.toContain("batch_stats.22000");
    expect(summaryText).not.toContain("AA:BB:CC:DD:EE:FF");
    expect(summaryText).not.toContain("Cafe");

    clickFileByName("batch_stats.try");
    await flushAsync();
    expect(document.getElementById("crack-handshake-set-summary").textContent.trim()).toBe("");
  });

  test("openMultiCrackingPanel sorts batch files and keeps batch selected", async () => {
    const uiCracking = loadUiCrackingModule();
    mockAPI.getBatchFiles.mockResolvedValueOnce([
      { name: "batch_zeta.22000", type: "batch", size: 200, modified: 1700000003 },
      { name: "batch_alpha.22000", type: "batch", size: 200, modified: 1700000001 },
      { name: "batch_beta.try", type: "try", size: 10, modified: 1700000002 },
    ]);

    await uiCracking.openMultiCrackingPanel("batch_alpha.22000");

    const names = Array.from(document.querySelectorAll("#crack-file-list .file-item .file-name-text"))
      .map((el) => el.textContent.trim());
    expect(names).toEqual(["batch_alpha.22000", "batch_beta.try", "batch_zeta.22000"]);

    const selected = document.querySelector("#crack-file-list .file-item.selected .file-name-text");
    expect(selected?.textContent.trim()).toBe("batch_alpha.22000");
  });

  test("openCrackingPanel handles pcap selection when optional elements are missing", async () => {
    const uiCracking = loadUiCrackingModule();
    document.getElementById("crack-pcap-conversions").remove();
    document.getElementById("aircrack-legacy-toggle").remove();
    document.querySelector(".crack-status-container").remove();

    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.pcap");
    expect(document.getElementById("crack-file-list").textContent).toContain("capture.pcap");
  });

  test("selectFile cracked success loads file content", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "capture.cracked", type: "cracked", size: 100, modified: 1700000000 },
    ]);
    mockAPI.getFileContent.mockResolvedValueOnce("hash:pass");
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.cracked");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain("hash:pass");
  });

  test("association preview warns when target is missing or mode is invalid", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    uiCracking.__test.setSelectedFile({ name: "capture.try", type: "try" });
    document.getElementById("btn-association-preview").click();
    expect(mockLog).toHaveBeenCalledWith(
      "Select a .22000 or batch file to preview association candidates.",
      "error"
    );

    uiCracking.__test.setSelectedFile({ name: "capture.22000", type: "22000" });
    document.getElementById("custom-mode-select").value = "straight";
    document.getElementById("btn-association-preview").click();
    expect(mockLog).toHaveBeenCalledWith(
      "Association preview is available only for association modes.",
      "error"
    );
  });

  test("association preview renders warnings and handles capped payloads", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    setMode("association");
    mockAPI.previewAssociationCandidates.mockResolvedValueOnce({
      status: "success",
      mode: "association",
      candidate_count: 3,
      capped: true,
      cap: 3,
      sample_candidates: ["a", "b"],
      sources: { seed_counts: { ssid: 1, hint: 0, fallback_hint: 0, ssid_fallback: 0 }, ssid_count: 1, hint_count: 0 },
      warnings: ["low entropy"],
    });

    document.getElementById("btn-association-preview").click();
    await flushAsync();

    expect(document.getElementById("crack-file-feedback").textContent).toContain("Warnings");
    expect(document.getElementById("crack-file-feedback").textContent).toContain("low entropy");
  });

  test("loadAttackRecommendation handles null and error recommendations", async () => {
    const uiCracking = loadUiCrackingModule();

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "capture.22000", type: "22000", size: 100, modified: 1700000000 },
    ]);
    mockAPI.getAttackRecommendation.mockResolvedValueOnce(null);
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.22000");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain(
      "No recommendation data available."
    );

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "capture.22000", type: "22000", size: 100, modified: 1700000000 },
    ]);
    mockAPI.getAttackRecommendation.mockRejectedValueOnce(new Error());
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.22000");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain(
      "Failed to load recommendation"
    );
  });

  test("renderDetailsView covers context severity and attempt outcomes", () => {
    const uiCracking = loadUiCrackingModule();
    const baseDetails = { ssid: "Test", bssid: "AA:BB:CC:DD:EE:FF" };

    const skipHtml = uiCracking.__test.renderDetailsView(baseDetails, {
      action: "skip",
      attack_score: { score: 10, priority: "low" },
      candidate_modes: ["rules"],
      attempt_feedback: {
        totals: { attempts: 1, distinct_modes: 1, cracked: 1, exhausted: 0, fatal: 0 },
        by_mode: [{ mode: "rules", attempts: 1 }],
        recent: [{ started_at: "2026-01-01T10:00:00", mode: "rules", outcome: "cracked", params: {} }],
      },
    });
    expect(skipHtml).toContain("CRACKED");
    expect(skipHtml).toContain("LOW");

    const prepareHtml = uiCracking.__test.renderDetailsView(baseDetails, {
      action: "prepare",
      attack_score: { score: 40, priority: "low" },
      candidate_modes: ["rules"],
      attempt_feedback: {
        totals: { attempts: 1, distinct_modes: 1, cracked: 0, exhausted: 0, fatal: 0 },
        by_mode: [{ mode: "rules", attempts: 1 }],
        recent: [{ started_at: "2026-01-02T10:00:00", mode: "rules", outcome: "running", params: {} }],
      },
    });
    expect(prepareHtml).toContain("RUNNING");
    expect(prepareHtml).toContain("MEDIUM");

    const lowHtml = uiCracking.__test.renderDetailsView(baseDetails, {
      action: "run",
      attack_score: { score: 10, priority: "low" },
      candidate_modes: ["rules"],
      attempt_feedback: {
        totals: { attempts: 1, distinct_modes: 1, cracked: 0, exhausted: 0, fatal: 0 },
        by_mode: [{ mode: "rules", attempts: 1 }],
        recent: [{ started_at: "2026-01-03T10:00:00", mode: "rules", outcome: "other", params: {} }],
      },
    });
    expect(lowHtml).toContain("LOW");
    expect(lowHtml).toContain("no params");
  });

  test("openMultiCrackingPanel dispatches exitAnalyticsView and handles manifest errors", async () => {
    const uiCracking = loadUiCrackingModule();
    const exitListener = jest.fn();
    document.addEventListener("exitAnalyticsView", exitListener);

    mockState.modes.analytics = true;
    mockAPI.getMultiFileContent.mockRejectedValueOnce(new Error("manifest fail"));
    mockAPI.getBatchFiles.mockResolvedValueOnce([
      { name: "batch_ctx.22000", type: "batch", size: 100, modified: 1700001000 },
    ]);

    await uiCracking.openMultiCrackingPanel("batch_ctx.22000");
    await flushAsync();
    expect(exitListener).toHaveBeenCalled();
  });

  test("details view tolerates recommendation errors and startCracking batch branch", async () => {
    const uiCracking = loadUiCrackingModule();

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "capture.details", type: "details", size: 100, modified: 1700000000 },
    ]);
    mockAPI.getFingerprintDetails.mockResolvedValueOnce({ bssid: "AA:BB:CC:DD:EE:FF", ssid: "Net" });
    mockAPI.getAttackRecommendation.mockRejectedValueOnce(new Error("insights down"));
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "Net", "capture.details");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").innerHTML).toContain("details-view-scroll");

    uiCracking.__test.setSelectedFile({ name: "batch_ctx.22000", type: "batch" });
    document.getElementById("custom-mode-select").value = "rules";
    document.getElementById("crack-wordlist-select").innerHTML = '<option value="/wl.txt">wl</option>';
    document.getElementById("crack-wordlist-select").value = "/wl.txt";
    mockAPI.startCracking.mockResolvedValueOnce({ status: "started", job_id: "job-batch" });
    await uiCracking.__test.startCracking();
    expect(mockAPI.getAttackRecommendation).toHaveBeenCalledWith(
      expect.objectContaining({ filename: "batch_ctx.22000" })
    );
  });

  test("openMultiCrackingPanel covers API fallback and cracked badge rendering", async () => {
    const uiCracking = loadUiCrackingModule();

    mockAPI.getBatchFiles.mockRejectedValueOnce(new Error("batch failed"));
    await uiCracking.openMultiCrackingPanel("batch_missing.22000");
    expect(document.getElementById("crack-file-list").textContent).toContain("batch_missing.22000");

    mockAPI.getBatchFiles.mockResolvedValueOnce([
      { name: "batch_ok.22000", type: "batch", size: 100, modified: 1700001000 },
      { name: "batch_ok.cracked", type: "cracked", size: 50, modified: 1700001001 },
    ]);
    await uiCracking.openMultiCrackingPanel("batch_ok.22000");
    expect(document.getElementById("crack-file-list").textContent).toContain("CRACKED");
  });

  test("loadCrackingResources selects passphrase rules, styles directory wordlists and catches API errors", async () => {
    const uiCracking = loadUiCrackingModule();
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    const originalTextDescriptor = Object.getOwnPropertyDescriptor(HTMLOptionElement.prototype, "text");

    Object.defineProperty(HTMLOptionElement.prototype, "text", {
      configurable: true,
      get() {
        return this.innerText || this.textContent || "";
      },
      set(value) {
        this.innerText = value;
      },
    });

    try {
      mockAPI.getHashcatRules.mockResolvedValueOnce([
        { name: "passphrase-rule1.rule", path: "/r1.rule" },
        { name: "passphrase-rule2.rule", path: "/r2.rule" },
      ]);
      mockAPI.getCustomWordlists.mockResolvedValueOnce([
        { name: "[DIR] giant", path: "/wl/giant", type: "directory", size: "12 GB" },
      ]);
      await uiCracking.__test.loadCrackingResources();

      expect(document.getElementById("crack-rule-select").value).toBe("/r1.rule");
      expect(document.getElementById("crack-rule-2-select").value).toBe("/r2.rule");
      const wlOpt = document.getElementById("crack-wordlist-select").options[0];
      expect(wlOpt.text).toContain("giant");
      expect(wlOpt.text).toContain("12 GB");
      expect(wlOpt.style.fontWeight).toBe("bold");

      mockAPI.getHashcatDevices.mockRejectedValueOnce(new Error("resource fail"));
      await uiCracking.__test.loadCrackingResources();
      expect(errorSpy).toHaveBeenCalledWith("Failed to load resources", expect.any(Error));
    } finally {
      if (originalTextDescriptor) {
        Object.defineProperty(HTMLOptionElement.prototype, "text", originalTextDescriptor);
      }
      errorSpy.mockRestore();
    }
  });

  test("selectFile covers running/fallback status branches across pcap, 22000, batch, details and unknown types", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "capture.pcap", type: "pcap", size: 1024, modified: 1700000000 },
      { name: "capture.22000", type: "22000", size: 1024, modified: 1700000001 },
      { name: "capture.details", type: "details", size: 100, modified: 1700000002 },
      { name: "capture.unknown", type: "unknown", size: 50, modified: 1700000003 },
    ]);
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID");

    mockActiveProcesses.runPcap = {
      details: "capture.22000",
      status: "RUNNING",
      type: "HASHCAT [MASK]",
      percentage: 10,
      extraInfo: "",
      indeterminate: false,
    };
    clickFileByName("capture.pcap");
    await flushAsync();
    expect(document.getElementById("btn-extract-details").disabled).toBe(true);
    expect(document.getElementById("btn-pcap-generate-hash").disabled).toBe(true);
    expect(document.getElementById("btn-quick-attack").disabled).toBe(true);

    delete mockActiveProcesses.runPcap;
    mockActiveProcesses.failedPcap = {
      details: "capture.22000",
      status: "FAILED",
      type: "HASHCAT [MASK]",
      percentage: 100,
      extraInfo: "",
      indeterminate: false,
    };
    clickFileByName("capture.pcap");
    await flushAsync();
    expect(document.getElementById("btn-pcap-generate-hash").disabled).toBe(false);

    mockActiveProcesses.run22000 = {
      details: "capture.22000",
      status: "RUNNING",
      type: "HASHCAT [MASK]",
      percentage: 12,
      extraInfo: "",
      indeterminate: false,
    };
    clickFileByName("capture.22000");
    await flushAsync();
    expect(document.getElementById("btn-convert-hash").disabled).toBe(true);

    mockAPI.getFingerprintDetails.mockRejectedValueOnce(new Error("details down"));
    clickFileByName("capture.details");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain("Failed to load details");
    expect(document.getElementById("crack-file-feedback").classList.contains("crack-feedback-details")).toBe(true);

    clickFileByName("capture.unknown");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain("File type not recognized");
    expect(document.getElementById("crack-file-feedback").classList.contains("crack-feedback-details")).toBe(false);

    mockAPI.getBatchFiles.mockResolvedValueOnce([
      { name: "batch_alpha.22000", type: "batch", size: 2048, modified: 1700001000 },
    ]);
    mockActiveProcesses.batchRun = {
      details: "batch_alpha.22000",
      status: "RUNNING",
      type: "HASHCAT [MASK]",
      percentage: 1,
      extraInfo: "",
      indeterminate: false,
    };
    await uiCracking.openMultiCrackingPanel("batch_alpha.22000");
    expect(document.getElementById("btn-convert-hash").disabled).toBe(true);
  });

  test("selectFile cracked catch, indeterminate status branch and completion side-effect refresh", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();

    mockAPI.getHandshakeFiles.mockResolvedValueOnce([
      { name: "capture.cracked", type: "cracked", size: 100, modified: 1700000000 },
    ]);
    mockAPI.getFileContent.mockRejectedValueOnce(new Error("cant-read"));
    await uiCracking.openCrackingPanel("AA:BB:CC:DD:EE:FF", "My SSID", "capture.cracked");
    await flushAsync();
    expect(document.getElementById("crack-file-feedback").textContent).toContain("Failed to load file content");

    uiCracking.updateCrackingPanelStatus({
      status: "RUNNING",
      percentage: 100,
      type: "HASHCAT [MASK]",
      extraInfo: "autotune",
      indeterminate: true,
    });
    expect(document.getElementById("crack-mini-bar").classList.contains("indeterminate")).toBe(true);
    expect(document.getElementById("crack-progress-text").innerText).toContain("RUNNING");

    mockActiveProcesses["job-refresh"] = {
      type: "GENERATE HASH (22000)",
      details: "capture.pcap",
    };
    uiCracking.__test.setSelectedFile({ name: "capture.pcap", type: "pcap" });
    mockAPI.getHandshakeFiles.mockResolvedValueOnce([]);
    uiCracking.handleJobCompletionSideEffects({ id: "job-refresh" });
    await flushAsync();
    expect(mockAPI.getHandshakeFiles).toHaveBeenCalled();
  });

  test("listeners cover rules visibility and mask help alert", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.setupCrackingListeners();
    await openReady22000Panel(uiCracking);

    uiCracking.__test.updateWordlistVisibility("rules");
    expect(document.getElementById("crack-rule-row").style.display).toBe("flex");
    expect(document.getElementById("crack-rule-label").innerText).toBe("RULE:");

    document.getElementById("mask-help-btn").click();
    expect(window.alert).toHaveBeenCalled();

    const legacy = document.getElementById("aircrack-legacy-toggle");
    legacy.click();
    legacy.click();
    expect(legacy.getAttribute("data-expanded")).toBe("false");
  });

  test("startFingerprint covers pcap path and unsupported type guard", async () => {
    const uiCracking = loadUiCrackingModule();
    document.getElementById("crack-mac").innerText = "AA:BB:CC:DD:EE:FF";
    document.getElementById("crack-ssid").innerText = "My SSID";

    uiCracking.__test.setSelectedFile({ name: "capture.pcap", type: "pcap" });
    await uiCracking.__test.startFingerprint("btn-extract-details");
    expect(mockAPI.extractFingerprint).toHaveBeenCalledWith("capture.pcap", false, null, null, null);

    mockAPI.extractFingerprint.mockClear();
    uiCracking.__test.setSelectedFile({ name: "capture.txt", type: "txt" });
    await uiCracking.__test.startFingerprint("btn-extract-details");
    expect(mockAPI.extractFingerprint).not.toHaveBeenCalled();
  });

  test("startCracking passphrase stacks rules and getSelectedFile hook returns current selection", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.22000", type: "22000" });

    const modeSelect = document.getElementById("custom-mode-select");
    modeSelect.innerHTML += '<option value="passphrase">passphrase</option>';
    modeSelect.value = "passphrase";

    document.getElementById("crack-wordlist-select").innerHTML = '<option value="/wl.txt">wl</option>';
    document.getElementById("crack-wordlist-select").value = "/wl.txt";
    document.getElementById("crack-rule-select").innerHTML = '<option value="/r1.rule">r1</option>';
    document.getElementById("crack-rule-2-select").innerHTML = '<option value="/r2.rule">r2</option>';
    document.getElementById("crack-rule-select").value = "/r1.rule";
    document.getElementById("crack-rule-2-select").value = "/r2.rule";

    await uiCracking.__test.startCracking();
    const args = mockAPI.startCracking.mock.calls[mockAPI.startCracking.mock.calls.length - 1];
    expect(args[4]).toBe("/r1.rule;/r2.rule");
    expect(uiCracking.__test.getSelectedFile()).toEqual({ name: "capture.22000", type: "22000" });
  });

  test("startCracking blocks combinator_passphrase when second wordlist is missing", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.22000", type: "22000" });

    const modeSelect = document.getElementById("custom-mode-select");
    modeSelect.value = "combinator_passphrase";
    document.getElementById("crack-wordlist-select").innerHTML = '<option value="/wl1.txt">wl1</option>';
    document.getElementById("crack-wordlist-select").value = "/wl1.txt";
    document.getElementById("crack-wordlist-2-select").innerHTML = '<option value="">none</option>';
    document.getElementById("crack-wordlist-2-select").value = "";

    await uiCracking.__test.startCracking();
    expect(mockAPI.startCracking).not.toHaveBeenCalled();
    expect(document.getElementById("crack-progress-text").innerText).toBe(
      "SECOND WORDLIST REQUIRED"
    );
  });

  test("startCracking sends mask profile for hybrid mask-profile variants", async () => {
    const uiCracking = loadUiCrackingModule();
    uiCracking.__test.setSelectedFile({ name: "capture.22000", type: "22000" });
    document.getElementById("crack-wordlist-select").innerHTML = '<option value="/wl1.txt">wl1</option>';
    document.getElementById("crack-wordlist-select").value = "/wl1.txt";
    document.getElementById("crack-mask-profile-select").innerHTML =
      '<option value="/wifi.hcmask">wifi</option>';
    document.getElementById("crack-mask-profile-select").value = "/wifi.hcmask";

    document.getElementById("custom-mode-select").value = "hybrid_mask_profile";
    await uiCracking.__test.startCracking();
    let args = mockAPI.startCracking.mock.calls[mockAPI.startCracking.mock.calls.length - 1];
    expect(args[1]).toBe("hybrid_mask_profile");
    expect(args[14]).toBe("/wifi.hcmask");

    document.getElementById("custom-mode-select").value = "hybrid_reverse_mask_profile";
    await uiCracking.__test.startCracking();
    args = mockAPI.startCracking.mock.calls[mockAPI.startCracking.mock.calls.length - 1];
    expect(args[1]).toBe("hybrid_reverse_mask_profile");
    expect(args[14]).toBe("/wifi.hcmask");
  });

  test("updateCrackingPanelStatus covers guard, queued color and retry labels for 22000/aircrack", () => {
    const uiCracking = loadUiCrackingModule();

    const progress = document.getElementById("crack-progress-text");
    const bar = document.getElementById("crack-mini-bar");
    progress.remove();
    bar.remove();
    uiCracking.updateCrackingPanelStatus({
      status: "RUNNING",
      percentage: 1,
      type: "HASHCAT [MASK]",
      extraInfo: "",
      indeterminate: false,
    });

    document.body.insertAdjacentHTML(
      "beforeend",
      '<div id="crack-progress-text"></div><div id="crack-mini-bar"></div>'
    );
    uiCracking.updateCrackingPanelStatus({
      status: "QUEUED",
      percentage: 10,
      type: "HASHCAT [MASK]",
      extraInfo: "",
      indeterminate: false,
    });
    expect(document.getElementById("crack-progress-text").innerText).toContain("QUEUED");

    uiCracking.updateCrackingPanelStatus({
      status: "FAILED",
      percentage: 100,
      type: "22000 CONVERTER",
      extraInfo: "",
      indeterminate: false,
    });
    expect(document.getElementById("btn-pcap-generate-hash").innerText).toBe("RETRY");

    uiCracking.updateCrackingPanelStatus({
      status: "FAILED",
      percentage: 100,
      type: "AIRCRACK-NG",
      extraInfo: "",
      indeterminate: false,
    });
    expect(document.getElementById("btn-quick-attack").innerText).toBe("RETRY");
  });

  test("renderDetailsView covers fallback and classification branches", () => {
    const uiCracking = loadUiCrackingModule();

    const empty = uiCracking.__test.renderDetailsView(null);
    expect(empty).toContain("details-view-scroll");
    expect(empty).toContain("No details available");

    const lowConfidence = uiCracking.__test.renderDetailsView({
      ssid: "X",
      bssid: "AA:BB",
      security: {},
      wps: { present: false },
      classification: { type: "unknown", confidence: 0.2, evidence: [] },
      meta: {},
    });
    expect(lowConfidence).toContain("Insufficient evidence");
    expect(lowConfidence).toContain("Not present");

    const highConfidence = uiCracking.__test.renderDetailsView({
      ssid: "Y",
      bssid: "CC:DD",
      security: { wpa_version: "WPA2", akm: ["PSK"], pairwise_ciphers: ["CCMP"], group_cipher: "CCMP", pmf: "capable" },
      wps: { present: true, manufacturer: "ACME", model_name: "M1", device_name: "R1" },
      classification: { type: "router", confidence: 0.9, evidence: ["ssid_pattern"] },
      raw_sniffer: {
        present: true,
        files_count: 1,
        aggregate: {
          beacon_count_total: 100,
          beacon_count_peak: 100,
          eapol_count_total: 4,
          eapol_count_peak: 4,
          probe_client_count_peak: 8,
          channels: [6],
          frequencies_mhz: [2437],
          last_seen_offset_s_max: 9.2,
          warnings: ["[raw_1.pcap] partial capture"],
        },
        files: [
          {
            source_file: "raw_1.pcap",
            beacon_count: 100,
            eapol_count: 4,
            probe_client_count: 8,
            channel: 6,
            frequency_mhz: 2437,
            ssid: "Y",
            ssid_raw_hex: "59",
            warnings: ["partial capture"],
          },
        ],
      },
      meta: { source: "test", timestamp: "now", warnings: ["weak"], ssid_raw_hex: "414243" },
      vendor: "Vendor",
    });
    expect(highConfidence).toContain("Router AP");
    expect(highConfidence).toContain("ssid_pattern");
    expect(highConfidence).toContain("Original SSID hex");
    expect(highConfidence).toContain("Raw Sniffer");
    expect(highConfidence).toContain("raw_1.pcap");
    expect(highConfidence).toContain("details-view-scroll");

    const minimal = uiCracking.__test.renderDetailsView({});
    expect(minimal).toContain("Insufficient evidence");
    expect(minimal).toContain("Unknown");

    const camera = uiCracking.__test.renderDetailsView({
      classification: { type: "camera_ap", confidence: 0.95, evidence: ["oui"] },
      security: { akm: [], pairwise_ciphers: [] },
      wps: { present: true },
      meta: { warnings: [] },
    });
    expect(camera).toContain("Camera AP");

    const printer = uiCracking.__test.renderDetailsView({
      classification: { type: "printer_ap", confidence: 0.95, evidence: ["ie"] },
      security: { akm: ["PSK"], pairwise_ciphers: ["CCMP"] },
      wps: { present: true, manufacturer: "", model_name: " ", device_name: " " },
      meta: { warnings: [] },
    });
    expect(printer).toContain("Printer AP");
  });

  test("renderDetailsView renders radio, rates, caps, qbss and insights with area context", () => {
    const uiCracking = loadUiCrackingModule();

    mockState.allPositions["AA:BB:CC:DD:EE:FF"] = { lat: 1, lng: 2 };
    mockState.analyticsUi = {
      hotspots: [
        {
          id: "HCTX",
          center_lat: 1,
          center_lng: 2,
          radius_m: 500,
          score: 77,
          locked_count: 4,
          top_channels: ["11"],
        },
      ],
    };

    const recommendation = {
      action: "run",
      recommended_mode: "rules",
      candidate_modes: ["rules", "mask"],
      reasons: ["prior tests"],
      suggested_hints: ["ssid", "vendor"],
      attack_score: {
        score: 85,
        priority: "high",
        score_reasons: [{ delta: 5, reason: "signal" }],
      },
      handshake_readiness: {
        status: "ready",
        score: 88,
        reason: "ok",
        signals: { valid_hash_lines: 3, raw_eapol_total: 1, raw_beacon_total: 2, raw_files_count: 1 },
        enrichment: { pending_hash_files: ["a.22000"], existing_hash_files: ["b.22000"] },
      },
      attempt_feedback: {
        totals: { attempts: 1, distinct_modes: 1, cracked: 0, exhausted: 0, fatal: 0 },
        by_mode: [{ mode: "rules", attempts: 1 }],
        recent: [],
      },
    };

    const html = uiCracking.__test.renderDetailsView(
      {
        ssid: "RichNet",
        bssid: "AA:BB:CC:DD:EE:FF",
        security: { wpa_version: "WPA2", akm: ["PSK"], pairwise_ciphers: ["CCMP"], group_cipher: "CCMP", pmf: "capable" },
        wps: { present: true, manufacturer: "ACME", model_name: "M2", device_name: "Device" },
        classification: { type: "iot_ap", confidence: 0.9, evidence: ["oui"], tier: "gold" },
        vendor: "VendorX",
        radio: {
          channel: 6,
          band: 2.4,
          frequency_mhz: 2437,
          signal_dbm_avg: -40,
          signal_dbm_min: -80,
          signal_dbm_max: -20,
          datarate_mbps_avg: 11,
          datarate_mbps_max: 54,
        },
        rates: { all: [1, 2, 5.5], max_rate_mbps: 54 },
        phy: { ht_present: true, ht_width_code: "20", vht_width_code: "80" },
        capabilities: { flags: ["SHORT_PREAMBLE", "QOS"] },
        qbss: { station_count: 4, channel_utilization: 80, available_capacity: 100 },
      },
      recommendation
    );

    expect(html).toContain("Radio");
    expect(html).toContain("Rates");
    expect(html).toContain("PHY");
    expect(html).toContain("Caps");
    expect(html).toContain("QBSS");
    expect(html).toContain("ATTACK INSIGHTS");
    expect(html).toContain("Area Context");
    expect(html).toContain("Handshake Readiness");
    expect(html).toContain("Suggested Hints");
    expect(html).toContain("AA:BB:CC:DD:EE:FF");
  });

  test("renderDetailsView uses cracking insights layout without extra heading", () => {
    const uiCracking = loadUiCrackingModule();

    const html = uiCracking.__test.renderDetailsView(
      {
        ssid: "Test",
        bssid: "AA:BB:CC:DD:EE:FF",
        security: {},
        wps: { present: false },
        classification: { type: "unknown", confidence: 0.2, evidence: [] },
        meta: {},
      },
      {
        action: "run",
        recommended_mode: "rules",
        candidate_modes: ["rules"],
        reasons: ["context"],
        attack_score: { score: 70, priority: "high", score_reasons: [] },
        attempt_feedback: {
          totals: { attempts: 1, distinct_modes: 1, cracked: 0, exhausted: 0, fatal: 0 },
          by_mode: [{ mode: "rules", attempts: 1 }],
          recent: [{ started_at: "2026-01-01T10:00:00", mode: "rules", outcome: "queued", params: {} }],
        },
      }
    );

    expect((html.match(/ATTACK INSIGHTS/g) || []).length).toBe(1);
    expect((html.match(/ATTACK MEMORY/g) || []).length).toBe(1);
    expect(html).not.toContain("Attack Insights");
  });

  test("updateWordlistVisibility and defaults cover missing element and device fallback branches", async () => {
    const uiCracking = loadUiCrackingModule();

    const row = document.getElementById("crack-wordlist-row");
    row.remove();
    uiCracking.__test.updateWordlistVisibility("mask");

    mountCrackingDom();
    document.getElementById("crack-device-select").innerHTML = `
      <option value="all">Auto / All</option>
      <option value="1">GPU #1</option>
    `;
    mockAPI.getConfig.mockResolvedValueOnce({
      hashcat_optimized: true,
      hashcat_slow: false,
      hashcat_device_default: "999",
    });
    await uiCracking.__test.loadCrackingDefaults();
    expect(document.getElementById("flag-optimized").checked).toBe(true);
    expect(document.getElementById("flag-slow").checked).toBe(false);
    expect(document.getElementById("crack-device-select").value).toBe("all");

    mockAPI.getConfig.mockResolvedValueOnce({
      hashcat_optimized: false,
      hashcat_slow: true,
    });
    await uiCracking.__test.loadCrackingDefaults();
    expect(document.getElementById("flag-slow").checked).toBe(true);
  });

  test("startFingerprint covers null selection, missing button and saved-path fallback", async () => {
    const uiCracking = loadUiCrackingModule();

    uiCracking.__test.setSelectedFile(null);
    await uiCracking.__test.startFingerprint("btn-extract-details");
    expect(mockAPI.extractFingerprint).not.toHaveBeenCalled();

    uiCracking.__test.setSelectedFile({ name: "capture.details", type: "details" });
    uiCracking.__test.setCurrentFiles(null);
    document.getElementById("crack-mac").innerText = "AA:BB:CC:DD:EE:FF";
    document.getElementById("crack-ssid").innerText = "My SSID";
    document.getElementById("btn-extract-details").remove();
    mockAPI.extractFingerprint.mockResolvedValueOnce({ details: {} });
    await uiCracking.__test.startFingerprint("btn-extract-details");
    expect(mockAPI.extractFingerprint).toHaveBeenCalledWith("capture.pcap", false, null, null, null);
  });
});
