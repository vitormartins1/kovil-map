const mockAPI = {
  listRawSnifferFiles: jest.fn(),
  getRawSnifferHashes: jest.fn(),
  getRawSnifferMetadata: jest.fn(),
  getRawSnifferAnalysis: jest.fn(),
  analyzeRawSniffer: jest.fn(),
  extractRawSniffer: jest.fn(),
  deleteRawSnifferFile: jest.fn(),
};

const mockLog = jest.fn();
const mockAddProcess = jest.fn();
const mockUpdateProcess = jest.fn();
const mockOpenCrackingPanel = jest.fn();

const mockState = {
  rawUi: null,
  rawFiles: [],
  rawHashes: [],
  rawSelectedFile: null,
  rawSelectedRawItemId: null,
  rawSelectedHash: null,
  rawMetadataByFile: {},
  rawAnalysisByKey: {},
  rawSelectedNetworkByFile: {},
  allPositions: {},
};

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
  escapeHtml: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  addProcess: (...args) => mockAddProcess(...args),
  updateProcess: (...args) => mockUpdateProcess(...args),
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: (...args) => mockOpenCrackingPanel(...args),
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
}));

const {
  getRawUiState,
  renderRawFilesList,
  renderRawHashesList,
  renderRawMetadata,
  refreshRawFiles,
  loadRawMetadata,
  setupRawListeners,
} = require("../../src/modules/ui_raw.js");

function mountRawDom() {
  document.body.innerHTML = `
    <div id="raw-files-list"></div>
    <div id="raw-hashes-list"></div>
    <div id="raw-details-view"></div>
    <span id="raw-files-count-info"></span>
    <span id="raw-net-count-info"></span>
    <input id="raw-file-search" />
    <select id="raw-file-status"></select>
    <select id="raw-file-sort"></select>
    <input id="raw-network-search" />
    <select id="raw-network-sort"></select>
    <button id="btn-raw-refresh"></button>
    <button id="btn-raw-analyze-selected"></button>
    <button id="btn-raw-delete-selected"></button>
    <button id="btn-raw-reprocess-selected"></button>
    <button id="btn-raw-reprocess-pending"></button>
  `;

  document.getElementById("raw-file-status").innerHTML =
    '<option value="all">ALL</option><option value="cached">CACHED</option><option value="pending">PENDING</option>';
  document.getElementById("raw-file-sort").innerHTML =
    '<option value="modified_desc">RECENT</option><option value="modified_asc">OLD</option><option value="size_desc">SIZE</option><option value="size_asc">SIZE_ASC</option><option value="networks_desc">NETS</option><option value="name_asc">NAME</option>';
  document.getElementById("raw-network-sort").innerHTML =
    '<option value="beacon_desc">BEACON</option><option value="eapol_desc">EAPOL</option><option value="probe_desc">PROBE</option><option value="ssid_asc">SSID</option><option value="bssid_asc">BSSID</option>';
}

function resetState() {
  mockState.rawUi = null;
  mockState.rawFiles = [];
  mockState.rawHashes = [];
  mockState.rawSelectedFile = null;
  mockState.rawSelectedRawItemId = null;
  mockState.rawSelectedHash = null;
  mockState.rawMetadataByFile = {};
  mockState.rawAnalysisByKey = {};
  mockState.rawSelectedNetworkByFile = {};
  mockState.allPositions = {};
}

function resetMocks() {
  [
    mockAPI.listRawSnifferFiles,
    mockAPI.getRawSnifferHashes,
    mockAPI.getRawSnifferMetadata,
    mockAPI.getRawSnifferAnalysis,
    mockAPI.analyzeRawSniffer,
    mockAPI.extractRawSniffer,
    mockAPI.deleteRawSnifferFile,
    mockLog,
    mockAddProcess,
    mockUpdateProcess,
    mockOpenCrackingPanel,
  ].forEach((fn) => fn.mockReset());

  mockAPI.listRawSnifferFiles.mockResolvedValue([]);
  mockAPI.getRawSnifferHashes.mockResolvedValue([]);
  mockAPI.getRawSnifferMetadata.mockResolvedValue({});
  mockAPI.getRawSnifferAnalysis.mockResolvedValue({});
  mockAPI.analyzeRawSniffer.mockResolvedValue({ status: "success", data: {} });
  mockAPI.extractRawSniffer.mockResolvedValue({ status: "ok" });
  mockAPI.deleteRawSnifferFile.mockResolvedValue({ deleted: [] });
}

beforeEach(() => {
  mountRawDom();
  resetState();
  resetMocks();
});

test("getRawUiState seeds defaults", () => {
  const state = getRawUiState();
  expect(state.fileSearch).toBe("");
  expect(state.fileStatus).toBe("all");
  state.fileSearch = "raw";
  expect(getRawUiState().fileSearch).toBe("raw");
});

test("renderRawFilesList handles filters and empty state", () => {
  mockState.rawUi = {
    fileSearch: "",
    fileStatus: "all",
    fileSort: "size_desc",
    networkSearch: "",
    networkSort: "beacon_desc",
  };
  mockState.rawFiles = [
    { filename: "cap_small.pcap", size: 100, modified: 10, networks_count: 1, cached_up_to_date: false },
    { filename: "cap_big.pcap", size: 300, modified: 20, networks_count: 2, cached_up_to_date: true },
    { filename: "cap_mid.pcap", size: 200, modified: 30, networks_count: 3, cached_up_to_date: false },
  ];

  renderRawFilesList();

  const items = Array.from(document.querySelectorAll("#raw-files-list .list-item"));
  expect(items).toHaveLength(3);
  expect(items[0].getAttribute("data-filename")).toBe("cap_big.pcap");
  expect(document.getElementById("raw-files-count-info").textContent).toBe("3/3");

  mockState.rawUi.fileStatus = "cached";
  renderRawFilesList();
  const cachedItems = Array.from(document.querySelectorAll("#raw-files-list .list-item"));
  expect(cachedItems).toHaveLength(1);
  expect(cachedItems[0].getAttribute("data-filename")).toBe("cap_big.pcap");

  mockState.rawUi.fileStatus = "pending";
  mockState.rawUi.fileSort = "modified_asc";
  renderRawFilesList();
  const pendingItems = Array.from(document.querySelectorAll("#raw-files-list .list-item"));
  expect(pendingItems).toHaveLength(2);
  expect(pendingItems[0].getAttribute("data-filename")).toBe("cap_small.pcap");

  mockState.rawUi.fileStatus = "all";
  mockState.rawUi.fileSort = "name_asc";
  renderRawFilesList();
  const nameItems = Array.from(document.querySelectorAll("#raw-files-list .list-item"));
  expect(nameItems[0].getAttribute("data-filename")).toBe("cap_big.pcap");

  mockState.rawUi.fileSort = "size_asc";
  renderRawFilesList();
  const sizeAscItems = Array.from(document.querySelectorAll("#raw-files-list .list-item"));
  expect(sizeAscItems[0].getAttribute("data-filename")).toBe("cap_small.pcap");

  mockState.rawUi.fileSort = "networks_desc";
  renderRawFilesList();
  const networksItems = Array.from(document.querySelectorAll("#raw-files-list .list-item"));
  expect(networksItems[0].getAttribute("data-filename")).toBe("cap_mid.pcap");

  mockState.rawUi.fileSort = "modified_desc";
  renderRawFilesList();
  const modifiedItems = Array.from(document.querySelectorAll("#raw-files-list .list-item"));
  expect(modifiedItems[0].getAttribute("data-filename")).toBe("cap_mid.pcap");

  mockState.rawUi.fileSearch = "mid";
  renderRawFilesList();
  expect(document.getElementById("raw-files-count-info").textContent).toBe("1/3");

  mockState.rawFiles = [];
  renderRawFilesList();
  expect(document.getElementById("raw-files-list").innerHTML).toContain("NO RAW FILES");
});

test("renderRawFilesList formats zero-size entries and missing timestamps", () => {
  mockState.rawUi = {
    fileSearch: "",
    fileStatus: "all",
    fileSort: "modified_desc",
    networkSearch: "",
    networkSort: "beacon_desc",
  };
  mockState.rawFiles = [
    { filename: "zero.pcap", size: 0, modified: 0, networks_count: 0, cached_up_to_date: false },
  ];

  renderRawFilesList();

  const html = document.getElementById("raw-files-list").innerHTML;
  expect(html).toContain("0 B");
  expect(html).toContain("N/A");
});

test("renderRawFilesList sorts by size desc and formats KB values", () => {
  mockState.rawUi = {
    fileSearch: "",
    fileStatus: "all",
    fileSort: "size_desc",
    networkSearch: "",
    networkSort: "beacon_desc",
  };
  mockState.rawFiles = [
    { filename: "small.pcap", size: 12, modified: 2, networks_count: 1, cached_up_to_date: true },
    { filename: "big.pcap", size: 2048, modified: 1, networks_count: 1, cached_up_to_date: true },
  ];

  renderRawFilesList();

  const items = Array.from(document.querySelectorAll("#raw-files-list .list-item .item-name"));
  expect(items[0].textContent).toContain("big.pcap");
  expect(document.getElementById("raw-files-list").innerHTML).toContain("2.0 KB");
});

test("raw reprocess buttons handle info, success and error paths", async () => {
  const { setupRawListeners } = require("../../src/modules/ui_raw.js");
  setupRawListeners();

  mockState.rawSelectedFile = "raw_1.pcap";
  mockAPI.extractRawSniffer
    .mockResolvedValueOnce({ status: "noop", message: "No raw files to process" })
    .mockRejectedValueOnce(new Error("boom"))
    .mockResolvedValueOnce({ status: "started", job_id: "raw-job", total_files: 2 })
    .mockRejectedValueOnce(new Error("pending-fail"));

  document.getElementById("btn-raw-reprocess-selected").click();
  await Promise.resolve();
  expect(mockLog).toHaveBeenCalledWith("No raw files to process", "info");

  document.getElementById("btn-raw-reprocess-selected").click();
  await Promise.resolve();
  expect(mockLog).toHaveBeenCalledWith("Failed to start raw extraction: boom", "error");

  document.getElementById("btn-raw-reprocess-pending").click();
  await Promise.resolve();
  expect(mockAddProcess).toHaveBeenCalledWith("raw-job", "RAW SNIFFER", "Pending (2 files)", "STARTING");

  document.getElementById("btn-raw-reprocess-pending").click();
  await Promise.resolve();
  expect(mockLog).toHaveBeenCalledWith("Failed to start raw extraction: pending-fail", "error");
});

test("renderRawHashesList selects first valid hash and handles empty", () => {
  mockState.rawHashes = [
    { filename: "raw_0.22000", has_context: false, valid_hash_lines: 0, modified: 1 },
    { filename: "raw_1.22000", has_context: true, valid_hash_lines: 4, modified: 2, primary_bssid: "AA:BB:CC:DD:EE:FF", source_raw_file: "raw_1.pcap" },
  ];
  mockState.rawSelectedHash = "missing.22000";

  renderRawHashesList();

  expect(mockState.rawSelectedHash).toBe("raw_1.22000");
  const selected = document.querySelector("#raw-hashes-list .list-item.selected");
  expect(selected).toBeTruthy();
  expect(selected.getAttribute("data-filename")).toBe("raw_1.22000");

  mockState.rawHashes = [];
  renderRawHashesList();
  expect(document.getElementById("raw-hashes-list").innerHTML).toContain("NO RAW HASHES");
});

test("renderRawHashesList keeps selection null when no usable context exists", () => {
  mockState.rawHashes = [
    { filename: "raw_empty.22000", has_context: false, valid_hash_lines: 0, modified: 0 },
    { filename: "raw_bad.22000", has_context: true, valid_hash_lines: 0, modified: 0 },
  ];
  mockState.rawSelectedHash = null;

  renderRawHashesList();
  expect(mockState.rawSelectedHash).toBeNull();
});

test("renderRawMetadata renders networks and warnings", () => {
  const filename = "raw_1.pcap";
  mockState.rawSelectedNetworkByFile[filename] = "FF:EE:DD:CC:BB:AA";
  mockState.allPositions["AA:BB:CC:DD:EE:FF"] = {
    ssid: "MAP_SSID",
    sources: ["raw"],
  };

  renderRawMetadata(filename, {
    source_file: filename,
    processed_at: "now",
    stats: {
      networks_count: 2,
      beacon_frames: 10,
      probe_requests: 1,
      eapol_frames: 2,
    },
    warnings: ["warn-1"],
    networks: [
      {
        bssid: "AA:BB:CC:DD:EE:FF",
        ssid: "TestNet",
        channel: 6,
        frequency_mhz: 2437,
        beacon_count: 5,
        eapol_count: 1,
        probe_client_count: 2,
        last_seen_offset_s: 3,
      },
      {
        bssid: "11:22:33:44:55:66",
        ssid: null,
        channel: 1,
        frequency_mhz: 2412,
        beacon_count: 2,
        eapol_count: 0,
        probe_client_count: 0,
      },
    ],
  });

  expect(document.getElementById("raw-net-count-info").textContent).toBe("2/2");
  expect(document.querySelectorAll(".raw-network-row")).toHaveLength(2);
  expect(document.getElementById("raw-details-view").innerHTML).toContain("WARNINGS");
  expect(document.getElementById("raw-details-view").innerHTML).toContain("Map SSID / Src");
  expect(mockState.rawSelectedNetworkByFile[filename]).toBe("AA:BB:CC:DD:EE:FF");
});

test("renderRawMetadata filters and sorts networks", () => {
  const filename = "raw_sort.pcap";
  mockState.rawUi = {
    fileSearch: "",
    fileStatus: "all",
    fileSort: "modified_desc",
    networkSearch: "alpha",
    networkSort: "ssid_asc",
  };
  const metadata = {
    source_file: filename,
    processed_at: "now",
    stats: {},
    warnings: [],
    networks: [
      {
        bssid: "AA:AA:AA:AA:AA:AA",
        ssid: "Alpha",
        channel: 1,
        beacon_count: 5,
        eapol_count: 10,
        probe_client_count: 1,
      },
      {
        bssid: "BB:BB:BB:BB:BB:BB",
        ssid: "Beta",
        channel: 6,
        beacon_count: 8,
        eapol_count: 2,
        probe_client_count: 5,
      },
    ],
  };

  renderRawMetadata(filename, metadata);
  expect(document.getElementById("raw-net-count-info").textContent).toBe("1/2");

  mockState.rawUi.networkSearch = "";
  mockState.rawUi.networkSort = "eapol_desc";
  renderRawMetadata(filename, metadata);
  expect(document.querySelector(".raw-network-row").getAttribute("data-bssid")).toBe("AA:AA:AA:AA:AA:AA");

  mockState.rawUi.networkSort = "probe_desc";
  renderRawMetadata(filename, metadata);
  expect(document.querySelector(".raw-network-row").getAttribute("data-bssid")).toBe("BB:BB:BB:BB:BB:BB");

  mockState.rawUi.networkSort = "bssid_asc";
  renderRawMetadata(filename, metadata);
  expect(document.querySelector(".raw-network-row").getAttribute("data-bssid")).toBe("AA:AA:AA:AA:AA:AA");

  mockState.rawUi.networkSort = "ssid_asc";
  renderRawMetadata(filename, metadata);
  expect(document.querySelector(".raw-network-row").getAttribute("data-bssid")).toBe("AA:AA:AA:AA:AA:AA");
});

test("renderRawMetadata shows empty message when filters remove all networks", () => {
  const filename = "raw_filter_empty.pcap";
  mockState.rawUi = {
    fileSearch: "",
    fileStatus: "all",
    fileSort: "modified_desc",
    networkSearch: "zz",
    networkSort: "beacon_desc",
  };

  renderRawMetadata(filename, {
    source_file: filename,
    processed_at: "now",
    networks: [
      {
        bssid: "AA:AA:AA:AA:AA:AA",
        ssid: "Test",
        channel: 6,
        beacon_count: 1,
        eapol_count: 0,
        probe_client_count: 0,
      },
    ],
  });

  const html = document.getElementById("raw-details-view").innerHTML;
  expect(html).toContain("NO NETWORKS FOR CURRENT FILTERS");
});

test("renderRawMetadata handles null metadata", () => {
  renderRawMetadata("raw_2.pcap", null);
  expect(document.getElementById("raw-net-count-info").textContent).toBe("0/0");
  expect(document.getElementById("raw-details-view").innerHTML).toContain("No metadata cached");
});

test("renderRawMetadata handles empty networks and missing map entry", () => {
  renderRawMetadata("raw_empty.pcap", {
    source_file: "raw_empty.pcap",
    processed_at: "now",
    stats: { networks_count: 0 },
    warnings: [],
    networks: [],
  });

  const html = document.getElementById("raw-details-view").innerHTML;
  expect(html).toContain("NO NETWORKS FOR CURRENT FILTERS");
  expect(html).toContain("WARNINGS:</b> none");
});

test("renderRawMetadata shows RAW analysis when cached for the selected file", () => {
  mockState.rawFiles = [
    {
      filename: "raw_1.pcap",
      raw_item_id: "raw::pcap::abc123",
      analysis_present: true,
      device_label: "Bruce",
    },
  ];
  mockState.rawSelectedFile = "raw_1.pcap";
  mockState.rawSelectedRawItemId = "raw::pcap::abc123";
  mockState.rawAnalysisByKey["raw::pcap::abc123"] = {
    capture: {
      duration_s: 12.5,
      networks_count: 2,
      clients_count: 1,
      frame_totals: { beacons: 10, eapol: 2, probe_requests: 1 },
      warnings: [],
    },
    highlights: {
      handshake_candidate_count: 1,
      handshake_candidates: [
        { bssid: "AA:BB:CC:DD:EE:FF", ssid: "Test", eapol_count: 2, tier: "medium" },
      ],
      top_networks: [
        { bssid: "AA:BB:CC:DD:EE:FF", ssid: "Test", beacon_count: 10, client_count: 1 },
      ],
      top_clients: [
        { mac: "11:22:33:44:55:66", total_frames: 2, network_count: 1, eapol_count: 2 },
      ],
      hidden_network_count: 0,
      revealed_hidden_count: 0,
      noisy_capture: false,
    },
  };

  renderRawMetadata("raw_1.pcap", {
    source_file: "raw_1.pcap",
    processed_at: "now",
    stats: { networks_count: 1, beacon_frames: 10, probe_requests: 1, eapol_frames: 2 },
    warnings: [],
    networks: [],
  });

  const html = document.getElementById("raw-details-view").innerHTML;
  expect(html).toContain("RAW ANALYSIS");
  expect(html).toContain("Handshake Candidates");
  expect(html).toContain("Top Clients");
});

test("refreshRawFiles populates state and handles failures", async () => {
  mockAPI.listRawSnifferFiles.mockResolvedValue([
    { filename: "raw_1.pcap", size: 10, modified: 1, networks_count: 1, cached_up_to_date: true },
  ]);
  mockAPI.getRawSnifferHashes.mockResolvedValue([
    { filename: "raw_1.22000", has_context: true, valid_hash_lines: 2, modified: 2, primary_bssid: "AA:BB:CC:DD:EE:FF" },
  ]);
  mockAPI.getRawSnifferMetadata.mockResolvedValue({
    status: "success",
    data: { source_file: "raw_1.pcap", networks: [] },
  });

  mockState.rawSelectedFile = "missing.pcap";
  await refreshRawFiles();

  expect(mockState.rawFiles).toHaveLength(1);
  expect(mockState.rawHashes).toHaveLength(1);
  expect(mockState.rawSelectedFile).toBe("raw_1.pcap");
  expect(mockState.rawMetadataByFile["raw_1.pcap"]).toBeTruthy();

  const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
  mockAPI.getRawSnifferHashes.mockRejectedValueOnce(new Error("hash fail"));
  await refreshRawFiles();
  expect(mockState.rawHashes).toEqual([]);
  warnSpy.mockRestore();

  const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  mockAPI.listRawSnifferFiles.mockRejectedValueOnce(new Error("files fail"));
  await refreshRawFiles();
  errSpy.mockRestore();

  mockAPI.listRawSnifferFiles.mockResolvedValueOnce([]);
  mockAPI.getRawSnifferHashes.mockResolvedValueOnce([]);
  await refreshRawFiles();
  expect(mockState.rawSelectedFile).toBeNull();
  expect(document.getElementById("raw-details-view").innerHTML).toContain("No metadata cached");
});

test("loadRawMetadata handles API failures", async () => {
  mockAPI.getRawSnifferMetadata.mockRejectedValueOnce(new Error("fail"));
  await loadRawMetadata("raw_fail.pcap", false);
  expect(mockState.rawMetadataByFile["raw_fail.pcap"]).toBeNull();
});

test("setupRawListeners wires actions", async () => {
  setupRawListeners();

  const warnSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  const confirmSpy = jest.spyOn(window, "confirm").mockReturnValue(true);

  const fileSearch = document.getElementById("raw-file-search");
  fileSearch.value = "cap";
  fileSearch.dispatchEvent(new Event("input", { bubbles: true }));
  expect(mockState.rawUi.fileSearch).toBe("cap");

  const fileStatus = document.getElementById("raw-file-status");
  fileStatus.value = "cached";
  fileStatus.dispatchEvent(new Event("change", { bubbles: true }));
  expect(mockState.rawUi.fileStatus).toBe("cached");

  const fileSort = document.getElementById("raw-file-sort");
  fileSort.value = "name_asc";
  fileSort.dispatchEvent(new Event("change", { bubbles: true }));
  expect(mockState.rawUi.fileSort).toBe("name_asc");

  document.getElementById("btn-raw-reprocess-selected").click();
  expect(mockLog).toHaveBeenCalledWith("Select a RAW file first.", "warn");

  document.getElementById("btn-raw-delete-selected").click();
  expect(mockLog).toHaveBeenCalledWith("Select a RAW file first.", "warn");

  document.getElementById("btn-raw-analyze-selected").click();
  expect(mockLog).toHaveBeenCalledWith("Select a RAW file first.", "warn");

  mockState.rawSelectedFile = "raw_1.pcap";
  mockState.rawSelectedRawItemId = "raw::pcap::abc123";
  mockAPI.extractRawSniffer.mockResolvedValueOnce({ status: "started", job_id: "job-1" });
  document.getElementById("btn-raw-reprocess-selected").click();
  await Promise.resolve();
  expect(mockAddProcess).toHaveBeenCalledWith("job-1", "RAW SNIFFER", "raw_1.pcap", "STARTING");

  mockState.rawFiles = [
    {
      filename: "raw_1.pcap",
      raw_item_id: "raw::pcap::abc123",
      analysis_present: false,
      device_label: "Bruce",
    },
  ];
  mockState.rawMetadataByFile["raw_1.pcap"] = { source_file: "raw_1.pcap", networks: [] };
  mockAPI.analyzeRawSniffer.mockResolvedValueOnce({
    status: "success",
    data: {
      capture: {
        duration_s: 9,
        networks_count: 1,
        clients_count: 0,
        frame_totals: { beacons: 2, eapol: 0, probe_requests: 0 },
        warnings: [],
      },
      highlights: {
        handshake_candidate_count: 0,
        handshake_candidates: [],
        top_networks: [],
        top_clients: [],
        hidden_network_count: 0,
        revealed_hidden_count: 0,
        noisy_capture: false,
      },
    },
  });
  document.getElementById("btn-raw-analyze-selected").click();
  await Promise.resolve();
  await Promise.resolve();
  expect(mockAPI.analyzeRawSniffer).toHaveBeenCalledWith("raw::pcap::abc123", false);
  expect(mockAddProcess).toHaveBeenCalledWith(
    expect.stringMatching(/^raw-analysis-/),
    "RAW ANALYSIS",
    "raw_1.pcap",
    "STARTING"
  );
  expect(mockUpdateProcess).toHaveBeenCalledWith(
    expect.stringMatching(/^raw-analysis-/),
    15,
    "RUNNING",
    "Building capture-wide report",
    true
  );
  expect(mockUpdateProcess).toHaveBeenCalledWith(
    expect.stringMatching(/^raw-analysis-/),
    100,
    "COMPLETED",
    "RAW analysis ready",
    false
  );

  mockState.rawMetadataByFile["raw_1.pcap"] = { source_file: "raw_1.pcap" };
  mockState.rawSelectedNetworkByFile["raw_1.pcap"] = "AA:BB:CC:DD:EE:FF";
  mockState.rawSelectedHash = "raw_1.22000";
  confirmSpy.mockReturnValueOnce(false);
  document.getElementById("btn-raw-delete-selected").click();
  await Promise.resolve();
  expect(mockAPI.deleteRawSnifferFile).not.toHaveBeenCalled();

  mockAPI.deleteRawSnifferFile.mockResolvedValueOnce({
    deleted: ["raw_1.pcap", "raw_1.pcap.json", "raw_1.22000"],
  });
  mockAPI.listRawSnifferFiles.mockResolvedValueOnce([]);
  mockAPI.getRawSnifferHashes.mockResolvedValueOnce([]);
  confirmSpy.mockReturnValueOnce(true);
  document.getElementById("btn-raw-delete-selected").click();
  await Promise.resolve();
  await Promise.resolve();
  expect(mockAPI.deleteRawSnifferFile).toHaveBeenCalledWith("raw_1.pcap");
  expect(mockState.rawSelectedFile).toBeNull();
  expect(mockState.rawSelectedHash).toBeNull();
  expect(mockState.rawMetadataByFile["raw_1.pcap"]).toBeUndefined();
  expect(mockState.rawSelectedNetworkByFile["raw_1.pcap"]).toBeUndefined();

  mockAPI.extractRawSniffer.mockResolvedValueOnce({ status: "noop", message: "No raw files" });
  document.getElementById("btn-raw-reprocess-pending").click();
  await Promise.resolve();
  expect(mockLog).toHaveBeenCalledWith("No raw files", "info");

  mockState.rawFiles = [
    { filename: "raw_1.pcap", raw_item_id: "raw::pcap::abc123", size: 10, modified: 1, networks_count: 1, cached_up_to_date: true },
  ];
  renderRawFilesList();
  mockAPI.getRawSnifferMetadata.mockResolvedValueOnce({
    status: "success",
    data: { source_file: "raw_1.pcap", networks: [] },
  });
  document.querySelector("#raw-files-list .list-item").click();
  await Promise.resolve();
  expect(mockState.rawSelectedFile).toBe("raw_1.pcap");

  mockState.rawHashes = [
    { filename: "raw_no_context.22000", has_context: false, valid_hash_lines: 2, modified: 1 },
    { filename: "raw_invalid_bssid.22000", has_context: true, valid_hash_lines: 2, modified: 2, primary_bssid: "ZZ" },
    { filename: "raw_ok.22000", has_context: true, valid_hash_lines: 2, modified: 3, primary_bssid: "AA:BB:CC:DD:EE:FF" },
  ];
  renderRawHashesList();
  const hashItems = Array.from(document.querySelectorAll("#raw-hashes-list .list-item"));
  hashItems[0].click();
  hashItems[1].click();
  hashItems[2].click();
  await Promise.resolve();
  expect(mockOpenCrackingPanel).toHaveBeenCalledWith(
    "AA:BB:CC:DD:EE:FF",
    "RAW HASH raw_ok.22000",
    "raw_ok.22000",
    { scope: "raw_hash" }
  );

  renderRawMetadata("raw_1.pcap", {
    source_file: "raw_1.pcap",
    processed_at: "now",
    networks: [
      { bssid: "AA:BB:CC:DD:EE:FF", ssid: "Test", channel: 6, beacon_count: 1, eapol_count: 0, probe_client_count: 0 },
    ],
  });
  mockState.rawMetadataByFile["raw_1.pcap"] = {
    source_file: "raw_1.pcap",
    networks: [
      { bssid: "AA:BB:CC:DD:EE:FF", ssid: "Test", channel: 6, beacon_count: 1, eapol_count: 0, probe_client_count: 0 },
    ],
  };
  const networkSearch = document.getElementById("raw-network-search");
  networkSearch.value = "aa:bb";
  networkSearch.dispatchEvent(new Event("input", { bubbles: true }));
  expect(mockState.rawUi.networkSearch).toBe("aa:bb");

  const networkSort = document.getElementById("raw-network-sort");
  networkSort.value = "ssid_asc";
  networkSort.dispatchEvent(new Event("change", { bubbles: true }));
  expect(mockState.rawUi.networkSort).toBe("ssid_asc");

  document.querySelector(".raw-network-row").dispatchEvent(new Event("click", { bubbles: true }));
  expect(mockState.rawSelectedNetworkByFile["raw_1.pcap"]).toBe("AA:BB:CC:DD:EE:FF");

  confirmSpy.mockRestore();
  warnSpy.mockRestore();
});

test("setupRawListeners tolerates missing optional controls", () => {
  document.getElementById("raw-file-search").remove();
  document.getElementById("raw-file-status").remove();
  document.getElementById("raw-file-sort").remove();
  document.getElementById("raw-network-search").remove();
  document.getElementById("raw-network-sort").remove();
  document.getElementById("btn-raw-analyze-selected").remove();
  document.getElementById("btn-raw-delete-selected").remove();
  document.getElementById("btn-raw-reprocess-selected").remove();
  document.getElementById("btn-raw-reprocess-pending").remove();
  document.getElementById("raw-files-list").remove();
  document.getElementById("raw-hashes-list").remove();
  document.getElementById("raw-details-view").remove();

  expect(() => setupRawListeners()).not.toThrow();
});
