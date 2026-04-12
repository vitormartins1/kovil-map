const mockAPI = {
  cancelJob: jest.fn(),
  listJobs: jest.fn(),
  listMultiFiles: jest.fn(),
};

const mockLog = jest.fn();
const mockUpdateTargetsList = jest.fn();
const mockUpdateNoGpsList = jest.fn();
const mockUpdateMarkerStatusByMac = jest.fn();
const mockOpenCrackingPanel = jest.fn();
const mockUpdateCrackingPanelStatus = jest.fn();
const mockOpenBatchFromProcess = jest.fn();
const mockTogglePowerSave = jest.fn();

const mockSelectedFile = { name: null };

const mockState = {
  modes: { process: false },
  allPositions: {},
  crackingByMac: {},
  activeCrackingStatus: {},
  isCrackingActive: false,
};

const mockSaveModes = jest.fn();

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
  escapeHtml: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
  saveModes: (...args) => mockSaveModes(...args),
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => ({
  updateTargetsList: (...args) => mockUpdateTargetsList(...args),
  updateNoGpsList: (...args) => mockUpdateNoGpsList(...args),
}));

jest.mock("../../src/modules/map.js", () => ({
  updateMarkerStatusByMac: (...args) => mockUpdateMarkerStatusByMac(...args),
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: (...args) => mockOpenCrackingPanel(...args),
  updateCrackingPanelStatus: (...args) => mockUpdateCrackingPanelStatus(...args),
  selectedFile: mockSelectedFile,
}));

jest.mock("../../src/modules/ui.js", () => ({
  openBatchFromProcess: (...args) => mockOpenBatchFromProcess(...args),
}));

jest.mock("../../src/modules/platform.js", () => ({
  Platform: {
    togglePowerSave: (...args) => mockTogglePowerSave(...args),
  },
}));

function mountProcessDom() {
  document.body.innerHTML = `
    <button id="btn-process"></button>
    <div id="process-panel" style="display:none">
      <button id="btn-process-clear"></button>
      <button class="close-panel"></button>
    </div>
    <div id="process-list"></div>
    <div id="crack-mac"></div>
    <div id="crack-ssid"></div>
  `;

  const processList = document.getElementById("process-list");
  if (typeof processList.innerText === "undefined") {
    Object.defineProperty(processList, "innerText", {
      configurable: true,
      get() {
        return this.textContent || "";
      },
      set(value) {
        this.textContent = value;
      },
    });
  }
}

function resetState() {
  mockState.modes.process = false;
  mockState.allPositions = {};
  mockState.crackingByMac = {};
  mockState.activeCrackingStatus = {};
  mockState.isCrackingActive = false;
  mockSelectedFile.name = null;
}

function resetMocks() {
  [
    mockAPI.cancelJob,
    mockAPI.listJobs,
    mockAPI.listMultiFiles,
    mockLog,
    mockUpdateTargetsList,
    mockUpdateNoGpsList,
    mockUpdateMarkerStatusByMac,
    mockOpenCrackingPanel,
    mockUpdateCrackingPanelStatus,
    mockOpenBatchFromProcess,
    mockTogglePowerSave,
    mockSaveModes,
  ].forEach((fn) => fn.mockReset());

  mockAPI.cancelJob.mockResolvedValue({ status: "ok" });
  mockAPI.listJobs.mockResolvedValue([]);
  mockAPI.listMultiFiles.mockResolvedValue([]);
}

function loadModule() {
  jest.resetModules();
  return require("../../src/modules/ui_components/ui_processes.js");
}

describe("ui_processes", () => {
  beforeEach(() => {
    jest.useFakeTimers();
    mountProcessDom();
    resetState();
    resetMocks();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  test("addProcess inserts process, toggles power-save and opens panel when hidden", () => {
    const uiProcesses = loadModule();
    const clickSpy = jest.spyOn(document.getElementById("btn-process"), "click");

    uiProcesses.addProcess("job-1", "HASHCAT [MASK]", "capture.22000", "STARTING", "AA:BB:CC:DD:EE:FF");

    expect(uiProcesses.activeProcesses["job-1"]).toEqual(
      expect.objectContaining({
        type: "HASHCAT [MASK]",
        details: "capture.22000",
        status: "STARTING",
        mac: "AA:BB:CC:DD:EE:FF",
      })
    );
    expect(mockUpdateTargetsList).toHaveBeenCalled();
    expect(mockTogglePowerSave).toHaveBeenCalledWith(true);
    expect(clickSpy).toHaveBeenCalled();
  });

  test("addProcess normalizes non-string details safely", () => {
    const uiProcesses = loadModule();
    uiProcesses.addProcess(
      "job-obj",
      "RAW SNIFFER",
      { source_file: "raw_1.pcap", meta: { bssid: "AA:BB:CC:DD:EE:FF" } },
      "STARTING"
    );

    expect(typeof uiProcesses.activeProcesses["job-obj"].details).toBe("string");
    expect(uiProcesses.activeProcesses["job-obj"].details).toContain("raw_1.pcap");
  });

  test("updateProcess updates progress and syncs cracking panel for selected file", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-2", "HASHCAT [RULES]", "selected.22000", "STARTING", "AA:BB:CC:DD:EE:01");
    mockSelectedFile.name = "selected.22000";

    uiProcesses.updateProcess("job-2", 42, "RUNNING", "100kH/s", false);

    expect(uiProcesses.activeProcesses["job-2"].percentage).toBe(42);
    expect(uiProcesses.activeProcesses["job-2"].status).toBe("RUNNING");
    expect(uiProcesses.activeProcesses["job-2"].extraInfo).toBe("100kH/s");
    expect(mockUpdateCrackingPanelStatus).toHaveBeenCalledWith(
      expect.objectContaining({ status: "RUNNING", percentage: 42 })
    );
  });

  test("updateProcess normalizes extra info and removes empty pipe segments", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-clean", "SYNC", "Bruce handshakes", "RUNNING");
    uiProcesses.updateProcess(
      "job-clean",
      60,
      "RUNNING",
      " | ETA: 1m |  | HS_A.pcap [1.0 KB / 2.0 KB]",
      false
    );

    expect(uiProcesses.activeProcesses["job-clean"].extraInfo).toBe(
      "ETA: 1m | HS_A.pcap [1.0 KB / 2.0 KB]"
    );
  });

  test("updateProcess ignores stale running updates after a process is finalized", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-final", "SYNC", "M5Evil handshakes", "RUNNING");
    uiProcesses.updateProcess("job-final", 100, "COMPLETED", "Imported 1/1 handshake file(s)", false);
    uiProcesses.updateProcess("job-final", 95, "RUNNING", "1/1 imported | HS_TEST.pcap", false);

    expect(uiProcesses.activeProcesses["job-final"].percentage).toBe(100);
    expect(uiProcesses.activeProcesses["job-final"].status).toBe("COMPLETED");
    expect(uiProcesses.activeProcesses["job-final"].extraInfo).toBe("Imported 1/1 handshake file(s)");
  });

  test("renderProcessList renders running and finished actions", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-3", "HASHCAT", "run.22000", "RUNNING");
    jest.advanceTimersByTime(1200);

    let row = document.querySelector('.process-item[data-job-id="job-3"]');
    expect(row).not.toBeNull();
    expect(row.querySelector(".process-cancel")).not.toBeNull();

    uiProcesses.updateProcess("job-3", 100, "FAILED", "", false);
    jest.advanceTimersByTime(1200);

    row = document.querySelector('.process-item[data-job-id="job-3"]');
    expect(row.querySelector(".process-remove")).not.toBeNull();
    expect(row.querySelector(".process-cancel")).toBeNull();
  });

  test("renderProcessList treats UP TO DATE as finished success", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-up", "RAW SNIFFER PREPARE ALL", "AA:BB:CC:DD:EE:FF (3 files)", "RUNNING");
    uiProcesses.updateProcess("job-up", 100, "UP TO DATE", "already synchronized", false);
    uiProcesses.renderProcessList();

    const row = document.querySelector('.process-item[data-job-id="job-up"]');
    expect(row).not.toBeNull();
    expect(row.querySelector(".process-remove")).not.toBeNull();
    expect(row.querySelector(".process-cancel")).toBeNull();
    expect(row.querySelector(".process-status").textContent).toBe("UP TO DATE");
  });

  test("renderProcessList clears empty placeholder and honors noCancel", () => {
    const uiProcesses = loadModule();
    const list = document.getElementById("process-list");

    uiProcesses.renderProcessList();
    expect(list.textContent).toContain("NO ACTIVE PROCESSES");

    uiProcesses.activeProcesses["job-nc"] = {
      type: "HASHCAT",
      details: "queued.22000",
      percentage: 0,
      status: "QUEUED",
      extraInfo: "",
      indeterminate: false,
      noCancel: true,
      mac: null,
    };

    uiProcesses.renderProcessList();

    const row = document.querySelector('.process-item[data-job-id="job-nc"]');
    expect(row).not.toBeNull();
    expect(row.querySelector(".process-cancel")).toBeNull();
    expect(row.querySelector(".process-remove")).toBeNull();
  });

  test("renderProcessList adds cancel when noCancel flips and renders finished on create", () => {
    const uiProcesses = loadModule();

    uiProcesses.activeProcesses["job-toggle"] = {
      type: "HASHCAT",
      details: "queued.22000",
      percentage: 0,
      status: "QUEUED",
      extraInfo: "",
      indeterminate: false,
      noCancel: true,
      mac: null,
    };
    uiProcesses.renderProcessList();

    let row = document.querySelector('.process-item[data-job-id="job-toggle"]');
    expect(row.querySelector(".process-cancel")).toBeNull();

    uiProcesses.activeProcesses["job-toggle"].noCancel = false;
    uiProcesses.renderProcessList();

    row = document.querySelector('.process-item[data-job-id="job-toggle"]');
    expect(row.querySelector(".process-cancel")).not.toBeNull();

    uiProcesses.activeProcesses["job-finished"] = {
      type: "HASHCAT",
      details: "done.22000",
      percentage: 100,
      status: "FAILED",
      extraInfo: "",
      indeterminate: false,
      mac: null,
    };
    uiProcesses.renderProcessList();

    const finishedRow = document.querySelector('.process-item[data-job-id="job-finished"]');
    expect(finishedRow.querySelector(".process-remove")).not.toBeNull();
    expect(finishedRow.querySelector(".process-cancel")).toBeNull();
  });

  test("renderProcessList removes cancel button when noCancel is set after creation", () => {
    const uiProcesses = loadModule();
    uiProcesses.activeProcesses["job-nocancel"] = {
      type: "PROCESS",
      details: "file.txt",
      percentage: 10,
      status: "RUNNING",
      extraInfo: "",
      indeterminate: false,
      noCancel: false,
    };

    uiProcesses.renderProcessList();
    expect(document.querySelector('.process-item[data-job-id="job-nocancel"] .process-cancel')).toBeTruthy();

    uiProcesses.activeProcesses["job-nocancel"].noCancel = true;
    uiProcesses.renderProcessList();
    expect(document.querySelector('.process-item[data-job-id="job-nocancel"] .process-cancel')).toBeFalsy();
  });

  test("clearFinishedProcesses removes only final-status jobs", () => {
    const uiProcesses = loadModule();

    uiProcesses.activeProcesses["job-run"] = {
      type: "HASHCAT",
      details: "running.22000",
      percentage: 40,
      status: "RUNNING",
      extraInfo: "",
      indeterminate: false,
      mac: null,
    };
    uiProcesses.activeProcesses["job-ok"] = {
      type: "HASHCAT",
      details: "done.22000",
      percentage: 100,
      status: "COMPLETED",
      extraInfo: "",
      indeterminate: false,
      mac: null,
    };
    uiProcesses.activeProcesses["job-fail"] = {
      type: "HASHCAT",
      details: "failed.22000",
      percentage: 100,
      status: "FAILED",
      extraInfo: "",
      indeterminate: false,
      mac: null,
    };

    const removed = uiProcesses.clearFinishedProcesses();
    expect(removed).toBe(2);
    expect(uiProcesses.activeProcesses["job-run"]).toBeTruthy();
    expect(uiProcesses.activeProcesses["job-ok"]).toBeUndefined();
    expect(uiProcesses.activeProcesses["job-fail"]).toBeUndefined();
  });

  test("setupProcessListeners binds clear button to clearFinishedProcesses", () => {
    const uiProcesses = loadModule();
    uiProcesses.setupProcessListeners();

    uiProcesses.activeProcesses["job-running"] = {
      type: "PROCESS",
      details: "a",
      percentage: 0,
      status: "RUNNING",
      extraInfo: "",
      indeterminate: false,
      mac: null,
    };
    uiProcesses.activeProcesses["job-completed"] = {
      type: "PROCESS",
      details: "b",
      percentage: 100,
      status: "SUCCESS",
      extraInfo: "",
      indeterminate: false,
      mac: null,
    };

    document.getElementById("btn-process-clear").click();
    expect(uiProcesses.activeProcesses["job-running"]).toBeTruthy();
    expect(uiProcesses.activeProcesses["job-completed"]).toBeUndefined();
  });

  test("renderProcessList updates existing rows for indeterminate and finished states", () => {
    const uiProcesses = loadModule();

    uiProcesses.activeProcesses["job-update"] = {
      type: "HASHCAT",
      details: "run.22000",
      percentage: 10,
      status: "RUNNING",
      extraInfo: "100kH/s",
      indeterminate: false,
      noCancel: false,
      mac: null,
    };
    uiProcesses.renderProcessList();

    let row = document.querySelector('.process-item[data-job-id="job-update"]');
    const bar = row.querySelector(".progress-bar");
    const text = row.querySelector(".progress-text");
    expect(text.textContent).toContain("100kH/s");
    expect(bar.classList.contains("indeterminate")).toBe(false);

    uiProcesses.activeProcesses["job-update"].indeterminate = true;
    uiProcesses.activeProcesses["job-update"].extraInfo = "";
    uiProcesses.renderProcessList();

    row = document.querySelector('.process-item[data-job-id="job-update"]');
    expect(row.querySelector(".progress-bar").classList.contains("indeterminate")).toBe(true);
    expect(row.querySelector(".progress-text").textContent).toBe("RUNNING...");

    uiProcesses.activeProcesses["job-update"].status = "FAILED";
    uiProcesses.activeProcesses["job-update"].indeterminate = false;
    uiProcesses.renderProcessList();

    row = document.querySelector('.process-item[data-job-id="job-update"]');
    expect(row.querySelector(".process-remove")).not.toBeNull();
    expect(row.querySelector(".process-cancel")).toBeNull();
  });

  test("cancelProcess marks job canceled on success", async () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-4", "HASHCAT", "cancel.22000", "RUNNING");
    await uiProcesses.cancelProcess("job-4");

    expect(mockAPI.cancelJob).toHaveBeenCalledWith("job-4");
    expect(uiProcesses.activeProcesses["job-4"].status).toBe("CANCELED");
    expect(uiProcesses.activeProcesses["job-4"].percentage).toBe(0);
  });

  test("cancelProcess logs error on API failure", async () => {
    const uiProcesses = loadModule();
    mockAPI.cancelJob.mockRejectedValueOnce(new Error("network error"));

    uiProcesses.addProcess("job-5", "HASHCAT", "cancel_fail.22000", "RUNNING");
    await uiProcesses.cancelProcess("job-5");

    expect(mockLog).toHaveBeenCalledWith("Failed to cancel job: network error", "error");
  });

  test("syncActiveCrackingState updates marker status and emits active/idle events", () => {
    const uiProcesses = loadModule();

    const activeEvents = [];
    const idleEvents = [];
    document.addEventListener("crackingActive", () => activeEvents.push(true));
    document.addEventListener("crackingIdle", () => idleEvents.push(true));

    uiProcesses.addProcess("job-6", "HASHCAT", "ssid_aabbccddeeff.22000", "RUNNING");
    uiProcesses.syncActiveCrackingState();

    expect(mockState.isCrackingActive).toBe(true);
    expect(mockState.crackingByMac["AA:BB:CC:DD:EE:FF"]).toEqual(
      expect.objectContaining({ status: "RUNNING", type: "HASHCAT" })
    );
    expect(mockUpdateMarkerStatusByMac).toHaveBeenCalledWith("AA:BB:CC:DD:EE:FF");
    expect(activeEvents.length).toBe(1);

    uiProcesses.updateProcess("job-6", 100, "COMPLETED", "", false);
    uiProcesses.syncActiveCrackingState();

    expect(mockState.isCrackingActive).toBe(false);
    expect(idleEvents.length).toBe(1);
  });

  test("restoreActiveJobs rebuilds process list from backend jobs", async () => {
    const uiProcesses = loadModule();
    const clickSpy = jest.spyOn(document.getElementById("btn-process"), "click");

    mockAPI.listJobs.mockResolvedValueOnce([
      {
        id: "j1",
        type: "cracking",
        status: "running",
        command: ["hashcat", "/tmp/capture_112233445566.22000"],
      },
      {
        id: "j2",
        type: "conversion_multi",
        status: "queued",
        command: ["python", "convert"],
        meta: { output_file: "batch_abc.22000" },
        start_time: "2026-02-08T10:00:00Z",
      },
    ]);
    mockAPI.listMultiFiles.mockResolvedValueOnce([{ name: "batch_abc.22000", modified: 1000 }]);

    await uiProcesses.restoreActiveJobs();

    expect(uiProcesses.activeProcesses["j1"]).toEqual(
      expect.objectContaining({
        type: "CRACKING (HASHCAT)",
        details: "capture_112233445566.22000",
        status: "RUNNING",
      })
    );
    expect(uiProcesses.activeProcesses["j2"]).toEqual(
      expect.objectContaining({
        type: "MULTI CONVERSION",
        details: "batch_abc.22000",
        status: "QUEUED",
      })
    );
    expect(clickSpy).toHaveBeenCalled();
  });

  test("restoreActiveJobs handles fingerprint/rawsniffer/aircrack jobs", async () => {
    const uiProcesses = loadModule();
    const clickSpy = jest.spyOn(document.getElementById("btn-process"), "click");

    mockAPI.listJobs.mockResolvedValueOnce([
      {
        id: "j3",
        type: "fingerprint_multi",
        status: "running",
        command: ["python", "fingerprint"],
        progress_data: { total_steps: 4 },
      },
      {
        id: "j4",
        type: "rawsniffer_multi",
        status: "pending",
        command: ["python", "rawsniffer"],
        meta: { files_to_process: ["a.pcap", "b.pcap", "c.pcap"] },
      },
      {
        id: "j5",
        type: "aircrack",
        status: "queued",
        command: ["aircrack", "/tmp/capture_alpha.pcap"],
      },
      {
        id: "j6",
        type: "raw_prepare_all",
        status: "running",
        command: "internal:multi",
        meta: { bssid: "AA:BB:CC:DD:EE:FF" },
        progress_data: { total_steps: 2 },
      },
    ]);
    mockAPI.listMultiFiles.mockResolvedValueOnce([]);

    await uiProcesses.restoreActiveJobs();

    expect(uiProcesses.activeProcesses["j3"]).toEqual(
      expect.objectContaining({
        type: "BRUCE PCAP IMPORT",
        details: "Import 4 files",
        status: "RUNNING",
      })
    );
    expect(uiProcesses.activeProcesses["j4"]).toEqual(
      expect.objectContaining({
        type: "RAW SNIFFER",
        details: "Process 3 files",
        status: "PENDING",
      })
    );
    expect(uiProcesses.activeProcesses["j5"]).toEqual(
      expect.objectContaining({
        type: "AIRCRACK-NG",
        details: "capture_alpha.pcap",
        status: "QUEUED",
      })
    );
    expect(uiProcesses.activeProcesses["j6"]).toEqual(
      expect.objectContaining({
        type: "RAW SNIFFER PREPARE ALL",
        details: "AA:BB:CC:DD:EE:FF (2 files)",
        status: "RUNNING",
      })
    );
    expect(clickSpy).toHaveBeenCalled();
  });

  test("restoreActiveJobs restores sync import jobs with locked controls", async () => {
    const uiProcesses = loadModule();

    mockAPI.listJobs.mockResolvedValueOnce([
      {
        id: "sync-m5-hs",
        type: "sync_import",
        status: "running",
        command: "internal:sync",
        meta: {
          display_type: "SYNC",
          display_details: "M5Evil handshakes",
          no_cancel: true,
        },
        progress_data: {
          percentage: 42,
          stage: "RUNNING",
          extra: "HS_A.pcap [512 B / 1.0 KB @ 2.0 KB/s]",
        },
      },
      {
        id: "sync-bruce-raw",
        type: "sync_import",
        status: "queued",
        command: "internal:sync",
        meta: {
          display_type: "SYNC",
          display_details: "Bruce raw sniffer",
          no_cancel: true,
        },
        progress_data: {
          percentage: 0,
          stage: "QUEUED",
          extra: "Queued behind Bruce handshakes",
        },
      },
    ]);
    mockAPI.listMultiFiles.mockResolvedValueOnce([]);

    await uiProcesses.restoreActiveJobs();

    expect(uiProcesses.activeProcesses["sync-m5-hs"]).toEqual(
      expect.objectContaining({
        type: "SYNC",
        details: "M5Evil handshakes",
        status: "RUNNING",
        percentage: 42,
        extraInfo: "HS_A.pcap [512 B / 1.0 KB @ 2.0 KB/s]",
        noCancel: true,
      })
    );
    expect(uiProcesses.activeProcesses["sync-bruce-raw"]).toEqual(
      expect.objectContaining({
        type: "SYNC",
        details: "Bruce raw sniffer",
        status: "QUEUED",
        extraInfo: "Queued behind Bruce handshakes",
        noCancel: true,
      })
    );
  });

  test("setupProcessListeners toggles panel and opens cracking for clicked process", async () => {
    const uiProcesses = loadModule();
    const dispatchSpy = jest.spyOn(document, "dispatchEvent");
    uiProcesses.setupProcessListeners();
    const countLayoutEvents = () =>
      dispatchSpy.mock.calls.filter(([evt]) => evt && evt.type === "rightPanelsModeChanged").length;

    document.getElementById("btn-process").click();
    expect(mockState.modes.process).toBe(true);
    expect(document.getElementById("process-panel").style.display).toBe("flex");
    expect(mockSaveModes).toHaveBeenCalled();
    expect(countLayoutEvents()).toBe(1);

    document.querySelector("#process-panel .close-panel").click();
    expect(mockState.modes.process).toBe(false);
    expect(document.getElementById("process-panel").style.display).toBe("none");
    expect(countLayoutEvents()).toBe(2);

    mockState.allPositions = {
      "AA:BB:CC:DD:EE:FF": {
        mac: "AA:BB:CC:DD:EE:FF",
        ssid: "HomeNet",
      },
    };

    uiProcesses.addProcess("job-7", "HASHCAT", "HomeNet_aabbccddeeff.22000", "RUNNING");
    jest.advanceTimersByTime(1200);

    const processItem = document.querySelector('.process-item[data-job-id="job-7"]');
    processItem.click();

    expect(mockOpenCrackingPanel).toHaveBeenCalledWith(
      "AA:BB:CC:DD:EE:FF",
      "HomeNet",
      "HomeNet_aabbccddeeff.22000"
    );
    dispatchSpy.mockRestore();
  });

  test("setupProcessListeners opens batch view for multi process and supports remove button", () => {
    const uiProcesses = loadModule();
    uiProcesses.setupProcessListeners();

    uiProcesses.addProcess("job-8", "MULTI CONVERSION", "batch_run.22000", "RUNNING");
    jest.advanceTimersByTime(1200);

    const item = document.querySelector('.process-item[data-job-id="job-8"]');
    item.click();
    expect(mockOpenBatchFromProcess).toHaveBeenCalledWith("batch_run.22000");

    uiProcesses.updateProcess("job-8", 100, "FAILED", "", false);
    jest.advanceTimersByTime(1200);

    const removeBtn = document.querySelector('.process-item[data-job-id="job-8"] .process-remove');
    removeBtn.dispatchEvent(new MouseEvent("click", { bubbles: true }));

    expect(uiProcesses.activeProcesses["job-8"]).toBeUndefined();
  });

  test("handleJobCompletionSideEffects appends generated hash file and refreshes open cracking panel", () => {
    const uiProcesses = loadModule();

    mockState.allPositions = {
      "AA:BB:CC:DD:EE:10": {
        mac: "AA:BB:CC:DD:EE:10",
        handshake_files: [],
      },
    };

    document.getElementById("crack-mac").innerText = "AA:BB:CC:DD:EE:10";
    document.getElementById("crack-ssid").innerText = "RefreshedNet";

    uiProcesses.addProcess("job-9", "GENERATE HASH (22000)", "RefreshedNet_aabbccddee10.pcap", "RUNNING");
    mockSelectedFile.name = "RefreshedNet_aabbccddee10.pcap";

    uiProcesses.handleJobCompletionSideEffects({ id: "job-9" });

    expect(mockState.allPositions["AA:BB:CC:DD:EE:10"].handshake_files).toContain(
      "RefreshedNet_aabbccddee10.22000"
    );
    expect(mockUpdateNoGpsList).toHaveBeenCalledTimes(1);
    expect(mockOpenCrackingPanel).toHaveBeenCalledWith(
      "AA:BB:CC:DD:EE:10",
      "RefreshedNet",
      "RefreshedNet_aabbccddee10.pcap"
    );
  });

  test("getActiveHashcatJob returns running hashcat job only", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-10", "AIRCRACK-NG", "air.pcap", "RUNNING");
    uiProcesses.addProcess("job-11", "HASHCAT [MASK]", "mask.22000", "RUNNING");

    const active = uiProcesses.getActiveHashcatJob();

    expect(active).toEqual(expect.objectContaining({ type: "HASHCAT [MASK]" }));
  });

  test("addProcess does not auto-click process button when panel mode is already enabled", () => {
    const uiProcesses = loadModule();
    mockState.modes.process = true;
    const clickSpy = jest.spyOn(document.getElementById("btn-process"), "click");

    uiProcesses.addProcess("job-12", "HASHCAT [RULES]", "existing.22000", "RUNNING");

    expect(clickSpy).not.toHaveBeenCalled();
    expect(mockTogglePowerSave).toHaveBeenCalledWith(true);
  });

  test("updateProcess ignores unknown job and keeps previous extra info when new extra is empty", () => {
    const uiProcesses = loadModule();
    uiProcesses.updateProcess("missing", 10, "RUNNING", "", false);

    uiProcesses.addProcess("job-13", "HASHCAT", "extra.22000", "RUNNING");
    uiProcesses.updateProcess("job-13", 10, "RUNNING", "100kH/s", false);
    uiProcesses.updateProcess("job-13", 11, "RUNNING", "", false);

    expect(uiProcesses.activeProcesses["job-13"].extraInfo).toBe("100kH/s");
  });

  test("removeProcess handles missing job and removes existing process", () => {
    const uiProcesses = loadModule();
    uiProcesses.removeProcess("missing");

    uiProcesses.addProcess("job-14", "HASHCAT", "remove.22000", "RUNNING");
    expect(uiProcesses.activeProcesses["job-14"]).toBeDefined();

    uiProcesses.removeProcess("job-14");
    expect(uiProcesses.activeProcesses["job-14"]).toBeUndefined();
  });

  test("renderProcessList shows empty state and indeterminate status text", () => {
    const uiProcesses = loadModule();

    uiProcesses.renderProcessList();
    expect(document.getElementById("process-list").textContent).toContain("NO ACTIVE PROCESSES");

    uiProcesses.addProcess("job-15", "HASHCAT", "indeterminate.22000", "RUNNING");
    jest.advanceTimersByTime(1200);
    uiProcesses.updateProcess("job-15", 33, "RUNNING", "Kernel compile", true);
    jest.advanceTimersByTime(1200);

    const row = document.querySelector('.process-item[data-job-id="job-15"]');
    expect(row).not.toBeNull();
    expect(row.querySelector(".progress-bar").classList.contains("indeterminate")).toBe(true);
    expect(row.querySelector(".progress-text").textContent).toContain("Kernel compile");
  });

  test("restoreActiveJobs supports conversion/aircrack parsing and batch fallback by nearest timestamp", async () => {
    const uiProcesses = loadModule();

    mockAPI.listJobs.mockResolvedValueOnce([
      {
        id: "j-conv",
        type: "conversion",
        status: "started",
        command: "python convert /tmp/track_aabbccddeeaa.pcap",
      },
      {
        id: "j-air",
        type: "aircrack",
        status: "pending",
        command: "aircrack /tmp/wifi_aabbccddeeab.pcap",
      },
      {
        id: "j-multi",
        type: "conversion_multi",
        status: "running",
        command: "python convert_multi",
        start_time: "2026-02-08T10:00:00Z",
      },
    ]);
    mockAPI.listMultiFiles.mockResolvedValueOnce([
      { name: "batch_old.22000", modified: 1707386300 },
      { name: "batch_new.22000", modified: 1707386400 },
    ]);

    await uiProcesses.restoreActiveJobs();

    expect(uiProcesses.activeProcesses["j-conv"]).toEqual(
      expect.objectContaining({
        type: "GENERATE HASH (22000)",
        details: "track_aabbccddeeaa.pcap",
      })
    );
    expect(uiProcesses.activeProcesses["j-air"]).toEqual(
      expect.objectContaining({
        type: "AIRCRACK-NG",
        details: "wifi_aabbccddeeab.pcap",
      })
    );
    expect(uiProcesses.activeProcesses["j-multi"].details).toBe("batch_new.22000");
  });

  test("restoreActiveJobs falls back to first batch when no metadata is available", async () => {
    const uiProcesses = loadModule();

    mockAPI.listJobs.mockResolvedValueOnce([
      { id: "j-multi-first", type: "conversion_multi", status: "running", command: "python convert_multi" },
    ]);
    mockAPI.listMultiFiles.mockResolvedValueOnce([
      { name: "batch_first.22000", modified: 1 },
      { name: "batch_second.22000", modified: 2 },
    ]);

    await uiProcesses.restoreActiveJobs();

    expect(uiProcesses.activeProcesses["j-multi-first"].details).toBe("batch_first.22000");
  });

  test("restoreActiveJobs handles list errors and does not break", async () => {
    const uiProcesses = loadModule();
    const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    mockAPI.listJobs.mockRejectedValueOnce(new Error("jobs down"));
    await uiProcesses.restoreActiveJobs();

    expect(errSpy).toHaveBeenCalledWith("Failed to restore jobs:", expect.any(Error));
    errSpy.mockRestore();
  });

  test("syncActiveCrackingState ignores unsupported process types and parses MAC from colon format", () => {
    const uiProcesses = loadModule();
    const activeEvents = [];
    const idleEvents = [];
    document.addEventListener("crackingActive", () => activeEvents.push(true));
    document.addEventListener("crackingIdle", () => idleEvents.push(true));

    uiProcesses.addProcess("job-16", "PROCESS", "misc.txt", "RUNNING");
    uiProcesses.addProcess("job-17", "AIRCRACK-NG", "capture_AA:BB:CC:DD:EE:12.pcap", "QUEUED");
    uiProcesses.syncActiveCrackingState();

    expect(mockState.crackingByMac["AA:BB:CC:DD:EE:12"]).toEqual(
      expect.objectContaining({ status: "QUEUED", type: "AIRCRACK-NG" })
    );
    expect(mockState.crackingByMac["MISC"]).toBeUndefined();
    expect(activeEvents.length).toBe(1);

    uiProcesses.updateProcess("job-17", 100, "FAILED", "", false);
    uiProcesses.syncActiveCrackingState();
    expect(idleEvents.length).toBe(1);
  });

  test("syncActiveCrackingState flags status changes for running jobs", () => {
    const uiProcesses = loadModule();
    mockState.crackingByMac = {
      "AA:BB:CC:DD:EE:12": { status: "RUNNING", type: "HASHCAT" },
    };

    uiProcesses.addProcess("job-17b", "HASHCAT", "SSID_aabbccddee12.22000", "QUEUED");
    uiProcesses.syncActiveCrackingState();

    expect(mockUpdateMarkerStatusByMac).toHaveBeenCalledWith("AA:BB:CC:DD:EE:12");
  });

  test("syncActiveCrackingState parses mac from non-hex 12-char suffix", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-17c", "HASHCAT", "SSID_ABCDEFGHIJKL.22000", "RUNNING");
    uiProcesses.syncActiveCrackingState();

    expect(mockUpdateMarkerStatusByMac).toHaveBeenCalledWith("AB:CD:EF:GH:IJ:KL");
  });

  test("setupProcessListeners handles cancel click and fallback open by parsed MAC when target is unknown", async () => {
    const uiProcesses = loadModule();
    uiProcesses.setupProcessListeners();

    uiProcesses.addProcess("job-18", "HASHCAT", "UnknownSSID_aabbccddeecc.22000", "RUNNING");
    jest.advanceTimersByTime(1200);

    const item = document.querySelector('.process-item[data-job-id="job-18"]');
    item.querySelector(".process-cancel").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    await Promise.resolve();
    expect(mockAPI.cancelJob).toHaveBeenCalledWith("job-18");

    item.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockOpenCrackingPanel).toHaveBeenCalledWith(
      "AA:BB:CC:DD:EE:CC",
      "UnknownSSID",
      "UnknownSSID_aabbccddeecc.22000"
    );
  });

  test("setupProcessListeners finds target by filename substring when no mac suffix", () => {
    const uiProcesses = loadModule();
    uiProcesses.setupProcessListeners();

    mockState.allPositions = {
      "AA:BB:CC:DD:EE:FF": {
        mac: "AA:BB:CC:DD:EE:FF",
        ssid: "FallbackNet",
      },
    };

    uiProcesses.addProcess("job-18b", "HASHCAT", "captureaabbccddeeff.22000", "RUNNING");
    jest.advanceTimersByTime(1200);

    const item = document.querySelector('.process-item[data-job-id="job-18b"]');
    item.click();

    expect(mockOpenCrackingPanel).toHaveBeenCalledWith(
      "AA:BB:CC:DD:EE:FF",
      "FallbackNet",
      "captureaabbccddeeff.22000"
    );
  });

  test("handleJobCompletionSideEffects avoids duplicates and no-ops for non-generate job types", () => {
    const uiProcesses = loadModule();
    mockState.allPositions = {
      "AA:BB:CC:DD:EE:20": {
        mac: "AA:BB:CC:DD:EE:20",
        handshake_files: ["Known_aabbccddee20.22000"],
      },
    };

    uiProcesses.addProcess("job-19", "GENERATE HASH (22000)", "Known_aabbccddee20.pcap", "RUNNING");
    mockSelectedFile.name = "different_file.22000";
    uiProcesses.handleJobCompletionSideEffects({ id: "job-19" });

    expect(mockState.allPositions["AA:BB:CC:DD:EE:20"].handshake_files).toEqual([
      "Known_aabbccddee20.22000",
    ]);
    expect(mockUpdateNoGpsList).not.toHaveBeenCalled();

    uiProcesses.addProcess("job-20", "AIRCRACK-NG", "Known_aabbccddee20.pcap", "RUNNING");
    uiProcesses.handleJobCompletionSideEffects({ id: "job-20" });
    expect(mockOpenCrackingPanel).not.toHaveBeenCalledWith(
      "AA:BB:CC:DD:EE:20",
      expect.any(String),
      "Known_aabbccddee20.pcap"
    );
  });

  test("getActiveHashcatJob returns null when hashcat process is not in running status", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-21", "HASHCAT [RULES]", "done.22000", "COMPLETED");
    uiProcesses.addProcess("job-22", "PROCESS", "misc.txt", "RUNNING");

    expect(uiProcesses.getActiveHashcatJob()).toBeNull();
  });

  test("cancelProcess handles unknown local process without throwing", async () => {
    const uiProcesses = loadModule();

    await uiProcesses.cancelProcess("unknown-job");
    expect(mockAPI.cancelJob).toHaveBeenCalledWith("unknown-job");
    expect(uiProcesses.activeProcesses["unknown-job"]).toBeUndefined();
  });

  test("renderProcessList removes stale rows and keeps stable DOM on repeated render", () => {
    const uiProcesses = loadModule();
    const list = document.getElementById("process-list");
    list.innerHTML = '<div class="process-item" data-job-id="ghost"></div>';

    uiProcesses.addProcess("job-23", "HASHCAT", "queued.22000", "QUEUED");
    jest.advanceTimersByTime(1200);
    uiProcesses.renderProcessList();

    expect(document.querySelector('.process-item[data-job-id="ghost"]')).toBeNull();
    const statusEl = document.querySelector('.process-item[data-job-id="job-23"] .process-status');
    expect(statusEl.textContent).toContain("QUEUED");

    const before = document.getElementById("process-list").innerHTML;
    uiProcesses.renderProcessList();
    const after = document.getElementById("process-list").innerHTML;
    expect(after).toBe(before);
  });

  test("renderProcessList shows RUNNING fallback text for indeterminate process without extra info", () => {
    const uiProcesses = loadModule();

    uiProcesses.addProcess("job-24", "HASHCAT", "indeterminate_no_info.22000", "RUNNING");
    jest.advanceTimersByTime(1200);
    uiProcesses.updateProcess("job-24", 12, "RUNNING", "", true);
    jest.advanceTimersByTime(1200);

    const row = document.querySelector('.process-item[data-job-id="job-24"]');
    expect(row.querySelector(".progress-text").textContent).toContain("RUNNING...");
  });

  test("restoreActiveJobs handles empty active list and non-array batch responses", async () => {
    const uiProcesses = loadModule();

    mockAPI.listJobs.mockResolvedValueOnce([
      { id: "done-1", type: "cracking", status: "completed", command: "hashcat" },
    ]);
    mockAPI.listMultiFiles.mockResolvedValueOnce({ unexpected: true });

    await uiProcesses.restoreActiveJobs();
    expect(Object.keys(uiProcesses.activeProcesses).length).toBe(0);

    mockAPI.listJobs.mockResolvedValueOnce([
      {
        id: "multi-fallback",
        type: "conversion_multi",
        status: "running",
        command: "python convert_multi",
      },
    ]);
    mockAPI.listMultiFiles.mockResolvedValueOnce({ not: "array" });
    await uiProcesses.restoreActiveJobs();

    expect(uiProcesses.activeProcesses["multi-fallback"]).toEqual(
      expect.objectContaining({
        type: "MULTI CONVERSION",
        details: "multi",
      })
    );
  });

  test("setupProcessListeners ignores process rows without details", () => {
    const uiProcesses = loadModule();
    uiProcesses.setupProcessListeners();

    uiProcesses.addProcess("job-25", "HASHCAT", "ignored.22000", "RUNNING");
    uiProcesses.activeProcesses["job-25"].details = "";
    jest.advanceTimersByTime(1200);

    const item = document.querySelector('.process-item[data-job-id="job-25"]');
    item.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockOpenCrackingPanel).not.toHaveBeenCalled();
    expect(mockOpenBatchFromProcess).not.toHaveBeenCalled();
  });

  test("handleJobCompletionSideEffects no-ops when generator job has no details", () => {
    const uiProcesses = loadModule();
    uiProcesses.addProcess("job-26", "GENERATE HASH (22000)", "", "RUNNING");

    uiProcesses.handleJobCompletionSideEffects({ id: "job-26" });
    expect(mockUpdateNoGpsList).not.toHaveBeenCalled();
  });
});
