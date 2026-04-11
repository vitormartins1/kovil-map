const mockState = {
  multiUi: null,
  multiFilter: "all",
  multiSelection: [],
  multiFiles: [],
  multiSelectedFile: null,
  multiFileContents: {},
  multiItemStatus: {},
  allPositions: {},
};

const mockAPI = {
  listMultiFiles: jest.fn(),
  getMultiFileContent: jest.fn(),
  convertMultiPcaps: jest.fn(),
  deleteMultiFile: jest.fn(),
};

const mockLog = jest.fn();
const mockUpdateMultiList = jest.fn();

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
}));

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  addProcess: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openMultiCrackingPanel: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => ({
  updateMultiList: (...args) => mockUpdateMultiList(...args),
  updateMultiFilesList: jest.fn(),
  updateMultiContentsList: jest.fn(),
}));

const {
  getMultiUiState,
  setupMultiListeners,
  refreshMultiFiles,
  loadMultiContents,
  handleMultiCreate,
} = require("../../src/modules/ui_multi.js");

function mountMultiDom() {
  document.body.innerHTML = `
    <input id="multi-filter-search" />
    <select id="multi-filter-location"></select>
    <select id="multi-filter-source"></select>
    <select id="multi-filter-artifact"></select>
    <button id="btn-multi-filter-all"></button>
    <button id="btn-multi-filter-locked"></button>
  `;
}

beforeEach(() => {
  mockState.multiUi = null;
  mockState.multiFilter = "all";
  mockState.multiSelection = [];
  mockState.allPositions = {};
  mockUpdateMultiList.mockClear();
  mockLog.mockClear();
  mountMultiDom();
});

test("getMultiUiState seeds defaults and syncs multiFilter", () => {
  mockState.multiFilter = "locked";
  const uiState = getMultiUiState();
  expect(uiState.status).toBe("locked");
  expect(uiState.search).toBe("");

  mockState.multiUi = { search: null, status: "all", location: null, source: null, artifact: null };
  mockState.multiFilter = "custom";
  const updated = getMultiUiState();
  expect(updated.location).toBe("all");
  expect(mockState.multiFilter).toBe("all");
});

test("setupMultiListeners updates filter button state when locked", () => {
  mockState.multiUi = { search: "", status: "locked", location: "all", source: "all", artifact: "all" };
  mockState.multiFilter = "locked";

  setupMultiListeners();

  expect(document.getElementById("btn-multi-filter-locked").classList.contains("active")).toBe(true);
  expect(document.getElementById("btn-multi-filter-all").classList.contains("active")).toBe(false);
});

test("setupMultiListeners toggles multi selection via change events", () => {
  document.body.insertAdjacentHTML(
    "beforeend",
    `
    <div id="multi-all-list">
      <div class="list-item">
        <input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:01" type="checkbox" />
      </div>
    </div>
  `
  );

  setupMultiListeners();

  const chk = document.querySelector(".multi-select-chk");
  chk.checked = true;
  chk.dispatchEvent(new Event("change", { bubbles: true }));
  expect(mockState.multiSelection).toEqual(["AA:AA:AA:AA:AA:01"]);

  chk.checked = false;
  chk.dispatchEvent(new Event("change", { bubbles: true }));
  expect(mockState.multiSelection).toEqual([]);
});

test("refreshMultiFiles and loadMultiContents update state on success and error", async () => {
  mockAPI.listMultiFiles.mockResolvedValueOnce([{ name: "batch_a.22000" }]);
  await refreshMultiFiles();
  expect(mockState.multiFiles).toEqual([{ name: "batch_a.22000" }]);

  mockAPI.getMultiFileContent.mockResolvedValueOnce({ items: [{ ssid: "Net" }] });
  await loadMultiContents("batch_a.22000");
  expect(mockState.multiFileContents["batch_a.22000"]).toEqual([{ ssid: "Net" }]);

  mockAPI.getMultiFileContent.mockRejectedValueOnce(new Error("fail"));
  await loadMultiContents("batch_fail.22000");
  expect(mockState.multiFileContents["batch_fail.22000"]).toEqual([]);
});

test("refreshMultiFiles logs error when API fails", async () => {
  const errSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  mockAPI.listMultiFiles.mockRejectedValueOnce(new Error("nope"));
  await refreshMultiFiles();
  expect(errSpy).toHaveBeenCalled();
  errSpy.mockRestore();
});

test("handleMultiCreate ignores missing positions and pcaps", async () => {
  mockState.multiSelection = ["AA:AA:AA:AA:AA:01"];
  await handleMultiCreate();
  expect(mockLog).toHaveBeenCalledWith("No PCAP files found for selected networks.", "error");

  mockState.allPositions = {
    "AA:AA:AA:AA:AA:01": { handshake_files: ["file.txt"] },
  };
  await handleMultiCreate();
  expect(mockLog).toHaveBeenCalledWith("No PCAP files found for selected networks.", "error");
});

test("handleMultiCreate warns when no selection exists", async () => {
  mockState.multiSelection = [];
  await handleMultiCreate();
  expect(mockLog).toHaveBeenCalledWith("Select at least one network to create a multi file.", "warn");
  expect(mockAPI.convertMultiPcaps).not.toHaveBeenCalled();
});

test("handleMultiCreate starts conversion when pcaps exist", async () => {
  mockState.multiSelection = ["AA:AA:AA:AA:AA:01"];
  mockState.allPositions = {
    "AA:AA:AA:AA:AA:01": { handshake_files: ["cap_1.pcap"] },
  };
  mockAPI.convertMultiPcaps.mockResolvedValueOnce({ status: "started", job_id: "job-1", output_file: "batch_a.22000" });

  await handleMultiCreate();
  expect(mockState.multiSelection).toEqual([]);
});

test("handleMultiCreate logs errors for non-started status and exceptions", async () => {
  mockState.multiSelection = ["AA:AA:AA:AA:AA:01"];
  mockState.allPositions = {
    "AA:AA:AA:AA:AA:01": { handshake_files: ["cap_1.pcap"] },
  };
  mockAPI.convertMultiPcaps.mockResolvedValueOnce({ status: "error", message: "nope" });

  await handleMultiCreate();
  expect(mockLog).toHaveBeenCalledWith("Multi conversion failed to start: nope", "error");

  mockAPI.convertMultiPcaps.mockRejectedValueOnce(new Error("boom"));
  await handleMultiCreate();
  expect(mockLog).toHaveBeenCalledWith("Multi conversion error: boom", "error");
});

test("setupMultiListeners ignores non-checkbox changes and disabled rows", () => {
  document.body.insertAdjacentHTML(
    "beforeend",
    `
    <div id="multi-all-list">
      <div class="list-item">
        <input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:01" type="checkbox" disabled />
      </div>
      <div class="list-item">
        <input class="multi-select-chk" data-mac="" type="checkbox" />
      </div>
    </div>
  `
  );

  setupMultiListeners();

  const list = document.getElementById("multi-all-list");
  list.dispatchEvent(new Event("change", { bubbles: true }));
  list.querySelector(".list-item").dispatchEvent(new MouseEvent("click", { bubbles: true }));

  const emptyMacRow = list.querySelectorAll(".list-item")[1];
  emptyMacRow.querySelector(".multi-select-chk").dispatchEvent(new Event("change", { bubbles: true }));
  emptyMacRow.dispatchEvent(new MouseEvent("click", { bubbles: true }));

  expect(mockState.multiSelection).toEqual([]);
});

test("setupMultiListeners handles shift-range selection and filter controls", () => {
  document.body.insertAdjacentHTML(
    "beforeend",
    `
    <div id="multi-all-list">
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:01" type="checkbox" /></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:02" type="checkbox" /></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:03" type="checkbox" /></div>
    </div>
  `
  );

  setupMultiListeners();

  const rows = document.querySelectorAll("#multi-all-list .list-item");
  mockState.multiLastClickedMac = "AA:AA:AA:AA:AA:01";
  rows[2].dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true }));
  expect(mockState.multiSelection).toContain("AA:AA:AA:AA:AA:03");

  document.getElementById("btn-multi-filter-all").click();
  document.getElementById("btn-multi-filter-locked").click();

  const search = document.getElementById("multi-filter-search");
  search.value = "abc";
  search.dispatchEvent(new Event("input", { bubbles: true }));

  const location = document.getElementById("multi-filter-location");
  location.value = "gps";
  location.dispatchEvent(new Event("change", { bubbles: true }));

  const source = document.getElementById("multi-filter-source");
  source.value = "pwn";
  source.dispatchEvent(new Event("change", { bubbles: true }));

  const artifact = document.getElementById("multi-filter-artifact");
  artifact.value = "has_22000";
  artifact.dispatchEvent(new Event("change", { bubbles: true }));

  expect(mockState.multiUi.search).toBe("abc");
});

test("setupMultiListeners handles click edge cases and shift fallback", () => {
  document.body.insertAdjacentHTML(
    "beforeend",
    `
    <div id="multi-all-list">
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:01" type="checkbox" /></div>
      <div class="list-item"><input class="multi-select-chk" data-mac="AA:AA:AA:AA:AA:02" type="checkbox" /></div>
    </div>
    <div id="multi-files-list"></div>
  `
  );

  setupMultiListeners();

  const list = document.getElementById("multi-all-list");
  const firstRow = list.querySelector(".list-item");
  const clickGuard = document.createElement("span");
  clickGuard.className = "multi-select-chk";
  firstRow.appendChild(clickGuard);

  // Click directly on checkbox-like target should no-op in click handler
  clickGuard.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  expect(mockState.multiSelection).toEqual([]);

  // Click on container without list-item should no-op
  list.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  expect(mockState.multiSelection).toEqual([]);

  // Shift click with missing anchor should fall back to single toggle
  mockState.multiLastClickedMac = "MISSING";
  const rows = list.querySelectorAll(".list-item");
  rows[1].dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true }));
  expect(mockState.multiSelection).toEqual(["AA:AA:AA:AA:AA:02"]);
});

test("setupMultiListeners handles multi file selection and deletion paths", async () => {
  const { updateMultiFilesList, updateMultiContentsList } = require("../../src/modules/ui_components/ui_lists.js");
  const { openMultiCrackingPanel } = require("../../src/modules/ui_components/ui_cracking.js");
  updateMultiFilesList.mockClear();
  updateMultiContentsList.mockClear();
  openMultiCrackingPanel.mockClear();

  document.body.insertAdjacentHTML(
    "beforeend",
    `
      <div id="multi-files-list">
        <div class="list-item" data-name="batch_a.22000">
          <button class="multi-delete" data-name="batch_a.22000"></button>
        </div>
      </div>
    `
  );

  setupMultiListeners();

  mockState.multiSelectedFile = "batch_a.22000";
  mockAPI.deleteMultiFile.mockResolvedValueOnce({ deleted: true });
  mockAPI.listMultiFiles.mockResolvedValueOnce([]);

  document.querySelector(".multi-delete").dispatchEvent(new MouseEvent("click", { bubbles: true }));
  await new Promise((resolve) => setTimeout(resolve, 0));

  expect(updateMultiContentsList).toHaveBeenCalled();
  expect(updateMultiFilesList).toHaveBeenCalled();

  mockAPI.deleteMultiFile.mockResolvedValueOnce({ deleted: false, message: "nope" });
  document.querySelector(".multi-delete").dispatchEvent(new MouseEvent("click", { bubbles: true }));
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(mockLog).toHaveBeenCalledWith("Failed to delete multi file: nope", "error");

  mockAPI.deleteMultiFile.mockRejectedValueOnce(new Error("boom"));
  document.querySelector(".multi-delete").dispatchEvent(new MouseEvent("click", { bubbles: true }));
  await new Promise((resolve) => setTimeout(resolve, 0));
  expect(mockLog).toHaveBeenCalledWith("Delete error: boom", "error");

  mockAPI.getMultiFileContent.mockResolvedValueOnce({ items: [{ ssid: "Net" }] });
  document.querySelector("#multi-files-list .list-item").dispatchEvent(
    new MouseEvent("click", { bubbles: true })
  );
  await new Promise((resolve) => setTimeout(resolve, 0));

  expect(mockState.multiSelectedFile).toBe("batch_a.22000");
  expect(updateMultiFilesList).toHaveBeenCalled();
  expect(updateMultiContentsList).toHaveBeenCalled();
  expect(openMultiCrackingPanel).toHaveBeenCalledWith("batch_a.22000");
});

test("setupMultiListeners tolerates missing filter controls", () => {
  document.getElementById("btn-multi-filter-all").remove();
  document.getElementById("btn-multi-filter-locked").remove();
  document.getElementById("multi-filter-search").remove();
  document.getElementById("multi-filter-location").remove();
  document.getElementById("multi-filter-source").remove();
  document.getElementById("multi-filter-artifact").remove();

  expect(() => setupMultiListeners()).not.toThrow();
});
