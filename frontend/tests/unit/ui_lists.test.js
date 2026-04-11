const mockState = {
  lists: { targets: [], favs: [] },
  allPositions: {},
  filters: { search: "" },
  multiSelection: [],
  multiFilter: "all",
  multiUi: {
    search: "",
    status: "all",
    location: "all",
    source: "all",
    artifact: "all",
  },
  noGpsUi: {
    search: "",
    device: "all",
    status: "all",
    visibility: "all",
    artifact: "all",
  },
  multiFiles: [],
  multiSelectedFile: null,
  multiFileContents: {},
};

const mockToggleTarget = jest.fn();
const mockToggleFav = jest.fn();
const mockFocusAndOpenPopup = jest.fn();
const mockGetMapInstance = jest.fn();
const mockOpenCrackingPanel = jest.fn();
const mockActiveProcesses = {};
const mockUiConfig = {
  iconPwned: "fa-skull",
  iconLocked: "fa-shield-halved",
};

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
}));

jest.mock("../../src/modules/map.js", () => ({
  toggleTarget: (...args) => mockToggleTarget(...args),
  toggleFav: (...args) => mockToggleFav(...args),
  focusAndOpenPopup: (...args) => mockFocusAndOpenPopup(...args),
  getMapInstance: (...args) => mockGetMapInstance(...args),
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: (...args) => mockOpenCrackingPanel(...args),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  activeProcesses: mockActiveProcesses,
}));

jest.mock("../../src/modules/ui_components/ui_settings.js", () => ({
  uiConfig: mockUiConfig,
}));

const {
  updateTargetsList,
  updateFavsList,
  updateZonesList,
  updateNoGpsList,
  updateMultiList,
  updateMultiFilesList,
  updateMultiContentsList,
} = require("../../src/modules/ui_components/ui_lists.js");

function mountListsDom() {
  document.body.innerHTML = `
    <div id="targets-list"></div>
    <span id="target-count"></span>
    <div id="favs-list"></div>
    <span id="fav-count"></span>
    <div id="conquered-zones-divider" style="display:none"></div>
    <div id="conquered-zones-section"></div>
    <span id="conquered-zone-count"></span>
    <input id="no-gps-filter-search" />
    <select id="no-gps-filter-device"><option value="all">ALL</option><option value="raw">RAW</option><option value="unknown">UNKNOWN</option></select>
    <select id="no-gps-filter-status"><option value="all">ALL</option><option value="cracked">CRACKED</option><option value="locked">LOCKED</option><option value="open">OPEN</option></select>
    <select id="no-gps-filter-visibility"><option value="all">ALL</option><option value="hidden">HIDDEN</option><option value="named">NAMED</option></select>
    <select id="no-gps-filter-artifact"><option value="all">ALL</option><option value="has_pcap">PCAP</option><option value="has_22000">22000</option><option value="no_artifacts">NONE</option></select>
    <span id="no-gps-filter-count"></span>
    <div id="no-gps-list-pwned"></div>
    <div id="no-gps-list-locked"></div>
    <div id="multi-all-list"></div>
    <span id="multi-selected-count"></span>
    <span id="multi-visible-count"></span>
    <span id="multi-eligible-count"></span>
    <span id="multi-excluded-open-count"></span>
    <div id="multi-files-list"></div>
    <div id="multi-contents-list"></div>
  `;
}

function resetState() {
  mockState.lists.targets = [];
  mockState.lists.favs = [];
  mockState.allPositions = {};
  mockState.filters.search = "";
  mockState.multiSelection = [];
  mockState.multiFilter = "all";
  mockState.multiUi = {
    search: "",
    status: "all",
    location: "all",
    source: "all",
    artifact: "all",
  };
  mockState.noGpsUi = {
    search: "",
    device: "all",
    status: "all",
    visibility: "all",
    artifact: "all",
  };
  mockState.multiFiles = [];
  mockState.multiSelectedFile = null;
  mockState.multiFileContents = {};

  Object.keys(mockActiveProcesses).forEach((key) => delete mockActiveProcesses[key]);
}

describe("ui_lists", () => {
  beforeEach(() => {
    mountListsDom();
    resetState();
    mockToggleTarget.mockClear();
    mockToggleFav.mockClear();
    mockFocusAndOpenPopup.mockClear();
    mockGetMapInstance.mockReset();
    mockOpenCrackingPanel.mockClear();
    global.L = {
      latLngBounds: jest.fn(() => "mock-bounds"),
    };
  });

  test("updateTargetsList renders items, status badge and click actions", () => {
    const mac = "AA:BB:CC:DD:EE:FF";
    mockState.lists.targets = [mac];
    mockState.allPositions = {
      one: { mac, ssid: "My Net" },
    };
    mockActiveProcesses["job-1"] = {
      details: "target aabbccddeeff",
      status: "EXHAUSTED",
    };

    updateTargetsList();

    expect(document.getElementById("target-count").innerText).toBe(1);
    const row = document.querySelector(`#targets-list .list-item[data-mac="${mac}"]`);
    expect(row).not.toBeNull();
    expect(row.querySelector(".target-status").textContent).toContain("NOT FOUND");

    row.querySelector(".target-remove").dispatchEvent(
      new MouseEvent("click", { bubbles: true })
    );
    expect(mockToggleTarget).toHaveBeenCalledWith(mac);

    row.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockFocusAndOpenPopup).toHaveBeenCalledWith(mac);
    expect(mockOpenCrackingPanel).toHaveBeenCalledWith(mac, "My Net");
  });

  test("updateTargetsList handles non-string process details without crashing", () => {
    const mac = "AA:BB:CC:DD:EE:FF";
    mockState.lists.targets = [mac];
    mockState.allPositions = {
      one: { mac, ssid: "Hybrid Net" },
    };
    mockActiveProcesses["job-obj"] = {
      details: { command: ["hcx", "aabbccddeeff"], meta: { file: "raw_1.pcap" } },
      status: "RUNNING",
    };

    expect(() => updateTargetsList()).not.toThrow();
    const row = document.querySelector(`#targets-list .list-item[data-mac="${mac}"]`);
    expect(row).not.toBeNull();
    const badge = row.querySelector(".target-status");
    expect(badge).not.toBeNull();
    expect(badge.textContent).toContain("RUNNING");
  });

  test("updateTargetsList removes stale rows and updates existing item with queued status", () => {
    const mac = "AA:BB:CC:00:00:01";
    mockState.lists.targets = [mac];
    mockState.allPositions = {
      one: { mac, ssid: "Queue Net" },
    };
    mockActiveProcesses["job-queued"] = {
      details: "queue net processing",
      status: "QUEUED",
    };

    document.getElementById("targets-list").innerHTML = `
      <div class="list-item" data-mac="${mac}">
        <div class="item-name">Old Name</div>
      </div>
      <div class="list-item" data-mac="AA:BB:CC:99:99:99">
        <div class="item-name">Stale</div>
      </div>
    `;

    updateTargetsList();

    const rows = document.querySelectorAll("#targets-list .list-item");
    expect(rows.length).toBe(1);
    const badge = rows[0].querySelector(".target-status");
    expect(badge).not.toBeNull();
    expect(badge.textContent).toContain("QUEUED");
    expect(badge.className).toContain("t-queued");
  });

  test("updateFavsList renders favorite rows and supports remove/focus", () => {
    const mac = "11:22:33:44:55:66";
    mockState.lists.favs = [mac];
    mockState.allPositions = {
      one: { mac, ssid: "Fav Net" },
    };

    updateFavsList();

    expect(document.getElementById("fav-count").innerText).toBe(1);
    const row = document.querySelector(`#favs-list .list-item[data-mac="${mac}"]`);
    expect(row).not.toBeNull();

    row.querySelector(".fav-remove").dispatchEvent(
      new MouseEvent("click", { bubbles: true })
    );
    expect(mockToggleFav).toHaveBeenCalledWith(mac);

    row.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockFocusAndOpenPopup).toHaveBeenCalledWith(mac);
  });

  test("updateZonesList normalizes clusters and zooms when clicking a zone", () => {
    const fitBounds = jest.fn();
    mockGetMapInstance.mockReturnValue({ fitBounds });

    updateZonesList([
      [
        { lat: -22.9, lng: -43.2 },
        { lat: -22.8, lng: -43.1 },
      ],
      {
        id: 7,
        count: 2,
        parts: [
          [{ lat: -22.7, lng: -43.0 }],
          [{ lat: -22.6, lng: -42.9 }],
        ],
      },
    ]);

    expect(document.getElementById("conquered-zone-count").innerText).toBe(3);
    expect(document.getElementById("conquered-zones-divider").style.display).toBe("flex");
    const rows = document.querySelectorAll("#conquered-zones-section .list-item");
    expect(rows.length).toBe(3);

    rows[0].dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(global.L.latLngBounds).toHaveBeenCalled();
    expect(fitBounds).toHaveBeenCalledWith(
      "mock-bounds",
      expect.objectContaining({ animate: true })
    );
  });

  test("updateNoGpsList shows empty state and renders cracked/locked buckets", () => {
    updateNoGpsList();
    expect(document.getElementById("no-gps-list-pwned").textContent).toContain("NO ITEMS");
    expect(document.getElementById("no-gps-list-locked").textContent).toContain("NO ITEMS");

    mockState.allPositions = {
      a: {
        type: "no-gps",
        mac: "AA:00:00:00:00:01",
        ssid: "Cracked AP",
        pass: "secret",
        encryption: "WPA2",
        handshake_files: [],
      },
      b: {
        type: "no-gps",
        mac: "AA:00:00:00:00:02",
        ssid: "Locked AP",
        pass: "",
        encryption: "WPA2",
        handshake_files: ["file.pcap", "file.22000"],
      },
    };

    updateNoGpsList();

    const pwnedRows = document.querySelectorAll("#no-gps-list-pwned .list-item");
    const lockedRows = document.querySelectorAll("#no-gps-list-locked .list-item");
    expect(pwnedRows.length).toBe(1);
    expect(lockedRows.length).toBe(1);
    expect(document.getElementById("no-gps-filter-count").innerText).toBe("2/2");

    lockedRows[0].dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(mockOpenCrackingPanel).toHaveBeenCalledWith(
      "AA:00:00:00:00:02",
      "Locked AP"
    );
  });

  test("updateNoGpsList applies no-gps specific filters by status and hidden", () => {
    mockState.noGpsUi.status = "locked";
    mockState.noGpsUi.visibility = "hidden";
    mockState.allPositions = {
      a: {
        type: "no-gps",
        mac: "AA:00:00:00:00:10",
        ssid: "",
        pass: "",
        encryption: "WPA2",
        handshake_files: ["x.pcap"],
      },
      b: {
        type: "no-gps",
        mac: "AA:00:00:00:00:11",
        ssid: "Visible Locked",
        pass: "",
        encryption: "WPA2",
        handshake_files: ["y.pcap"],
      },
      c: {
        type: "no-gps",
        mac: "AA:00:00:00:00:12",
        ssid: "Open Net",
        pass: "",
        encryption: "OPEN",
        handshake_files: [],
      },
      d: {
        type: "no-gps",
        mac: "AA:00:00:00:00:13",
        ssid: "Cracked Net",
        pass: "12345678",
        encryption: "WPA2",
        handshake_files: ["z.22000"],
      },
    };

    updateNoGpsList();

    const pwnedRows = document.querySelectorAll("#no-gps-list-pwned .list-item");
    const lockedRows = document.querySelectorAll("#no-gps-list-locked .list-item");
    expect(pwnedRows.length).toBe(0);
    expect(lockedRows.length).toBe(1);
    expect(document.getElementById("no-gps-list-locked").textContent).toContain("HIDDEN");
    expect(document.getElementById("no-gps-filter-count").innerText).toBe("1/4");
  });

  test("updateNoGpsList applies no-gps device and artifact filters", () => {
    mockState.noGpsUi.device = "raw";
    mockState.noGpsUi.artifact = "has_22000";
    mockState.allPositions = {
      a: {
        type: "no-gps",
        mac: "AA:00:00:00:00:21",
        ssid: "Raw Locked",
        pass: "",
        encryption: "WPA2",
        sources: ["rawsniffer"],
        handshake_files: ["a.22000"],
      },
      b: {
        type: "no-gps",
        mac: "AA:00:00:00:00:22",
        ssid: "Raw No Hash",
        pass: "",
        encryption: "WPA2",
        sources: ["rawsniffer"],
        handshake_files: ["b.pcap"],
      },
      c: {
        type: "no-gps",
        mac: "AA:00:00:00:00:23",
        ssid: "Pwn With Hash",
        pass: "",
        encryption: "WPA2",
        sources: ["pwnagotchi"],
        handshake_files: ["c.22000"],
      },
    };

    updateNoGpsList();

    const lockedText = document.getElementById("no-gps-list-locked").textContent;
    expect(lockedText).toContain("Raw Locked");
    expect(lockedText).not.toContain("Raw No Hash");
    expect(lockedText).not.toContain("Pwn With Hash");
    expect(document.getElementById("no-gps-filter-count").innerText).toBe("1/3");
  });

  test("updateNoGpsList applies search filter and shows empty bucket messages", () => {
    mockState.filters.search = "locked";
    mockState.allPositions = {
      locked: {
        type: "no-gps",
        mac: "AA:11:11:11:11:11",
        ssid: "Locked Open AP",
        pass: "",
        encryption: "OPEN",
        handshake_files: [],
      },
      hidden: {
        type: "no-gps",
        mac: "AA:22:22:22:22:22",
        ssid: "Other AP",
        pass: "",
        encryption: "WPA2",
        handshake_files: [],
      },
    };

    updateNoGpsList();

    const pwnedText = document.getElementById("no-gps-list-pwned").textContent;
    const lockedText = document.getElementById("no-gps-list-locked").textContent;
    expect(pwnedText).toContain("NO CRACKED");
    expect(lockedText).toContain("Locked Open AP");
  });

  test("updateNoGpsList matches MAC search without separators", () => {
    mockState.filters.search = "aa3333333333";
    mockState.allPositions = {
      locked: {
        type: "no-gps",
        mac: "AA:33:33:33:33:33",
        ssid: "MAC Filter AP",
        pass: "",
        encryption: "WPA2",
        handshake_files: [],
      },
      hidden: {
        type: "no-gps",
        mac: "AA:44:44:44:44:44",
        ssid: "Other AP",
        pass: "",
        encryption: "WPA2",
        handshake_files: [],
      },
    };

    updateNoGpsList();

    const lockedText = document.getElementById("no-gps-list-locked").textContent;
    expect(lockedText).toContain("MAC Filter AP");
    expect(lockedText).not.toContain("Other AP");
  });

  test("updateMultiList applies lock filter and updates selected count", () => {
    mockState.multiFilter = "locked";
    mockState.multiSelection = ["AA:AA:AA:AA:AA:02"];
    mockState.allPositions = {
      pwned: {
        mac: "AA:AA:AA:AA:AA:01",
        ssid: "Pwned AP",
        pass: "secret",
        type: "gps",
        handshake_files: ["pwned.pcap"],
      },
      locked: {
        mac: "AA:AA:AA:AA:AA:02",
        ssid: "Locked AP",
        pass: "",
        type: "no-gps",
        handshake_files: ["locked.pcap"],
      },
    };

    updateMultiList();

    const rows = document.querySelectorAll("#multi-all-list .list-item");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("Locked AP");
    expect(document.getElementById("multi-selected-count").innerText).toBe("1");
    expect(rows[0].querySelector(".multi-select-chk").checked).toBe(true);
  });

  test("updateMultiList seeds multiUi defaults and syncs multiFilter", () => {
    mockState.multiFilter = "locked";
    mockState.multiUi = {
      search: null,
      status: null,
      location: null,
      source: null,
      artifact: null,
    };
    mockState.allPositions = {
      locked: {
        mac: "AA:AA:AA:AA:AA:02",
        ssid: "Locked AP",
        pass: "",
        type: "gps",
        encryption: "WPA2",
        handshake_files: ["locked.pcap"],
      },
    };

    updateMultiList();

    expect(mockState.multiUi.search).toBe("");
    expect(mockState.multiUi.location).toBe("all");
    expect(mockState.multiUi.source).toBe("all");
    expect(mockState.multiUi.artifact).toBe("all");
    expect(mockState.multiUi.status).toBe("locked");
    expect(mockState.multiFilter).toBe("locked");
  });

  test("updateMultiList overrides invalid multiFilter from ui state", () => {
    mockState.multiFilter = "custom";
    mockState.multiUi = {
      search: "",
      status: "all",
      location: "all",
      source: "all",
      artifact: "all",
    };
    mockState.allPositions = {
      locked: {
        mac: "AA:AA:AA:AA:AA:02",
        ssid: "Locked AP",
        pass: "",
        type: "gps",
        encryption: "WPA2",
        handshake_files: ["locked.pcap"],
      },
    };

    updateMultiList();

    expect(mockState.multiFilter).toBe("all");
  });

  test("updateMultiList hides OPEN/WEP networks and updates counters/tags", () => {
    mockState.multiFilter = "all";
    mockState.allPositions = {
      open: {
        mac: "AA:AA:AA:AA:AA:10",
        ssid: "Open AP",
        pass: "",
        type: "gps",
        encryption: "OPEN",
        handshake_files: ["open.pcap"],
      },
      wep: {
        mac: "AA:AA:AA:AA:AA:11",
        ssid: "Legacy AP",
        pass: "",
        type: "gps",
        encryption: "WEP",
        handshake_files: ["legacy.pcap"],
      },
      secure: {
        mac: "AA:AA:AA:AA:AA:12",
        ssid: "Secure AP",
        pass: "",
        type: "no-gps",
        encryption: "WPA2",
        handshake_files: ["secure.pcap", "secure.22000"],
        sources: ["pwnagotchi", "bruce_raw"],
      },
    };

    updateMultiList();

    const rows = document.querySelectorAll("#multi-all-list .list-item");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("Secure AP");
    expect(rows[0].textContent).toContain("SEC:WPA2");
    expect(rows[0].textContent).toContain("SRC:PWNAGOTCHI+BRUCEGOTCHI+RAWSNIFFER");
    expect(document.getElementById("multi-visible-count").innerText).toBe("V 1");
    expect(document.getElementById("multi-eligible-count").innerText).toBe("E 1");
    expect(document.getElementById("multi-excluded-open-count").innerText).toBe("X 2");
  });

  test("updateMultiList shows empty eligible message when only open networks exist", () => {
    mockState.multiFilter = "all";
    mockState.allPositions = {
      open: {
        mac: "AA:AA:AA:AA:AA:10",
        ssid: "Open AP",
        pass: "",
        type: "gps",
        encryption: "OPEN",
        handshake_files: ["open.pcap"],
      },
    };

    updateMultiList();

    expect(document.getElementById("multi-all-list").textContent).toContain(
      "NO ELIGIBLE NETWORKS"
    );
  });

  test("updateMultiList initializes multiUi and filters by source/artifact/search", () => {
    mockState.multiUi = null;
    mockState.multiFilter = "all";
    mockState.allPositions = {
      secure: {
        mac: "AA:AA:AA:AA:AA:30",
        ssid: "Secure AP",
        pass: "",
        type: "gps",
        encryption: "WPA2",
        handshake_files: [],
        sources: ["pwnagotchi"],
      },
    };

    updateMultiList();
    expect(mockState.multiUi).toBeTruthy();

    mockState.multiUi = {
      search: "",
      status: "all",
      location: "all",
      source: "ward",
      artifact: "all",
    };
    updateMultiList();
    expect(document.getElementById("multi-all-list").textContent).toContain(
      "NO NETWORKS MATCH CURRENT FILTERS"
    );

    mockState.multiUi = {
      search: "",
      status: "all",
      location: "all",
      source: "all",
      artifact: "has_pcap",
    };
    updateMultiList();
    expect(document.getElementById("multi-all-list").textContent).toContain(
      "NO NETWORKS MATCH CURRENT FILTERS"
    );

    mockState.allPositions.secure.handshake_files = ["secure.22000"];
    mockState.multiUi.artifact = "no_22000";
    updateMultiList();
    expect(document.getElementById("multi-all-list").textContent).toContain(
      "NO NETWORKS MATCH CURRENT FILTERS"
    );

    mockState.multiUi = {
      search: "missing",
      status: "all",
      location: "all",
      source: "all",
      artifact: "all",
    };
    updateMultiList();
    expect(document.getElementById("multi-all-list").textContent).toContain(
      "NO NETWORKS MATCH CURRENT FILTERS"
    );
  });

  test("updateMultiList applies location/source/artifact/search filters", () => {
    mockState.multiFilter = "all";
    mockState.multiUi = {
      search: "ward",
      status: "all",
      location: "no-gps",
      source: "ward",
      artifact: "has_22000",
    };
    mockState.allPositions = {
      wardMatch: {
        mac: "AA:AA:AA:AA:AA:21",
        ssid: "Ward Candidate",
        pass: "",
        type: "no-gps",
        encryption: "WPA2",
        handshake_files: ["ward.pcap", "ward.22000"],
        sources: ["wardrive"],
      },
      wardNoHash: {
        mac: "AA:AA:AA:AA:AA:22",
        ssid: "Ward No Hash",
        pass: "",
        type: "no-gps",
        encryption: "WPA2",
        handshake_files: ["ward2.pcap"],
        sources: ["wardrive"],
      },
      gpsWard: {
        mac: "AA:AA:AA:AA:AA:23",
        ssid: "Ward GPS",
        pass: "",
        type: "gps",
        encryption: "WPA2",
        handshake_files: ["ward3.pcap", "ward3.22000"],
        sources: ["wardrive"],
      },
    };

    updateMultiList();

    const rows = document.querySelectorAll("#multi-all-list .list-item");
    expect(rows.length).toBe(1);
    expect(rows[0].textContent).toContain("Ward Candidate");
  });

  test("updateMultiFilesList supports empty and selected states", () => {
    updateMultiFilesList();
    expect(document.getElementById("multi-files-list").textContent).toContain(
      "NO MULTI FILES"
    );

    mockState.multiFiles = [{ name: "batch_a.22000", size: 4096, count: 3 }];
    mockState.multiSelectedFile = "batch_a.22000";
    updateMultiFilesList();

    const row = document.querySelector('#multi-files-list .list-item[data-name="batch_a.22000"]');
    expect(row).not.toBeNull();
    expect(row.classList.contains("selected")).toBe(true);
    expect(row.textContent).toContain("3 items");
  });

  test("updateMultiContentsList handles no selection, empty and sorted cracked rows", () => {
    updateMultiContentsList();
    expect(document.getElementById("multi-contents-list").textContent).toContain(
      "SELECT A MULTI FILE"
    );

    mockState.multiSelectedFile = "batch_z.22000";
    mockState.multiFileContents = { "batch_z.22000": [] };
    updateMultiContentsList();
    expect(document.getElementById("multi-contents-list").textContent).toContain(
      "NO CONTENTS"
    );

    mockState.multiFileContents = {
      "batch_z.22000": [
        { ssid: "Locked AP", mac: "AA:AA:AA:AA:AA:10", status: "FAILED" },
        {
          ssid: "Cracked AP",
          mac: "AA:AA:AA:AA:AA:11",
          status: "OK",
          cracked: true,
        },
      ],
    };
    updateMultiContentsList();

    const rows = document.querySelectorAll("#multi-contents-list .list-item");
    expect(rows.length).toBe(2);
    expect(rows[0].classList.contains("batch-item-cracked")).toBe(true);
    expect(rows[0].textContent).toContain("Cracked AP");
    expect(rows[0].textContent).toContain("HANDSHAKE OK");
    expect(rows[1].textContent).toContain("CONVERSION FAILED");
  });

  test("updateMultiContentsList applies failed reason class for EAPOL invalid", () => {
    mockState.multiSelectedFile = "batch_error.22000";
    mockState.multiFileContents = {
      "batch_error.22000": [
        {
          ssid: "Broken AP",
          mac: "AA:AA:AA:AA:AA:99",
          status: "FAILED",
          reason: "EAPOL MISSING/INVALID",
        },
      ],
    };

    updateMultiContentsList();

    const reason = document.querySelector("#multi-contents-list .batch-reason-failed");
    expect(reason).not.toBeNull();
    expect(reason.textContent).toContain("EAPOL MISSING/INVALID");
  });

  test("updateZonesList ignores invalid clusters and does not crash without map", () => {
    mockGetMapInstance.mockReturnValue(null);

    updateZonesList([null, { points: [] }, { parts: [] }]);

    expect(document.querySelectorAll("#zones-list .list-item").length).toBe(0);
    expect(document.getElementById("conquered-zone-count").innerText).toBe(0);
    expect(document.getElementById("conquered-zones-divider").style.display).toBe("none");
  });

test("updateTargetsList handles success/failed badges and missing target positions", () => {
  const macOk = "AA:10:10:10:10:10";
  const macFail = "AA:20:20:20:20:20";
  const macMissing = "AA:30:30:30:30:30";

    mockState.lists.targets = [macOk, macFail, macMissing];
    mockState.allPositions = {
      one: { mac: macOk, ssid: "OkNet" },
      two: { mac: macFail, ssid: "FailNet" },
    };
    mockActiveProcesses["job-ok"] = {
      details: "oknet",
      status: "CRACKED",
    };
    mockActiveProcesses["job-fail"] = {
      details: "failnet",
      status: "FAILED",
    };

    updateTargetsList();

    const rows = document.querySelectorAll("#targets-list .list-item");
  expect(rows.length).toBe(2);
  expect(rows[0].textContent + rows[1].textContent).toContain("CRACKED");
  expect(rows[0].textContent + rows[1].textContent).toContain("FAILED");
});

test("updateTargetsList maps success and exhausted statuses", () => {
  const macSuccess = "AA:40:40:40:40:40";
  const macExhausted = "AA:50:50:50:50:50";

  mockState.lists.targets = [macSuccess, macExhausted];
  mockState.allPositions = {
    one: { mac: macSuccess, ssid: "SuccessNet" },
    two: { mac: macExhausted, ssid: "ExhaustedNet" },
  };
  mockActiveProcesses["job-success"] = {
    details: macSuccess.replace(/:/g, "").toLowerCase(),
    status: "SUCCESS",
  };
  mockActiveProcesses["job-exhausted"] = {
    details: "exhaustednet",
    status: "EXHAUSTED",
  };

  updateTargetsList();

  const text = document.getElementById("targets-list").textContent;
  expect(text).toContain("SUCCESS");
  expect(text).toContain("NOT FOUND");
});

  test("updateFavsList removes stale rows when favorites change", () => {
    const list = document.getElementById("favs-list");
    list.innerHTML = `
      <div class="list-item" data-mac="AA:AA:AA:AA:AA:AA"></div>
      <div class="list-item" data-mac="BB:BB:BB:BB:BB:BB"></div>
    `;

    mockState.lists.favs = ["AA:AA:AA:AA:AA:AA"];
    mockState.allPositions = {
      one: { mac: "AA:AA:AA:AA:AA:AA", ssid: "Fav Kept" },
    };

    updateFavsList();
    expect(document.querySelectorAll("#favs-list .list-item").length).toBe(1);
  });

  test("updateNoGpsList safely returns when required containers are missing and covers hidden/open icons", () => {
    document.getElementById("no-gps-list-pwned").remove();
    updateNoGpsList();

    mountListsDom();
    mockState.allPositions = {
      hidden: {
        type: "no-gps",
        mac: "AA:44:44:44:44:44",
        ssid: "",
        pass: "",
        encryption: "WPA2",
        handshake_files: [],
      },
      open: {
        type: "no-gps",
        mac: "AA:55:55:55:55:55",
        ssid: "Open AP",
        pass: "",
        encryption: "OPEN",
        handshake_files: ["open.pcap"],
      },
    };

    updateNoGpsList();

    const lockedText = document.getElementById("no-gps-list-locked").textContent;
    expect(lockedText).toContain("HIDDEN");
    expect(lockedText).toContain("Open AP");
    expect(lockedText).toContain("PCAP");
  });

  test("updateMultiList handles missing list node and disables selection when no pcap", () => {
    document.getElementById("multi-all-list").remove();
    updateMultiList();

    mountListsDom();
    mockState.multiSelection = ["AA:66:66:66:66:66"];
    mockState.allPositions = {
      b: {
        mac: "AA:66:66:66:66:66",
        ssid: "Beta",
        pass: "",
        type: "gps",
        handshake_files: [],
      },
      a: {
        mac: "AA:77:77:77:77:77",
        ssid: "Alpha",
        pass: "",
        type: "gps",
        handshake_files: ["alpha.pcap"],
      },
    };

    updateMultiList();
    const rows = document.querySelectorAll("#multi-all-list .list-item");
    expect(rows.length).toBe(2);
    expect(rows[0].textContent).toContain("Alpha");
    const betaChk = rows[1].querySelector(".multi-select-chk");
    expect(betaChk.disabled).toBe(true);
  });

  test("updateMultiFilesList and updateMultiContentsList cover optional fields and fallback labels", () => {
    mockState.multiFiles = [{ name: "batch_optional.22000", size: 2048 }];
    updateMultiFilesList();
    expect(document.getElementById("multi-files-list").textContent).toContain("batch_optional.22000");

    mockState.multiSelectedFile = "batch_optional.22000";
    mockState.multiFileContents = {
      "batch_optional.22000": [
        { filename: "unknown_file", status: "FAILED", reason: "EMPTY OUTPUT" },
        { ssid: "Known AP", mac: "", status: "OK", cracked: true },
      ],
    };

    updateMultiContentsList();
    const rows = document.querySelectorAll("#multi-contents-list .list-item");
    expect(rows.length).toBe(2);
    expect(document.getElementById("multi-contents-list").textContent).toContain("unknown_file");
    expect(document.getElementById("multi-contents-list").textContent).toContain("EMPTY OUTPUT");
  });

  test("updateTargetsList handles existing rows without item-name and processes without details", () => {
    const mac = "AA:88:88:88:88:88";
    mockState.lists.targets = [mac];
    mockState.allPositions = { one: { mac, ssid: "Existing Row" } };
    mockActiveProcesses["job-empty"] = { details: "", status: "RUNNING" };

    document.getElementById("targets-list").innerHTML = `
      <div class="list-item" data-mac="${mac}">
        <div class="other-node"></div>
      </div>
    `;

    updateTargetsList();
    expect(document.querySelectorAll("#targets-list .list-item").length).toBe(1);
  });

  test("updateZonesList click flow uses hull when present and safely skips empty part sources", () => {
    const fitBounds = jest.fn();
    mockGetMapInstance.mockReturnValue({ fitBounds });

    updateZonesList([
      {
        count: 2,
        points: [{ lat: -23.0, lng: -43.0 }],
        hull: [
          { lat: -23.1, lng: -43.1 },
          { lat: -23.2, lng: -43.2 },
          { lat: -23.3, lng: -43.3 },
        ],
      },
      {
        count: 1,
        parts: [null],
      },
    ]);

    const rows = document.querySelectorAll("#conquered-zones-section .list-item");
    expect(rows.length).toBe(2);

    rows[0].dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(global.L.latLngBounds).toHaveBeenCalledTimes(1);
    expect(fitBounds).toHaveBeenCalledTimes(1);

    rows[1].dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(fitBounds).toHaveBeenCalledTimes(1);
  });

  test("updateNoGpsList shows NO LOCKED and uses icon fallbacks when config icons are empty", () => {
    const prevPwnedIcon = mockUiConfig.iconPwned;
    const prevLockedIcon = mockUiConfig.iconLocked;
    mockUiConfig.iconPwned = "";
    mockUiConfig.iconLocked = "";
    mockState.allPositions = {
      pwned: {
        type: "no-gps",
        mac: "AA:90:90:90:90:90",
        ssid: "Pwned",
        pass: "12345678",
        encryption: "WPA2",
        handshake_files: [],
      },
      locked: {
        type: "no-gps",
        mac: "AA:91:91:91:91:91",
        ssid: "Locked WPA2",
        pass: "",
        encryption: "WPA2",
        handshake_files: [],
      },
    };

    updateNoGpsList();
    const lockedIconHtml = document.getElementById("no-gps-list-locked").innerHTML;
    expect(lockedIconHtml).toContain("fa-shield-halved");

    mockState.allPositions = {
      onlyPwned: {
        type: "no-gps",
        mac: "AA:92:92:92:92:92",
        ssid: "Only Pwned",
        pass: "secret",
        encryption: "WPA2",
        handshake_files: [],
      },
    };
    updateNoGpsList();

    const pwnedIconHtml = document.getElementById("no-gps-list-pwned").innerHTML;
    expect(pwnedIconHtml).toContain("fa-skull");
    expect(document.getElementById("no-gps-list-locked").textContent).toContain("NO LOCKED");

    mockUiConfig.iconPwned = prevPwnedIcon;
    mockUiConfig.iconLocked = prevLockedIcon;
  });

  test("updateMultiFilesList and updateMultiContentsList exit early when containers are missing", () => {
    document.getElementById("multi-files-list").remove();
    document.getElementById("multi-contents-list").remove();
    expect(() => updateMultiFilesList()).not.toThrow();
    expect(() => updateMultiContentsList()).not.toThrow();
  });
});
