const mockAPI = {};
const mockMap = {
  focusReconGeoHypothesis: jest.fn(),
};

jest.mock("../../src/modules/state.js", () => ({
  STATE: {
    lists: { targets: [] },
    modes: { analytics: false },
    ui: {},
    allPositions: {},
    lastDataHash: "",
    reconUi: { activeTab: "attack-surface", selectedMac: null },
  },
  saveLists: jest.fn(),
}));

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: jest.fn(),
  escapeHtml: (value) => String(value ?? ""),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  addProcess: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: jest.fn(),
}));

jest.mock("../../src/modules/map.js", () => mockMap);

const reconModule = require("../../src/modules/ui_recon.js");
const { __test } = reconModule;

describe("ui_recon compact renderers", () => {
  beforeEach(() => {
    const { STATE } = require("../../src/modules/state.js");
    sessionStorage.clear();
    document.body.innerHTML = "";
    STATE.modes.analytics = false;
    STATE.reconUi.activeTab = "attack-surface";
    STATE.reconUi.selectedMac = null;
    mockAPI.getReconProbeDerandom = jest.fn().mockResolvedValue({ groups: [] });
    mockAPI.getReconProbeGeocorrelation = jest.fn().mockResolvedValue({ clients: [], summary: {} });
    mockAPI.getReconKillChainSummary = jest.fn();
    mockAPI.getReconKillChainStage = jest.fn();
    mockAPI.getReconTargetDetail = jest.fn();
    mockAPI.getReconCacheManifest = jest.fn().mockResolvedValue({ scope: "scope-a" });
    mockMap.focusReconGeoHypothesis.mockReset();
  });

  test("renderReconSecurityMiniBar builds stacked segments and totals", () => {
    const html = __test._renderReconSecurityMiniBar(
      { WPA2: 4, Open: 2, Unknown: 1 },
      { title: "Security", compact: true, legendLimit: 3 }
    );

    const root = document.createElement("div");
    root.innerHTML = html;

    expect(root.querySelector(".recon-security-mini-total").textContent).toBe("7");
    expect(root.querySelectorAll(".recon-security-mini-segment")).toHaveLength(3);
    expect(root.textContent).toContain("WPA2");
    expect(root.textContent).toContain("OPEN");
    expect(root.textContent).toContain("UNKNOWN");
  });

  test("renderCommsDeviceIntel keeps metrics fixed and removes expandable details", () => {
    const html = __test._renderCommsDeviceIntel(
      {
        total: 10,
        raw_activity: { beacons: 5, eapol: 2, probes: 9 },
        by_type: [
          {
            type: "router_ap",
            count: 4,
            encryption: { WPA2: 3, Open: 1 },
            channel_distribution: { 6: 3, 11: 1 },
            rssi_stats: { min: -81, avg: -63.5, max: -42 },
            sample_networks: [
              { ssid: "Alpha", mac: "AA:AA:AA:AA:AA:AA" },
            ],
          },
        ],
      },
      ""
    );

    const root = document.createElement("div");
    root.innerHTML = html;

    expect(root.querySelectorAll(".recon-comms-device-card")).toHaveLength(1);
    expect(root.querySelector(".recon-comms-device-tag").textContent).toContain("router_ap");
    expect(root.textContent).toContain("CH6 (3)");
    expect(root.textContent).toContain("-81 / -63.5 / -42");
    expect(root.textContent).toContain("40% of total");
    expect(root.querySelector("[data-comms-toggle]")).toBeNull();
    expect(root.textContent).not.toContain("Networks:");
    expect(root.textContent).not.toContain("Alpha");
    expect(root.textContent).not.toContain("Acme Wireless");
    expect(root.textContent).not.toContain("TOP VENDORS");
  });

  test("renderCommsTopVendors renders vendor cards as its own section content", () => {
    const html = __test._renderCommsTopVendors(
      {
        total: 10,
        by_oui: [
          {
            vendor: "Acme Wireless",
            count: 4,
            oui_prefixes: ["00:11:22"],
            encryption: { WPA2: 3, Open: 1 },
            sample_macs: [
              { mac: "00:11:22:33:44:55", ssid: "Alpha" },
            ],
          },
        ],
      },
      ""
    );

    const root = document.createElement("div");
    root.innerHTML = html;

    expect(root.querySelectorAll(".recon-oui-card")).toHaveLength(1);
    expect(root.textContent).toContain("Acme Wireless");
    expect(root.textContent).toContain("00:11:22");
    expect(root.textContent).toContain("Alpha");
    expect(root.textContent).toContain("Security");
  });

  test("renderCommsClusters explains mixed labels and shows compact security summary", () => {
    const html = __test._renderCommsClusters(
      {
        total_located: 3,
        clusters: [
          {
            label: "Mixed",
            count: 3,
            radius_m: 22.4,
            dominant_encryption: "WPA2",
            avg_rssi: -58.3,
            source_breakdown: { wardrive: 2, pwnagotchi: 1 },
            device_breakdown: { router_ap: 2, camera: 1 },
            encryption_breakdown: { WPA2: 2, Open: 1 },
            networks: [
              { ssid: "Cafe Alpha", mac: "AA:AA:AA:AA:AA:AA", encryption: "WPA2" },
              { ssid: "Office Beta", mac: "BB:BB:BB:BB:BB:BB", encryption: "OPEN" },
            ],
          },
        ],
      },
      ""
    );

    const root = document.createElement("div");
    root.innerHTML = html;

    expect(root.querySelector(".recon-comms-cluster-hint").textContent).toContain("50%");
    expect(root.querySelector(".recon-comms-cluster-origins")).not.toBeNull();
    expect(root.querySelector(".recon-comms-cluster-devices")).not.toBeNull();
    expect(root.querySelector(".recon-comms-cluster-security")).not.toBeNull();
    expect(root.textContent).toContain("Wardrive");
    expect(root.textContent).toContain("Pwnagotchi");
    expect(root.textContent).toContain("Router/AP");
    expect(root.textContent).toContain("Camera");
    expect(root.textContent).toContain("Dominant");
    expect(root.querySelector("[data-comms-toggle]")).toBeNull();
  });

  test("renderReconFindingsPanel uses compact dashboard panels instead of report rows", () => {
    const html = __test._renderReconFindingsPanel({
      total_networks: 12,
      cracked: 4,
      crackable_remaining: 5,
      with_handshake: 7,
      with_eapol_evidence: 6,
      crack_rate_percent: 33.3,
      encryption_distribution: { WPA2: 8, OPEN: 2, WPA3: 2 },
      device_distribution: { router_ap: 6, camera: 3, iot: 2, bridge: 1 },
    });

    const root = document.createElement("div");
    root.innerHTML = html;

    expect(root.querySelector(".recon-findings-grid")).not.toBeNull();
    expect(root.querySelectorAll(".recon-findings-panel")).toHaveLength(3);
    expect(root.querySelectorAll(".recon-findings-kpi")).toHaveLength(6);
    expect(root.querySelector(".recon-findings-donut")).not.toBeNull();
    expect(root.querySelectorAll(".recon-findings-device-row").length).toBeGreaterThan(0);
    expect(root.querySelector(".recon-report-row")).toBeNull();
  });

  test("renderSigintData clarifies probe intelligence scope and enriches ssid/client context", async () => {
    const container = document.createElement("div");
    document.body.appendChild(container);

    __test._renderSigintData(
      container,
      {
        summary: {
          total_probes: 12,
          unique_clients: 3,
          unique_ssids: 2,
          broadcast_probes: 1,
          pcaps_scanned: 2,
        },
        ssids: [
          {
            ssid: "HomeNet",
            client_count: 3,
            probe_count: 5,
            is_known: true,
            name_shape: "human",
            known_context: {
              network_count: 2,
              sample_mac: "aa:bb:cc:dd:ee:01",
              dominant_encryption: "WPA2",
              dominant_device_type: "router_ap",
              sources: ["wardrive", "pwnagotchi"],
            },
          },
          {
            ssid: "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            client_count: 1,
            probe_count: 2,
            is_known: false,
            name_shape: "uuid_like",
            known_context: {
              network_count: 0,
              sample_mac: null,
              dominant_encryption: null,
              dominant_device_type: null,
              sources: [],
            },
          },
        ],
        clients: [
          {
            client_mac: "00:11:22:33:44:55",
            oui_prefix: "00:11:22",
            vendor: "Acme Wireless",
            ssids_probed: ["HomeNet", "3fa85f64-5717-4562-b3fc-2c963f66afa6"],
            known_ssid_count: 1,
            unmatched_ssid_count: 1,
            known_ssid_preview: ["HomeNet"],
            unmatched_ssid_preview: ["3fa85f64-5717-4562-b3fc-2c963f66afa6"],
            probe_count: 2,
            avg_signal: -50,
            first_seen: 1712000100,
            last_seen: 1712000500,
          },
        ],
      },
      new Set(["homenet"])
    );

    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(container.textContent).toContain("UNMATCHED TARGET SSIDs");
    expect(container.textContent).toContain("MOST PROBED SSIDs");
    expect(container.textContent).toContain("TOP PROBING CLIENTS");
    expect(container.textContent).toContain("Probe Intelligence view");
    expect(container.textContent).toContain("Known network");
    expect(container.textContent).toContain("Router/AP");
    expect(container.textContent).toContain("Acme Wireless");
    expect(container.textContent).toContain("1 known");
    expect(container.textContent).toContain("1 unmatched");
    expect(container.textContent).toContain("UUID-like");
    expect(container.querySelectorAll(".ui-hint-trigger").length).toBeGreaterThan(0);
    container.remove();
  });

  test("renderSigintData renders likely device groups with friendly labels", async () => {
    mockAPI.getReconProbeDerandom = jest.fn().mockResolvedValue({
      groups: [
        {
          group_label: "Likely Device 01",
          confidence: "high",
          total_macs: 2,
          rule_summary: "2 randomized MACs share 3 probed SSIDs.",
          first_seen: 1712000100,
          last_seen: 1712000500,
          ssid_fingerprint: ["NetA", "NetB", "NetC"],
          known_ssid_count: 2,
          known_ssid_preview: ["NetA", "NetC"],
          members: [
            {
              mac: "d2:ab:cd:ef:00:01",
              is_random: true,
              vendor: "Acme Wireless",
              probe_count: 5,
              avg_signal: -50,
            },
            {
              mac: "f6:ab:cd:ef:00:02",
              is_random: true,
              vendor: "Acme Wireless",
              probe_count: 4,
              avg_signal: -55,
            },
          ],
        },
      ],
    });

    const container = document.createElement("div");
    document.body.appendChild(container);
    __test._renderSigintData(
      container,
      {
        summary: {
          total_probes: 5,
          unique_clients: 2,
          unique_ssids: 3,
          broadcast_probes: 0,
          pcaps_scanned: 1,
        },
        ssids: [],
        clients: [],
      },
      new Set()
    );

    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(container.textContent).toContain("LIKELY DEVICE GROUPS");
    expect(container.textContent).toContain("Likely Device 01");
    expect(container.textContent).toContain("2 randomized MACs share 3 probed SSIDs.");
    expect(container.textContent).toContain("Randomized");
    expect(container.textContent).toContain("Acme Wireless");
    expect(container.textContent).toContain("NetA");
    expect(container.querySelectorAll(".recon-derandom-card")).toHaveLength(1);
    container.remove();
  });

  test("renderSigintData renders probe geocorrelation cards and focuses map", async () => {
    mockAPI.getReconProbeGeocorrelation = jest.fn().mockResolvedValue({
      summary: {
        correlated_clients: 1,
        high_confidence_clients: 1,
        matched_networks: 3,
        median_radius_m: 85,
      },
      clients: [
        {
          client_mac: "52:ab:cd:ef:00:01",
          oui_prefix: "52:ab:cd",
          vendor: "Acme Wireless",
          probe_count: 5,
          total_probed_ssids: 4,
          match_count: 3,
          matched_ssid_count: 3,
          known_match_ratio: 0.75,
          estimated_center: { lat: 40.0, lng: -74.0 },
          estimated_radius_m: 85,
          confidence: "high",
          ambiguity_level: "low",
          alternative_cluster_count: 1,
          first_seen: 1712000100,
          last_seen: 1712000500,
          source_breakdown: { wardrive: 2, pwnagotchi: 1 },
          security_breakdown: { WPA2: 2, Open: 1 },
          located_ssids: [
            {
              ssid: "NetA",
              network_count: 2,
              dominant_encryption: "WPA2",
              dominant_device_type: "router_ap",
              sources: ["wardrive"],
              lat: 40.0001,
              lng: -74.0001,
              distance_to_center_m: 20,
            },
            {
              ssid: "NetC",
              network_count: 1,
              dominant_encryption: "OPEN",
              dominant_device_type: "camera",
              sources: ["pwnagotchi"],
              lat: 40.0003,
              lng: -74.0002,
              distance_to_center_m: 44,
            },
          ],
        },
      ],
    });

    const container = document.createElement("div");
    document.body.appendChild(container);
    __test._renderSigintData(
      container,
      {
        summary: {
          total_probes: 8,
          unique_clients: 1,
          unique_ssids: 4,
          broadcast_probes: 0,
          pcaps_scanned: 1,
        },
        ssids: [],
        clients: [],
      },
      new Set()
    );

    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(container.textContent).toContain("PROBE GEO-CORRELATION");
    expect(container.textContent).toContain("CORRELATED");
    expect(container.textContent).toContain("Acme Wireless");
    expect(container.textContent).toContain("Known SSIDs");
    expect(container.textContent).toContain("Focus on map");
    expect(container.textContent).toContain("Origins");
    expect(container.textContent).toContain("Security");
    expect(container.querySelectorAll(".recon-geocorr-card")).toHaveLength(1);

    container.querySelector(".recon-geocorr-focus-btn").click();
    expect(mockMap.focusReconGeoHypothesis).toHaveBeenCalledWith({
      center: { lat: 40.0, lng: -74.0 },
      radius_m: 85,
      points: [
        { lat: 40.0001, lng: -74.0001 },
        { lat: 40.0003, lng: -74.0002 },
      ],
    });
    container.remove();
  });

  test("renderCommsGraph explains when probe intelligence is not ready", () => {
    const html = __test._renderCommsGraph({
      nodes: [
        { id: "aa:bb:cc:dd:ee:ff", type: "ap", label: "HomeNet", has_password: false, encryption: "WPA2" },
      ],
      edges: [],
      ap_count: 1,
      client_count: 0,
      ssid_target_count: 0,
      probe_context: {
        cached: false,
        available: false,
        pcap_count: 3,
        summary: {},
      },
    });

    const root = document.createElement("div");
    root.innerHTML = html;

    expect(root.textContent).toContain("Probe intelligence not ready yet");
    expect(root.textContent).toContain("SIGINT");
    expect(root.textContent).toContain("3 PCAPs found");
    expect(root.querySelector("#recon-graph-canvas")).toBeNull();
  });

  test("renderCommsGraph shows known and unresolved probe context", () => {
    const html = __test._renderCommsGraph({
      nodes: [
        { id: "ap_1", type: "ap", label: "CafeNet", has_password: false, encryption: "WPA2" },
        { id: "ssid_guest", type: "ssid_target", label: "GuestPortal" },
        { id: "client_1", type: "client", label: "52:ab:cd:ef:00:01", probe_count: 5, avg_signal: -60 },
      ],
      edges: [
        { source: "client_1", target: "ap_1", type: "probe_known" },
        { source: "client_1", target: "ssid_guest", type: "probe_unknown" },
      ],
      ap_count: 1,
      client_count: 1,
      ssid_target_count: 1,
      probe_context: {
        cached: true,
        available: true,
        stale: false,
        pcap_count: 2,
        summary: {
          total_probes: 5,
          pcaps_scanned: 2,
        },
      },
    });

    const root = document.createElement("div");
    root.innerHTML = html;

    expect(root.textContent).toContain("Probe-to-network relationship map");
    expect(root.textContent).toContain("UNRESOLVED SSIDs");
    expect(root.textContent).toContain("KNOWN LINKS");
    expect(root.textContent).toContain("UNRESOLVED LINKS");
    expect(root.textContent).toContain("Most linked APs");
    expect(root.textContent).toContain("Unresolved probe targets");
    expect(root.querySelector("#recon-graph-canvas")).not.toBeNull();
    expect(root.querySelector("#recon-graph-detail")).not.toBeNull();
  });

  test("tab cache persists in session storage and is invalidated by manifest scope changes", () => {
    __test._applyReconCacheManifest({ scope: "scope-a" });
    __test._tdc_set("reports", { generated_at: "now" });
    __test._clearReconPayloadCaches({ clearSession: false, clearManifest: false });

    expect(__test._tdc_get("reports")).toEqual({ generated_at: "now" });

    __test._applyReconCacheManifest({ scope: "scope-b" });
    expect(__test._tdc_get("reports")).toBeNull();
  });

  test("renderAttackSurface shows preview targets immediately and paginates stage expansion", async () => {
    mockAPI.getReconKillChainSummary.mockResolvedValue({
      total: 3,
      hash_intel: { total_with_hash: 1, total_pmkid: 1, total_eapol_hash: 0, pmkid_only: 1, eapol_only: 0, both: 0 },
      stages: [
        {
          stage: "discovered",
          count: 4,
          preview_count: 2,
          preview_networks: [
            { mac: "AA:AA:AA:AA:AA:01", ssid: "Alpha", encryption: "WPA2" },
            { mac: "AA:AA:AA:AA:AA:02", ssid: "Beta", encryption: "OPEN" },
          ],
        },
        { stage: "captured", count: 1, preview_count: 1, preview_networks: [{ mac: "AA:AA:AA:AA:AA:03", ssid: "CaptureOne", encryption: "WPA2" }] },
        { stage: "fingerprinted", count: 0, preview_count: 0, preview_networks: [] },
        { stage: "hash_ready", count: 0, preview_count: 0, preview_networks: [] },
        { stage: "under_attack", count: 0, preview_count: 0, preview_networks: [] },
        { stage: "cracked", count: 0, preview_count: 0, preview_networks: [] },
      ],
    });
    mockAPI.getReconKillChainStage.mockResolvedValue({
      stage: "discovered",
      total: 4,
      offset: 2,
      limit: 50,
      networks: [
        { mac: "AA:AA:AA:AA:AA:04", ssid: "Gamma", encryption: "WPA2" },
        { mac: "AA:AA:AA:AA:AA:05", ssid: "Delta", encryption: "OPEN" },
      ],
    });

    const container = document.createElement("div");
    document.body.appendChild(container);

    await __test.renderAttackSurface(container);
    expect(mockAPI.getReconKillChainSummary).toHaveBeenCalledTimes(1);
    expect(mockAPI.getReconKillChainStage).not.toHaveBeenCalled();
    expect(container.textContent).toContain("Alpha");
    expect(container.textContent).toContain("Beta");
    expect(container.textContent).toContain("Load more");

    container.querySelector('.recon-expand-btn[data-load-stage="discovered"]').click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(mockAPI.getReconKillChainStage).toHaveBeenCalledWith({
      stage: "discovered",
      search: "",
      limit: 50,
      offset: 2,
    });
    expect(container.textContent).toContain("Gamma");
    expect(container.textContent).toContain("Delta");
    container.remove();
  });

  test("refreshReconPanel renders cached surface immediately without waiting for manifest revalidation", async () => {
    const { STATE } = require("../../src/modules/state.js");
    STATE.modes.analytics = true;
    STATE.reconUi.activeTab = "attack-surface";
    STATE.reconUi.selectedMac = null;

    document.body.innerHTML = `
      <div class="panel-split-content">
        <div class="panel-split-col panel-split-col--recon-left">
          <div id="recon-tab-content"></div>
        </div>
        <div class="panel-split-divider"></div>
        <div class="panel-split-col panel-split-col--recon-right">
          <div id="recon-right-content"></div>
        </div>
      </div>
      <div id="recon-drawer" class="recon-drawer">
        <div id="recon-drawer-content"></div>
      </div>
    `;

    __test._applyReconCacheManifest({ scope: "scope-a" });
    __test._tdc_set("attack-surface:summary", {
      total: 1,
      hash_intel: { total_with_hash: 0, total_pmkid: 0, total_eapol_hash: 0, pmkid_only: 0, eapol_only: 0, both: 0 },
      stages: [
        {
          stage: "discovered",
          count: 1,
          preview_count: 1,
          preview_networks: [{ mac: "AA:AA:AA:AA:AA:01", ssid: "CachedNet", encryption: "WPA2" }],
        },
        { stage: "captured", count: 0, preview_count: 0, preview_networks: [] },
        { stage: "fingerprinted", count: 0, preview_count: 0, preview_networks: [] },
        { stage: "hash_ready", count: 0, preview_count: 0, preview_networks: [] },
        { stage: "under_attack", count: 0, preview_count: 0, preview_networks: [] },
        { stage: "cracked", count: 0, preview_count: 0, preview_networks: [] },
      ],
    });
    mockAPI.getReconCacheManifest.mockImplementation(() => new Promise(() => {}));

    await reconModule.refreshReconPanel();

    expect(document.getElementById("recon-tab-content").textContent).toContain("CachedNet");
    expect(document.getElementById("recon-drawer").classList.contains("recon-drawer--hidden")).toBe(true);
    document.body.innerHTML = "";
  });

  test("syncReconLayoutState keeps target details hidden on surface boot without selection", () => {
    const { STATE } = require("../../src/modules/state.js");
    STATE.reconUi.selectedMac = null;
    document.body.innerHTML = `
      <div class="panel-split-content">
        <div class="panel-split-col panel-split-col--recon-left">
          <div id="recon-tab-content"></div>
        </div>
        <div class="panel-split-divider"></div>
        <div class="panel-split-col panel-split-col--recon-right">
          <div id="recon-right-content"></div>
        </div>
      </div>
      <div id="recon-drawer" class="recon-drawer"></div>
    `;

    __test._syncReconLayoutState("attack-surface");

    expect(document.getElementById("recon-drawer").classList.contains("recon-drawer--hidden")).toBe(true);
    expect(document.querySelector(".panel-split-content").classList.contains("recon-drawer-active")).toBe(true);
    document.body.innerHTML = "";
  });

  test("selectTarget fetches target detail without falling back to vulnerability matrix", async () => {
    const { STATE } = require("../../src/modules/state.js");
    STATE.reconUi.activeTab = "operations";
    STATE.allPositions = {
      "AA:BB:CC:DD:EE:01": {
        ssid: "HomeNet",
        encryption: "WPA2",
        device_type: "router_ap",
        sources: ["wardrive"],
      },
    };

    mockAPI.getReconTargetDetail.mockResolvedValue({
      mac: "AA:BB:CC:DD:EE:01",
      ssid: "HomeNet",
      encryption: "WPA2",
      stage: "hash_ready",
      attack_score: 82,
      readiness_status: "ready",
      readiness_score: 80,
      device_type: "router_ap",
      sources: ["wardrive"],
      has_handshake: true,
      raw_eapol: 2,
      raw_beacon: 10,
      has_password: false,
      has_pmkid: true,
      has_eapol_hash: false,
      pmkid_count: 1,
      eapol_hash_count: 0,
      flags: [],
      akm: [],
      lat: null,
      lng: null,
    });
    mockAPI.getReconAttackEffectiveness = jest.fn().mockResolvedValue({ crack_velocity: [] });
    mockAPI.getReconVulnerabilityMatrix = jest.fn();

    const panel = document.createElement("div");
    panel.id = "recon-right-content";
    document.body.appendChild(panel);

    await __test.selectTarget("AA:BB:CC:DD:EE:01");
    expect(mockAPI.getReconTargetDetail).toHaveBeenCalledTimes(1);
    expect(mockAPI.getReconVulnerabilityMatrix).not.toHaveBeenCalled();
    expect(panel.textContent).toContain("HomeNet");

    await __test.selectTarget("AA:BB:CC:DD:EE:01");
    expect(mockAPI.getReconTargetDetail).toHaveBeenCalledTimes(1);
    panel.remove();
  });
});
