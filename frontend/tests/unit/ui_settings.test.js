const mockAPI = {
  getConfig: jest.fn(),
  getHashcatDevices: jest.fn(),
  getDemoDataStatus: jest.fn(),
  saveConfig: jest.fn(),
  probePwnagotchiSync: jest.fn(),
  probeM5EvilSync: jest.fn(),
  probeBruceSync: jest.fn(),
};

const mockLog = jest.fn();
const mockSetMarkerIcons = jest.fn();
const mockSetClusterConfig = jest.fn();
const mockUpdateNoGpsList = jest.fn();
const mockState = {
  modes: { noGps: false },
  ui: { hidePasswords: false },
};

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/utils.js", () => ({
  log: (...args) => mockLog(...args),
}));

jest.mock("../../src/modules/map.js", () => ({
  setMarkerIcons: (...args) => mockSetMarkerIcons(...args),
  setClusterConfig: (...args) => mockSetClusterConfig(...args),
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: mockState,
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => ({
  updateNoGpsList: (...args) => mockUpdateNoGpsList(...args),
}));

function mountSettingsDom() {
  document.body.innerHTML = `
    <div id="hud-layer"></div>
    <div id="settings-modal" style="display:none">
      <button id="btn-conf-pwn-test" type="button">test</button>
      <div id="conf-pwn-test-status"></div>
      <button id="btn-conf-m5-test" type="button">test</button>
      <div id="conf-m5-test-status"></div>
      <button id="btn-conf-bruce-test" type="button">test</button>
      <div id="conf-bruce-test-status"></div>
      <div id="demo-data-status"></div>
      <div id="demo-data-summary"></div>
      <button id="btn-install-demo-data" type="button">install</button>
      <button id="btn-remove-demo-data" type="button">remove</button>
    </div>
    <details id="settings-advanced"></details>

    <input id="conf-ip" value="" />
    <input id="conf-port" value="" />
    <input id="conf-user" value="" />
    <input id="conf-pass" value="" />
    <input id="conf-path" value="" />
    <input id="conf-m5-host" value="" />
    <input id="conf-m5-port" value="" />
    <input id="conf-m5-user" value="" />
    <input id="conf-m5-password" value="" />
    <input id="conf-bruce-host" value="" />
    <input id="conf-bruce-port" value="" />
    <input id="conf-bruce-user" value="" />
    <input id="conf-bruce-password" value="" />
    <input id="conf-hashcat" value="" />
    <input id="conf-hcx" value="" />
    <input id="conf-aircrack" value="" />
    <input id="conf-tshark" value="" />
    <input id="conf-custom-wordlists" value="" />
    <input id="conf-custom-rules" value="" />
    <input id="conf-custom-masks" value="" />
    <input id="conf-known-hosts" value="" />

    <input id="conf-wsl" type="checkbox" />
    <input id="conf-pwn-enabled" type="checkbox" />
    <input id="conf-force-sync" type="checkbox" />
    <input id="conf-m5-enabled" type="checkbox" />
    <input id="conf-m5-force-sync" type="checkbox" />
    <input id="conf-bruce-enabled" type="checkbox" />
    <input id="conf-bruce-force-sync" type="checkbox" />
    <input id="conf-optimized" type="checkbox" />
    <input id="conf-slow" type="checkbox" />
    <input id="conf-potfile" type="checkbox" />
    <input id="conf-hide-passwords" type="checkbox" />
    <input id="conf-wardrive-replay-autoplay" type="checkbox" />
    <input id="conf-wardrive-replay-auto-focus" type="checkbox" />
    <input id="conf-wardrive-replay-follow-camera-default" type="checkbox" />
    <input id="conf-wardrive-merge-confirmation" type="checkbox" />

    <select id="conf-map-tile">
      <option value="carto_dark">carto_dark</option>
      <option value="osm">osm</option>
    </select>

    <select id="conf-map-cluster">
      <option value="surgical">surgical</option>
      <option value="adaptive">adaptive</option>
    </select>

    <select id="conf-hashcat-device"></select>
    <select id="conf-attack-mode">
      <option value="straight">straight</option>
      <option value="hybrid_mask_profile">hybrid_mask_profile</option>
    </select>
    <select id="conf-workload-profile">
      <option value="1">1</option>
      <option value="3">3</option>
      <option value="4">4</option>
    </select>

    <select id="conf-ui-theme">
      <option value="cyan">cyan</option>
      <option value="purple">purple</option>
      <option value="green">green</option>
      <option value="pink">pink</option>
      <option value="orange">orange</option>
    </select>

    <select id="conf-ui-visual-theme">
      <option value="cyberpunk">cyberpunk</option>
      <option value="professional">professional</option>
      <option value="synthwave">synthwave</option>
      <option value="military">military</option>
    </select>

    <select id="conf-icon-pwned">
      <option value="fa-skull">fa-skull</option>
      <option value="fa-bolt">fa-bolt</option>
    </select>

    <select id="conf-icon-locked">
      <option value="fa-shield-halved">fa-shield-halved</option>
      <option value="fa-lock">fa-lock</option>
    </select>

    <select id="conf-icon-open">
      <option value="fa-bolt">fa-bolt</option>
      <option value="fa-wifi">fa-wifi</option>
    </select>

    <select id="conf-icon-wardrive">
      <option value="fa-tower-broadcast">fa-tower-broadcast</option>
      <option value="fa-satellite-dish">fa-satellite-dish</option>
    </select>

    <select id="conf-wardrive-color">
      <option value="teal">teal</option>
      <option value="cyan">cyan</option>
    </select>

    <select id="conf-wardrive-style">
      <option value="icon">icon</option>
      <option value="pulse">pulse</option>
    </select>

    <select id="conf-wardrive-route-accent-color">
      <option value="theme">theme</option>
      <option value="orange">orange</option>
    </select>

    <select id="conf-wardrive-primary-zone-accent-color">
      <option value="theme">theme</option>
      <option value="purple">purple</option>
    </select>

    <select id="conf-wardrive-secondary-accent-color">
      <option value="amber">amber</option>
      <option value="white">white</option>
    </select>

    <select id="conf-ui-hud-density">
      <option value="compact">compact</option>
      <option value="balanced">balanced</option>
      <option value="comfortable">comfortable</option>
    </select>

    <select id="conf-ui-sidebar-preset">
      <option value="narrow">narrow</option>
      <option value="standard">standard</option>
      <option value="wide">wide</option>
    </select>

    <select id="conf-ui-font-scale">
      <option value="90">90</option>
      <option value="100">100</option>
      <option value="110">110</option>
    </select>

    <select id="conf-ui-cracking-accordion-mode">
      <option value="multi">multi</option>
      <option value="single">single</option>
    </select>

    <select id="conf-ui-cracking-attack-panel-mode">
      <option value="multi">multi</option>
      <option value="single">single</option>
    </select>

    <select id="conf-wardrive-replay-speed-default">
      <option value="0.05">0.05</option>
      <option value="0.1">0.1</option>
      <option value="0.5">0.5</option>
      <option value="1">1</option>
      <option value="2">2</option>
      <option value="8">8</option>
    </select>

    <select id="conf-wardrive-replay-follow-zoom-default">
      <option value="current">current</option>
      <option value="13">13</option>
      <option value="15">15</option>
      <option value="17">17</option>
      <option value="19">19</option>
    </select>

    <select id="conf-wardrive-replay-timing-mode-default">
      <option value="real_time">real_time</option>
      <option value="compress_idle">compress_idle</option>
      <option value="uniform_path">uniform_path</option>
    </select>

    <select id="conf-wardrive-sessions-sort-by-default">
      <option value="none">none</option>
      <option value="date">date</option>
      <option value="distance">distance</option>
    </select>

    <select id="conf-wardrive-sessions-sort-direction-default">
      <option value="asc">asc</option>
      <option value="desc">desc</option>
    </select>
  `;
}

function setDefaults() {
  mockAPI.getConfig.mockResolvedValue({
    pwn_sync_enabled: true,
    pwn_host: "10.0.0.1",
    pwn_port: 2222,
    pwn_user: "pi",
    pwn_pass_configured: true,
    remote_path: "/root/handshakes",
    pwn_force_sync: true,
    m5_sync_enabled: true,
    m5_force_sync: true,
    m5_host: "192.168.4.1",
    m5_port: 80,
    m5_web_protocol: "http",
    m5_admin_base_path: "/evil-menu",
    m5_web_user: "evil",
    m5_web_password_configured: true,
    m5_handshake_remote_path: "evil/handshakes",
    m5_wardrive_remote_path: "evil/wardriving",
    bruce_sync_enabled: true,
    bruce_force_sync: true,
    bruce_host: "bruce.local",
    bruce_port: 80,
    bruce_web_user: "admin",
    bruce_web_password_configured: true,
    hashcat_path: "hashcat",
    hcxpcapngtool_path: "hcxpcapngtool",
    aircrack_path: "aircrack-ng",
    tshark_path: "tshark",
    custom_wordlists_path: "/lists",
    custom_rules_path: "/rules",
    custom_masks_path: "/masks",
    ssh_known_hosts_path: "/ssh/known_hosts",
    use_wsl: true,
    map_tile: "osm",
    map_cluster_mode: "adaptive",
    force_sync: true,
    attack_mode: "hybrid_mask_profile",
    workload_profile: "4",
    hashcat_optimized: true,
    hashcat_slow: false,
    hashcat_potfile: true,
    hashcat_device_default: "2",
    ui_visual_theme: "cyberpunk",
    ui_theme: "green",
    ui_icon_pwned: "fa-bolt",
    ui_icon_locked: "fa-lock",
    ui_icon_open: "fa-wifi",
    ui_icon_wardrive: "fa-satellite-dish",
    ui_wardrive_color: "cyan",
    ui_wardrive_style: "pulse",
    ui_hide_passwords: true,
    ui_hud_density: "compact",
    ui_sidebar_preset: "wide",
    ui_font_scale: "110",
    ui_cracking_accordion_mode: "single",
    ui_cracking_attack_panel_mode: "single",
    ui_wardrive_replay_speed_default: "2",
    ui_wardrive_replay_autoplay: true,
    ui_wardrive_replay_auto_focus: false,
    ui_wardrive_replay_follow_camera_default: true,
    ui_wardrive_replay_follow_zoom_default: "19",
    ui_wardrive_replay_timing_mode_default: "compress_idle",
    ui_wardrive_sessions_sort_by: "distance",
    ui_wardrive_sessions_sort_direction: "asc",
    ui_wardrive_merge_confirmation: false,
    ui_wardrive_route_accent_color: "orange",
    ui_wardrive_primary_zone_accent_color: "purple",
    ui_wardrive_secondary_accent_color: "white",
  });

  mockAPI.getHashcatDevices.mockResolvedValue([
    { id: "1", name: "GPU 1", type: "OpenCL", backend: "OpenCL" },
    { id: "2", name: "GPU 2", type: "CUDA", backend: "CUDA" },
  ]);
  mockAPI.getDemoDataStatus.mockResolvedValue({
    active: false,
    available_profiles: [{ profile_id: "showcase-core-v5", label: "Showcase Core v5" }],
    snapshot_available: false,
    summary: null,
  });

  mockAPI.saveConfig.mockResolvedValue({ status: "ok" });
  mockAPI.probePwnagotchiSync.mockResolvedValue({
    status: "success",
    details: { files_found: 3 },
  });
  mockAPI.probeM5EvilSync.mockResolvedValue({
    status: "success",
    details: {
      handshake_files_found: 1,
      rawsniffer_files_found: 3,
      mastersniffer_files_found: 4,
      wardrive_files_found: 2,
    },
  });
  mockAPI.probeBruceSync.mockResolvedValue({
    status: "success",
    details: {
      handshake_files_found: 0,
      handshake_file_count_skipped: true,
      handshake_path_ok: true,
      rawsniffer_files_found: 5,
      wardrive_path_ok: true,
      wardrive_files_found: 0,
    },
  });
}

describe("ui_settings", () => {
  beforeEach(() => {
    jest.resetModules();
    mountSettingsDom();
    setDefaults();
    mockLog.mockClear();
    mockSetMarkerIcons.mockClear();
    mockSetClusterConfig.mockClear();
    mockUpdateNoGpsList.mockClear();
    mockState.modes.noGps = false;
    mockState.ui.hidePasswords = false;
    window.setTileLayer = jest.fn();
    window.setClusterConfig = jest.fn();
  });

  test("applyTheme updates css variables", () => {
    const { applyTheme, applyVisualTheme } = require("../../src/modules/ui_components/ui_settings.js");

    applyVisualTheme("cyberpunk");

    applyTheme("purple");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#bc13fe");

    applyTheme("cyan");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#00f3ff");
  });

  test("applyTheme supports green/pink/orange palettes", () => {
    const { applyTheme, applyVisualTheme } = require("../../src/modules/ui_components/ui_settings.js");

    applyVisualTheme("cyberpunk");

    applyTheme("green");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#00ff41");

    applyTheme("pink");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#ff00ff");

    applyTheme("orange");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#ff8c00");
  });

  test("applyVisualTheme swaps root theme classes", () => {
    const { applyVisualTheme } = require("../../src/modules/ui_components/ui_settings.js");

    applyVisualTheme("professional");
    expect(document.documentElement.classList.contains("theme-professional")).toBe(true);

    applyVisualTheme("synthwave");
    expect(document.documentElement.classList.contains("theme-synthwave")).toBe(true);
    expect(document.documentElement.classList.contains("theme-professional")).toBe(false);

    applyVisualTheme("military");
    expect(document.documentElement.classList.contains("theme-military")).toBe(true);
    expect(document.documentElement.classList.contains("theme-synthwave")).toBe(false);
  });

  test("applyTheme supports professional, synthwave and military palettes", () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");

    settings.applyVisualTheme("professional");
    settings.applyTheme("steel");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#2faad4");

    settings.applyVisualTheme("synthwave");
    settings.applyTheme("sunset");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#ff6b9d");

    settings.applyVisualTheme("military");
    settings.applyTheme("tactical");
    expect(document.documentElement.style.getPropertyValue("--neon-cyan")).toBe("#4a7c3f");
  });

  test("theme helpers use professional/slate and cyberpunk/purple as defaults", () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");

    expect(settings.uiConfig.visualTheme).toBe("professional");
    expect(settings.uiConfig.theme).toBe("slate");
    expect(settings.__testUiSettingsHelpers.normalizeVisualTheme("")).toBe("professional");
    expect(settings.__testUiSettingsHelpers.normalizeThemeForVisual("", "professional")).toBe("slate");
    expect(settings.__testUiSettingsHelpers.normalizeThemeForVisual("", "cyberpunk")).toBe("purple");

    const professionalPresets = settings.getThemePresetsForVisual("professional");
    const cyberpunkPresets = settings.getThemePresetsForVisual("cyberpunk");
    expect(professionalPresets[0].value).toBe("slate");
    expect(cyberpunkPresets[0].value).toBe("purple");
  });

  test("openSettings loads backend config and devices into form", async () => {
    const { openSettings } = require("../../src/modules/ui_components/ui_settings.js");

    await openSettings();

    expect(document.getElementById("settings-modal").style.display).toBe("flex");
    expect(document.getElementById("conf-ip").value).toBe("10.0.0.1");
    expect(document.getElementById("conf-port").value).toBe("2222");
    expect(document.getElementById("conf-custom-masks").value).toBe("/masks");
    expect(document.getElementById("conf-known-hosts").value).toBe("/ssh/known_hosts");
    expect(document.getElementById("conf-pass").value).toBe("");
    expect(document.getElementById("conf-pass").placeholder).toContain("leave blank");
    expect(document.getElementById("conf-pwn-enabled").checked).toBe(true);
    expect(document.getElementById("conf-force-sync").checked).toBe(true);
    expect(document.getElementById("conf-m5-enabled").checked).toBe(true);
    expect(document.getElementById("conf-m5-force-sync").checked).toBe(true);
    expect(document.getElementById("conf-m5-host").value).toBe("192.168.4.1");
    expect(document.getElementById("conf-m5-port").value).toBe("80");
    expect(document.getElementById("conf-m5-user").value).toBe("evil");
    expect(document.getElementById("conf-m5-password").value).toBe("");
    expect(document.getElementById("conf-m5-password").placeholder).toContain("leave blank");
    expect(document.getElementById("conf-bruce-enabled").checked).toBe(true);
    expect(document.getElementById("conf-bruce-force-sync").checked).toBe(true);
    expect(document.getElementById("conf-bruce-host").value).toBe("bruce.local");
    expect(document.getElementById("conf-bruce-port").value).toBe("80");
    expect(document.getElementById("conf-bruce-user").value).toBe("admin");
    expect(document.getElementById("conf-bruce-password").value).toBe("");
    expect(document.getElementById("conf-bruce-password").placeholder).toContain("leave blank");
    expect(document.getElementById("conf-wsl").checked).toBe(true);
    expect(document.getElementById("conf-map-tile").value).toBe("osm");
    expect(document.getElementById("conf-hashcat-device").value).toBe("2");
    expect(document.getElementById("conf-attack-mode").value).toBe("hybrid_mask_profile");
    expect(document.getElementById("conf-workload-profile").value).toBe("4");
    expect(document.getElementById("conf-ui-theme").value).toBe("green");
    expect(document.getElementById("conf-icon-open").value).toBe("fa-wifi");
    expect(document.getElementById("conf-icon-wardrive").value).toBe("fa-satellite-dish");
    expect(document.getElementById("conf-wardrive-color").value).toBe("cyan");
    expect(document.getElementById("conf-wardrive-style").value).toBe("pulse");
    expect(document.getElementById("conf-ui-hud-density").value).toBe("compact");
    expect(document.getElementById("conf-ui-sidebar-preset").value).toBe("wide");
    expect(document.getElementById("conf-ui-font-scale").value).toBe("110");
    expect(document.getElementById("conf-ui-cracking-accordion-mode").value).toBe("single");
    expect(document.getElementById("conf-ui-cracking-attack-panel-mode").value).toBe("single");
    expect(document.getElementById("conf-wardrive-replay-speed-default").value).toBe("2");
    expect(document.getElementById("conf-wardrive-replay-autoplay").checked).toBe(true);
    expect(document.getElementById("conf-wardrive-replay-auto-focus").checked).toBe(false);
    expect(document.getElementById("conf-wardrive-replay-follow-camera-default").checked).toBe(true);
    expect(document.getElementById("conf-wardrive-replay-follow-zoom-default").value).toBe("19");
    expect(document.getElementById("conf-wardrive-replay-timing-mode-default").value).toBe("compress_idle");
    expect(document.getElementById("conf-wardrive-sessions-sort-by-default").value).toBe("distance");
    expect(document.getElementById("conf-wardrive-sessions-sort-direction-default").value).toBe("asc");
    expect(document.getElementById("conf-wardrive-merge-confirmation").checked).toBe(false);
    expect(document.getElementById("conf-wardrive-route-accent-color").value).toBe("orange");
    expect(document.getElementById("conf-wardrive-primary-zone-accent-color").value).toBe("purple");
    expect(document.getElementById("conf-wardrive-secondary-accent-color").value).toBe("white");
    expect(document.getElementById("settings-advanced").open).toBe(false);
    expect(document.getElementById("demo-data-status").textContent).toBe("DEMO DATA: INACTIVE");
    expect(document.getElementById("btn-install-demo-data").disabled).toBe(false);
    expect(document.getElementById("btn-remove-demo-data").disabled).toBe(true);
  });

  test("openSettings fallback device to all when default not available", async () => {
    mockAPI.getConfig.mockResolvedValueOnce({
      pwn_host: "127.0.0.1",
      pwn_user: "u",
      pwn_pass_configured: true,
      remote_path: "/tmp",
      hashcat_device_default: "99",
    });
    mockAPI.getHashcatDevices.mockResolvedValueOnce([
      { id: "1", name: "GPU", type: "OpenCL", backend: "OpenCL" },
    ]);

    const { openSettings } = require("../../src/modules/ui_components/ui_settings.js");

    await openSettings();

    expect(document.getElementById("conf-hashcat-device").value).toBe("all");
  });

  test("openSettings logs error when backend load fails", async () => {
    mockAPI.getConfig.mockRejectedValueOnce(new Error("offline"));

    const { openSettings } = require("../../src/modules/ui_components/ui_settings.js");

    await openSettings();

    expect(mockLog).toHaveBeenCalledWith("Failed to load config from backend", "error");
  });

  test("saveSettings persists config and applies ui updates", async () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");

    document.getElementById("conf-ip").value = "192.168.0.10";
    document.getElementById("conf-port").value = "2022";
    document.getElementById("conf-user").value = "admin";
    document.getElementById("conf-pass").value = "pass";
    document.getElementById("conf-path").value = "/data";
    document.getElementById("conf-pwn-enabled").checked = true;
    document.getElementById("conf-m5-enabled").checked = true;
    document.getElementById("conf-m5-force-sync").checked = true;
    document.getElementById("conf-m5-host").value = "10.0.0.55";
    document.getElementById("conf-m5-port").value = "8080";
    document.getElementById("conf-m5-user").value = "evil";
    document.getElementById("conf-m5-password").value = "test";
    document.getElementById("conf-bruce-enabled").checked = true;
    document.getElementById("conf-bruce-force-sync").checked = true;
    document.getElementById("conf-bruce-host").value = "192.168.1.200";
    document.getElementById("conf-bruce-port").value = "80";
    document.getElementById("conf-bruce-user").value = "admin";
    document.getElementById("conf-bruce-password").value = "brucepass";
    document.getElementById("conf-hashcat").value = "hashcat-bin";
    document.getElementById("conf-hcx").value = "hcx-bin";
    document.getElementById("conf-aircrack").value = "aircrack-bin";
    document.getElementById("conf-tshark").value = "tshark-bin";
    document.getElementById("conf-custom-wordlists").value = "/wls";
    document.getElementById("conf-custom-rules").value = "/rls";
    document.getElementById("conf-custom-masks").value = "/mks";
    document.getElementById("conf-known-hosts").value = "/ssh/custom_known_hosts";
    document.getElementById("conf-wsl").checked = true;
    document.getElementById("conf-map-tile").value = "osm";
    document.getElementById("conf-map-cluster").value = "adaptive";
    document.getElementById("conf-force-sync").checked = true;
    document.getElementById("conf-attack-mode").value = "hybrid_mask_profile";
    document.getElementById("conf-workload-profile").value = "4";
    document.getElementById("conf-optimized").checked = true;
    document.getElementById("conf-slow").checked = true;
    document.getElementById("conf-potfile").checked = true;
    document.getElementById("conf-hashcat-device").innerHTML = '<option value="all">all</option><option value="2">2</option>';
    document.getElementById("conf-hashcat-device").value = "2";
    document.getElementById("conf-ui-visual-theme").innerHTML = '<option value="cyberpunk">cyberpunk</option><option value="professional">professional</option>';
    document.getElementById("conf-ui-visual-theme").value = "cyberpunk";
    document.getElementById("conf-ui-theme").value = "orange";
    document.getElementById("conf-icon-pwned").value = "fa-bolt";
    document.getElementById("conf-icon-locked").value = "fa-lock";
    document.getElementById("conf-icon-open").value = "fa-wifi";
    document.getElementById("conf-icon-wardrive").value = "fa-satellite-dish";
    document.getElementById("conf-wardrive-color").value = "cyan";
    document.getElementById("conf-wardrive-style").value = "pulse";
    document.getElementById("conf-hide-passwords").checked = true;
    document.getElementById("conf-ui-hud-density").value = "comfortable";
    document.getElementById("conf-ui-sidebar-preset").value = "narrow";
    document.getElementById("conf-ui-font-scale").value = "90";
    document.getElementById("conf-ui-cracking-accordion-mode").value = "single";
    document.getElementById("conf-ui-cracking-attack-panel-mode").value = "single";
    document.getElementById("conf-wardrive-replay-speed-default").value = "0.1";
    document.getElementById("conf-wardrive-replay-autoplay").checked = true;
    document.getElementById("conf-wardrive-replay-auto-focus").checked = false;
    document.getElementById("conf-wardrive-replay-follow-camera-default").checked = true;
    document.getElementById("conf-wardrive-replay-follow-zoom-default").value = "19";
    document.getElementById("conf-wardrive-replay-timing-mode-default").value = "uniform_path";
    document.getElementById("conf-wardrive-sessions-sort-by-default").value = "distance";
    document.getElementById("conf-wardrive-sessions-sort-direction-default").value = "asc";
    document.getElementById("conf-wardrive-merge-confirmation").checked = false;
    document.getElementById("conf-wardrive-route-accent-color").value = "orange";
    document.getElementById("conf-wardrive-primary-zone-accent-color").value = "purple";
    document.getElementById("conf-wardrive-secondary-accent-color").value = "white";

    mockState.modes.noGps = true;

    await settings.saveSettings();

    expect(mockAPI.saveConfig).toHaveBeenCalledWith(
      expect.objectContaining({
        pwn_host: "192.168.0.10",
        pwn_port: 2022,
        pwn_sync_enabled: true,
        pwn_force_sync: true,
        m5_sync_enabled: true,
        m5_force_sync: true,
        m5_host: "10.0.0.55",
        m5_port: 8080,
        m5_web_protocol: "http",
        m5_admin_base_path: "/evil-menu",
        m5_web_user: "evil",
        m5_web_password: "test",
        m5_handshake_remote_path: "evil/handshakes",
        m5_wardrive_remote_path: "evil/wardriving",
        bruce_sync_enabled: true,
        bruce_force_sync: true,
        bruce_host: "192.168.1.200",
        bruce_port: 80,
        bruce_web_protocol: "http",
        bruce_web_user: "admin",
        bruce_web_password: "brucepass",
        custom_masks_path: "/mks",
        ssh_known_hosts_path: "/ssh/custom_known_hosts",
        hashcat_device_default: "2",
        attack_mode: "hybrid_mask_profile",
        workload_profile: "4",
        ui_theme: "orange",
        ui_icon_open: "fa-wifi",
        ui_icon_wardrive: "fa-satellite-dish",
        ui_wardrive_color: "cyan",
        ui_wardrive_style: "pulse",
        ui_hide_passwords: true,
        ui_hud_density: "comfortable",
        ui_sidebar_preset: "narrow",
        ui_font_scale: "90",
        ui_cracking_accordion_mode: "single",
        ui_cracking_attack_panel_mode: "single",
        ui_wardrive_replay_speed_default: "0.1",
        ui_wardrive_replay_autoplay: true,
        ui_wardrive_replay_auto_focus: false,
        ui_wardrive_replay_follow_camera_default: true,
        ui_wardrive_replay_follow_zoom_default: "19",
        ui_wardrive_replay_timing_mode_default: "uniform_path",
        ui_wardrive_sessions_sort_by: "distance",
        ui_wardrive_sessions_sort_direction: "asc",
        ui_wardrive_merge_confirmation: false,
        ui_wardrive_route_accent_color: "orange",
        ui_wardrive_primary_zone_accent_color: "purple",
        ui_wardrive_secondary_accent_color: "white",
      })
    );
    expect(mockLog).toHaveBeenCalledWith("Configuration saved to backend.", "success");
    expect(document.getElementById("settings-modal").style.display).toBe("none");
    expect(settings.uiConfig.theme).toBe("orange");
    expect(settings.uiConfig.iconPwned).toBe("fa-bolt");
    expect(settings.uiConfig.iconLocked).toBe("fa-lock");
    expect(settings.uiConfig.iconOpen).toBe("fa-wifi");
    expect(settings.uiConfig.iconWardrive).toBe("fa-satellite-dish");
    expect(settings.uiConfig.wardriveColor).toBe("cyan");
    expect(settings.uiConfig.wardriveStyle).toBe("pulse");
    expect(mockState.ui.hidePasswords).toBe(true);
    expect(mockSetMarkerIcons).toHaveBeenCalledWith(
      "fa-bolt",
      "fa-lock",
      "fa-satellite-dish",
      "pulse",
      "fa-wifi"
    );
    expect(window.setTileLayer).toHaveBeenCalledWith("osm");
    expect(window.setClusterConfig).toHaveBeenCalledWith("adaptive");
    expect(mockUpdateNoGpsList).toHaveBeenCalledTimes(1);
  });

  test("saveSettings logs failure when API rejects", async () => {
    const { saveSettings } = require("../../src/modules/ui_components/ui_settings.js");
    mockAPI.saveConfig.mockRejectedValueOnce(new Error("save failed"));

    await saveSettings();

    expect(mockLog).toHaveBeenCalledWith("Failed to save config.", "error");
  });

  test("testBruceConnection probes WebUI and logs success", async () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");
    document.getElementById("conf-bruce-enabled").checked = true;
    document.getElementById("conf-bruce-host").value = "bruce.local";
    document.getElementById("conf-bruce-port").value = "80";
    document.getElementById("conf-bruce-user").value = "admin";
    document.getElementById("conf-bruce-password").value = "secret";

    await settings.testBruceConnection();

    expect(mockAPI.probeBruceSync).toHaveBeenCalledWith(
      expect.objectContaining({
        bruce_host: "bruce.local",
        bruce_port: 80,
        bruce_web_user: "admin",
        bruce_web_password: "secret",
      })
    );
    expect(mockLog).toHaveBeenCalledWith(
      "Bruce WebUI OK (quick probe (deep count skipped)): handshake path reachable | 5 RAW sniffer file(s) | Wardrive path reachable",
      "success"
    );
    expect(document.getElementById("conf-bruce-test-status").textContent).toContain(
      "Connected (quick probe (deep count skipped)): handshake path reachable | 5 RAW sniffer file(s) | Wardrive path reachable"
    );
  });

  test("testBruceConnection shows authentication failure", async () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");
    mockAPI.probeBruceSync.mockResolvedValueOnce({
      status: "error",
      message: "Bruce WebUI authentication failed. Check username and password.",
      details: {
        connection_ok: true,
        auth_ok: false,
      },
    });

    await settings.testBruceConnection();

    expect(document.getElementById("conf-bruce-test-status").textContent).toContain(
      "Reached Bruce WebUI, but authentication failed."
    );
    expect(mockLog).toHaveBeenCalledWith(
      "Bruce WebUI authentication failed. Check username and password.",
      "error"
    );
  });

  test("testM5Connection probes Admin WebUI and logs success", async () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");
    document.getElementById("conf-m5-enabled").checked = true;
    document.getElementById("conf-m5-host").value = "192.168.4.1";
    document.getElementById("conf-m5-port").value = "80";
    document.getElementById("conf-m5-user").value = "evil";
    document.getElementById("conf-m5-password").value = "test";
    await settings.testM5Connection();

    expect(mockAPI.probeM5EvilSync).toHaveBeenCalledWith(
      expect.objectContaining({
        m5_host: "192.168.4.1",
        m5_admin_base_path: "/evil-menu",
        m5_web_user: "evil",
        m5_web_password: "test",
      })
    );
    expect(mockLog).toHaveBeenCalledWith(
      "M5Evil Admin WebUI OK: 1 handshake file(s) | 3 RAW sniffer file(s) | 4 Master Sniffer file(s) | 2 Wardrive CSV file(s)",
      "success"
    );
    expect(document.getElementById("conf-m5-test-status").textContent).toContain(
      "Connected: 1 handshake file(s) | 3 RAW sniffer file(s) | 4 Master Sniffer file(s) | 2 Wardrive CSV file(s)"
    );
  });

  test("testPwnagotchiConnection probes SSH and logs success", async () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");
    document.getElementById("conf-ip").value = "10.0.0.2";
    document.getElementById("conf-port").value = "22";
    document.getElementById("conf-user").value = "pi";
    document.getElementById("conf-pass").value = "raspberry";
    document.getElementById("conf-path").value = "/home/pi/handshakes";

    await settings.testPwnagotchiConnection();

    expect(mockAPI.probePwnagotchiSync).toHaveBeenCalledWith({
      pwn_host: "10.0.0.2",
      pwn_port: 22,
      pwn_user: "pi",
      pwn_pass: "raspberry",
      remote_path: "/home/pi/handshakes",
    });
    expect(mockLog).toHaveBeenCalledWith(
      "Pwnagotchi SSH OK: 3 file(s) visible in remote path",
      "success"
    );
    expect(document.getElementById("conf-pwn-test-status").textContent).toContain(
      "Connected: 3 file(s) visible in remote path"
    );
  });

  test("testPwnagotchiConnection shows host-key trust issue clearly", async () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");
    mockAPI.probePwnagotchiSync.mockResolvedValueOnce({
      status: "error",
      message: "SSH host key not trusted. Confirm fingerprint before testing or syncing.",
      details: {
        connection_ok: true,
        auth_ok: false,
        host_key_trusted: false,
      },
    });

    await settings.testPwnagotchiConnection();

    expect(document.getElementById("conf-pwn-test-status").textContent).toContain(
      "host key is not trusted yet"
    );
    expect(mockLog).toHaveBeenCalledWith(
      "SSH host key not trusted. Confirm fingerprint before testing or syncing.",
      "error"
    );
  });

  test("testM5Connection shows parser mismatch as connected but not parseable", async () => {
    const settings = require("../../src/modules/ui_components/ui_settings.js");
    mockAPI.probeM5EvilSync.mockResolvedValueOnce({
      status: "error",
      message: "Connected and authenticated, but the current firmware Browse SD page could not be parsed",
      details: {
        connection_ok: true,
        auth_ok: true,
        browse_root_ok: false,
        failure_phase: "browse_root",
      },
    });

    await settings.testM5Connection();

    expect(document.getElementById("conf-m5-test-status").textContent).toContain(
      "Connected and authenticated, but Browse SD could not be parsed"
    );
    expect(mockLog).toHaveBeenCalledWith(
      "Connected and authenticated, but the current firmware Browse SD page could not be parsed",
      "error"
    );
  });

  test("closeSettings hides modal", () => {
    const { closeSettings } = require("../../src/modules/ui_components/ui_settings.js");
    document.getElementById("settings-modal").style.display = "flex";

    closeSettings();

    expect(document.getElementById("settings-modal").style.display).toBe("none");
  });

  test("applyLayoutSettings updates hud density, sidebars and font scale vars", () => {
    const { applyLayoutSettings } = require("../../src/modules/ui_components/ui_settings.js");
    const root = document.documentElement;
    const hud = document.getElementById("hud-layer");

    applyLayoutSettings({
      ui_hud_density: "compact",
      ui_sidebar_preset: "narrow",
      ui_font_scale: "90",
    });

    expect(hud.classList.contains("hud-density-compact")).toBe(true);
    expect(root.style.getPropertyValue("--left-sidebar-w")).toBe("250px");
    expect(root.style.getPropertyValue("--right-panels-w")).toBe("420px");
    expect(root.style.getPropertyValue("--ui-font-scale")).toBe("90%");
    expect(root.style.getPropertyValue("--ui-font-scale-factor")).toBe("0.9");
  });

  test("applyLayoutSettings falls back to defaults for invalid inputs", () => {
    const { applyLayoutSettings } = require("../../src/modules/ui_components/ui_settings.js");
    const root = document.documentElement;
    const hud = document.getElementById("hud-layer");

    applyLayoutSettings({
      ui_hud_density: "invalid",
      ui_sidebar_preset: "giant",
      ui_font_scale: "999",
    });

    expect(hud.classList.contains("hud-density-compact")).toBe(false);
    expect(hud.classList.contains("hud-density-comfortable")).toBe(false);
    expect(root.style.getPropertyValue("--left-sidebar-w")).toBe("280px");
    expect(root.style.getPropertyValue("--right-panels-w")).toBe("500px");
    expect(root.style.getPropertyValue("--ui-font-scale")).toBe("100%");
    expect(root.style.getPropertyValue("--ui-font-scale-factor")).toBe("1");
  });

  test("applyWardriveColor resolves palette and default", () => {
    const { applyWardriveColor } = require("../../src/modules/ui_components/ui_settings.js");
    const root = document.documentElement;

    applyWardriveColor("purple");
    expect(root.style.getPropertyValue("--wardrive-color")).toBe("#bc13fe");

    applyWardriveColor("unknown");
    expect(root.style.getPropertyValue("--wardrive-color")).toBe("#00ffd0");
  });

  test("openSettings populates hashcat device select when devices exist", async () => {
    const { openSettings } = require("../../src/modules/ui_components/ui_settings.js");
    mockAPI.getConfig.mockResolvedValueOnce({
      pwn_host: "127.0.0.1",
      pwn_user: "u",
      pwn_pass_configured: true,
      remote_path: "/tmp",
      hashcat_device_default: "2",
    });
    mockAPI.getHashcatDevices.mockResolvedValueOnce([
      { id: "1", name: "GPU", type: "OpenCL", backend: "OpenCL" },
      { id: "2", name: "CPU", type: "OpenCL", backend: "OpenCL" },
    ]);

    await openSettings();

    const deviceSelect = document.getElementById("conf-hashcat-device");
    expect(deviceSelect.options.length).toBe(3);
    expect(deviceSelect.value).toBe("2");
  });

  test("helper normalizers and section helpers cover invalid values and UI binding", () => {
    const { __testUiSettingsHelpers } = require("../../src/modules/ui_components/ui_settings.js");

    document.getElementById("settings-modal").insertAdjacentHTML(
      "beforeend",
      `
        <button data-settings-section-target="appearance"></button>
        <button data-settings-section-target="advanced"></button>
        <button data-settings-shortcut-target="advanced"></button>
        <div data-settings-panel="appearance"></div>
        <div data-settings-panel="advanced"></div>
      `
    );

    expect(__testUiSettingsHelpers.normalizeHudDensity("COMFORTABLE")).toBe("comfortable");
    expect(__testUiSettingsHelpers.normalizeHudDensity("weird")).toBe("balanced");
    expect(__testUiSettingsHelpers.normalizeSidebarPreset("WIDE")).toBe("wide");
    expect(__testUiSettingsHelpers.normalizeSidebarPreset("giant")).toBe("standard");
    expect(__testUiSettingsHelpers.normalizeFontScale("110")).toBe("110");
    expect(__testUiSettingsHelpers.normalizeFontScale("111")).toBe("100");
    expect(__testUiSettingsHelpers.normalizeCrackingAccordionMode("SINGLE")).toBe("single");
    expect(__testUiSettingsHelpers.normalizeCrackingAccordionMode("tabs")).toBe("multi");
    expect(__testUiSettingsHelpers.normalizeWardriveReplaySpeedDefault("0.05")).toBe("0.05");
    expect(__testUiSettingsHelpers.normalizeWardriveReplaySpeedDefault("8")).toBe("8");
    expect(__testUiSettingsHelpers.normalizeWardriveReplaySpeedDefault("2.5")).toBe("2.5");
    expect(__testUiSettingsHelpers.normalizeWardriveReplaySpeedDefault("7")).toBe("1");
    expect(__testUiSettingsHelpers.normalizeWardriveReplayTimingModeDefault("COMPRESS_IDLE")).toBe("compress_idle");
    expect(__testUiSettingsHelpers.normalizeWardriveReplayTimingModeDefault("warp")).toBe("real_time");
    expect(__testUiSettingsHelpers.normalizeWardriveReplayFollowZoomDefault("19")).toBe("19");
    expect(__testUiSettingsHelpers.normalizeWardriveReplayFollowZoomDefault("21")).toBe("current");
    expect(__testUiSettingsHelpers.normalizeWardriveSessionsSortBy("DATE")).toBe("date");
    expect(__testUiSettingsHelpers.normalizeWardriveSessionsSortBy("odd")).toBe("none");
    expect(__testUiSettingsHelpers.normalizeSortDirection("ASC")).toBe("asc");
    expect(__testUiSettingsHelpers.normalizeSortDirection("sideways")).toBe("desc");
    expect(__testUiSettingsHelpers.normalizeWardriveAccentColor("purple", "theme")).toBe(
      "purple"
    );
    expect(__testUiSettingsHelpers.normalizeWardriveAccentColor("invalid", "amber")).toBe(
      "amber"
    );

    __testUiSettingsHelpers.setInputValue("conf-ip", "192.168.1.1");
    expect(document.getElementById("conf-ip").value).toBe("192.168.1.1");

    __testUiSettingsHelpers.setCheckboxValue("conf-wsl", true);
    expect(document.getElementById("conf-wsl").checked).toBe(true);

    __testUiSettingsHelpers.setSelectValue("conf-map-tile", "missing", "carto_dark");
    expect(document.getElementById("conf-map-tile").value).toBe("carto_dark");

    __testUiSettingsHelpers.setPasswordInputState("conf-pass", true);
    expect(document.getElementById("conf-pass").dataset.configured).toBe("1");
    expect(document.getElementById("conf-pass").placeholder).toContain("leave blank");
    __testUiSettingsHelpers.setPasswordInputState("conf-pass", false);
    expect(document.getElementById("conf-pass").dataset.configured).toBe("0");
    __testUiSettingsHelpers.setSyncPasswordStates({
      pwn_pass_configured: true,
    });
    expect(document.getElementById("conf-pass").dataset.configured).toBe("1");
    __testUiSettingsHelpers.setPwnProbeStatus("Testing", "running");
    expect(document.getElementById("conf-pwn-test-status").dataset.state).toBe("running");
    expect(
      __testUiSettingsHelpers.formatPwnProbeFeedback({
        status: "success",
        details: { files_found: 4 },
      }).inline
    ).toContain("4 file(s)");

    __testUiSettingsHelpers.setSettingsSection("advanced");
    expect(
      document.querySelector('[data-settings-section-target="advanced"]').classList.contains(
        "active"
      )
    ).toBe(true);
    expect(document.querySelector('[data-settings-panel="advanced"]').style.display).toBe(
      "block"
    );

    __testUiSettingsHelpers.ensureSettingsUiBound();
    __testUiSettingsHelpers.ensureSettingsUiBound();
    document
      .querySelector('[data-settings-shortcut-target="advanced"]')
      .dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(document.getElementById("settings-advanced").open).toBe(true);
    expect(document.getElementById("settings-modal").dataset.sectionsBound).toBe("1");

    __testUiSettingsHelpers.applyM5CardputerPreset();
    expect(document.getElementById("conf-m5-host").value).toBe("192.168.4.1");
    expect(
      __testUiSettingsHelpers.formatM5ProbeFeedback({
        status: "error",
        details: {
          connection_ok: true,
          auth_ok: true,
          failure_phase: "browse_root",
        },
      }).inline
    ).toContain("Browse SD could not be parsed");

    __testUiSettingsHelpers.setBruceProbeStatus("Testing Bruce", "running");
    expect(document.getElementById("conf-bruce-test-status").dataset.state).toBe("running");
    expect(document.getElementById("conf-bruce-test-status").textContent).toBe("Testing Bruce");

    expect(
      __testUiSettingsHelpers.formatBruceProbeFeedback({
        status: "success",
        details: { handshake_files_found: 3, rawsniffer_files_found: 7 },
      }).inline
    ).toContain("3 handshake file(s) | 7 RAW sniffer file(s)");

    expect(
      __testUiSettingsHelpers.formatBruceProbeFeedback({
        status: "error",
        message: "Cannot reach Bruce WebUI.",
        details: { connection_ok: false },
      }).inline
    ).toBe("Cannot reach Bruce WebUI.");

    expect(
      __testUiSettingsHelpers.formatBruceProbeFeedback({
        status: "error",
        message: "Connected and authenticated, but the Bruce SD Files browser was not detected.",
        details: { connection_ok: true, auth_ok: true, failure_phase: "sd_browser" },
      }).inline
    ).toContain("SD Files browser was not detected");

    document.getElementById("conf-bruce-enabled").checked = true;
    document.getElementById("conf-bruce-host").value = "10.0.0.99";
    document.getElementById("conf-bruce-port").value = "8080";
    document.getElementById("conf-bruce-user").value = "root";
    const brucePayload = __testUiSettingsHelpers.buildBruceProbePayload();
    expect(brucePayload.bruce_host).toBe("10.0.0.99");
    expect(brucePayload.bruce_port).toBe(8080);
    expect(brucePayload.bruce_web_user).toBe("root");
    expect(brucePayload).not.toHaveProperty("bruce_web_password");
  });
});
