jest.mock("../../src/modules/api.js", () => ({
  API: {},
}));

jest.mock("../../src/modules/state.js", () => ({
  STATE: { modes: { cracking: false }, allPositions: {} },
  saveModes: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_lists.js", () => ({
  updateNoGpsList: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_processes.js", () => ({
  activeProcesses: {},
  addProcess: jest.fn(),
}));

jest.mock("../../src/modules/ui_components/ui_history.js", () => ({
  renderHistoryPanel: jest.fn(),
}));

function mountCrackingDom() {
  document.body.innerHTML = `
    <button id="btn-toggle-cracking"></button>
    <div id="cracking-panel"><button class="close-panel"></button></div>
    <button id="btn-convert-hash"></button>
    <button id="btn-pcap-generate-hash"></button>
    <button id="btn-quick-attack"></button>
    <button id="mask-help-btn"></button>
    <input id="flag-increment" type="checkbox" />
    <input id="flag-slow" type="checkbox" />
    <select id="custom-mode-select">
      <option value="straight">straight</option>
      <option value="association">association</option>
      <option value="association_hint_first">association_hint_first</option>
      <option value="association_hint_rule">association_hint_rule</option>
      <option value="mask_profile">mask_profile</option>
    </select>
    <span id="custom-mode-label"></span>
    <div id="crack-wordlist-row"></div>
    <div id="crack-wordlist-2-row"></div>
    <div id="crack-rule-row"></div>
    <div id="crack-rule-2-row"></div>
    <span id="crack-rule-label"></span>
    <div id="crack-mask-row"></div>
    <div id="crack-mask-profile-row"></div>
    <div id="crack-association-hint-row"></div>
    <div id="crack-association-hints-row"></div>
    <div id="crack-association-preview-row"></div>
    <div id="flag-increment-container"></div>
    <div id="crack-increment-row"></div>
    <input id="crack-mask-input" />
    <input id="auto-mask-chk" type="checkbox" />
    <button id="btn-association-preview"></button>
  `;
}

function changeMode(mode) {
  const select = document.getElementById("custom-mode-select");
  select.value = mode;
  select.dispatchEvent(new Event("change", { bubbles: true }));
}

describe("ui_cracking mode behavior", () => {
  beforeEach(() => {
    jest.resetModules();
    mountCrackingDom();
    window.alert = jest.fn();
  });

  test("association mode disables slow candidates and shows association hint row", () => {
    const { setupCrackingListeners } = require("../../src/modules/ui_components/ui_cracking.js");
    setupCrackingListeners();

    const slow = document.getElementById("flag-slow");
    slow.checked = true;

    changeMode("association");

    expect(slow.disabled).toBe(true);
    expect(slow.checked).toBe(false);
    expect(document.getElementById("crack-association-hint-row").style.display).toBe("flex");
    expect(document.getElementById("crack-association-preview-row").style.display).toBe("flex");
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("none");
    expect(document.getElementById("custom-mode-label").innerText).toBe("ASSOC SSID/HINT");
  });

  test("association_hint_first mode shows hints textarea row and keeps slow disabled", () => {
    const { setupCrackingListeners } = require("../../src/modules/ui_components/ui_cracking.js");
    setupCrackingListeners();

    changeMode("association_hint_first");

    expect(document.getElementById("crack-association-hints-row").style.display).toBe("flex");
    expect(document.getElementById("crack-association-hint-row").style.display).toBe("none");
    expect(document.getElementById("crack-association-preview-row").style.display).toBe("flex");
    expect(document.getElementById("flag-slow").disabled).toBe(true);
    expect(document.getElementById("custom-mode-label").innerText).toBe("ASSOC MULTI-HINT");
  });

  test("association_hint_rule mode shows hints textarea and rule row, hides preview button", () => {
    const { setupCrackingListeners } = require("../../src/modules/ui_components/ui_cracking.js");
    setupCrackingListeners();

    changeMode("association_hint_rule");

    expect(document.getElementById("crack-association-hints-row").style.display).toBe("flex");
    expect(document.getElementById("crack-rule-row").style.display).toBe("flex");
    expect(document.getElementById("crack-association-hint-row").style.display).toBe("none");
    expect(document.getElementById("crack-association-preview-row").style.display).toBe("none");
    expect(document.getElementById("flag-slow").disabled).toBe(false);
    expect(document.getElementById("custom-mode-label").innerText).toBe("ASSOC HINT + RULE");
  });

  test("switching back to straight re-enables slow candidates and restores wordlist row", () => {
    const { setupCrackingListeners } = require("../../src/modules/ui_components/ui_cracking.js");
    setupCrackingListeners();

    changeMode("mask_profile");
    const slow = document.getElementById("flag-slow");
    expect(slow.disabled).toBe(true);
    expect(document.getElementById("crack-mask-profile-row").style.display).toBe("flex");

    changeMode("straight");

    expect(slow.disabled).toBe(false);
    expect(slow.checked).toBe(false);
    expect(document.getElementById("crack-wordlist-row").style.display).toBe("flex");
    expect(document.getElementById("crack-association-preview-row").style.display).toBe("none");
    expect(document.getElementById("crack-mask-profile-row").style.display).toBe("none");
    expect(document.getElementById("custom-mode-label").innerText).toBe("STRAIGHT");
  });
});
