jest.mock("../../src/modules/ui_components/ui_cracking.js", () => ({
  openCrackingPanel: jest.fn(),
}));

const {
  __testBindPopupActionHandlers,
  __testInjectDetailsIntoPopup,
} = require("../../src/modules/map.js");
const { openCrackingPanel } = require("../../src/modules/ui_components/ui_cracking.js");

describe("map popup actions", () => {
  const mac = "AA:BB:CC:DD:EE:FF";
  const macKey = "AABBCCDDEEFF";

  beforeEach(() => {
    document.body.innerHTML = `
      <div class="data-card">
        <div id="data-rows-${macKey}"></div>
        <div id="hash-crack-btn" data-action="trigger-crack" data-mac="${mac}" data-ssid="Minha%20Rede"></div>
        <div id="vault-crack-btn" data-action="trigger-crack" data-mac="${mac}" data-ssid="Outra%20Rede"></div>
      </div>
    `;
    openCrackingPanel.mockClear();
  });

  test("hash // crack action opens cracking panel with decoded SSID", () => {
    __testBindPopupActionHandlers({ mac });

    document.getElementById("hash-crack-btn").click();

    expect(openCrackingPanel).toHaveBeenCalledTimes(1);
    expect(openCrackingPanel).toHaveBeenCalledWith(mac, "Minha Rede");
  });

  test("bolt action opens cracking panel with decoded SSID", () => {
    __testBindPopupActionHandlers({ mac });

    document.getElementById("vault-crack-btn").click();

    expect(openCrackingPanel).toHaveBeenCalledTimes(1);
    expect(openCrackingPanel).toHaveBeenCalledWith(mac, "Outra Rede");
  });

  test("binding twice keeps a single click listener", () => {
    __testBindPopupActionHandlers({ mac });
    __testBindPopupActionHandlers({ mac });

    document.getElementById("hash-crack-btn").click();

    expect(openCrackingPanel).toHaveBeenCalledTimes(1);
  });

  test("details injection renders untrusted values as text only", () => {
    document.body.innerHTML = `
      <div class="data-card">
        <div id="data-rows-${macKey}"></div>
        <div class="data-row" id="sec-row-${macKey}">
          <span class="d-label">SEC</span>
          <span class="d-val"></span>
        </div>
      </div>
    `;

    const payload = '<img src=x onerror="window.__xss__=1">';
    __testInjectDetailsIntoPopup(mac, {
      security: {
        wpa_version: payload,
        akm: [payload],
        pairwise_ciphers: [payload],
        pmf: payload,
      },
      wps: {
        present: true,
        manufacturer: payload,
        model_name: payload,
        device_name: payload,
      },
      classification: {
        type: payload,
        confidence: 0.9,
      },
    });

    const root = document.querySelector(".data-card");
    expect(root.querySelectorAll("img").length).toBe(0);
    expect(root.querySelectorAll("script").length).toBe(0);
    expect(root.textContent).toContain(payload);
  });
});
