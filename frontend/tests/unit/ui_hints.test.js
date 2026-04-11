const {
  buildHintTrigger,
  buildHintLabel,
  setupGlobalHints,
  hideGlobalHint,
} = require("../../src/modules/ui_components/ui_hints.js");

describe("ui_hints", () => {
  beforeAll(() => {
    setupGlobalHints();
  });

  beforeEach(() => {
    document.body.innerHTML = "";
    hideGlobalHint();
  });

  test("buildHintTrigger and buildHintLabel render reusable hint markup", () => {
    const triggerHtml = buildHintTrigger("Explains the metric", {
      title: "Metric",
      label: "Explain metric",
    });
    const labelHtml = buildHintLabel("Orphaned handshakes", "PCAP files without matching details.");

    const root = document.createElement("div");
    root.innerHTML = `${triggerHtml}${labelHtml}`;

    const triggers = root.querySelectorAll("[data-ui-hint]");
    expect(triggers).toHaveLength(2);
    expect(triggers[0].getAttribute("data-ui-hint-title")).toBe("Metric");
    expect(root.textContent).toContain("Orphaned handshakes");
  });

  test("clicking a trigger opens and closes the global hint popover", () => {
    document.body.innerHTML = `
      <button id="hint-a" type="button" data-ui-hint="PCAP files without a matching .details file." data-ui-hint-title="Orphaned handshakes">?</button>
      <div id="outside">outside</div>
    `;

    const trigger = document.getElementById("hint-a");
    trigger.dispatchEvent(new MouseEvent("click", { bubbles: true }));

    const popover = document.getElementById("ui-hint-popover");
    expect(popover).not.toBeNull();
    expect(popover.getAttribute("aria-hidden")).toBe("false");
    expect(popover.textContent).toContain("Orphaned handshakes");
    expect(popover.textContent).toContain("PCAP files without a matching .details file.");

    document.getElementById("outside").dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(popover.getAttribute("aria-hidden")).toBe("true");
  });
});
