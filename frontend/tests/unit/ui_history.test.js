const mockAPI = {
  getFileContent: jest.fn(),
};

jest.mock("../../src/modules/api.js", () => ({
  API: mockAPI,
}));

jest.mock("../../src/modules/utils.js", () => ({
  escapeHtml: (value) => String(value ?? ""),
}));

const { renderHistoryPanel } = require("../../src/modules/ui_components/ui_history.js");

describe("ui_history", () => {
  let container;

  beforeEach(() => {
    document.body.innerHTML = '<div id="history-root"></div>';
    container = document.getElementById("history-root");
    mockAPI.getFileContent.mockReset();
  });

  test("renderHistoryPanel parses, sorts and renders history entries", async () => {
    mockAPI.getFileContent.mockResolvedValue(
      JSON.stringify({
        entries: [
          {
            start_time: "2026-02-08T10:00:00Z",
            status: "SUCCESS",
            tool: "HASHCAT",
            command: "hashcat -a 0",
            duration: "00:10:00",
            params: { mode: "straight", wordlist: "wl.txt", empty: "", skip: null },
            result: "password found",
            meta: ["meta line 1"],
          },
          {
            start_time: "2026-02-08T12:00:00Z",
            status: "FAILED",
            tool: "AIRCRACK",
            command: "aircrack-ng capture.pcap",
            params: { mode: "quick" },
            meta: [],
          },
        ],
      })
    );

    await renderHistoryPanel("attack.try", container);

    expect(mockAPI.getFileContent).toHaveBeenCalledWith("attack.try", {});
    expect(container.querySelector(".crack-artifact-summary")).toBeTruthy();
    expect(container.querySelector(".crack-artifact-summary-kicker").textContent).toContain("Attack history");
    expect(container.querySelector(".file-type-tag").textContent).toContain("TRY");

    const entries = container.querySelectorAll(".history-entry");
    expect(entries.length).toBe(2);

    // newest first after sort
    expect(entries[0].textContent).toContain("AIRCRACK");
    expect(entries[1].textContent).toContain("HASHCAT");

    expect(container.textContent).toContain("mode: straight");
    expect(container.textContent).toContain("wordlist: wl.txt");
    expect(container.textContent).not.toContain("empty:");
    expect(container.textContent).toContain("password found");
    expect(container.textContent).toContain("meta line 1");
    expect(container.textContent).toContain("00:10:00");
  });

  test("renderHistoryPanel renders empty history message", async () => {
    mockAPI.getFileContent.mockResolvedValue(JSON.stringify({ entries: [] }));

    await renderHistoryPanel("empty.try", container);

    expect(container.querySelector(".crack-artifact-summary")).toBeTruthy();
    expect(container.textContent).toContain("No history entries found.");
  });

  test("renderHistoryPanel shows error when file content is invalid JSON", async () => {
    mockAPI.getFileContent.mockResolvedValue("not-json");

    await renderHistoryPanel("broken.try", container);

    expect(container.querySelector(".crack-summary-warnings")).toBeTruthy();
    expect(container.textContent).toContain("Failed to load history file");
    expect(container.textContent).toContain("Invalid JSON content");
  });

  test("renderHistoryPanel shows API error message", async () => {
    mockAPI.getFileContent.mockRejectedValue(new Error("backend unavailable"));

    await renderHistoryPanel("missing.try", container);

    expect(container.textContent).toContain("Failed to load history file");
    expect(container.textContent).toContain("backend unavailable");
  });
});
