const { Platform } = require("../../src/modules/platform.js");

describe("platform module", () => {
  beforeEach(() => {
    delete window.desktop;
    fetch.mockResolvedValue({ ok: true });
  });

  test("fetchApi falls back to window.fetch when bridge is unavailable", async () => {
    await Platform.fetchApi("http://127.0.0.1:8000/api/health");

    expect(fetch).toHaveBeenCalledWith("http://127.0.0.1:8000/api/health");
  });

  test("fetchApi delegates to desktop bridge when available", async () => {
    const response = { ok: true, json: jest.fn() };
    window.desktop = {
      fetchApi: jest.fn().mockResolvedValue(response),
    };

    const result = await Platform.fetchApi("http://127.0.0.1:8000/api/config", {
      method: "GET",
    });

    expect(window.desktop.fetchApi).toHaveBeenCalledWith(
      "http://127.0.0.1:8000/api/config",
      { method: "GET" },
    );
    expect(result).toBe(response);
  });

  test("fetchApi normalizes serializable bridge payloads into response-like objects", async () => {
    window.desktop = {
      fetchApi: jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        statusText: "OK",
        headers: {
          "content-type": "application/json",
        },
        bodyText: JSON.stringify({ status: "success", data: { ok: true } }),
      }),
    };

    const result = await Platform.fetchApi("http://127.0.0.1:8000/api/config");

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.headers.get("content-type")).toBe("application/json");
    await expect(result.json()).resolves.toEqual({
      status: "success",
      data: { ok: true },
    });
    await expect(result.text()).resolves.toBe(
      JSON.stringify({ status: "success", data: { ok: true } }),
    );
  });

  test("fetchApi falls back to window.fetch when bridge throws", async () => {
    window.desktop = {
      fetchApi: jest.fn(() => {
        throw new Error("boom");
      }),
    };

    await Platform.fetchApi("http://127.0.0.1:8000/api/health");

    expect(fetch).toHaveBeenCalledWith("http://127.0.0.1:8000/api/health");
  });

  test("buildWebSocketUrl returns base url when bridge is unavailable", () => {
    expect(Platform.buildWebSocketUrl("ws://127.0.0.1:8000/ws")).toBe(
      "ws://127.0.0.1:8000/ws",
    );
  });

  test("buildWebSocketUrl delegates to bridge and handles bridge errors", () => {
    window.desktop = {
      buildWebSocketUrl: jest.fn().mockReturnValue(
        "ws://127.0.0.1:8000/ws?token=session-token",
      ),
    };

    expect(Platform.buildWebSocketUrl("ws://127.0.0.1:8000/ws")).toBe(
      "ws://127.0.0.1:8000/ws?token=session-token",
    );

    window.desktop.buildWebSocketUrl.mockImplementation(() => {
      throw new Error("boom");
    });

    expect(Platform.buildWebSocketUrl("ws://127.0.0.1:8000/ws")).toBe(
      "ws://127.0.0.1:8000/ws",
    );
  });

  test("mergeHeaders adds token only when provided", () => {
    expect(Platform.mergeHeaders({ Accept: "application/json" }, "abc123")).toEqual({
      Accept: "application/json",
      "X-KOVIL-Token": "abc123",
    });
    expect(Platform.mergeHeaders({ Accept: "application/json" }, "")).toEqual({
      Accept: "application/json",
    });
  });

  test("window control methods call desktop bridge when available", () => {
    window.desktop = {
      minimizeWindow: jest.fn(),
      maximizeWindow: jest.fn(),
      closeWindow: jest.fn(),
      setProgressBar: jest.fn(),
      togglePowerSave: jest.fn(),
    };

    Platform.minimizeWindow();
    Platform.maximizeWindow();
    Platform.closeWindow();
    Platform.setProgressBar(0.5, "normal");
    Platform.togglePowerSave(true);

    expect(window.desktop.minimizeWindow).toHaveBeenCalledTimes(1);
    expect(window.desktop.maximizeWindow).toHaveBeenCalledTimes(1);
    expect(window.desktop.closeWindow).toHaveBeenCalledTimes(1);
    expect(window.desktop.setProgressBar).toHaveBeenCalledWith(0.5, "normal");
    expect(window.desktop.togglePowerSave).toHaveBeenCalledWith(true);
  });

  test("window control methods are no-op when bridge methods are missing", () => {
    window.desktop = {};

    expect(() => Platform.minimizeWindow()).not.toThrow();
    expect(() => Platform.maximizeWindow()).not.toThrow();
    expect(() => Platform.closeWindow()).not.toThrow();
    expect(() => Platform.setProgressBar(1)).not.toThrow();
    expect(() => Platform.togglePowerSave(false)).not.toThrow();
  });
});
