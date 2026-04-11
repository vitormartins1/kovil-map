function desktopBridge() {
  if (typeof window === "undefined") return null;
  return window.desktop || null;
}

function mergeHeaders(headers = {}, token = null) {
  const merged = { ...(headers || {}) };
  if (token) {
    merged["X-KOVIL-Token"] = token;
  }
  return merged;
}

function createHeadersShim(headers = {}) {
  const normalized = {};
  Object.entries(headers || {}).forEach(([key, value]) => {
    normalized[String(key).toLowerCase()] = value;
  });
  return {
    get(name) {
      return normalized[String(name || "").toLowerCase()] ?? null;
    },
  };
}

function createBridgeResponse(payload = {}) {
  const headers = createHeadersShim(payload.headers || {});
  let parsedJsonPromise = null;
  const bodyText = Object.prototype.hasOwnProperty.call(payload, "bodyText")
    ? String(payload.bodyText ?? "")
    : "";
  return {
    ok: !!payload.ok,
    status: Number(payload.status || 0),
    statusText: String(payload.statusText || ""),
    url: String(payload.url || ""),
    headers,
    async json() {
      if (!parsedJsonPromise) {
        parsedJsonPromise = Promise.resolve().then(() => {
          if (!bodyText) return null;
          return JSON.parse(bodyText);
        });
      }
      return parsedJsonPromise;
    },
    async text() {
      return bodyText;
    },
  };
}

function normalizeFetchResult(result) {
  if (result && typeof result.json === "function") {
    return result;
  }
  if (result && typeof result === "object") {
    return createBridgeResponse(result);
  }
  return result;
}

export const Platform = {
  async fetchApi(url, options = undefined) {
    try {
      const bridge = desktopBridge();
      if (bridge && typeof bridge.fetchApi === "function") {
        const result = await bridge.fetchApi(url, options);
        return normalizeFetchResult(result);
      }
    } catch (_err) {
      if (options === undefined) {
        return fetch(url);
      }
      return fetch(url, options);
    }
    if (options === undefined) {
      return fetch(url);
    }
    return fetch(url, options);
  },

  buildWebSocketUrl(baseUrl) {
    try {
      const bridge = desktopBridge();
      if (bridge && typeof bridge.buildWebSocketUrl === "function") {
        return bridge.buildWebSocketUrl(baseUrl) || baseUrl;
      }
    } catch (_err) {
      return baseUrl;
    }
    return baseUrl;
  },

  mergeHeaders(headers = {}, token = null) {
    return mergeHeaders(headers, token);
  },

  createBridgeResponse(payload = {}) {
    return createBridgeResponse(payload);
  },

  minimizeWindow() {
    const bridge = desktopBridge();
    if (bridge && typeof bridge.minimizeWindow === "function") {
      bridge.minimizeWindow();
    }
  },

  maximizeWindow() {
    const bridge = desktopBridge();
    if (bridge && typeof bridge.maximizeWindow === "function") {
      bridge.maximizeWindow();
    }
  },

  closeWindow() {
    const bridge = desktopBridge();
    if (bridge && typeof bridge.closeWindow === "function") {
      bridge.closeWindow();
    }
  },

  setProgressBar(value, mode = "normal") {
    const bridge = desktopBridge();
    if (bridge && typeof bridge.setProgressBar === "function") {
      bridge.setProgressBar(value, mode);
    }
  },

  togglePowerSave(enable) {
    const bridge = desktopBridge();
    if (bridge && typeof bridge.togglePowerSave === "function") {
      bridge.togglePowerSave(enable);
    }
  },
};
