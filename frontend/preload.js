const { contextBridge, ipcRenderer } = require("electron");

const apiToken = process.env.KOVIL_API_TOKEN || null;

function mergeHeadersWithToken(headers = {}) {
  const merged = { ...(headers || {}) };
  if (apiToken) {
    merged["X-KOVIL-Token"] = apiToken;
  }
  return merged;
}

function buildWebSocketUrl(baseUrl) {
  if (!apiToken) return baseUrl;
  try {
    const url = new URL(baseUrl);
    if (!url.searchParams.has("token")) {
      url.searchParams.set("token", apiToken);
    }
    return url.toString();
  } catch (_err) {
    const separator = String(baseUrl || "").includes("?") ? "&" : "?";
    return `${baseUrl}${separator}token=${encodeURIComponent(apiToken)}`;
  }
}

async function fetchApiOverBridge(url, options = undefined) {
  let requestOptions = options ? { ...options } : undefined;
  if (!requestOptions && apiToken) {
    requestOptions = {};
  }
  const currentHeaders = requestOptions?.headers || {};
  const nextHeaders = mergeHeadersWithToken(currentHeaders);
  if (requestOptions && Object.keys(nextHeaders).length > 0) {
    requestOptions.headers = nextHeaders;
  }

  const response = !requestOptions ? await fetch(url) : await fetch(url, requestOptions);
  const headers = {};
  if (response?.headers && typeof response.headers.forEach === "function") {
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
  }

  return {
    ok: !!response?.ok,
    status: Number(response?.status || 0),
    statusText: String(response?.statusText || ""),
    url: String(response?.url || url || ""),
    headers,
    bodyText: await response.text(),
  };
}

contextBridge.exposeInMainWorld("desktop", {
  fetchApi: fetchApiOverBridge,
  buildWebSocketUrl,
  minimizeWindow: () => ipcRenderer.send("minimize-window"),
  maximizeWindow: () => ipcRenderer.send("maximize-window"),
  closeWindow: () => ipcRenderer.send("close-window"),
  setProgressBar: (value, mode = "normal") =>
    ipcRenderer.send("set-progress-bar", { value, mode }),
  togglePowerSave: (enable) =>
    ipcRenderer.send("toggle-power-save", !!enable),
});
