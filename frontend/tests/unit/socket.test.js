function loadSocket() {
  jest.resetModules();
  return require("../../src/modules/socket.js").Socket;
}

let consoleErrorSpy;

beforeEach(() => {
  consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  consoleErrorSpy.mockRestore();
});

test("connect creates WebSocket with local ws endpoint", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  Socket.connect();

  expect(WebSocket.instances.length).toBe(1);
  expect(WebSocket.instances[0].url).toBe("ws://127.0.0.1:8000/ws");
});

test("connect uses desktop bridge to build the authenticated websocket url", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  window.desktop = {
    buildWebSocketUrl: jest.fn((url) => `${url}?token=abc123`),
  };
  const Socket = loadSocket();
  Socket.connect();

  expect(WebSocket.instances.length).toBe(1);
  expect(WebSocket.instances[0].url).toBe("ws://127.0.0.1:8000/ws?token=abc123");
  delete window.desktop;
});

test("connect uses wss when page protocol is https", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const originalLocation = window.location;
  Object.defineProperty(window, "location", {
    configurable: true,
    value: { protocol: "https:" },
  });

  const Socket = loadSocket();
  Socket.connect();

  expect(WebSocket.instances[0].url).toBe("wss://127.0.0.1:8000/ws");

  Object.defineProperty(window, "location", {
    configurable: true,
    value: originalLocation,
  });
});

test("on and off manage event handler delivery", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  const handler = jest.fn();

  Socket.on("job_progress", handler);
  Socket.connect();

  const ws = WebSocket.instances[0];
  ws.onmessage({ data: JSON.stringify({ type: "job_progress", payload: { pct: 10 } }) });
  expect(handler).toHaveBeenCalledWith({ pct: 10 });

  Socket.off("job_progress", handler);
  ws.onmessage({ data: JSON.stringify({ type: "job_progress", payload: { pct: 20 } }) });
  expect(handler).toHaveBeenCalledTimes(1);
});

test("onopen resets reconnect interval and logs connection", () => {
  jest.useFakeTimers();
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  Socket.connect();

  const firstWs = WebSocket.instances[0];
  firstWs.onclose();
  jest.advanceTimersByTime(2000);
  expect(WebSocket.instances.length).toBe(2);

  const secondWs = WebSocket.instances[1];
  secondWs.onopen();
  secondWs.onclose();
  jest.advanceTimersByTime(2000);

  // After onopen, reconnect interval should reset back to 2000ms.
  expect(WebSocket.instances.length).toBe(3);
  jest.useRealTimers();
});

test("message without known type does not call handlers", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  const handler = jest.fn();
  Socket.on("job_progress", handler);
  Socket.connect();

  const ws = WebSocket.instances[0];
  ws.onmessage({ data: JSON.stringify({ payload: { pct: 1 } }) });
  expect(handler).not.toHaveBeenCalled();
});

test("off for unknown event type is a no-op", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  const handler = jest.fn();

  expect(() => Socket.off("unknown_event", handler)).not.toThrow();
});

test("registering two handlers for same event keeps existing handler list", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  const h1 = jest.fn();
  const h2 = jest.fn();
  Socket.on("job_progress", h1);
  Socket.on("job_progress", h2);
  Socket.connect();

  const ws = WebSocket.instances[0];
  ws.onmessage({ data: JSON.stringify({ type: "job_progress", payload: { pct: 33 } }) });

  expect(h1).toHaveBeenCalledWith({ pct: 33 });
  expect(h2).toHaveBeenCalledWith({ pct: 33 });
});

test("invalid JSON on message does not throw", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  Socket.connect();

  const ws = WebSocket.instances[0];
  expect(() => ws.onmessage({ data: "{" })).not.toThrow();
  expect(consoleErrorSpy).toHaveBeenCalled();
});

test("onerror closes socket", () => {
  document.body.innerHTML = '<div id="log-panel"></div>';
  const Socket = loadSocket();
  Socket.connect();

  const ws = WebSocket.instances[0];
  ws.onerror(new Error("boom"));

  expect(ws.close).toHaveBeenCalled();
  expect(consoleErrorSpy).toHaveBeenCalled();
});

test("onclose schedules reconnect", () => {
  jest.useFakeTimers();
  document.body.innerHTML = '<div id="log-panel"></div>';

  const Socket = loadSocket();
  Socket.connect();
  const ws = WebSocket.instances[0];

  ws.onclose();
  expect(WebSocket.instances.length).toBe(1);

  jest.advanceTimersByTime(2000);
  expect(WebSocket.instances.length).toBe(2);

  jest.useRealTimers();
});
