class MockWebSocket {
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.onopen = null;
    this.onmessage = null;
    this.onclose = null;
    this.onerror = null;
    MockWebSocket.instances.push(this);
  }

  send = jest.fn();

  close = jest.fn(() => {
    if (typeof this.onclose === "function") {
      this.onclose();
    }
  });
}

function createLocalStorageMock() {
  let store = {};
  return {
    getItem: jest.fn((key) => (Object.prototype.hasOwnProperty.call(store, key) ? store[key] : null)),
    setItem: jest.fn((key, value) => {
      store[key] = String(value);
    }),
    removeItem: jest.fn((key) => {
      delete store[key];
    }),
    clear: jest.fn(() => {
      store = {};
    }),
  };
}

Object.defineProperty(global, "fetch", {
  writable: true,
  value: jest.fn(),
});

Object.defineProperty(global, "WebSocket", {
  writable: true,
  value: MockWebSocket,
});

Object.defineProperty(global, "requestAnimationFrame", {
  writable: true,
  value: (cb) => cb(),
});

Object.defineProperty(global, "localStorage", {
  writable: true,
  value: createLocalStorageMock(),
});

Object.defineProperty(global.navigator, "clipboard", {
  configurable: true,
  value: {
    writeText: jest.fn().mockResolvedValue(undefined),
  },
});

beforeEach(() => {
  document.body.innerHTML = "";
  delete window.desktop;
  fetch.mockReset();
  navigator.clipboard.writeText.mockClear();
  localStorage.clear();
  localStorage.getItem.mockClear();
  localStorage.setItem.mockClear();
  localStorage.removeItem.mockClear();
  localStorage.clear.mockClear();
  MockWebSocket.instances.length = 0;
  jest.clearAllMocks();
});
