const {
  readSessionStorageJson,
  removeSessionStorageKeysByPrefix,
  writeSessionStorageJson,
} = require("../../src/modules/cache_store.js");

describe("cache_store helpers", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  test("writes and reads JSON payloads from sessionStorage", () => {
    const ok = writeSessionStorageJson("pwn.test.entry", { ok: true, count: 2 });

    expect(ok).toBe(true);
    expect(readSessionStorageJson("pwn.test.entry")).toEqual({ ok: true, count: 2 });
  });

  test("respects maxBytes when persisting payloads", () => {
    const ok = writeSessionStorageJson("pwn.test.large", { text: "abcdef" }, { maxBytes: 5 });

    expect(ok).toBe(false);
    expect(readSessionStorageJson("pwn.test.large")).toBeNull();
  });

  test("removes namespaced keys while preserving explicit exceptions", () => {
    writeSessionStorageJson("pwn.test.one", { id: 1 });
    writeSessionStorageJson("pwn.test.two", { id: 2 });
    writeSessionStorageJson("pwn.other.keep", { id: 3 });

    removeSessionStorageKeysByPrefix("pwn.test.", { except: ["pwn.test.two"] });

    expect(readSessionStorageJson("pwn.test.one")).toBeNull();
    expect(readSessionStorageJson("pwn.test.two")).toEqual({ id: 2 });
    expect(readSessionStorageJson("pwn.other.keep")).toEqual({ id: 3 });
  });
});
