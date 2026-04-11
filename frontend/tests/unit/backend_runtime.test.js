const path = require("path");

const runtime = require("../../backend_runtime.js");

describe("backend runtime helpers", () => {
  test("chooses binary name by platform", () => {
    expect(runtime.getBackendBinaryName("win32")).toBe("kovil_backend.exe");
    expect(runtime.getBackendBinaryName("linux")).toBe("kovil_backend");
    expect(runtime.getBackendBinaryName("darwin")).toBe("kovil_backend");
  });

  test("builds candidate paths with preferred platform order", () => {
    const candidates = runtime.getPackagedBackendCandidates("/tmp/resources", "linux");
    expect(candidates).toEqual([
      path.join("/tmp/resources", "backend", "kovil_backend"),
      path.join("/tmp/resources", "backend", "kovil_backend.exe"),
    ]);
  });

  test("resolves first existing packaged backend candidate", () => {
    const resolved = runtime.resolvePackagedBackendPath(
      "/tmp/resources",
      "win32",
      (candidate) => candidate.endsWith("kovil_backend.exe"),
    );
    expect(resolved).toBe(path.join("/tmp/resources", "backend", "kovil_backend.exe"));
  });

  test("throws a clear error when packaged backend is missing", () => {
    expect(() =>
      runtime.resolvePackagedBackendPath("/tmp/resources", "linux", () => false),
    ).toThrow(/Packaged backend executable not found/);
  });
});
