const fs = require("fs");
const path = require("path");

function getBackendBinaryName(platform = process.platform) {
  return platform === "win32" ? "kovil_backend.exe" : "kovil_backend";
}

function getPackagedBackendCandidates(resourcesPath, platform = process.platform) {
  const preferred = getBackendBinaryName(platform);
  const fallback = preferred === "kovil_backend.exe" ? "kovil_backend" : "kovil_backend.exe";
  return [
    path.join(resourcesPath, "backend", preferred),
    path.join(resourcesPath, "backend", fallback),
  ];
}

function resolvePackagedBackendPath(
  resourcesPath,
  platform = process.platform,
  existsSync = fs.existsSync,
) {
  const candidates = getPackagedBackendCandidates(resourcesPath, platform);
  const resolved = candidates.find((candidate) => existsSync(candidate));

  if (resolved) {
    return resolved;
  }

  const expected = candidates.map((candidate) => path.basename(candidate)).join(" or ");
  throw new Error(
    `Packaged backend executable not found in resources/backend. Expected ${expected}.`,
  );
}

module.exports = {
  getBackendBinaryName,
  getPackagedBackendCandidates,
  resolvePackagedBackendPath,
};
