module.exports = {
  testEnvironment: "jsdom",
  rootDir: ".",
  testMatch: ["<rootDir>/tests/unit/**/*.test.js"],
  setupFilesAfterEnv: ["<rootDir>/tests/setup/jest.setup.js"],
  transform: {
    "^.+\\.[jt]sx?$": "babel-jest",
  },
  moduleFileExtensions: ["js", "mjs", "json"],
  collectCoverage: true,
  coverageReporters: ["text", "lcov", "clover", "json-summary"],
  collectCoverageFrom: ["src/modules/**/*.js"],
  coverageThreshold: {
    global: {
      branches: 72,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
};
