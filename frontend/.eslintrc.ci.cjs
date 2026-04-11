module.exports = {
  root: true,
  extends: ["eslint:recommended"],
  ignorePatterns: ["node_modules/", "dist/", "src/vendor/"],
  env: {
    es2022: true,
  },
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  rules: {
    "no-console": "off",
    "no-undef": "off",
    "no-unused-vars": "off",
  },
  overrides: [
    {
      files: ["main.js", "frontend/main.js"],
      env: {
        node: true,
        es2022: true,
      },
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "script",
      },
    },
    {
      files: [
        "src/**/*.js",
        "frontend/src/**/*.js",
        "tests/**/*.mjs",
        "frontend/tests/**/*.mjs",
      ],
      env: {
        browser: true,
        node: true,
        es2022: true,
      },
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module",
      },
    },
  ],
};
