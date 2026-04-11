# Runtime Modes

KOVIL MAP supports two practical ways to run the product: a packaged release for operators and a development setup for contributors.

This page explains what changes between them so the first-run experience is easier to reason about.

## Quick Comparison

| Mode | Best for | Backend startup | Auth expectation | Typical logs |
|---|---|---|---|---|
| Packaged release | daily use, demos, operators | started by the desktop app | local token auth expected by default | app logs and packaged runtime logs |
| Development mode | contribution, debugging, feature work | started manually by the developer | open local dev by default unless token mode is enabled | backend terminal plus frontend dev logs |

## Packaged Release Mode

This is the easiest path for most users.

What to expect:

- you install a build from GitHub Releases
- the Electron app starts the packaged backend automatically
- the backend normally stays local to `127.0.0.1`
- token auth is expected in packaged runtime by default
- this is the right mode when you just want to operate the tool

Use this mode when you want:

- the shortest setup path
- predictable operator behavior
- fewer moving parts during first launch

## Development Mode

This is the right mode when working on the codebase.

What to expect:

- you start the backend manually with `python main.py`
- you start the frontend manually with `npm start`
- you can inspect backend and frontend logs separately
- token auth can still be enabled with `KOVIL_API_TOKEN` or `KOVIL_REQUIRE_API_TOKEN=1`
- it is easier to debug file paths, API behavior, and UI/runtime interactions

Use this mode when you want:

- to contribute code or docs
- to inspect logs in detail
- to iterate on UI, backend, or workflows locally

## Local Auth Summary

KOVIL MAP does not use a browser-style login flow.

Instead:

- packaged runtime expects local token auth by default
- development can opt into the same behavior with `KOVIL_API_TOKEN`
- development can also force token mode with `KOVIL_REQUIRE_API_TOKEN=1`
- requests can use `X-KOVIL-Token` or `Authorization: Bearer ...`

## Recommended Choice

- choose **packaged release** if your goal is to operate the tool
- choose **development mode** if your goal is to change the codebase or debug internals

## Related Docs

- [Installation Guide](installation.md)
- [First Run Guide](first-run.md)
- [Configuration & Environment](../03-DEVELOPMENT/configuration.md)
- [API Overview](../01-ARCHITECTURE/api-overview.md)
