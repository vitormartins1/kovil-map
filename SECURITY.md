# Security Policy

KOVIL MAP is a local-first security tool with dual-use capabilities. Please use
it only on networks, captures, devices, and systems you own or are explicitly
authorized to assess.

## Reporting a Vulnerability

Do not open a public issue for sensitive vulnerabilities.

Preferred reporting channels:

1. GitHub private vulnerability reporting, if enabled for the repository
2. Private maintainer contact through the repository profile or security contact path

Include:

- affected component or file
- impacted version or commit
- reproduction steps or proof of concept
- expected impact
- any suggested mitigation if you already have one

## Scope

This policy covers:

- the FastAPI backend in `backend/`
- the Electron desktop application in `frontend/`
- local configuration handling in `backend/config.json`
- local runtime data under `backend/data/`
- repository workflows and release-related automation

## Response Targets

Best-effort targets for responsible disclosure:

- acknowledgment within 72 hours
- initial triage within 7 days
- coordinated remediation timing based on severity and exploitability

These are targets, not guarantees.

## Safe Harbor

We support good-faith security research that:

- avoids privacy violations and data destruction
- avoids service disruption or persistence
- uses the minimum necessary proof of concept
- keeps findings private until maintainers have time to triage

## Operational Security Notes

- keep the backend bound to localhost unless you have explicitly enabled auth
- prefer `KOVIL_API_TOKEN` or `KOVIL_REQUIRE_API_TOKEN=1` when exposing the API beyond loopback
- treat `backend/config.json` as sensitive if it contains device credentials or local paths
- treat `backend/data/` as sensitive if it contains captures, cracked outputs, GPS metadata, or sync artifacts
- validate SSH host trust before syncing with remote devices

## Out of Scope

The following are generally out of scope unless they directly result from a flaw in this repository:

- attacks that require physical access to an unlocked workstation
- unsafe operator choices in a local lab
- vulnerabilities that exist only in third-party tools outside our integration layer
- issues that cannot be reproduced on a supported branch or current release state

## Related Documents

- [`docs/08-SECURITY/README.md`](docs/08-SECURITY/README.md)
- [`docs/08-SECURITY/vulnerability-policy.md`](docs/08-SECURITY/vulnerability-policy.md)
- [`docs/08-SECURITY/hardening.md`](docs/08-SECURITY/hardening.md)
- [`docs/08-SECURITY/threat-model.md`](docs/08-SECURITY/threat-model.md)
