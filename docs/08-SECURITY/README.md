# Security

Security policies, threat modeling, hardening guidance, and responsible disclosure notes for KOVIL MAP.

## Security Documents

### [Threat Model](threat-model.md)

- assets and trust boundaries
- threat scenarios
- mitigations

### [Vulnerability Policy](vulnerability-policy.md)

- responsible disclosure
- how to report
- response expectations

### [CI/CD Security](ci-cd-security.md)

- secret scanning
- static analysis
- dependency checks

### [Best Practices](best-practices.md)

- validation
- safe rendering
- secure command execution

### [Technical Hardening](hardening.md)

- Electron hardening
- backend anti-injection
- SSH host verification

### [Legal & Ethics](legal-and-ethics.md)

- dual-use guidance
- operator responsibility
- safe lab usage

---

## Core Principles

1. Keep the backend local by default.
2. Keep secrets and operational data out of Git.
3. Treat sync credentials and captured artifacts as sensitive.
4. Prefer safe subprocess execution and strict path validation.
5. Document security-impacting changes when public behavior changes.

---

## Common Threats

| Threat | Impact | Mitigation |
|---|---|---|
| local auth bypass | critical | token auth and localhost-first design |
| unsafe file access | high | path validation and constrained file roots |
| command injection | critical | argument-list subprocess execution |
| XSS in renderer | high | safer DOM patterns, CSP, and preload boundaries |
| sensitive data leakage | critical | keep configs and runtime data local |
| supply-chain drift | medium | SAST, SCA, SBOM, and dependency review |

---

## Contributor Checklist

- validate all inputs
- keep secrets out of git
- log safely
- test security assumptions
- document security-relevant behavior changes

---

## Reporting Vulnerabilities

Use private disclosure channels for sensitive issues. Include the impacted file or line, a proof of concept, and the expected impact.
