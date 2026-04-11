# CI/CD Pipeline

KOVIL MAP uses GitHub Actions to protect code quality, security, and release readiness. The pipeline is split into quality and security workflows, with automated PR promotion between the main branches.

## Overview

- Platform: GitHub Actions
- Main workflows:
  - `quality.yml` for linting, tests, and structural validation
  - `security.yml` for SAST, SCA, secrets scanning, and SBOM generation
- Promotion helpers:
  - automatic PR flow from `feature/*` or equivalent branches into `dev`
  - automatic PR flow from `dev` into `main`
- README badges:
  - native GitHub Actions status badges for `Quality` and `Security` on `main`

## Quality Pipeline

`quality.yml` is the primary merge gate for day-to-day development.

### Current trigger model

- runs on `pull_request` into `dev` and `main`
- runs on `push` to `main`
- does not run on feature-branch push anymore; feature branches create an auto PR and gates execute on that PR

### Backend jobs

- artifact guardrails for generated coverage badge artifacts
- `ruff` linting
- `black --check`
- unit tests
- OpenAPI contract validation

### Frontend jobs

- JavaScript linting
- HTML validation
- CSS linting
- Jest unit tests
- Electron/project validation checks
- packaged-backend smoke test via `tests/unit/backend_runtime.test.js`

### Current goal

No code should move into `dev` or `main` without passing the quality workflow.

## Security Pipeline

`security.yml` runs as a required PR gate for `dev` and `main`, and also on `push` to `main` for post-merge verification.

### Current scanner categories

- SAST with `Semgrep`
- secrets detection with `Gitleaks`
- SCA with `Trivy`
- SCA with `Dependency-Check`
- runtime package review with `npm audit`
- SBOM generation with `Syft`

## Promotion Flow

1. A contributor creates a working branch from `dev`.
2. Pushing the branch creates or updates an automated PR into `dev`.
3. `quality.yml` and `security.yml` run on the PR into `dev`.
4. If required checks pass, the PR can be merged into `dev`.
5. After merge into `dev`, the automated `dev -> main` PR is created or updated.
6. `quality.yml` and `security.yml` run again on the PR into `main`.
7. If required checks pass, the PR can be merged into `main`.

## Coverage and Badges

- backend and frontend coverage are still generated during test jobs
- coverage artifacts remain available in workflow runs
- workflow summaries remain the main in-GitHub coverage view
- CI no longer commits generated coverage badge assets back into the repository
- repository badges now reflect workflow status instead of coverage percentage

## Local Validation

Run the critical checks locally before pushing to save CI time.

### Backend

```bash
ruff check backend/app
black --check backend/app
pytest backend/app/tests
```

### Frontend

```bash
npm run lint --prefix frontend
npm run test:unit --prefix frontend
npm run test:smoke:packaged --prefix frontend
```

## Related Docs

- [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md)
- [`testing.md`](testing.md)
- [`../08-SECURITY/README.md`](../08-SECURITY/README.md)
