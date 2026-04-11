# Contributing Guide

Thanks for helping improve KOVIL MAP.

This repository stays open source with a `main + dev` workflow:

- `main` is the stable branch
- `dev` is the integration branch
- feature work should normally target `dev`

## Ways to Contribute

- report bugs with the GitHub bug template
- propose features with the GitHub feature template
- improve docs, tests, UX, or automation
- submit focused pull requests against `dev`

## Branch Naming

Recommended branch names:

- `feature/<name>`
- `fix/<name>`
- `chore/<name>`
- `docs/<name>`

## Typical Contribution Flow

1. Branch from `dev`.
2. Make a focused change.
3. Run the relevant local checks.
4. Open a pull request into `dev`.
5. Address review feedback and failing checks.
6. After merge into `dev`, maintainers promote `dev` into `main`.

Maintainers may use the repository's auto-PR workflows for branch promotion, but external contributors should not rely on them. A normal pull request to `dev` is always acceptable.

## Local Validation Before Push

Backend:

```bash
pip install -r backend/requirements.txt
pip install -r backend/requirements-dev.txt
ruff check backend/app
black --check backend/app
pytest backend/app/tests --cov=backend/app --cov-fail-under=70
```

Frontend:

```bash
npm ci --prefix frontend
npm --prefix frontend run test:unit:coverage
```

## Pull Request Expectations

- keep each PR scoped to one problem or improvement
- include tests when behavior changes
- update docs when public behavior or setup changes
- do not commit secrets, tokens, personal configs, or operational captures
- describe user-visible impact and verification in the PR body

## CI Overview

Primary repository workflows:

- `.github/workflows/quality.yml`
- `.github/workflows/security.yml`

Promotion helpers used by maintainers:

- `.github/workflows/auto-pr-feature-to-dev.yml`
- `.github/workflows/auto-pr-dev-to-main.yml`

## Community Standards

- review [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) before participating
- use [`SECURITY.md`](SECURITY.md) for sensitive vulnerability reports
- treat local files under `backend/data/` and `backend/config.json` as sensitive runtime material

## Recommended Repository Settings

1. Set the default branch to `main`.
2. Protect both `dev` and `main`.
3. Require pull requests before merge.
4. Require the `Quality` and `Security` checks on protected branches.
5. Prefer `squash` merges for contributor PRs.
