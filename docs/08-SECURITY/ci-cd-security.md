# CI/CD Security Pipeline

KOVIL MAP uses GitHub Actions to catch secrets, insecure patterns, and vulnerable dependencies before code reaches the main branch.

## Pipeline Structure

The security workflow runs alongside quality checks and blocks promotion when it fails.

### Triggers

- push to `main` and `dev`
- manual `workflow_dispatch`

## Scanners

- **Gitleaks:** detects secrets in Git history
- **Semgrep:** catches unsafe code patterns in Python and JavaScript
- **Dependency checks:** scan frontend and backend dependencies for known CVEs
- **Syft:** generates an SBOM for supply-chain traceability

## Quality Gates

The pipeline fails when:

- any critical secret is found
- Semgrep reports an `ERROR` severity issue
- a high or critical dependency issue is found without an approved exception

## Handling False Positives

1. confirm the issue is real
2. suppress only confirmed false positives
3. fix the code or dependency when the issue is valid

## Remediation Flow

1. the pipeline fails
2. the logs identify the file and line
3. the developer fixes the issue locally
4. the next push validates the fix

## Pipeline Security

- keep CI secrets in GitHub Secrets
- use minimal permissions for `GITHUB_TOKEN`
- pin third-party actions by commit SHA
