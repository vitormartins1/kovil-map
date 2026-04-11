# Security Best Practices

This page summarizes security practices for users and contributors.

## For Users

- run with least privilege
- protect `config.json`
- use `KOVIL_API_TOKEN` if the backend is exposed beyond localhost
- verify SSH host keys when syncing with remote devices
- treat imported data as untrusted
- keep external tools and GPU drivers updated
- follow the ethics policy

## For Contributors

- validate all inputs
- prefer `textContent` over `innerHTML`
- never use `shell=True`
- never commit secrets
- keep Electron hardened
- return generic error messages
- add tests for malicious input

## Local Quality Checks

```bash
ruff check backend/app
black --check backend/app
pytest
```

```bash
npm run lint --prefix frontend
npm run test:unit --prefix frontend
```
