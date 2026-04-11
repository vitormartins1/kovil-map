# Testing Guide

This project uses separate test stacks for backend and frontend, with backend tests organized by domain and frontend tests focused on renderer modules.

## Backend

### Install dev dependencies

```bash
cd backend
source .venv/bin/activate
pip install -r requirements-dev.txt
```

### Run the full suite

```bash
pytest app/tests
```

### Run by domain

```bash
pytest app/tests/api
pytest app/tests/core
pytest app/tests/jobs
pytest app/tests/services
pytest app/tests/tools
pytest app/tests/utils
pytest app/tests/ws
```

### Coverage

```bash
pytest app/tests --cov=app/api --cov=app/core --cov=app/schemas --cov=app/services --cov=app/utils --cov-report=term-missing --cov-fail-under=90
```

## Frontend

Install dependencies:

```bash
cd frontend
npm install
```

Run tests:

```bash
npm run test:unit
```

Coverage:

```bash
npm run test:unit:coverage
```

## Notes

- backend tests live under `backend/app/tests/`
- frontend tests live under `frontend/tests/unit/`
- when updating docs or public contracts, keep tests and docs aligned in the same change when possible
