# Code Examples

This folder contains the code examples and contributor patterns that still exist in the repository.

## Available Files

- [`frontend-integration.js`](frontend-integration.js) - frontend-side integration example
- [`adding-new-feature.md`](adding-new-feature.md) - end-to-end feature checklist
- [`common-patterns.md`](common-patterns.md) - recurring patterns used in the codebase

## Current Guidance

The frontend is built with Electron plus vanilla JavaScript modules, so examples should follow the current renderer style instead of React component examples.

### Frontend pattern

```javascript
import { API } from '../modules/api.js';
import { log } from '../modules/utils.js';

export async function refreshSomething() {
    const payload = await API.getMapData();
    log(`Loaded ${Object.keys(payload || {}).length} records`, 'info');
    return payload;
}
```

### Backend pattern

```python
from app.utils.responses import ok


def build_summary(items: list[dict]) -> dict:
    return ok({
        "total": len(items),
        "items": items,
    })
```

## What Was Removed

This section no longer references missing example files or React-specific scaffolding that does not match the current codebase.
