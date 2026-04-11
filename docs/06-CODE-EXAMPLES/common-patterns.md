# Common Code Patterns

This page documents recurring implementation patterns used across KOVIL MAP. Following these patterns keeps the codebase safer, more predictable, and easier to evolve.

## Backend Patterns

### 1. Strict request validation

Use Pydantic models for write endpoints and reject unexpected payload fields when appropriate.

```python
from pydantic import BaseModel, Field


class CreateNetworkRequest(BaseModel):
    ssid: str = Field(..., min_length=1)
    bssid: str = Field(..., pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")

    class Config:
        extra = "forbid"
```

### 2. Safe subprocess execution

Never build shell commands through raw string concatenation when invoking system tools.

Unsafe:

```python
os.system(f"hashcat -m 22000 {filename}")
```

Preferred:

```python
import subprocess

cmd = ["hashcat", "-m", "22000", filename]
proc = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)
```

### 3. Long-running work through the Job Manager

Cracking, sync, and parsing-heavy tasks should not block request handling. Schedule them through the shared job infrastructure and stream updates over WebSocket.

### 4. Path safety

Resolve files under approved data roots and sanitize user-controlled filenames before joining paths.

```python
import os
from app.core.config import HANDSHAKES_DIR


def get_safe_path(filename: str) -> str:
    clean_name = os.path.basename(filename)
    full_path = os.path.join(HANDSHAKES_DIR, clean_name)
    if not full_path.startswith(os.path.abspath(HANDSHAKES_DIR)):
        raise ValueError("Path traversal attempt")
    return full_path
```

## Frontend Patterns

### 1. Renderer isolation

The renderer should not use Node.js APIs directly. Desktop integration must flow through the preload bridge.

### 2. Centralized state

Shared UI state belongs in `state.js` and related modules, not in scattered global variables.

### 3. Safe DOM updates

Prefer `textContent` and DOM node creation over raw `innerHTML` when rendering untrusted data such as SSIDs or vendor strings.

Unsafe:

```javascript
div.innerHTML = `Network: ${network.ssid}`;
```

Preferred:

```javascript
div.textContent = `Network: ${network.ssid}`;
```

### 4. Realtime updates through socket handlers

Job progress, sync completion, and data refreshes should be driven from the shared WebSocket layer instead of ad hoc polling.

## API Response Pattern

Success:

```json
{
  "status": "success",
  "data": {}
}
```

Error:

```json
{
  "status": "error",
  "error": {
    "message": "Readable error message"
  }
}
```

## Related Docs

- [`adding-new-feature.md`](adding-new-feature.md)
- [`../01-ARCHITECTURE/system-design.md`](../01-ARCHITECTURE/system-design.md)
- [`../08-SECURITY/hardening.md`](../08-SECURITY/hardening.md)
