# Adding a New Feature

This guide shows the expected end-to-end flow for adding a new full-stack feature to KOVIL MAP.

## Typical Workflow

1. Define the backend contract.
2. Implement service logic.
3. expose the router endpoints.
4. connect the frontend API client.
5. build or update the UI surface.
6. add tests and documentation.

## Backend Example

Assume we want to add a simple `Network Notes` feature.

### 1. Create a schema

`backend/app/schemas/notes.py`

```python
from pydantic import BaseModel, Field


class NoteCreate(BaseModel):
    mac: str = Field(..., pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    content: str = Field(..., min_length=1, max_length=500)


class NoteResponse(BaseModel):
    id: int
    mac: str
    content: str
    created_at: str
```

### 2. Create a service

`backend/app/services/notes_service.py`

```python
from datetime import datetime

notes_db = []


class NotesService:
    async def add_note(self, mac: str, content: str):
        note = {
            "id": len(notes_db) + 1,
            "mac": mac,
            "content": content,
            "created_at": datetime.now().isoformat(),
        }
        notes_db.append(note)
        return note

    async def get_notes(self, mac: str):
        return [note for note in notes_db if note["mac"] == mac]


notes_service = NotesService()
```

### 3. Expose the router

`backend/app/api/routers/notes.py`

```python
from fastapi import APIRouter
from app.schemas.notes import NoteCreate
from app.services.notes_service import notes_service
from app.utils.responses import ok

router = APIRouter()


@router.post("/api/notes")
async def create_note(payload: NoteCreate):
    return ok(await notes_service.add_note(payload.mac, payload.content))


@router.get("/api/notes/{mac}")
async def list_notes(mac: str):
    return ok(await notes_service.get_notes(mac))
```

### 4. Register the router

Add the router to the backend router registry used by `backend/main.py`.

## Frontend Example

### 1. Extend the API client

`frontend/src/modules/api.js`

```javascript
async function addNote(mac, content) {
    return await API.post('/api/notes', { mac, content });
}

async function getNotes(mac) {
    return await API.get(`/api/notes/${mac}`);
}
```

### 2. Add a UI component

`frontend/src/modules/ui_components/ui_notes.js`

```javascript
import { API } from '../api.js';

export async function renderNotesPanel(mac) {
    const container = document.getElementById('notes-container');
    container.textContent = 'Loading...';

    const notes = await API.getNotes(mac);
    container.innerHTML = '';
    notes.forEach((note) => {
        const row = document.createElement('div');
        row.className = 'note-item';
        row.textContent = `${note.created_at}: ${note.content}`;
        container.appendChild(row);
    });
}
```

## Final Checklist

- input is validated
- service logic is isolated from the router
- success and error responses follow the project envelope
- frontend loading and error states are handled
- tests cover the new behavior
- docs are updated in `docs/`
