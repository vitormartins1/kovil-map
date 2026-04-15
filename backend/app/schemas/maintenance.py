from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DemoInstallRequest(BaseModel):
    profile_id: str = "showcase-core-v1"
    frontend_state: dict[str, Any] | None = None
