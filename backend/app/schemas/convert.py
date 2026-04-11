from pydantic import BaseModel
from typing import List, Optional


class ConvertRequest(BaseModel):
    filename: Optional[str] = None
    capture_id: Optional[str] = None
    raw_item_id: Optional[str] = None


class ConvertMultiRequest(BaseModel):
    filenames: Optional[List[str]] = None
    capture_ids: Optional[List[str]] = None
