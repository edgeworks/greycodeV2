# greycode_core/models/events.py

from pydantic import BaseModel

class ProcessEvent(BaseModel):
    sha256: str
    user: str
