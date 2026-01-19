from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class AlertEvent:
    alert_type: str               # e.g. "HASH_RED"
    sha256: str

    status: str                   # "RED"
    vt_malicious: int = 0
    vt_suspicious: int = 0

    computer: str = ""
    image: str = ""

    source: str = ""              # "vt" etc.
    vt_link: Optional[str] = None
    ui_link: Optional[str] = None

    # extra room for future enrichers
    message: Optional[str] = None
