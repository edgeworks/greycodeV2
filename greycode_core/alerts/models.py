from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class AlertEvent:
    # Core alert identity
    alert_type: str                    # e.g. HASH_RED, IP_LISTED, DOMAIN_DELISTED
    status: str                        # e.g. RED / GREY / INFO

    # Generic indicator model
    indicator_type: str = ""           # sha256 | ip | domain | url
    indicator: str = ""                # generic value for the indicator

    # VT / hash compatibility
    sha256: str = ""
    vt_malicious: int = 0
    vt_suspicious: int = 0

    # Context
    computer: str = ""
    image: str = ""
    source: str = ""                   # vt / blacklist / etc.

    # Links
    vt_link: Optional[str] = None
    ui_link: Optional[str] = None

    # Transition-aware blacklist alerts
    transition: str = ""               # LISTED | DELISTED | ""
    listed_by: List[str] = field(default_factory=list)
    vendors_added: List[str] = field(default_factory=list)
    vendors_removed: List[str] = field(default_factory=list)

    # Human-readable fallback
    message: Optional[str] = None

    @property
    def effective_indicator_type(self) -> str:
        """
        Backward-compatible helper:
        - explicit indicator_type wins
        - otherwise infer sha256 if sha256 is present
        """
        if self.indicator_type:
            return self.indicator_type
        if self.sha256:
            return "sha256"
        return ""

    @property
    def effective_indicator(self) -> str:
        """
        Backward-compatible helper:
        - explicit indicator wins
        - otherwise fall back to sha256
        """
        if self.indicator:
            return self.indicator
        if self.sha256:
            return self.sha256
        return ""