from __future__ import annotations

import os
from typing import List

from .models import AlertEvent
from .email_sink import EmailSink


def _env_bool(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip() == "1"


class AlertRouter:
    def __init__(self) -> None:
        self.sinks = self._build_sinks()

    def _build_sinks(self) -> List[object]:
        sinks: List[object] = []

        if _env_bool("ALERT_EMAIL_ENABLED", "0"):
            sinks.append(EmailSink.from_env())

        # Later:
        # if _env_bool("ALERT_TEAMS_ENABLED", "0"): sinks.append(TeamsSink.from_env())
        # if _env_bool("ALERT_SPLUNK_ENABLED", "0"): sinks.append(SplunkSink.from_env())

        return sinks

    async def send(self, alert: AlertEvent) -> None:
        # Do not raise if a sink fails; log and continue.
        for sink in self.sinks:
            try:
                await sink.send(alert)
            except Exception as e:
                print(f"[alerts] sink={sink.__class__.__name__} failed: {e}")
