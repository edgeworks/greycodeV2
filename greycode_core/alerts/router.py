from __future__ import annotations

import os
from typing import List, Protocol

import redis.asyncio as redis

from .models import AlertEvent
from .email_sink import EmailSink


CFG_KEY = "greycode:cfg"
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))


def _boolish(v: str, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on", "enabled")


class AlertSink(Protocol):
    async def send(self, alert: AlertEvent) -> None: ...


class AlertRouter:
    def __init__(self) -> None:
        self.r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    async def _build_sinks(self) -> List[AlertSink]:
        sinks: List[AlertSink] = []

        cfg = await self.r.hgetall(CFG_KEY)

        if _boolish(cfg.get("notify_email_enabled", "0"), default=False):
            try:
                sinks.append(EmailSink.from_cfg(cfg))
            except Exception as e:
                print(f"[alerts] EmailSink disabled/misconfigured: {e}")

        # Later:
        # if _boolish(cfg.get("notify_teams_enabled", "0")):
        #     sinks.append(TeamsSink.from_cfg(cfg))
        # if _boolish(cfg.get("notify_splunk_enabled", "0")):
        #     sinks.append(SplunkSink.from_cfg(cfg))

        return sinks

    async def send(self, alert: AlertEvent) -> None:
        sinks = await self._build_sinks()

        if not sinks:
            return

        for sink in sinks:
            try:
                await sink.send(alert)
            except Exception as e:
                print(f"[alerts] sink={sink.__class__.__name__} failed: {e}")