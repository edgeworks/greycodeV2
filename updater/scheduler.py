# updater/scheduler.py

import asyncio
import importlib
import os
import time
from pathlib import Path
from typing import Dict, Tuple


PLUGIN_DIR = Path(__file__).resolve().parent / "plugins"

SCHEDULER_TICK_SECONDS = int(os.getenv("SCHEDULER_TICK_SECONDS", "5"))
DEFAULT_PLUGIN_INTERVAL = int(os.getenv("DEFAULT_PLUGIN_INTERVAL", "3600"))


def discover_plugins() -> Tuple[str, ...]:
    return tuple(
        f.stem
        for f in PLUGIN_DIR.glob("*.py")
        if f.is_file() and not f.name.startswith("__")
    )


async def run_plugin(module_name: str) -> None:
    module = importlib.import_module(f"plugins.{module_name}")
    update_fn = getattr(module, "update", None)
    if not callable(update_fn):
        raise RuntimeError(f"Plugin plugins.{module_name} has no update()")

    result = update_fn()
    if asyncio.iscoroutine(result):
        await result


async def main() -> None:
    plugins = discover_plugins()
    if not plugins:
        print(f"[scheduler] No plugins found in {PLUGIN_DIR}")
        return

    next_run: Dict[str, float] = {}
    intervals: Dict[str, int] = {}

    # load intervals once; restart container to pick up new plugins/intervals
    for p in plugins:
        try:
            module = importlib.import_module(f"plugins.{p}")
            intervals[p] = int(getattr(module, "UPDATE_INTERVAL", DEFAULT_PLUGIN_INTERVAL))
        except Exception as e:
            print(f"[scheduler] Failed to import plugins.{p}: {e}")
            intervals[p] = DEFAULT_PLUGIN_INTERVAL
        next_run[p] = 0.0  # run immediately

    print(f"[scheduler] Loaded plugins: {plugins}")
    print(f"[scheduler] Intervals: {intervals}")
    print(f"[scheduler] Tick: {SCHEDULER_TICK_SECONDS}s")

    while True:
        now = time.time()

        for p in plugins:
            if now < next_run.get(p, 0.0):
                continue

            try:
                await run_plugin(p)
                next_run[p] = now + intervals[p]
                print(f"[scheduler] plugins.{p} OK (next in {intervals[p]}s)")
            except Exception as e:
                # retry sooner on failures
                backoff = min(300, max(10, intervals[p] // 6))
                next_run[p] = now + backoff
                print(f"[scheduler] plugins.{p} ERROR: {e} (retry in {backoff}s)")

        await asyncio.sleep(SCHEDULER_TICK_SECONDS)


if __name__ == "__main__":
    asyncio.run(main())
