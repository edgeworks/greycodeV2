# updater/scheduler.py

import asyncio
import importlib
import os
from pathlib import Path

UPDATE_INTERVAL = 3600  # seconds

async def run_plugins():
    plugin_folder = Path("./plugins")
    plugins = [f.stem for f in plugin_folder.glob("*.py") if not f.name.startswith("__")]
    for plugin in plugins:
        module = importlib.import_module(f"plugins.{plugin}")
        await module.update()

async def main():
    while True:
        await run_plugins()
        await asyncio.sleep(UPDATE_INTERVAL)

if __name__ == "__main__":
    asyncio.run(main())
