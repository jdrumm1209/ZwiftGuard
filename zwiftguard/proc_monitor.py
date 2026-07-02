# Copyright (c) 2026 Jason Drummond. All rights reserved.
# Proprietary software: see the "Proprietary License" file in this
# repository. No use, copying, or redistribution without written consent.
"""Process monitor: flags known sensor emulators and BLE/ANT bridge software."""

from __future__ import annotations

import asyncio
from typing import Any

import psutil

from .engine import IntegrityEngine


class ProcessMonitor:
    def __init__(self, engine: IntegrityEngine, config: dict[str, Any]):
        self.engine = engine
        self.cfg = config
        self.patterns = [p.lower() for p in config.get("process_blocklist", [])]

    def _scan(self) -> list[tuple[int, str, str, str]]:
        hits = []
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                name = (proc.info["name"] or "").lower()
                exe = (proc.info["exe"] or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            for pat in self.patterns:
                if pat in name or pat in exe:
                    hits.append((proc.info["pid"], proc.info["name"] or "",
                                 proc.info["exe"] or "", pat))
                    break
        return hits

    async def run(self, stop: asyncio.Event) -> None:
        interval = self.cfg.get("process_poll_interval", 10)
        self.engine.emit("INFO", "proc-monitor",
                         f"Process watch running ({len(self.patterns)} blocklist patterns)")
        while not stop.is_set():
            try:
                for pid, name, exe, pat in await asyncio.to_thread(self._scan):
                    self.engine.observe_blocked_process(pid, name, exe, pat)
            except Exception as e:
                self.engine.emit("WARN", "proc-monitor", f"Process scan error: {e}")
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
