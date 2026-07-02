# Copyright (c) 2026 Jason Drummond. All rights reserved.
# Proprietary software: see the "Proprietary License" file in this
# repository. No use, copying, or redistribution without written consent.
"""Live rider power feed.

Connects to the trainer/power meter's standard BLE Cycling Power service
(0x1818) and streams instantaneous power + cadence into the engine — an
independent second witness to the numbers Zwift is receiving.

Safety: it only ever connects to a device that is CURRENTLY ADVERTISING.
A sensor that Zwift holds exclusively over BLE stops advertising, so this
monitor can never steal or disturb Zwift's own connection. (Trainers used
via ANT+ or Direct Connect — and most modern multi-connection trainers —
keep a free BLE slot advertising; that is what we attach to.)
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any, Optional

from bleak import BleakClient

from .engine import IntegrityEngine

CPM_CHAR = "00002a63-0000-1000-8000-00805f9b34fb"  # Cycling Power Measurement


def parse_cpm(data: bytes) -> tuple[Optional[int], Optional[tuple[int, int]]]:
    """Return (instantaneous_watts, (cum_crank_revs, last_crank_event_1024s) | None)."""
    if len(data) < 4:
        return None, None
    flags, watts = struct.unpack_from("<Hh", data, 0)
    off = 4
    if flags & 0x0001:      # pedal power balance
        off += 1
    if flags & 0x0004:      # accumulated torque
        off += 2
    if flags & 0x0010:      # wheel revolution data
        off += 6
    crank = None
    if flags & 0x0020 and len(data) >= off + 4:  # crank revolution data
        crank = struct.unpack_from("<HH", data, off)
    return watts, crank


class CadenceTracker:
    """Cadence from cumulative crank revolutions + 1/1024s event times."""

    def __init__(self) -> None:
        self._prev: Optional[tuple[int, int]] = None
        self.rpm: Optional[int] = None

    def update(self, crank: Optional[tuple[int, int]]) -> Optional[int]:
        if crank is None:
            return self.rpm
        if self._prev is not None:
            revs = (crank[0] - self._prev[0]) & 0xFFFF
            ticks = (crank[1] - self._prev[1]) & 0xFFFF
            if ticks:
                self.rpm = round(revs * 60 * 1024 / ticks)
            elif revs == 0:
                self.rpm = 0   # crank stopped: same event time re-sent
        self._prev = crank
        return self.rpm


class PowerMonitor:
    def __init__(self, engine: IntegrityEngine, config: dict[str, Any]):
        self.engine = engine
        self.cfg = config

    def _pick_target(self) -> Optional[tuple[str, str]]:
        """Freshest advertising BLE device with the Cycling Power service."""
        best = None
        for fp in self.engine.devices.values():
            if fp.source != "ble" or "1818" not in fp.services:
                continue
            if best is None or fp.last_seen > best.last_seen:
                best = fp
        return (best.address, best.name) if best else None

    async def run(self, stop: asyncio.Event) -> None:
        if not self.cfg.get("live_power_monitor", True):
            return
        self.engine.emit("INFO", "power-monitor",
                         "Live power feed armed: waiting for an advertising power source")
        while not stop.is_set():
            target = self._pick_target()
            if target is None:
                await _sleep(stop, 5)
                continue
            address, name = target
            tracker = CadenceTracker()

            def on_data(_char, data: bytes) -> None:
                watts, crank = parse_cpm(bytes(data))
                if watts is not None:
                    self.engine.observe_power(int(watts), tracker.update(crank))

            try:
                async with BleakClient(address, timeout=15) as client:
                    self.engine.set_power_source(name or address, True)
                    self.engine.emit("INFO", "power-monitor",
                                     f"Live power feed connected to '{name}' ({address}) via BLE "
                                     f"Cycling Power — independent of Zwift's connection")
                    await client.start_notify(CPM_CHAR, on_data)
                    await stop.wait()
                    try:
                        await client.stop_notify(CPM_CHAR)
                    except Exception:
                        pass
            except Exception as e:
                self.engine.set_power_source(name or address, False)
                self.engine.emit("INFO", "power-monitor",
                                 f"Power feed unavailable ({e.__class__.__name__}: {e}) — retrying",
                                 dedupe=f"pmfail:{address}")
                await _sleep(stop, 10)
            else:
                self.engine.set_power_source(name or address, False)
                if not stop.is_set():
                    self.engine.emit("INFO", "power-monitor",
                                     f"Power feed to '{name}' dropped — reconnecting")
                    await _sleep(stop, 5)


async def _sleep(stop: asyncio.Event, secs: float) -> None:
    try:
        await asyncio.wait_for(stop.wait(), timeout=secs)
    except asyncio.TimeoutError:
        pass
