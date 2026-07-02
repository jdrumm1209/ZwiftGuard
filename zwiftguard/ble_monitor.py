"""BLE advertisement monitor.

Passively scans Bluetooth LE advertisements and feeds every fitness-relevant
device into the engine: address (MAC), advertised name, RSSI, manufacturer
company IDs, and advertised services.

Passive observation matters here: we never connect to the sensors, so we do
not disturb the connection Zwift holds. A device that is *connected* to Zwift
typically stops advertising — the inventory is therefore built from the
pairing window at session start and from any device that keeps advertising
(most trainers keep a second advertising set alive; HRMs vary).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from bleak import BleakScanner

from .config import FITNESS_SERVICES
from .engine import IntegrityEngine

_BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def short_uuid(u: str) -> str:
    """Collapse a 128-bit Bluetooth base UUID to its 16-bit form ('1826')."""
    u = u.lower()
    if u.endswith(_BASE_UUID_SUFFIX) and u.startswith("0000"):
        return u[4:8]
    return u


async def get_local_adapter_macs() -> set[str]:
    """Best-effort read of this PC's own Bluetooth adapter address (WinRT)."""
    try:
        from winrt.windows.devices.bluetooth import BluetoothAdapter  # type: ignore
        adapter = await BluetoothAdapter.get_default_async()
        if adapter is None:
            return set()
        raw = adapter.bluetooth_address
        mac = ":".join(f"{(raw >> (8 * i)) & 0xFF:02X}" for i in reversed(range(6)))
        return {mac}
    except Exception:
        return set()


class BleMonitor:
    def __init__(self, engine: IntegrityEngine, config: dict[str, Any]):
        self.engine = engine
        self.cfg = config
        self._name_re = re.compile(config["watch_name_regex"], re.IGNORECASE)

    def _relevant(self, name: str, services: list[str]) -> bool:
        if any(s in FITNESS_SERVICES for s in services):
            return True
        return bool(name and self._name_re.search(name))

    def _on_advertisement(self, device, adv) -> None:
        services = [short_uuid(u) for u in (adv.service_uuids or [])]
        name = adv.local_name or device.name or ""
        if not self._relevant(name, services):
            return
        company_ids = sorted((adv.manufacturer_data or {}).keys())
        self.engine.observe_ble(
            address=device.address or "",
            name=name,
            rssi=adv.rssi,
            company_ids=company_ids,
            services=services,
        )

    async def run(self, stop: asyncio.Event) -> None:
        macs = await get_local_adapter_macs()
        if macs:
            self.engine.set_local_adapter_macs(macs)
            self.engine.emit("INFO", "ble-monitor",
                             f"Local Bluetooth adapter: {', '.join(sorted(macs))} "
                             f"(anything advertising from this address is a software emulator)")
        try:
            async with BleakScanner(self._on_advertisement):
                self.engine.emit("INFO", "ble-monitor", "BLE advertisement scan running")
                await stop.wait()
        except Exception as e:
            self.engine.emit("WARN", "ble-monitor",
                             f"BLE scanning unavailable: {e} (is Bluetooth switched on?)")
