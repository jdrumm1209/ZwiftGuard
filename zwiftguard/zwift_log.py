"""Zwift session-log tailer.

Zwift writes a live log to ~/Documents/Zwift/Logs/Log.txt for the current
session. It records which devices the game itself paired with (ANT+ device
IDs, BLE sensor names, FTMS connections). Tailing it gives us Zwift's OWN
view of the equipment, which we cross-check against what is really on the
air:

  - the ANT+ device ID for a role (power / HR / FE-C) changing mid-ride
    is flagged by the engine (R10);
  - a BLE pairing for a device we never saw advertising is flagged (R09) —
    that device reached Zwift through a bridge (Companion app, second
    adapter) or does not exist as hardware at all.

Zwift's log format is not documented and shifts between releases, so the
patterns below are deliberately broad and every match carries the raw log
line as evidence. Tune them in zwift_log.py if a new client version changes
the wording.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from .config import default_zwift_log_path
from .engine import IntegrityEngine

# (kind, compiled regex). Named groups: name, id (both optional per pattern).
# Order matters: exact formats verified against a real 2026 PC-client log
# come first, broad fallbacks for other client versions last.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    # "[BLE] Device selected for role (device: HR Strap 43692, role: HR)"
    ("ble", re.compile(r"\[BLE\]\s*Device selected for role\s*\(device:\s*(?P<name>[^,)]+),\s*role:\s*(?P<role>\w+)", re.IGNORECASE)),
    # '[BLE] Device: "HR Strap 43692" has new connection status: connected'
    ("ble", re.compile(r"Device:\s*\"(?P<name>[^\"]+)\"\s*has new connection status:\s*connected", re.IGNORECASE)),
    # '[BLE] WFTNPDeviceManager::Pairing device "Wahoo KICKR 6BA3 93"'
    ("ble", re.compile(r"WFTNPDeviceManager::Pairing device\s*\"(?P<name>[^\"]+)\"", re.IGNORECASE)),
    # 'CreateWFTNPDevice for "Wahoo KICKR 6BA3"' -> direct-connect (LAN) trainer
    ("tnp", re.compile(r"CreateWFTNPDevice for\s*\"(?P<name>[^\"]+?)(?:\._wahoo[\w\-\.]*)?\"", re.IGNORECASE)),
    # '[BLE] WFTNPDeviceManager: connecting to LAN device "Wahoo KICKR 6BA3"'
    ("tnp", re.compile(r"WFTNPDeviceManager:\s*connecting to LAN device\s*\"(?P<name>[^\"]+)\"", re.IGNORECASE)),
    # "[ANT_IMPORTANT] Pairing deviceID 43692 to channel 1, ..."
    ("ant", re.compile(r"\[ANT[_A-Z]*\]\s*Pairing deviceID\s*(?P<id>\d{2,7})\s*to channel\s*(?P<name>\d+)", re.IGNORECASE)),
    # "[ANT] dID 1141667 MFG 32 Model 1" (full ANT device identification)
    ("ant", re.compile(r"\[ANT\]\s*dID\s*(?P<id>\d{3,10})\b", re.IGNORECASE)),
    # "POWER SOURCE: Interval Stats: device = Wahoo KICKR 6BA3 93, count = ..."
    ("generic", re.compile(r"(?:POWER SOURCE|CADENCE|HEART RATE):\s*Interval Stats:\s*device\s*=\s*(?P<name>[^,]+),", re.IGNORECASE)),
    # ---- broad fallbacks for other client versions ----
    ("ant", re.compile(r"ant\S*\s*[:\]].*?(?:registered device|device\s*id)\D{0,6}(?P<id>\d{3,7})", re.IGNORECASE)),
    ("ble", re.compile(r"(?<![a-z])ble\s*[:\]].*?(?:connect(?:ing|ed)?|pair(?:ing|ed)?|found sensor|saved device)\b\s*(?:to|with|:)\s*(?P<name>[A-Za-z0-9][\w\s\.\-#]{2,40})", re.IGNORECASE)),
    ("generic", re.compile(r"\bpaired\b.*?\b(?:device|sensor)\b\s*:?\s*(?P<name>[A-Za-z0-9][\w\s\.\-#]{2,40})", re.IGNORECASE)),
    ("generic", re.compile(r"(?:power source|controllable trainer|heart rate monitor)\s*(?:set to|is|:)\s*(?P<name>[A-Za-z0-9][\w\s\.\-#]{2,40})", re.IGNORECASE)),
    ("ant", re.compile(r"\bpaired\s+(?P<name>power|pwr|hr|heart\s*rate|cadence|speed|fe-?c|controllable)\b\D{0,15}(?P<id>\d{3,6})", re.IGNORECASE)),
]


class ZwiftLogMonitor:
    def __init__(self, engine: IntegrityEngine, config: dict[str, Any]):
        self.engine = engine
        self.cfg = config
        self.path = Path(config.get("zwift_log_path") or default_zwift_log_path())
        self._pos = 0
        self._announced_missing = False

    _PLAYER_ID_RE = re.compile(r"player\s*id\D{0,6}(\d{4,12})", re.IGNORECASE)
    # "[ANT] dID 1141667 MFG 32 Model 1" -> manufacturer/model identification
    _ANT_IDENT_RE = re.compile(r"\[ANT\]\s*dID\s*(\d{3,10})\s*MFG\s*(\d+)\s*Model\s*(\d+)", re.IGNORECASE)
    # Equipment link-state changes reported by Zwift itself
    _STATUS_RES = [
        (re.compile(r"Device:\s*\"([^\"]+)\"\s*has new connection status:\s*disconnect", re.IGNORECASE),
         "disconnected"),
        (re.compile(r"\[BLE\]\s*Unpair\s*\"([^\"]+)\"", re.IGNORECASE), "unpaired"),
        (re.compile(r"WFTNPDeviceManager:\s*disconnecting LAN device\s*\"([^\"]+)\"", re.IGNORECASE),
         "disconnected (direct connect)"),
    ]

    def _parse_line(self, line: str) -> None:
        pid = self._PLAYER_ID_RE.search(line)
        if pid:
            self.engine.set_player_id(pid.group(1), line.strip())
            return
        ident_m = self._ANT_IDENT_RE.search(line)
        if ident_m:
            self.engine.observe_ant_ident(ident_m.group(1), int(ident_m.group(2)),
                                          int(ident_m.group(3)), line.strip())
            return
        for pat, status in self._STATUS_RES:
            m = pat.search(line)
            if m:
                self.engine.observe_equipment_status(m.group(1).strip(), status, line.strip())
                return
        for kind, pat in _PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            groups = m.groupdict()
            name = (groups.get("name") or "").strip().rstrip(".:,")
            ident = (groups.get("id") or "").strip()
            if not name and not ident:
                continue
            self.engine.observe_zwift_pairing(kind=kind, name=name, ident=ident,
                                              raw_line=line.strip(),
                                              role=(groups.get("role") or "").strip())
            return

    async def run(self, stop: asyncio.Event) -> None:
        interval = self.cfg.get("zwift_log_poll_interval", 2)
        self.engine.emit("INFO", "zwift-log", f"Watching Zwift log: {self.path}")
        while not stop.is_set():
            try:
                if self.path.exists():
                    size = self.path.stat().st_size
                    if size < self._pos:  # new session -> file recreated/truncated
                        self._pos = 0
                        self.engine.emit("INFO", "zwift-log", "Zwift log restarted (new session)")
                    if size > self._pos:
                        with self.path.open("r", encoding="utf-8", errors="replace") as f:
                            f.seek(self._pos)
                            for line in f:
                                self._parse_line(line)
                            self._pos = f.tell()
                    self._announced_missing = False
                elif not self._announced_missing:
                    self._announced_missing = True
                    self.engine.emit("WARN", "zwift-log",
                                     f"Zwift log not found at {self.path} — pairing cross-checks "
                                     f"disabled until Zwift starts (or set zwift_log_path in config)")
            except Exception as e:
                self.engine.emit("WARN", "zwift-log", f"Log tail error: {e}")
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
