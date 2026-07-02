# Copyright (c) 2026 Jason Drummond. All rights reserved.
# Proprietary software: see the "Proprietary License" file. Personal,
# non-commercial use of official releases is permitted; all other use,
# copying, or redistribution requires written consent.
"""Readers for Zwift's local data caches.

Two sources, both read-only:

* ``Documents/Zwift/cp/user<playerid>/cp2_N`` — one binary file per ride
  holding the ride's critical-power curve. Format (little-endian), verified
  against real files: uint32 version (=1), uint32 unix timestamp,
  uint32 reserved, then (uint16 duration_seconds, uint16 best_watts) pairs
  to EOF. Scanning every file yields the rider's genuine all-time bests —
  the reference curve the power-integrity rules compare against.

* ``Documents/Zwift/knowndevices.xml`` — Zwift's own memory of every sensor
  it has ever paired with. Equipment appearing in a session that Zwift has
  never seen before is worth an inventory note.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Optional

from .config import _documents_dir

# dashboard/profile windows: label -> seconds
BEST_WINDOWS = {"5s": 5, "1m": 60, "5m": 300, "20m": 1200}


def zwift_dir() -> Path:
    return _documents_dir() / "Zwift"


def parse_cp2(data: bytes) -> dict[int, int]:
    """duration_seconds -> best_watts for one ride file."""
    out: dict[int, int] = {}
    if len(data) < 12:
        return out
    version, _ts, _res = struct.unpack_from("<III", data, 0)
    if version != 1:
        return out
    for off in range(12, len(data) - 3, 4):
        dur, watts = struct.unpack_from("<HH", data, off)
        if dur == 0 or watts > 3000:  # corrupt tail guard
            continue
        if watts > out.get(dur, 0):
            out[dur] = watts
    return out


def cp_user_dir(player_id: str = "") -> Optional[Path]:
    cp = zwift_dir() / "cp"
    if not cp.is_dir():
        return None
    if player_id and (cp / f"user{player_id}").is_dir():
        return cp / f"user{player_id}"
    users = [d for d in cp.iterdir() if d.is_dir() and d.name.startswith("user")]
    if not users:
        return None
    # No/unknown player id: pick the most recently ridden profile.
    return max(users, key=lambda d: max((f.stat().st_mtime for f in d.iterdir()), default=0))


def load_power_bests(player_id: str = "") -> Optional[dict]:
    """All-time bests for the standard windows from the whole cp cache."""
    udir = cp_user_dir(player_id)
    if udir is None:
        return None
    curve: dict[int, int] = {}
    files = 0
    for f in udir.glob("cp2_*"):
        try:
            for dur, watts in parse_cp2(f.read_bytes()).items():
                if watts > curve.get(dur, 0):
                    curve[dur] = watts
        except OSError:
            continue
        files += 1
    if not curve:
        return None
    bests: dict[str, int] = {}
    for label, target in BEST_WINDOWS.items():
        if target in curve:
            bests[label] = curve[target]
        else:  # nearest recorded duration within 5%
            near = [d for d in curve if abs(d - target) <= target * 0.05]
            if near:
                bests[label] = curve[min(near, key=lambda d: abs(d - target))]
    return {
        "bests_w": bests,
        "rides_scanned": files,
        "player_dir": udir.name,
        "ftp_estimate_w": round(bests["20m"] * 0.95) if "20m" in bests else 0,
    }


_KNOWN_RE = re.compile(r"<DEVICE>\s*(?:\[[^\]]*\]\s*)*([^<\[][^<]*?)\s*</DEVICE>", re.IGNORECASE)


def load_known_devices() -> list[str]:
    """Device names from Zwift's knowndevices.xml (may be empty)."""
    path = zwift_dir() / "knowndevices.xml"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    names = []
    for m in _KNOWN_RE.finditer(text):
        name = m.group(1).strip()
        if name and name.lower() != "unknown device":
            names.append(name)
    return sorted(set(names))
